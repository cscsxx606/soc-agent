#!/usr/bin/env python3
"""Playbook 管理 API"""

import os
import sys
import json
import yaml
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    @app.route('/api/admin/playbooks/list')
    @login_required
    def list_playbooks():
        conn = get_db()
        rows = conn.execute("SELECT * FROM playbooks ORDER BY id DESC").fetchall()
        conn.close()
        return jsonify({
            'success': True,
            'playbooks': [dict(r) for r in rows]
        })

    @app.route('/api/admin/playbooks/get/<int:pid>')
    @login_required
    def get_playbook(pid):
        conn = get_db()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'success': False, 'error': '不存在'}), 404
        return jsonify({'success': True, 'playbook': dict(row)})

    @app.route('/api/admin/playbooks/create', methods=['POST'])
    @role_required('admin')
    def create_playbook():
        data = request.get_json()
        pb_id = data.get('playbook_id', '').strip()
        name = data.get('name', '').strip()
        yaml_content = data.get('yaml_content', '')

        if not pb_id or not name or not yaml_content:
            return jsonify({'success': False, 'error': 'ID/名称/YAML 内容必填'}), 400

        # 简单 YAML 校验（支持 frontmatter）
        try:
            yaml_text = yaml_content
            if yaml_text.startswith('---\n'):
                yaml_text = yaml_text[4:]
            docs = yaml_text.split('\n---\n')
            for d in docs:
                if d.strip():
                    yaml.safe_load(d)
        except yaml.YAMLError as e:
            return jsonify({'success': False, 'error': f'YAML 格式错误: {e}'}), 400

        try:
            conn = get_db()
            conn.execute("""
                INSERT INTO playbooks (playbook_id, name, description, yaml_content,
                                       trigger_alert_type, trigger_severity, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                pb_id, name, data.get('description', ''), yaml_content,
                data.get('trigger_alert_type', ''),
                json.dumps(data.get('trigger_severity', [])),
                getattr(request, 'username', 'system')
            ))
            conn.commit()
            conn.close()

            log_action('create', 'playbooks', pb_id, f'创建 Playbook: {name}')
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/playbooks/update/<int:pid>', methods=['POST'])
    @role_required('admin')
    def update_playbook(pid):
        data = request.get_json()
        yaml_content = data.get('yaml_content', '')

        try:
            yaml_text = yaml_content
            if yaml_text.startswith('---\n'):
                yaml_text = yaml_text[4:]
            docs = yaml_text.split('\n---\n')
            for d in docs:
                if d.strip():
                    yaml.safe_load(d)
        except yaml.YAMLError as e:
            return jsonify({'success': False, 'error': f'YAML 格式错误: {e}'}), 400

        conn = get_db()
        old = conn.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()

        if not old:
            conn.close()
            return jsonify({'success': False, 'error': '不存在'}), 404

        # 备份旧版本到 yml 文件
        if old and old['yaml_content']:
            backup_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'playbooks', 'backup')
            os.makedirs(backup_dir, exist_ok=True)
            backup_file = os.path.join(backup_dir, f"{old['playbook_id']}_v{old['version']}_{int(datetime.now().timestamp())}.yml")
            with open(backup_file, 'w', encoding='utf-8') as f:
                f.write(old['yaml_content'])

        conn.execute("""
            UPDATE playbooks
            SET name=?, description=?, yaml_content=?,
                trigger_alert_type=?, trigger_severity=?, enabled=?,
                version=version+1, updated_at=CURRENT_TIMESTAMP, updated_by=?
            WHERE id=?
        """, (
            data.get('name', old['name']),
            data.get('description', old['description']),
            yaml_content,
            data.get('trigger_alert_type', old['trigger_alert_type']),
            json.dumps(data.get('trigger_severity', json.loads(old['trigger_severity'] or '[]'))),
            data.get('enabled', old['enabled']),
            getattr(request, 'username', 'system'),
            pid
        ))
        conn.commit()
        conn.close()

        log_action('update', 'playbooks', str(pid), f'更新 Playbook: {old["name"]}')
        return jsonify({'success': True})

    @app.route('/api/admin/playbooks/delete/<int:pid>', methods=['POST'])
    @role_required('admin')
    def delete_playbook(pid):
        conn = get_db()
        conn.execute("DELETE FROM playbooks WHERE id=?", (pid,))
        conn.commit()
        conn.close()
        log_action('delete', 'playbooks', str(pid), '删除 Playbook')
        return jsonify({'success': True})

    @app.route('/api/admin/playbooks/toggle/<int:pid>', methods=['POST'])
    @login_required
    def toggle_playbook(pid):
        conn = get_db()
        row = conn.execute("SELECT enabled FROM playbooks WHERE id=?", (pid,)).fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': '不存在'}), 404

        new_state = 0 if row['enabled'] else 1
        conn.execute("UPDATE playbooks SET enabled=? WHERE id=?", (new_state, pid))
        conn.commit()
        conn.close()

        log_action('toggle', 'playbooks', str(pid), f'{"启用" if new_state else "禁用"} Playbook')
        return jsonify({'success': True, 'enabled': new_state})

    @app.route('/api/admin/playbooks/test/<int:pid>', methods=['POST'])
    @login_required
    def test_playbook(pid):
        """用模拟告警测试 Playbook"""
        data = request.get_json() or {}
        conn = get_db()
        pb = conn.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()
        conn.close()

        if not pb:
            return jsonify({'success': False, 'error': 'Playbook 不存在'}), 404

        # 解析 YAML 获取触发条件和动作（去除前后的 --- 分隔符）
        try:
            yaml_text = pb['yaml_content']
            # 去掉开头的 ---
            if yaml_text.startswith('---\n'):
                yaml_text = yaml_text[4:]
            # 查找内部其他 --- 并只保留第一个文档
            docs = yaml_text.split('\n---\n')
            content = yaml.safe_load(docs[0])
        except Exception as e:
            return jsonify({'success': False, 'error': f'YAML 解析失败: {e}'}), 400

        test_alert = data.get('alert', {
            "id": "PB-TEST-001",
            "alert_type": pb['trigger_alert_type'] or 'unknown',
            "severity": "high",
            "source_ip": "203.0.113.99",
            "dest_ip": "10.0.0.99"
        })

        # 检查是否匹配触发条件
        triggered = True
        if pb['trigger_alert_type'] and test_alert.get('alert_type') != pb['trigger_alert_type']:
            triggered = False

        return jsonify({
            'success': True,
            'triggered': triggered,
            'alert': test_alert,
            'parsed_content': content,
            'playbook_name': pb['name']
        })
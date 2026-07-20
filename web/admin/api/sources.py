#!/usr/bin/env python3
"""数据源管理 API"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    @app.route('/api/admin/sources/list')
    @login_required
    def list_sources():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM data_sources ORDER BY id DESC").fetchall()
        return jsonify({
            'success': True,
            'sources': [dict(r) for r in rows]
        })

    @app.route('/api/admin/sources/create', methods=['POST'])
    @role_required('admin')
    def create_source():
        data = request.get_json()
        name = data.get('name', '').strip()
        stype = data.get('type', '').strip()
        config = data.get('config', {})

        if not name or not stype:
            return jsonify({'success': False, 'error': '名称和类型必填'}), 400

        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO data_sources (name, type, config_json, enabled)
                    VALUES (?, ?, ?, ?)
                """, (name, stype, json.dumps(config, ensure_ascii=False), data.get('enabled', 1)))
                conn.commit()

            log_action('create', 'sources', name, f'创建数据源: {stype}')
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/sources/update/<int:sid>', methods=['POST'])
    @role_required('admin')
    def update_source(sid):
        data = request.get_json()
        with get_db() as conn:
            conn.execute("""
                UPDATE data_sources
                SET name=?, type=?, config_json=?, enabled=?, updated_at=?
                WHERE id=?
            """, (
                data.get('name'),
                data.get('type'),
                json.dumps(data.get('config', {}), ensure_ascii=False),
                data.get('enabled', 1),
                datetime.now().isoformat(),
                sid
            ))
            conn.commit()

        log_action('update', 'sources', str(sid), f'更新数据源: {data.get("name")}')
        return jsonify({'success': True})

    @app.route('/api/admin/sources/delete/<int:sid>', methods=['POST'])
    @role_required('admin')
    def delete_source(sid):
        with get_db() as conn:
            conn.execute("DELETE FROM data_sources WHERE id=?", (sid,))
            conn.commit()
        log_action('delete', 'sources', str(sid), '删除数据源')
        return jsonify({'success': True})

    @app.route('/api/admin/sources/test', methods=['POST'])
    @login_required
    def test_source():
        """测试数据源连通性"""
        data = request.get_json()
        stype = data.get('type')
        config = data.get('config', {})

        try:
            if stype == 'file':
                path = config.get('path', '')
                if os.path.exists(path):
                    return jsonify({'success': True, 'message': f'文件存在: {path}'})
                return jsonify({'success': False, 'error': f'文件不存在: {path}'}), 400

            elif stype == 'splunk':
                import requests
                host = config.get('host')
                port = config.get('port', 8089)
                token = config.get('token')
                resp = requests.get(
                    f"https://{host}:{port}/services/auth/login",
                    headers={'Authorization': f'Bearer {token}'},
                    verify=False,
                    timeout=10
                )
                return jsonify({'success': resp.status_code == 200, 'message': f'Splunk 响应: {resp.status_code}'})

            elif stype == 'elk':
                import requests
                host = config.get('host')
                port = config.get('port', 9200)
                user = config.get('username')
                pwd = config.get('password')
                resp = requests.get(
                    f"http://{host}:{port}/",
                    auth=(user, pwd) if user else None,
                    timeout=10
                )
                return jsonify({'success': resp.status_code == 200, 'message': f'Elasticsearch 响应: {resp.status_code}'})

            elif stype == 'wazuh':
                import requests
                host = config.get('host')
                port = config.get('port', 55000)
                user = config.get('username')
                pwd = config.get('password')
                resp = requests.post(
                    f"https://{host}:{port}/security/user/authenticate",
                    auth=(user, pwd),
                    verify=False,
                    timeout=10
                )
                return jsonify({'success': resp.status_code == 200, 'message': f'Wazuh 响应: {resp.status_code}'})

            elif stype == 'edr':
                """Osquery EDR 探针连接测试"""
                import requests
                host = config.get('host', 'soc-edr')
                port = config.get('port', 9000)
                try:
                    resp = requests.get(
                        f"http://{host}:{port}/api/edr/health",
                        timeout=10
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return jsonify({
                            'success': True,
                            'message': f"EDR 连接成功，已注册 {data.get('enrolled_hosts', 0)} 台主机"
                        })
                    return jsonify({'success': False, 'error': f'EDR 响应异常: {resp.status_code}'}), 400
                except requests.exceptions.ConnectionError:
                    return jsonify({'success': False, 'error': '无法连接 EDR 服务，请确认 soc-edr 容器已启动'}), 400
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)}), 400

            else:
                return jsonify({'success': True, 'message': '测试模拟通过（演示模式）'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/sources/sync/<int:sid>', methods=['POST'])
    @login_required
    def sync_source(sid):
        """手动触发同步"""
        with get_db() as conn:
            source = conn.execute("SELECT * FROM data_sources WHERE id=?", (sid,)).fetchone()
            if not source:
                return jsonify({'success': False, 'error': '数据源不存在'}), 404

            try:
                # 实际同步逻辑（演示用）
                # 真实场景下应该调用 data_source.py 中的对应适配器
                conn.execute("""
                    UPDATE data_sources
                    SET last_sync=?, last_status='success', last_error=NULL
                    WHERE id=?
                """, (datetime.now().isoformat(), sid))
                conn.commit()
            except Exception as e:
                conn.execute("""
                    UPDATE data_sources
                    SET last_sync=?, last_status='failed', last_error=?
                    WHERE id=?
                """, (datetime.now().isoformat(), str(e), sid))
                conn.commit()
                return jsonify({'success': False, 'error': str(e)}), 400

        log_action('sync', 'sources', str(sid), f'同步数据源: {source["name"]}')
        return jsonify({'success': True, 'message': '同步任务已启动'})
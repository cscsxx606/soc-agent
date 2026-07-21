#!/usr/bin/env python3
"""系统设置 API"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    @app.route('/api/admin/settings/list')
    @login_required
    def list_settings():
        conn = get_db()
        rows = conn.execute("SELECT key, value, category, encrypted, updated_at FROM settings ORDER BY category, key").fetchall()
        conn.close()

        # 加密的密钥值不返回明文
        result = []
        for r in rows:
            d = dict(r)
            if d['encrypted'] and d['value']:
                d['value'] = '******' + d['value'][-4:] if len(d['value']) > 4 else '********'
                d['has_value'] = True
            else:
                d['has_value'] = bool(d['value'])
            result.append(d)

        # 按 category 分组
        grouped = {}
        for r in result:
            cat = r['category']
            grouped.setdefault(cat, []).append(r)

        return jsonify({'success': True, 'settings': grouped, 'flat': result})

    @app.route('/api/admin/settings/update', methods=['POST'])
    @role_required('admin')
    def update_setting():
        data = request.get_json()
        key = data.get('key')
        value = data.get('value', '')

        if not key:
            return jsonify({'success': False, 'error': '键名必填'}), 400

        conn = get_db()
        conn.execute("""
            UPDATE settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key=?
        """, (value, key))
        conn.commit()
        conn.close()

        log_action('update', 'settings', key, '更新系统设置')
        return jsonify({'success': True})

    @app.route('/api/admin/settings/test-notification', methods=['POST'])
    @role_required('admin')
    def test_notification():
        """测试通知通道"""
        data = request.get_json()
        channel = data.get('channel')  # feishu / email
        config = data.get('config', {})

        try:
            if channel == 'feishu':
                import requests
                webhook = config.get('webhook_url')
                if not webhook:
                    return jsonify({'success': False, 'error': 'Webhook URL 必填'}), 400

                resp = requests.post(webhook, json={
                    "msg_type": "text",
                    "content": {"text": "🛡️ AegisGuard 控制台通知测试\n\n这是一条测试消息。"}
                }, timeout=10)
                return jsonify({
                    'success': resp.status_code == 200,
                    'message': f'飞书响应: {resp.status_code} {resp.text[:200]}'
                })

            elif channel == 'email':
                # SMTP 测试
                import smtplib
                host = config.get('smtp_host')
                port = int(config.get('smtp_port', 587))
                user = config.get('username')
                pwd = config.get('password')

                if not host or not user:
                    return jsonify({'success': False, 'error': 'SMTP 配置不完整'}), 400

                server = smtplib.SMTP(host, port, timeout=10)
                server.starttls()
                server.login(user, pwd)
                server.quit()
                return jsonify({'success': True, 'message': 'SMTP 登录成功'})

            return jsonify({'success': False, 'error': '未知通道'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
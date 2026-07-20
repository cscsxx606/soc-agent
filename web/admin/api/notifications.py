#!/usr/bin/env python3
"""通知配置 API - 通道/模板管理 + 测试发送"""

import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    # ====== 通知通道 ======

    @app.route('/api/admin/notifications/channels')
    @login_required
    def notification_channels():
        tid = getattr(request, 'tenant_id', 1)
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM notification_channels WHERE tenant_id=? ORDER BY id", (tid,)).fetchall()
        return jsonify({'success': True, 'channels': [dict(r) for r in rows]})

    @app.route('/api/admin/notifications/channel/create', methods=['POST'])
    @role_required('admin')
    def notification_channel_create():
        data = request.get_json()
        tid = getattr(request, 'tenant_id', 1)
        try:
            with get_db() as conn:
                conn.execute("""INSERT INTO notification_channels
                    (tenant_id, name, channel, config_json, enabled)
                    VALUES (?, ?, ?, ?, ?)""",
                    (tid, data.get('name'), data.get('channel'),
                     json.dumps(data.get('config', {}), ensure_ascii=False),
                     data.get('enabled', 1)))
                conn.commit()
            log_action('create', 'notification_channel', data.get('name', ''), '创建通知通道')
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/notifications/channel/update/<int:cid>', methods=['POST'])
    @role_required('admin')
    def notification_channel_update(cid):
        data = request.get_json()
        try:
            with get_db() as conn:
                conn.execute("""UPDATE notification_channels SET
                    name=?, channel=?, config_json=?, enabled=?
                    WHERE id=?""",
                    (data.get('name'), data.get('channel'),
                     json.dumps(data.get('config', {}), ensure_ascii=False),
                     data.get('enabled', 1), cid))
                conn.commit()
            log_action('update', 'notification_channel', str(cid), '更新通知通道')
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/notifications/channel/delete/<int:cid>', methods=['POST'])
    @role_required('admin')
    def notification_channel_delete(cid):
        with get_db() as conn:
            conn.execute("DELETE FROM notification_channels WHERE id=?", (cid,))
            conn.commit()
        log_action('delete', 'notification_channel', str(cid), '删除通知通道')
        return jsonify({'success': True})

    @app.route('/api/admin/notifications/channel/test/<int:cid>', methods=['POST'])
    @role_required('admin')
    def notification_channel_test(cid):
        with get_db() as conn:
            row = conn.execute("SELECT * FROM notification_channels WHERE id=?", (cid,)).fetchone()
        if not row:
            return jsonify({'success': False, 'error': '通道不存在'}), 404
        from core.notification import Notifier
        n = Notifier()
        config = json.loads(row['config_json']) if isinstance(row['config_json'], str) else row['config_json']
        result = n.test_channel({'channel': row['channel'], 'config_json': config})
        with get_db() as conn:
            conn.execute("UPDATE notification_channels SET test_result=?, last_tested_at=CURRENT_TIMESTAMP WHERE id=?",
                         (json.dumps(result, ensure_ascii=False), cid))
            conn.commit()
        return jsonify({'success': result.get('success', False), 'result': result})

    # ====== 通知模板 ======

    @app.route('/api/admin/notifications/templates')
    @login_required
    def notification_templates():
        tid = getattr(request, 'tenant_id', 1)
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM notification_templates WHERE tenant_id=? ORDER BY id", (tid,)).fetchall()
        return jsonify({'success': True, 'templates': [dict(r) for r in rows]})

    @app.route('/api/admin/notifications/template/create', methods=['POST'])
    @role_required('admin')
    def notification_template_create():
        data = request.get_json()
        tid = getattr(request, 'tenant_id', 1)
        try:
            with get_db() as conn:
                conn.execute("""INSERT INTO notification_templates
                    (tenant_id, name, event_type, title_template, body_template, channels)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (tid, data.get('name'), data.get('event_type'),
                     data.get('title_template'), data.get('body_template'),
                     json.dumps(data.get('channels', []), ensure_ascii=False)))
                conn.commit()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/notifications/template/delete/<int:tid>', methods=['POST'])
    @role_required('admin')
    def notification_template_delete(tid):
        with get_db() as conn:
            conn.execute("DELETE FROM notification_templates WHERE id=?", (tid,))
            conn.commit()
        return jsonify({'success': True})

    # ====== 品牌配置 ======

    @app.route('/api/admin/branding/get')
    @login_required
    def branding_get():
        tid = getattr(request, 'tenant_id', 1)
        with get_db() as conn:
            row = conn.execute("SELECT * FROM branding WHERE tenant_id=?", (tid,)).fetchone()
        if not row:
            return jsonify({'success': True, 'branding': {
                'site_name': 'SOC 控制台', 'primary_color': '#6366f1', 'footer_text': ''}})
        return jsonify({'success': True, 'branding': dict(row)})

    @app.route('/api/admin/branding/update', methods=['POST'])
    @role_required('admin')
    def branding_update():
        data = request.get_json()
        tid = getattr(request, 'tenant_id', 1)
        with get_db() as conn:
            existing = conn.execute("SELECT id FROM branding WHERE tenant_id=?", (tid,)).fetchone()
            if existing:
                conn.execute("""UPDATE branding SET site_name=?, logo_url=?, favicon_url=?,
                    primary_color=?, footer_text=?, updated_at=CURRENT_TIMESTAMP
                    WHERE tenant_id=?""",
                    (data.get('site_name'), data.get('logo_url'), data.get('favicon_url'),
                     data.get('primary_color'), data.get('footer_text'), tid))
            else:
                conn.execute("""INSERT INTO branding
                    (tenant_id, site_name, logo_url, favicon_url, primary_color, footer_text)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (tid, data.get('site_name'), data.get('logo_url'), data.get('favicon_url'),
                     data.get('primary_color'), data.get('footer_text')))
            conn.commit()
        log_action('update', 'branding', f'tenant={tid}', '更新品牌配置')
        return jsonify({'success': True})

    # ====== 租户管理 ======

    @app.route('/api/admin/tenants/list')
    @role_required('admin')
    def tenant_list():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM tenants ORDER BY id").fetchall()
        return jsonify({'success': True, 'tenants': [dict(r) for r in rows]})

    @app.route('/api/admin/tenants/create', methods=['POST'])
    @role_required('admin')
    def tenant_create():
        data = request.get_json()
        try:
            with get_db() as conn:
                conn.execute("""INSERT INTO tenants
                    (tenant_key, name, contact_email, plan, max_users, max_assets)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (data.get('tenant_key'), data.get('name'), data.get('contact_email'),
                     data.get('plan', 'free'), data.get('max_users', 10), data.get('max_assets', 100)))
                conn.commit()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
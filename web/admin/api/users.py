#!/usr/bin/env python3
"""用户管理 API"""

import os
import sys
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, hash_password, log_action
from db import get_db


def register(app):

    @app.route('/api/admin/users/list')
    @role_required('admin')
    def list_users():
        conn = get_db()
        rows = conn.execute("""
            SELECT id, username, email, full_name, role, is_active,
                   created_at, last_login, api_token
            FROM users ORDER BY id
        """).fetchall()
        conn.close()

        # 不返回密码哈希
        users = []
        for r in rows:
            d = dict(r)
            d['api_token'] = d['api_token'][:20] + '...' if d['api_token'] else None
            users.append(d)

        return jsonify({'success': True, 'users': users})

    @app.route('/api/admin/users/create', methods=['POST'])
    @role_required('admin')
    def create_user():
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'analyst')

        if not username or not password:
            return jsonify({'success': False, 'error': '用户名和密码必填'}), 400

        if len(password) < 8:
            return jsonify({'success': False, 'error': '密码至少 8 个字符'}), 400
        # 复杂度检查：至少包含字母+数字
        import re
        if not re.search(r'[a-zA-Z]', password) or not re.search(r'\d', password):
            return jsonify({'success': False, 'error': '密码必须包含字母和数字'}), 400

        try:
            conn = get_db()
            conn.execute("""
                INSERT INTO users (username, password_hash, email, full_name, role)
                VALUES (?, ?, ?, ?, ?)
            """, (
                username,
                hash_password(password),
                data.get('email', ''),
                data.get('full_name', ''),
                role
            ))
            conn.commit()
            conn.close()

            log_action('create_user', 'users', username, f'创建用户: {username} ({role})')
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/users/update/<int:uid>', methods=['POST'])
    @role_required('admin')
    def update_user(uid):
        data = request.get_json()
        conn = get_db()

        # 不允许修改自己的角色（防误操作）
        current_user = getattr(request, 'username', None)
        target = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()

        if target and target['username'] == current_user and data.get('role'):
            conn.close()
            return jsonify({'success': False, 'error': '不能修改自己的角色'}), 400

        update_fields = []
        params = []
        if 'email' in data:
            update_fields.append('email=?')
            params.append(data['email'])
        if 'full_name' in data:
            update_fields.append('full_name=?')
            params.append(data['full_name'])
        if 'role' in data:
            update_fields.append('role=?')
            params.append(data['role'])
        if 'is_active' in data:
            update_fields.append('is_active=?')
            params.append(1 if data['is_active'] else 0)
        if data.get('password'):
            update_fields.append('password_hash=?')
            params.append(hash_password(data['password']))

        if not update_fields:
            conn.close()
            return jsonify({'success': False, 'error': '无修改字段'}), 400

        params.append(uid)
        conn.execute(f"UPDATE users SET {', '.join(update_fields)} WHERE id=?", params)
        conn.commit()
        conn.close()

        log_action('update_user', 'users', str(uid), f'更新用户 #{uid}')
        return jsonify({'success': True})

    @app.route('/api/admin/users/delete/<int:uid>', methods=['POST'])
    @role_required('admin')
    def delete_user(uid):
        conn = get_db()
        target = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()

        if target and target['username'] == getattr(request, 'username', None):
            conn.close()
            return jsonify({'success': False, 'error': '不能删除自己'}), 400

        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        conn.close()

        log_action('delete_user', 'users', str(uid), '删除用户')
        return jsonify({'success': True})

    @app.route('/api/admin/users/<int:uid>/token', methods=['POST'])
    @role_required('admin')
    def generate_token(uid):
        """生成 API Token"""
        token = secrets.token_urlsafe(32)
        conn = get_db()
        conn.execute("UPDATE users SET api_token=? WHERE id=?", (token, uid))
        conn.commit()
        conn.close()

        log_action('generate_token', 'users', str(uid), '生成 API Token')
        return jsonify({'success': True, 'token': token})
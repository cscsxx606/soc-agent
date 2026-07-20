#!/usr/bin/env python3
"""扫描目标/资产管理 API"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    @app.route('/api/admin/targets/list')
    @login_required
    def list_assets():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM target_assets ORDER BY criticality DESC, hostname").fetchall()
        return jsonify({
            'success': True,
            'assets': [dict(r) for r in rows]
        })

    @app.route('/api/admin/targets/create', methods=['POST'])
    @role_required('admin', 'analyst')
    def create_asset():
        data = request.get_json()
        if not data.get('hostname'):
            return jsonify({'success': False, 'error': '主机名必填'}), 400

        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO target_assets (hostname, ip_address, asset_type, role,
                                              business_unit, criticality, owner, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data['hostname'],
                    data.get('ip_address', ''),
                    data.get('asset_type', 'server'),
                    data.get('role', 'unknown'),
                    data.get('business_unit', ''),
                    data.get('criticality', 'medium'),
                    data.get('owner', ''),
                    data.get('tags', '')
                ))
                conn.commit()

            log_action('create', 'targets', data['hostname'], '新增资产')
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/targets/update/<int:aid>', methods=['POST'])
    @role_required('admin', 'analyst')
    def update_asset(aid):
        data = request.get_json()
        with get_db() as conn:
            conn.execute("""
                UPDATE target_assets
                SET hostname=?, ip_address=?, asset_type=?, role=?,
                    business_unit=?, criticality=?, owner=?, tags=?, enabled=?
                WHERE id=?
            """, (
                data.get('hostname'),
                data.get('ip_address'),
                data.get('asset_type'),
                data.get('role'),
                data.get('business_unit'),
                data.get('criticality'),
                data.get('owner'),
                data.get('tags'),
                data.get('enabled', 1),
                aid
            ))
            conn.commit()
        log_action('update', 'targets', str(aid), f'更新资产: {data.get("hostname")}')
        return jsonify({'success': True})

    @app.route('/api/admin/targets/delete/<int:aid>', methods=['POST'])
    @role_required('admin')
    def delete_asset(aid):
        with get_db() as conn:
            conn.execute("DELETE FROM target_assets WHERE id=?", (aid,))
            conn.commit()
        log_action('delete', 'targets', str(aid), '删除资产')
        return jsonify({'success': True})

    @app.route('/api/admin/targets/import', methods=['POST'])
    @role_required('admin', 'analyst')
    def import_assets():
        """批量导入资产 (CSV 格式)"""
        data = request.get_json()
        csv_text = data.get('csv', '')

        if not csv_text:
            return jsonify({'success': False, 'error': 'CSV 内容为空'}), 400

        import csv
        import io
        reader = csv.DictReader(io.StringIO(csv_text))
        added = 0
        errors = []

        with get_db() as conn:
            for row in reader:
                try:
                    conn.execute("""
                        INSERT INTO target_assets (hostname, ip_address, asset_type, role,
                                                  business_unit, criticality, owner, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row.get('hostname', '').strip(),
                        row.get('ip_address', '').strip(),
                        row.get('asset_type', 'server'),
                        row.get('role', 'unknown'),
                        row.get('business_unit', ''),
                        row.get('criticality', 'medium'),
                        row.get('owner', ''),
                        row.get('tags', '')
                    ))
                    added += 1
                except Exception as e:
                    errors.append(f"{row.get('hostname', '?')}: {e}")

            conn.commit()

        log_action('import', 'targets', 'batch', f'批量导入 {added} 个资产')
        return jsonify({'success': True, 'added': added, 'errors': errors})
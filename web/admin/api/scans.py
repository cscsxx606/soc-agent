#!/usr/bin/env python3
"""主动扫描 API - 端口/服务/Web 漏洞扫描（含白名单授权检查）"""

import os
import sys
import json
import time
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask import request, jsonify
from auth import login_required, role_required, log_action
from db import get_db


def _is_authorized(ip: str) -> bool:
    """检查 IP 是否在白名单内（合规检查）"""
    import ipaddress
    try:
        target = ipaddress.ip_address(ip)
    except Exception:
        return False

    with get_db() as conn:
        rows = conn.execute("SELECT ip_or_cidr FROM scan_whitelist").fetchall()
    for r in rows:
        cidr = r['ip_or_cidr']
        try:
            if '/' in cidr:
                if target in ipaddress.ip_network(cidr, strict=False):
                    return True
            else:
                # 域名 / IP
                try:
                    if str(target) == cidr:
                        return True
                except Exception:
                    # 域名比对（简化：跳过）
                    pass
        except Exception:
            continue
    return False


def _get_tools_status() -> dict:
    """检测后端工具可用性（nmap/nuclei/sqlmap）"""
    import shutil
    return {
        'python_builtin': True,
        'nmap': shutil.which('nmap') is not None,
        'nuclei': shutil.which('nuclei') is not None,
        'sqlmap': shutil.which('sqlmap') is not None,
    }


def register(app):

    @app.route('/api/admin/scans/whitelist/list')
    @login_required
    def whitelist_list():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM scan_whitelist ORDER BY id").fetchall()
        return jsonify({'success': True, 'whitelist': [dict(r) for r in rows]})

    @app.route('/api/admin/scans/whitelist/add', methods=['POST'])
    @role_required('admin')
    def whitelist_add():
        data = request.get_json()
        ip = (data.get('ip_or_cidr') or '').strip()
        if not ip:
            return jsonify({'success': False, 'error': 'ip_or_cidr 必填'}), 400
        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO scan_whitelist (ip_or_cidr, label, scope, created_by)
                    VALUES (?, ?, ?, ?)
                """, (ip, data.get('label', ''), data.get('scope', 'custom'),
                      getattr(request, 'username', 'admin')))
                conn.commit()
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        log_action(request, 'create', 'scan_whitelist', ip, f'添加白名单: {ip}')
        return jsonify({'success': True})

    @app.route('/api/admin/scans/whitelist/delete/<int:wid>', methods=['POST'])
    @role_required('admin')
    def whitelist_delete(wid):
        with get_db() as conn:
            row = conn.execute("SELECT ip_or_cidr FROM scan_whitelist WHERE id=?", (wid,)).fetchone()
            if not row:
                return jsonify({'success': False, 'error': '不存在'}), 404
            conn.execute("DELETE FROM scan_whitelist WHERE id=?", (wid,))
            conn.commit()
        log_action(request, 'delete', 'scan_whitelist', row['ip_or_cidr'], '删除白名单')
        return jsonify({'success': True})

    @app.route('/api/admin/scans/tools')
    @login_required
    def tools_status():
        return jsonify({'success': True, 'tools': _get_tools_status()})

    @app.route('/api/admin/scans/start', methods=['POST'])
    @role_required('admin', 'analyst')
    def scan_start():
        """启动一个扫描任务"""
        data = request.get_json()
        target_ip = (data.get('target_ip') or '').strip()
        target_hostname = data.get('target_hostname', '')
        scan_type = data.get('scan_type', 'asset')
        enable_web = data.get('enable_web_scan', True)
        target_id = data.get('target_id')

        if not target_ip:
            return jsonify({'success': False, 'error': 'target_ip 必填'}), 400

        # 1. 合规检查：白名单授权
        authorized = _is_authorized(target_ip)
        if not authorized:
            return jsonify({
                'success': False,
                'error': f'目标 {target_ip} 不在授权白名单内',
                'authorized': False,
                'hint': '请先在「白名单」中添加此 IP/CIDR（仅添加你有授权扫描的目标）'
            }), 403

        # 1.5 SSRF 防护
        from core.scanner import is_target_blocked
        blocked_reason = is_target_blocked(target_ip)
        if blocked_reason:
            return jsonify({
                'success': False,
                'error': f'目标被安全策略拦截: {blocked_reason}',
                'blocked': True
            }), 403

        # 2. 创建任务
        task_id = f'SCAN-{datetime.now().strftime("%Y%m%d%H%M%S")}-{uuid.uuid4().hex[:6]}'
        with get_db() as conn:
            conn.execute("""
                INSERT INTO scan_tasks (task_id, target_id, target_ip, target_hostname,
                                        scan_type, enable_web_scan, authorized, status,
                                        started_at, triggered_by)
                VALUES (?, ?, ?, ?, ?, ?, 1, 'running', CURRENT_TIMESTAMP, ?)
            """, (task_id, target_id, target_ip, target_hostname, scan_type,
                  1 if enable_web else 0, getattr(request, 'username', 'admin')))
            conn.commit()

        # 3. 执行扫描（同步阻塞，超时 180s）
        try:
            from core.scanner import AssetScanner
            scanner = AssetScanner()
            target_dict = {
                'id': target_id,
                'ip_address': target_ip,
                'hostname': target_hostname or target_ip,
                'criticality': data.get('criticality', 'medium'),
                'owner': data.get('owner', 'unknown')
            }
            result = scanner.scan_target(target_dict, enable_service_id=enable_web)

            # 4. Web 漏洞扫描（如果有 HTTP 服务）
            web_findings = []
            if enable_web:
                from core.web_vuln_scanner import WebVulnerabilityScanner
                wv = WebVulnerabilityScanner()
                if wv.is_available():
                    for service in result.get('services', []):
                        url = service.get('url')
                        if url:
                            web_result = wv.scan_url(url)
                            web_findings.append({
                                'url': url,
                                'risk_score': web_result['risk_score'],
                                'risk_level': web_result['risk_level'],
                                'findings': web_result['findings']
                            })
                            result['risk_score'] += web_result['risk_score']

            # 5. 更新任务
            result['web_findings'] = web_findings
            risk = result['risk_score']
            if risk >= 60:
                level = 'critical'
            elif risk >= 30:
                level = 'high'
            elif risk >= 10:
                level = 'medium'
            else:
                level = 'low'

            with get_db() as conn:
                conn.execute("""
                    UPDATE scan_tasks SET status='completed', completed_at=CURRENT_TIMESTAMP,
                        risk_score=?, risk_level=?, ports_open=?, summary=?
                    WHERE task_id=?
                """, (
                    risk, level, len(result['ports_open']),
                    f'{len(result["ports_open"])} ports open, {len(web_findings)} web services scanned, risk={risk} ({level})',
                    task_id
                ))
                conn.commit()

            # 保存结果
            scanner.save_result({**result, 'task_id': task_id})
            log_action(request, 'scan', 'scan_task', task_id,
                       f'扫描 {target_ip}: 风险分 {risk} ({level})')

            # 发送通知（扫描完成事件）
            try:
                from core.notification import Notifier
                with get_db() as conn2:
                    channels = conn2.execute("SELECT * FROM notification_channels WHERE tenant_id=1 AND enabled=1").fetchall()
                    templates = conn2.execute(
                        "SELECT * FROM notification_templates WHERE tenant_id=1 AND event_type='scan_completed'"
                    ).fetchall()
                if channels and templates:
                    n = Notifier([dict(c) for c in channels])
                    for tpl in templates:
                        n.send('scan_completed', dict(tpl), {
                            'scan': {
                                'hostname': target_hostname or target_ip,
                                'ip_address': target_ip,
                                'risk_level': level,
                                'risk_score': risk,
                                'port_count': len(result['ports_open']),
                                'scan_start': result.get('scan_start', ''),
                                'scan_duration': result.get('scan_duration', 0),
                                'recommendations': result.get('recommendations', [])
                            }
                        })
            except Exception as notif_err:
                import logging
                logging.getLogger(__name__).error(f'通知发送失败: {notif_err}')

            return jsonify({
                'success': True,
                'task_id': task_id,
                'authorized': True,
                'result': result,
                'risk_score': risk,
                'risk_level': level
            })

        except Exception as e:
            with get_db() as conn:
                conn.execute("""
                    UPDATE scan_tasks SET status='failed', completed_at=CURRENT_TIMESTAMP, summary=?
                    WHERE task_id=?
                """, (str(e)[:200], task_id))
                conn.commit()
            import traceback
            return jsonify({
                'success': False,
                'error': str(e),
                'trace': traceback.format_exc()[:500]
            }), 500

    @app.route('/api/admin/scans/list')
    @login_required
    def scans_list():
        limit = int(request.args.get('limit', 50))
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_tasks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return jsonify({'success': True, 'tasks': [dict(r) for r in rows]})

    @app.route('/api/admin/scans/result/<task_id>')
    @login_required
    def scan_result(task_id):
        from core.scanner import AssetScanner
        scanner = AssetScanner()
        result = scanner.get_result(task_id)
        if not result:
            return jsonify({'success': False, 'error': '结果不存在或已过期'}), 404
        return jsonify({'success': True, 'result': result})

    @app.route('/api/admin/scans/check-auth', methods=['POST'])
    @login_required
    def check_authorization():
        """检查 IP 是否在白名单内（扫描前预览）"""
        data = request.get_json()
        ip = (data.get('ip') or '').strip()
        if not ip:
            return jsonify({'success': False, 'error': 'ip 必填'}), 400
        authorized = _is_authorized(ip)
        return jsonify({
            'success': True,
            'ip': ip,
            'authorized': authorized,
            'message': '✅ 已授权，可以扫描' if authorized else '❌ 未在白名单内，请先添加'
        })

    @app.route('/api/admin/scans/stats')
    @login_required
    def scans_stats():
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0]
            running = conn.execute("SELECT COUNT(*) FROM scan_tasks WHERE status='running'").fetchone()[0]
            completed = conn.execute("SELECT COUNT(*) FROM scan_tasks WHERE status='completed'").fetchone()[0]
            failed = conn.execute("SELECT COUNT(*) FROM scan_tasks WHERE status='failed'").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM scan_tasks WHERE risk_level='critical'").fetchone()[0]
            high_risk = conn.execute("SELECT COUNT(*) FROM scan_tasks WHERE risk_level IN ('critical','high')").fetchone()[0]
            by_level = conn.execute("""
                SELECT risk_level, COUNT(*) as c FROM scan_tasks
                WHERE status='completed' GROUP BY risk_level
            """).fetchall()
            recent = conn.execute("""
                SELECT task_id, target_ip, target_hostname, risk_score, risk_level, ports_open, completed_at
                FROM scan_tasks WHERE status='completed' ORDER BY id DESC LIMIT 5
            """).fetchall()
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'running': running,
                'completed': completed,
                'failed': failed,
                'critical': critical,
                'high_risk': high_risk,
                'by_level': {r['risk_level']: r['c'] for r in by_level},
                'recent': [dict(r) for r in recent],
                'tools': _get_tools_status()
            }
        })
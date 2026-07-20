#!/usr/bin/env python3
"""Scan Scheduler API + Report Export API"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask import request, jsonify, send_file, Response
from auth import login_required, role_required, log_action
from db import get_db


def register(app):

    # ====== Scheduler APIs ======

    @app.route('/api/admin/scheduler/list')
    @login_required
    def scheduler_list():
        from core.scan_scheduler import ScanScheduler
        sched = ScanScheduler()
        return jsonify({'success': True, 'schedules': sched.list_schedules()})

    @app.route('/api/admin/scheduler/presets')
    @login_required
    def scheduler_presets():
        from core.scan_scheduler import ScanScheduler
        return jsonify({'success': True, 'presets': ScanScheduler.PRESETS})

    @app.route('/api/admin/scheduler/parse', methods=['POST'])
    @login_required
    def scheduler_parse():
        from core.scan_scheduler import CronParser
        data = request.get_json()
        expr = (data.get('cron_expr') or '').strip()
        if not expr:
            return jsonify({'success': False, 'error': 'cron_expr required'}), 400
        try:
            desc = CronParser.describe(expr)
            next_run = CronParser.next_fire_time(expr)
            return jsonify({
                'success': True,
                'cron_expr': expr,
                'description': desc,
                'next_run': next_run.isoformat() if next_run else None
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/admin/scheduler/create', methods=['POST'])
    @role_required('admin')
    def scheduler_create():
        from core.scan_scheduler import ScanScheduler
        data = request.get_json()
        name = (data.get('name') or '').strip()
        cron_expr = (data.get('cron_expr') or '').strip()
        if not name or not cron_expr:
            return jsonify({'success': False, 'error': 'name and cron_expr required'}), 400
        sched = ScanScheduler()
        result = sched.add_schedule(
            name=name,
            cron_expr=cron_expr,
            target_ids=data.get('target_ids') or [],
            target_ips=data.get('target_ips') or [],
            enable_web_scan=data.get('enable_web_scan', True),
            risk_alert_threshold=data.get('risk_alert_threshold', 30),
            notify_channel=data.get('notify_channel', 'log'),
            created_by=getattr(request, 'username', 'admin')
        )
        if result['success']:
            log_action(request, 'create', 'scan_schedule', result['schedule']['schedule_id'],
                       'Create schedule: ' + name + ' (' + cron_expr + ')')
        return jsonify(result)

    @app.route('/api/admin/scheduler/toggle/<schedule_id>', methods=['POST'])
    @role_required('admin')
    def scheduler_toggle(schedule_id):
        from core.scan_scheduler import ScanScheduler
        data = request.get_json() or {}
        enabled = data.get('enabled', True)
        sched = ScanScheduler()
        if sched.toggle_schedule(schedule_id, enabled):
            log_action(request, 'update', 'scan_schedule', schedule_id,
                       'Enable' if enabled else 'Disable')
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Schedule not found'}), 404

    @app.route('/api/admin/scheduler/delete/<schedule_id>', methods=['POST'])
    @role_required('admin')
    def scheduler_delete(schedule_id):
        from core.scan_scheduler import ScanScheduler
        sched = ScanScheduler()
        if sched.delete_schedule(schedule_id):
            log_action(request, 'delete', 'scan_schedule', schedule_id, 'Delete schedule')
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Schedule not found'}), 404

    @app.route('/api/admin/scheduler/history')
    @login_required
    def scheduler_history():
        from core.scan_scheduler import ScanScheduler
        sched = ScanScheduler()
        limit = int(request.args.get('limit', 20))
        return jsonify({'success': True, 'history': sched.get_history(limit)})

    @app.route('/api/admin/scheduler/start', methods=['POST'])
    @role_required('admin')
    def scheduler_start():
        from core.scan_scheduler import ScanScheduler
        sched = ScanScheduler()
        sched.start()
        return jsonify({'success': True, 'message': 'Scheduler started (background thread)'})

    @app.route('/api/admin/scheduler/status')
    @login_required
    def scheduler_status():
        from core.scan_scheduler import ScanScheduler
        sched = ScanScheduler()
        return jsonify({
            'success': True,
            'running': sched.running,
            'thread_alive': sched.thread.is_alive() if sched.thread else False,
            'total_schedules': len(sched.list_schedules())
        })

    # ====== Report Export APIs ======

    @app.route('/api/admin/scans/report/<task_id>/html')
    @login_required
    def report_html(task_id):
        from core.scanner import AssetScanner
        from core.report_generator import ReportGenerator
        scanner = AssetScanner()
        result = scanner.get_result(task_id)
        if not result:
            return jsonify({'success': False, 'error': 'Result expired'}), 404
        gen = ReportGenerator()
        html = gen.generate_html(result)
        filename = 'report_' + str(result['ip_address']) + '_' + task_id[:20] + '.html'
        log_action(request, 'export', 'scan_report', task_id, 'Export HTML: ' + filename)
        return Response(html, mimetype='text/html',
                       headers={'Content-Disposition': 'attachment; filename="' + filename + '"'})

    @app.route('/api/admin/scans/report/<task_id>/zip')
    @login_required
    def report_zip(task_id):
        from core.scanner import AssetScanner
        from core.report_generator import ReportGenerator
        scanner = AssetScanner()
        result = scanner.get_result(task_id)
        if not result:
            return jsonify({'success': False, 'error': 'Result expired'}), 404
        gen = ReportGenerator()
        zip_bytes = gen.generate_zip(result)
        filename = 'report_' + str(result['ip_address']) + '_' + task_id[:20] + '.zip'
        log_action(request, 'export', 'scan_report', task_id, 'Export ZIP: ' + filename)
        return Response(zip_bytes, mimetype='application/zip',
                       headers={'Content-Disposition': 'attachment; filename="' + filename + '"'})

    @app.route('/api/admin/scans/report/<task_id>/pdf')
    @login_required
    def report_pdf(task_id):
        """PDF 报告（使用 fpdf2 库）"""
        from core.scanner import AssetScanner
        from core.report_generator import ReportGenerator
        scanner = AssetScanner()
        result = scanner.get_result(task_id)
        if not result:
            return jsonify({'success': False, 'error': 'Result expired'}), 404
        try:
            from fpdf import FPDF
            import os, re

            def strip_non_ascii(s):
                if not isinstance(s, str): return str(s)
                return s.encode('ascii', errors='ignore').decode('ascii')

            pdf = FPDF()
            pdf.add_page()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.set_font('Helvetica', 'B', 16)
            title_text = strip_non_ascii('Scan Report: ' + str(result.get('hostname', result.get('ip_address', 'Unknown'))))
            pdf.cell(0, 15, title_text, ln=True)
            pdf.set_font('Helvetica', '', 10)
            pdf.cell(0, 8, 'IP: ' + strip_non_ascii(str(result.get('ip_address', ''))), ln=True)
            pdf.cell(0, 8, 'Risk Score: ' + str(result.get('risk_score', 0)) + '/100', ln=True)
            pdf.cell(0, 8, 'Open Ports: ' + str(result.get('port_count', 0)), ln=True)
            pdf.ln(5)
            ports = result.get('ports_open', [])
            if ports:
                pdf.set_font('Helvetica', 'B', 12)
                pdf.cell(0, 10, 'Open Ports (' + str(len(ports)) + ')', ln=True)
                pdf.set_font('Helvetica', '', 9)
                for p in ports:
                    line = 'Port ' + str(p.get('port', '')) + ' (' + strip_non_ascii(str(p.get('service', ''))) + ')'
                    pdf.cell(0, 6, line, ln=True)
            recs = result.get('recommendations', [])
            if recs:
                pdf.ln(3)
                pdf.set_font('Helvetica', 'B', 12)
                pdf.cell(0, 10, 'Recommendations', ln=True)
                pdf.set_font('Helvetica', '', 9)
                for rec in recs:
                    pdf.multi_cell(0, 6, '- ' + strip_non_ascii(str(rec)))
            pdf.ln(5)
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(0, 6, 'Generated by SOC Agent v2.0', ln=True)
            filename = 'report_' + str(result['ip_address']) + '_' + task_id[:20] + '.pdf'
            log_action(request, 'export', 'scan_report', task_id, 'Export PDF: ' + filename)
            import io
            return Response(io.BytesIO(pdf.output(dest='S')).getvalue(),
                           mimetype='application/pdf',
                           headers={'Content-Disposition': 'attachment; filename="' + filename + '"'})
        except ImportError:
            return jsonify({'success': False, 'error': 'PDF library not installed. Run: pip install fpdf2'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/admin/scans/report/<task_id>/preview')
    @login_required
    def report_preview(task_id):
        from core.scanner import AssetScanner
        from core.report_generator import ReportGenerator
        scanner = AssetScanner()
        result = scanner.get_result(task_id)
        if not result:
            return '<h1>Result not found or expired</h1>', 404
        gen = ReportGenerator()
        return gen.generate_html(result)

    @app.route('/api/admin/scans/reports/list')
    @login_required
    def reports_list():
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                    'reports')
        if not os.path.exists(reports_dir):
            return jsonify({'success': True, 'reports': []})
        files = []
        for f in sorted(os.listdir(reports_dir), reverse=True):
            if f.endswith('.html'):
                fp = os.path.join(reports_dir, f)
                stat = os.stat(fp)
                files.append({
                    'filename': f,
                    'size': stat.st_size,
                    'created_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'url': '/api/admin/scans/reports/file/' + f
                })
        return jsonify({'success': True, 'reports': files[:50]})

    @app.route('/api/admin/scans/reports/file/<filename>')
    @login_required
    def report_file(filename):
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                    'reports')
        # 安全检查
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400
        fp = os.path.join(reports_dir, filename)
        if not os.path.exists(fp):
            return jsonify({'success': False, 'error': 'File not found'}), 404
        return send_file(fp, as_attachment=False)
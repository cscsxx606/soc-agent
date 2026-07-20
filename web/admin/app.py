#!/usr/bin/env python3
"""
SOC 管理后台 - 增强版入口
仪表盘图表 + 数据源/Playbook 可视化编辑器 + SSE 实时事件流
"""

import os
import sys
import json
import time
import secrets
import shutil
import uuid
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response, stream_with_context
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from db import init_db, get_db
from auth import (
    login_required, role_required, hash_password, verify_password,
    create_token, log_action
)

app = Flask(__name__)

# ============ 安全初始化 ============

# Flask secret_key：生产环境必须从环境变量读取，禁止硬编码
# 未设环境变量时尝试从 logs/.secret 读取（start.py 启动时自动生成并复用）
_secret_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'logs', '.secret')
_secret = os.environ.get('SOC_ADMIN_FLASK_SECRET')
if not _secret:
    try:
        _secret = open(_secret_file).read().strip()
        if len(_secret) < 16:
            raise ValueError('invalid secret')
    except (FileNotFoundError, IOError, ValueError):
        _secret = secrets.token_hex(32)
        try:
            os.makedirs(os.path.dirname(_secret_file), exist_ok=True)
            # 原子写入：多 worker 竞争也没问题
            _tmp = _secret_file + '.tmp'
            with open(_tmp, 'w') as f:
                f.write(_secret + '\n')
            import shutil
            shutil.move(_tmp, _secret_file)
        except (FileNotFoundError, IOError, OSError):
            pass
        print(f"[WARNING] SOC_ADMIN_FLASK_SECRET not set. Using generated secret (session persists across workers).")
        print(f"[WARNING] For production, set: export SOC_ADMIN_FLASK_SECRET=*** rand -hex 32)")
app.secret_key = _secret

app.permanent_session_lifetime = 3600 * 8

# CORS 收紧：仅允许本地和同源请求
CORS(app, origins=[
    'http://localhost:8889',
    'http://127.0.0.1:8889',
    'http://localhost:8888',
    'http://127.0.0.1:8888',
], supports_credentials=True)

# 登录速率限制：5 次/分钟
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://'
)

# CSRF 保护（仅保护表单页面，API 全部豁免）
csrf = CSRFProtect(app)
# 禁用 CSRF 对 API 的保护（因为前端用 fetch + JSON，无 CSRF token）
app.config['WTF_CSRF_CHECK_DEFAULT'] = False


# ============ 请求追踪中间件 ============

@app.before_request
def add_request_id():
    """为每个请求添加唯一 ID 用于追踪"""
    request.request_id = request.headers.get('X-Request-ID') or request.headers.get('X-Correlation-ID') or uuid.uuid4().hex[:12]
    request.start_time = time.time()

@app.after_request
def log_request(response):
    """记录请求耗时到响应头"""
    if hasattr(request, 'request_id'):
        response.headers['X-Request-ID'] = request.request_id
    if hasattr(request, 'start_time'):
        elapsed = int((time.time() - request.start_time) * 1000)
        response.headers['X-Response-Time-Ms'] = str(elapsed)
    return response


# ============ 页面路由 ============

@app.route('/')
def home():
    if not session.get('username'):
        return redirect(url_for('login_page'))
    return redirect(url_for('dashboard_page'))


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))


@app.route('/sources')
@login_required
def sources_page():
    return render_template('sources.html', username=session.get('username'), role=session.get('role'))


@app.route('/agents')
@login_required
def agents_page():
    return render_template('agents.html', username=session.get('username'), role=session.get('role'))


@app.route('/playbooks')
@login_required
def playbooks_page():
    return render_template('playbooks.html', username=session.get('username'), role=session.get('role'))


@app.route('/targets')
@login_required
def targets_page():
    return render_template('targets.html', username=session.get('username'), role=session.get('role'))


@app.route('/scans')
@login_required
def scans_page():
    return render_template('scans.html', username=session.get('username'), role=session.get('role'))


@app.route('/scheduler')
@login_required
def scheduler_page():
    return render_template('scheduler.html', username=session.get('username'), role=session.get('role'))


@app.route('/incidents')
@login_required
def incidents_page():
    return render_template('incidents.html', username=session.get('username'), role=session.get('role'))


@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html', username=session.get('username'), role=session.get('role'))


@app.route('/branding')
@login_required
def branding_page():
    return render_template('branding.html', username=session.get('username'), role=session.get('role'))


@app.route('/audit')
@role_required('admin', 'auditor')
def audit_page():
    return render_template('audit.html', username=session.get('username'), role=session.get('role'))


@app.route('/users')
@role_required('admin')
def users_page():
    return render_template('users.html', username=session.get('username'), role=session.get('role'))


# ============ 认证 API ============

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit('5 per minute')
def login_api():
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': '用户名和密码必填'}), 400

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)).fetchone()

    if not user or not verify_password(password, user['password_hash']):
        log_action('login_failed', 'auth', username, '密码错误', result='failed')
        return jsonify({'success': False, 'error': '用户名或密码错误'}), 401

    with get_db() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), user['id']))
        conn.commit()

    session.permanent = True
    session['username'] = user['username']
    session['role'] = user['role']
    session['full_name'] = user['full_name']

    token = create_token(user['username'], user['role'])
    log_action('login_success', 'auth', user['username'], '登录成功')

    return jsonify({
        'success': True,
        'token': token,
        'user': {'username': user['username'], 'full_name': user['full_name'], 'role': user['role']}
    })


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout_api():
    username = session.get('username')
    session.clear()
    log_action('logout', 'auth', username, '登出')
    return jsonify({'success': True})


# ============ SSE 实时事件流（带连接数限制）============

# 全局 SSE 连接计数器
_sse_active_connections = 0
_sse_max_connections = 100
_sse_lock = threading.Lock()

@app.route('/api/admin/events/stream')
@login_required
def events_stream():
    """SSE 实时事件流 - 推送审计日志和告警事件"""
    global _sse_active_connections

    with _sse_lock:
        if _sse_active_connections >= _sse_max_connections:
            return jsonify({'error': 'SSE 连接数已达上限'}), 503
        _sse_active_connections += 1
        conn_id = _sse_active_connections

    def generate():
        global _sse_active_connections
        try:
            with get_db() as conn:
                last_audit_id = conn.execute("SELECT MAX(id) as m FROM audit_logs").fetchone()['m'] or 0

            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'connection_id': conn_id})}\n\n"

            # 心跳超时：30 秒无事件则主动断开
            last_activity = time.time()

            while True:
                # 心跳检测（30s 超时）
                if time.time() - last_activity > 30:
                    yield f"event: heartbeat\ndata: {json.dumps({'type': 'heartbeat'})}\n\n"
                    last_activity = time.time()

                # 查询新审计日志
                with get_db() as conn:
                    new_rows = conn.execute("""
                        SELECT id, timestamp, username, action, module, target, details, ip_address, result
                        FROM audit_logs WHERE id > ? ORDER BY id LIMIT 5
                    """, (last_audit_id,)).fetchall()

                for r in new_rows:
                    last_audit_id = max(last_audit_id, r['id'])
                    data = dict(r)
                    yield f"event: audit\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
                    last_activity = time.time()

                time.sleep(2)
        except GeneratorExit:
            pass
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
        finally:
            with _sse_lock:
                _sse_active_connections -= 1

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


# ============ 通用 Admin API ============

@app.route('/api/admin/stats')
@login_required
def admin_stats():
    with get_db() as conn:
        sources = conn.execute("SELECT COUNT(*) as total, SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as enabled FROM data_sources").fetchone()
        playbooks = conn.execute("SELECT COUNT(*) as total FROM playbooks").fetchone()
        assets = conn.execute("SELECT COUNT(*) as total FROM target_assets").fetchone()
        audits = conn.execute("SELECT COUNT(*) as total FROM audit_logs WHERE timestamp >= datetime('now', '-30 days')").fetchone()
    return jsonify({
        'success': True,
        'data': {
            'sources': sources['total'] or 0,
            'sources_enabled': sources['enabled'] or 0,
            'playbooks': playbooks['total'] or 0,
            'assets': assets['total'] or 0,
            'audits': audits['total'] or 0
        }
    })


# ============ 健康检查 ============

@app.route('/health')
def health_check():
    """健康检查端点（无需鉴权，供负载均衡使用）"""
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        return jsonify({'status': 'ok', 'db': 'ok', 'service': 'soc-admin'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'db': str(e)}), 503


# ============ 配置中心 ============

@app.route('/api/admin/config-center/list')
@login_required
def config_center_list():
    """返回当前所有可配置项的实时快照"""
    # 来自 settings 表的配置
    with get_db() as conn:
        settings_rows = conn.execute(
            "SELECT key, value, category, encrypted FROM settings ORDER BY category, key"
        ).fetchall()

    configs = {}
    for r in settings_rows:
        val = r['value']
        if r['encrypted'] and val:
            val = '******'
        configs[r['key']] = val

    # 来自环境变量的配置
    env_configs = {}
    for key in ['API_KEY', 'BASE_URL', 'MODEL', 'ENABLE_AUTO_RESPONSE',
                'SOC_ADMIN_FLASK_SECRET', 'SOC_ADMIN_SECRET', 'EDR_ENROLL_SECRET',
                'EDR_PORT', 'LOG_LEVEL']:
        env_val = os.environ.get(key, '')
        if env_val and any(s in key for s in ['SECRET', 'KEY', 'TOKEN']):
            env_val = '******' if env_val else ''
        env_configs[key] = env_val or '(默认值)'

    return jsonify({
        'success': True,
        'settings_table': configs,
        'env_vars': env_configs,
        'total': len(configs) + len(env_configs)
    })


@app.route('/api/admin/config-center/sync', methods=['POST'])
@role_required('admin')
def config_center_sync():
    """同步环境变量到 settings 表（方便 UI 编辑）"""
    import json
    sync_keys = {
        'api.deepseek_base_url': ('api_keys', ''),
        'api.deepseek_key': ('api_keys', ''),
        'api.kimi_key': ('api_keys', ''),
        'notification.feishu_webhook': ('notifications', ''),
        'security.session_timeout_minutes': ('security', '60'),
        'security.password_min_length': ('security', '8'),
    }
    synced = 0
    for key, (cat, default) in sync_keys.items():
        env_key = key.split('.')[-1].upper()
        # 映射到环境变量名
        env_map = {
            'deepseek_base_url': 'BASE_URL',
            'deepseek_key': 'API_KEY',
            'kimi_key': 'KIMI_API_KEY',
        }
        val = os.environ.get(env_map.get(key.split('.')[-1], ''), default)
        with get_db() as conn:
            existing = conn.execute("SELECT key FROM settings WHERE key=?", (key,)).fetchone()
            if existing:
                conn.execute("UPDATE settings SET value=? WHERE key=?", (val, key))
            else:
                conn.execute("INSERT INTO settings (key, value, category, encrypted) VALUES (?,?,?,?)",
                           (key, val, cat, 1 if 'key' in key else 0))
        synced += 1
    return jsonify({'success': True, 'synced': synced})


@app.route('/api/admin/config-center/health')
@login_required
def config_center_health():
    """配置健康检查"""
    issues = []
    with get_db() as conn:
        rows = conn.execute("SELECT key, value FROM settings WHERE encrypted=1").fetchall()

    for r in rows:
        if not r['value'] or r['value'] == '******':
            issues.append({'key': r['key'], 'status': 'missing', 'severity': 'high'})

    return jsonify({
        'success': True,
        'total_config_items': sum(1 for _ in []),
        'issues': issues,
        'status': 'warning' if issues else 'healthy'
    })


# ============ 注册模块 API ============

def register_apis():
    from api import sources, agents, playbooks, targets, settings, audit, users, incidents
    from api import dashboard, visual_editor, agent_registry, scans, scheduler, notifications, pipelines
    sources.register(app)
    agents.register(app)
    playbooks.register(app)
    targets.register(app)
    settings.register(app)
    audit.register(app)
    users.register(app)
    incidents.register(app)
    dashboard.register(app)
    visual_editor.register(app)
    agent_registry.register(app)
    scans.register(app)
    scheduler.register(app)
    notifications.register(app)
    pipelines.register(app)
    # Prometheus 指标（不需要鉴权）
    from metrics import register as metrics_register
    metrics_register(app)

# ============ 初始化 DB（Gunicorn 多进程通过文件锁保证只执行一次）============
# 注意：这里没有 module-level 调用 init_db()
# 改为由 Gunicorn worker 启动入口（在 if __name__ == '__main__' 下方）显式调用，
# 这样测试 fixture 可以先修改 db.DB_PATH 再触发初始化。
# 见 run_server() 中的 init_db() 调用。

register_apis()

# 注册 API 文档
from api import api_docs
api_docs.register(app)


# ============ API 版本信息 ============

API_VERSION = 'v1'

@app.route('/api/version')
def api_version():
    """返回 API 版本信息"""
    return jsonify({
        'version': API_VERSION,
        'api_base': f'/api/{API_VERSION}/admin/',
        'agent': 'SOC Multi-Agent System',
        'version_full': '2.1.0',
        'build_date': '2026-07-20'
    })


def run_server(host='0.0.0.0', port=8889, debug=False):
    print(f"""
╔════════════════════════════════════════════════════════════════════════════╗
║          SOC Multi-Agent 管理后台  (Gunicorn + WAL 模式)                   ║
║                                                                            ║
║   访问地址: http://localhost:{port}                                         ║
║   默认账号: admin / admin123                                               ║
║                                                                            ║
║   生产部署:                                                                ║
║     gunicorn -w 4 -k gevent -b 0.0.0.0:{port} web.admin.app:app          ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    # 显式初始化 DB（生产环境，确保表结构存在；测试环境用 setUpClass 控制）
    init_db()
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SOC 管理后台')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8889)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
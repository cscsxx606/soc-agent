#!/usr/bin/env python3
"""
EDR 探针管理服务
- Osquery TLS API（接收被管理主机的 enrollment/logs/queries）
- 端点事件采集 API
- 用于 soc-server 查询远程主机状态
"""
import os, sys, json, time, hmac, hashlib
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# CORS origins 可通过 EDR_ALLOWED_ORIGINS 环境变量自定义（逗号分隔）
# 默认仅允许 localhost（同机部署）
_default_origins = 'http://localhost:8889,http://127.0.0.1:8889,http://localhost:9000,http://127.0.0.1:9000'
EDR_ALLOWED_ORIGINS = [o.strip() for o in os.getenv('EDR_ALLOWED_ORIGINS', _default_origins).split(',') if o.strip()]
CORS(app, origins=EDR_ALLOWED_ORIGINS, supports_credentials=True)

# 数据存储
DATA_DIR = Path(__file__).parent.parent / 'data' / 'edr'
DATA_DIR.mkdir(parents=True, exist_ok=True)
ENROLL_FILE = DATA_DIR / 'enrolled_hosts.json'
EVENTS_FILE = DATA_DIR / 'agent_events.json'
QUERY_RESULTS_FILE = DATA_DIR / 'query_results.json'

ENROLL_SECRET = os.environ.get('EDR_ENROLL_SECRET')
if not ENROLL_SECRET:
    import secrets as _secrets
    ENROLL_SECRET = _secrets.token_hex(32)
    print(f"[WARNING] EDR_ENROLL_SECRET not set. Using auto-generated secret.")
    print(f"[WARNING] For production, set: export EDR_ENROLL_SECRET=$(openssl rand -hex 32)")


def _load_json(path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2))


# ========== Osquery TLS API（兼容 osqueryd 协议）==========

@app.route('/api/v1/enroll', methods=['POST'])
def enroll():
    """Osquery 主机注册"""
    data = request.get_json() or {}
    enroll_secret = data.get('enroll_secret', '')
    host_id = data.get('host_identifier', f'host-{int(time.time())}')
    hostname = data.get('hostname', host_id)

    if enroll_secret != ENROLL_SECRET:
        return jsonify({'node_invalid': True}), 401

    hosts = _load_json(ENROLL_FILE)
    if host_id not in hosts:
        hosts[host_id] = {
            'host_identifier': host_id,
            'hostname': hostname,
            'enrolled_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'status': 'online',
            'platform': data.get('platform', 'unknown'),
            'os_version': data.get('os_version', ''),
            'ip_address': request.remote_addr
        }
        _save_json(ENROLL_FILE, hosts)
    else:
        hosts[host_id]['last_seen'] = datetime.now().isoformat()
        hosts[host_id]['status'] = 'online'
        hosts[host_id]['ip_address'] = request.remote_addr
        _save_json(ENROLL_FILE, hosts)

    return jsonify({'node_key': host_id, 'node_invalid': False})


@app.route('/api/v1/log', methods=['POST'])
def ingest_log():
    """接收 Osquery 结果日志"""
    data = request.get_json() or {}
    node_key = data.get('node_key', '')
    log_type = data.get('log_type', 'status')  # status / result / snapshot

    hosts = _load_json(ENROLL_FILE)
    if node_key not in hosts:
        return jsonify({'node_invalid': True}), 401

    # 更新心跳
    hosts[node_key]['last_seen'] = datetime.now().isoformat()
    _save_json(ENROLL_FILE, hosts)

    # 存储事件
    if log_type == 'result':
        events = _load_json(EVENTS_FILE)
        for event in data.get('data', []):
            event['host_identifier'] = node_key
            event['received_at'] = datetime.now().isoformat()
            events[f"{node_key}-{int(time.time()*1000)}"] = event
        _save_json(EVENTS_FILE, events)

    return jsonify({})


@app.route('/api/v1/config', methods=['POST'])
def get_config():
    """返回 osquery 配置（可按需下发查询）"""
    return jsonify({
        'schedule': {
            'process_events': {
                'query': 'SELECT * FROM processes ORDER BY start_time DESC LIMIT 100;',
                'interval': 300
            },
            'network_connections': {
                'query': 'SELECT * FROM process_open_sockets WHERE remote_address NOT IN ("127.0.0.1","::1");',
                'interval': 600
            },
            'listening_ports': {
                'query': 'SELECT * FROM listening_ports;',
                'interval': 600
            },
            'crontab': {
                'query': 'SELECT * FROM crontab;',
                'interval': 3600
            },
            'logged_in_users': {
                'query': 'SELECT * FROM logged_in_users;',
                'interval': 300
            }
        },
        'decorators': {
            'load': [
                'SELECT uuid AS host_uuid FROM system_info;',
                'SELECT hostname FROM system_info;'
            ]
        }
    })


@app.route('/api/v1/distributed/read', methods=['POST'])
def distributed_read():
    """Osquery 分布式查询（用于下发临时查询）"""
    # 返回待执行的查询
    return jsonify({})


@app.route('/api/v1/distributed/write', methods=['POST'])
def distributed_write():
    """接收分布式查询结果"""
    data = request.get_json() or {}
    node_key = data.get('node_key', '')
    queries = data.get('queries', {})

    results = _load_json(QUERY_RESULTS_FILE)
    results[node_key] = {
        'queries': queries,
        'received_at': datetime.now().isoformat()
    }
    _save_json(QUERY_RESULTS_FILE, results)
    return jsonify({})


# ========== 管理 API（给 soc-server 调用）==========

@app.route('/api/edr/hosts')
def list_hosts():
    """列出所有已注册主机"""
    hosts = _load_json(ENROLL_FILE)
    now = datetime.now()
    result = []
    for hid, info in hosts.items():
        last_seen = info.get('last_seen', '')
        if last_seen:
            try:
                delta = (now - datetime.fromisoformat(last_seen)).total_seconds()
                info['status'] = 'online' if delta < 300 else 'offline'
            except Exception:
                info['status'] = 'unknown'
        result.append(info)
    return jsonify({'success': True, 'hosts': result, 'total': len(result)})


@app.route('/api/edr/events')
def list_events():
    """列出采集到的端点事件"""
    events = _load_json(EVENTS_FILE)
    limit = int(request.args.get('limit', 100))
    items = sorted(events.values(), key=lambda x: x.get('received_at', ''), reverse=True)[:limit]
    return jsonify({'success': True, 'events': items, 'total': len(items)})


@app.route('/api/edr/health')
def health():
    hosts = _load_json(ENROLL_FILE)
    return jsonify({
        'success': True,
        'status': 'healthy',
        'enrolled_hosts': len(hosts)
    })


if __name__ == '__main__':
    port = int(os.environ.get('EDR_PORT', 9000))
    print(f"EDR 探针管理服务启动: http://0.0.0.0:{port}")
    print(f"  Osquery 注册地址: http://0.0.0.0:{port}/api/v1/enroll")
    print(f"  Osquery 日志地址: http://0.0.0.0:{port}/api/v1/log")
    app.run(host='0.0.0.0', port=port, debug=False)

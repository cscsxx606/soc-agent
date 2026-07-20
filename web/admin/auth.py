#!/usr/bin/env python3
"""认证模块 - JWT + bcrypt + 多租户支持"""

import os, sys, jwt, bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db import get_db

# JWT Secret：生产环境必须从环境变量读取，禁止硬编码
# 未设环境变量时尝试从 logs/.secret 读取（start.py/app.py 启动时自动生成并复用）
_jwt_secret_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'logs', '.secret')
JWT_SECRET = os.environ.get('SOC_ADMIN_SECRET')
if not JWT_SECRET:
    try:
        JWT_SECRET = open(_jwt_secret_file).read().strip()
        if len(JWT_SECRET) < 16:
            raise ValueError('invalid secret')
    except (FileNotFoundError, IOError, ValueError):
        import secrets as _secrets
        JWT_SECRET = _secrets.token_hex(32)
        # app.py 会把 secret 写回文件，这里只读不打
        print(f"[WARNING] SOC_ADMIN_SECRET not set. Using auto-generated secret (persists across restarts via .secret file).")
JWT_ALGO = 'HS256'
JWT_EXPIRE_HOURS = 8


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False


def create_token(username: str, role: str, tenant_id: int = 1) -> str:
    payload = {
        'username': username,
        'role': role,
        'tenant_id': tenant_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return {'error': 'token_expired'}
    except jwt.InvalidTokenError:
        return {'error': 'invalid_token'}


def _load_user_request():
    """从 session 或 JWT 加载用户信息到 request"""
    uid = session.get('user_id') or session.get('username')
    if uid:
        request.username = session.get('username', 'unknown')
        request.user_role = session.get('role', 'analyst')
        request.tenant_id = session.get('tenant_id', 1)
        return True
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        payload = decode_token(auth[7:])
        if 'error' not in payload:
            request.username = payload.get('username', 'unknown')
            request.user_role = payload.get('role', 'analyst')
            request.tenant_id = payload.get('tenant_id', 1)
            return True
    # 未登录时设置默认值
    request.username = 'anonymous'
    request.user_role = 'guest'
    request.tenant_id = 1
    return False


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        _load_user_request()
        if request.username == 'anonymous':
            return jsonify({'success': False, 'error': '未登录或会话已过期'}), 401
        return f(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if request.user_role not in allowed_roles and request.user_role != 'admin':
                return jsonify({'success': False, 'error': '权限不足'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def tenant_filter(table_alias: str = '', field: str = 'tenant_id'):
    """构建租户隔离 WHERE 子句"""
    t = getattr(request, 'tenant_id', 1)
    prefix = f'{table_alias}.' if table_alias else ''
    return f'{prefix}{field}={t}'


def log_action(action: str, module: str, target: str = '', details: str = '', result: str = 'success'):
    try:
        _load_user_request()
        with get_db() as conn:
            conn.execute("""
                INSERT INTO audit_logs (username, action, module, target, details, ip_address, result, tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.username, action, module, target, details,
                request.remote_addr or 'system', result,
                getattr(request, 'tenant_id', 1)
            ))
            conn.commit()
    except Exception as e:
        print(f"审计日志写入失败: {e}")


# 别名保持向后兼容
createToken = create_token
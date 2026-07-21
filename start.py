#!/usr/bin/env python3
"""SOC Agent 一键启动脚本 - 支持全部/单服务/后台模式"""

import os, sys, subprocess, time, signal, argparse, json, secrets, shutil
from pathlib import Path
from datetime import datetime, timedelta

ROOT = Path(__file__).parent.resolve()
LOG_DIR = ROOT / 'logs'
LOG_DIR.mkdir(exist_ok=True)
BACKUP_DIR = ROOT / 'backups'
BACKUP_DIR.mkdir(exist_ok=True)

VENV = ROOT / '..' / 'soc-agent-env' / 'bin' / 'python3'
if not VENV.exists():
    VENV = sys.executable  # fallback

ENV_FILE = ROOT / 'config' / '.env'
PID_FILE = ROOT / '.pids.json'


def rotate_logs():
    """日志轮转：清理 7 天前的日志，压缩 1 天前的日志"""
    now = datetime.now()
    for log_file in LOG_DIR.glob('*.log'):
        mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
        age = now - mtime
        if age > timedelta(days=7):
            log_file.unlink()
            print(f"  🗑 清理旧日志: {log_file.name}")
        elif age > timedelta(days=1) and not log_file.name.endswith('.gz'):
            # 压缩 1 天前的日志
            import gzip
            gz_path = log_file.with_suffix('.log.gz')
            with open(log_file, 'rb') as f_in, gzip.open(gz_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            log_file.unlink()
            print(f"  📦 压缩日志: {log_file.name} → {gz_path.name}")


def backup_db():
    """数据库备份：每日备份 SQLite，保留 30 天"""
    db_path = ROOT / 'data' / 'admin.db'
    if not db_path.exists():
        return
    backup_name = f"admin_{datetime.now().strftime('%Y%m%d')}.db"
    backup_path = BACKUP_DIR / backup_name
    if not backup_path.exists():
        shutil.copy2(db_path, backup_path)
        print(f"  💾 数据库备份: {backup_name}")
    # 清理 30 天前的备份
    for old_backup in BACKUP_DIR.glob('admin_*.db'):
        mtime = datetime.fromtimestamp(old_backup.stat().st_mtime)
        if (datetime.now() - mtime) > timedelta(days=30):
            old_backup.unlink()
            print(f"  🗑 清理旧备份: {old_backup.name}")


def ensure_env():
    """确保 .env 存在且有随机密钥"""
    if not ENV_FILE.exists():
        secret = secrets.token_hex(32)
        with open(ENV_FILE, 'w') as f:
            f.write(f"# SOC Agent 配置 (自动生成，请勿直接修改)\n")
            f.write(f"SOC_ADMIN_SECRET={secret}\n")
            f.write(f"SOC_ADMIN_FLASK_SECRET={secrets.token_hex(16)}\n")
            f.write(f"API_BASE_URL=https://api.siliconflow.cn/v1\n")
            f.write(f"API_MODEL=Qwen/Qwen2.5-7B-Instruct\n")
        print(f"✓ 已生成配置: {ENV_FILE}")
    # 读取密钥用于启动
    env = {}
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    return env


def load_pids():
    if PID_FILE.exists():
        try: return json.loads(PID_FILE.read_text())
        except (json.JSONDecodeError, OSError): pass
    return {}


def save_pids(pids):
    PID_FILE.write_text(json.dumps(pids, indent=2))


def start_service(name, script, port, env_vars=None):
    """启动一个服务并记录 PID"""
    existing = load_pids()
    if name in existing:
        old_pid = existing[name]
        if os.path.exists(f'/proc/{old_pid}' if sys.platform != 'darwin' else True):
            try:
                os.kill(old_pid, 0)
                print(f"⚠  {name} 已在运行 (PID={old_pid})，跳过")
                return existing[name]
            except OSError:
                pass

    log_file = open(LOG_DIR / f'{name}.log', 'a')
    err_file = open(LOG_DIR / f'{name}.err', 'a')

    cmd = [str(VENV), str(script)]
    if port:
        cmd.extend(['--port', str(port)])

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=log_file,
        stderr=err_file,
        env=env,
        start_new_session=True
    )
    existing[name] = proc.pid
    save_pids(existing)
    print(f"✓ {name} 已启动 (PID={proc.pid}, 端口={port or '—'})")
    return proc.pid


def start_all():
    """启动全部服务"""
    print("=" * 55)
    print(f"  SOC Agent v2.0  一键启动")
    print("=" * 55)
    print()

    # 0. 日志轮转 + 数据库备份
    print("[0/4] 日志轮转 + 数据库备份...")
    rotate_logs()
    backup_db()
    print()

    env = ensure_env()

    # 1. 初始化数据库
    print("[1/4] 初始化数据库...")
    subprocess.run([str(VENV), str(ROOT / 'web' / 'admin' / 'db.py')], cwd=str(ROOT), capture_output=True)

    # 2. 管理后台 8889 （Gunicorn 多进程模式）
    print("[2/4] 启动管理后台 (Gunicorn 4 workers)...")
    port = 8889
    cmd = [
        str(VENV), '-m', 'gunicorn',
        '-w', '4',
        '-k', 'gevent',
        '-b', f'0.0.0.0:{port}',
        '--timeout', '120',
        '--access-logfile', str(ROOT / 'logs' / 'access.log'),
        '--error-logfile', str(ROOT / 'logs' / 'error.log'),
        'web.admin.app:app'
    ]
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env)
    pids = load_pids()
    pids['admin'] = proc.pid
    save_pids(pids)
    print(f"✓ 管理后台 (Gunicorn 4 workers) PID={proc.pid} 端口={port}")

    time.sleep(2)
    print()
    print("=" * 55)
    print("  ✅ SOC Agent 已启动")
    print(f"  管理后台: http://localhost:{port}")
    print(f"  默认账号: admin / admin123")
    print("=" * 55)


def stop_all():
    """停止全部服务"""
    pids = load_pids()
    for name, pid in list(pids.items()):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            print(f"✗ {name} (PID={pid}) 已停止")
        except ProcessLookupError:
            print(f"  {name} (PID={pid}) 已不存在")
        except Exception as e:
            # try regular kill
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"✗ {name} (PID={pid}) 已停止")
            except ProcessLookupError:
                print(f"  {name} (PID={pid}) 已不存在")
            except Exception as e2:
                print(f"  {name} 停止失败: {e2}")
    save_pids({})
    print("✓ 所有服务已停止")


def status():
    """查看状态"""
    pids = load_pids()
    print("SOC Agent 状态:")
    print("─" * 40)
    services = {'admin': 8889}
    all_running = True
    for name, port in services.items():
        pid = pids.get(name)
        running = False
        if pid:
            try:
                # macOS: os.kill(pid, 0) may not work for subprocess-children
                # Try with process group kill detection
                import subprocess as sp
                result = sp.run(['ps', '-p', str(pid)], capture_output=True, timeout=3)
                running = result.returncode == 0
            except Exception:
                running = False
        status_icon = '✓' if running else '✗'
        print(f"  {status_icon} {name:8} 端口 {port}  {'PID=' + str(pid) if pid else '未启动'}")
        if not running:
            all_running = False
    print("─" * 40)
    return all_running


def install():
    """安装依赖和环境"""
    print("SOC Agent 安装向导")
    print("=" * 40)
    print()
    # 检查 Python
    print(f"✓ Python: {sys.version.split()[0]}")
    # 创建 .env
    ensure_env()
    # 安装依赖
    print("\n安装 Python 依赖...")
    result = subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("✓ 依赖安装完成")
    else:
        print(f"⚠ 部分依赖安装失败: {result.stderr[:200]}")
    # 初始化数据库
    print("\n初始化数据库...")
    subprocess.run([sys.executable, str(ROOT / 'web' / 'admin' / 'db.py')], cwd=str(ROOT))
    print("\n安装完成！运行 ./start.py 启动服务")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SOC Agent 一键启动/管理')
    parser.add_argument('action', nargs='?', default='start',
                        choices=['start', 'stop', 'restart', 'status', 'install'],
                        help='操作: start | stop | restart | status | install')
    parser.add_argument('--port', type=int, help='端口 (仅 single 模式)')
    args = parser.parse_args()

    if args.action == 'start':
        start_all()
    elif args.action == 'stop':
        stop_all()
    elif args.action == 'restart':
        stop_all()
        time.sleep(2)
        start_all()
    elif args.action == 'status':
        status()
    elif args.action == 'install':
        install()
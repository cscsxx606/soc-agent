#!/usr/bin/env python3
"""
轻量级资产扫描引擎
- TCP 端口扫描（socket 并发）
- 服务 Banner 抓取
- HTTP 头识别
- 后端预留 nmap/nuclei 接入
"""

import os
import sys
import json
import socket
import time
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed




# 禁止扫描的 IP 段（SSRF 防护 - 云元数据 + 内网保留段）
SSRF_BLACKLIST = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '255.255.255.255/32',
]

# 禁止解析的域名关键词
SSRF_DOMAIN_BLOCKLIST = [
    '169.254.169.254',
    'metadata.google.internal',
    'metadata.tencentyun.com',
    '100.100.100.200',
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
]


def is_target_blocked(target_ip_or_hostname: str) -> Optional[str]:
    """检查扫描目标是否在 SSRF 黑名单内。返回阻断原因或 None（安全）。"""
    target = target_ip_or_hostname.strip()
    if not target:
        return '目标为空'
    # 域名黑名单检查
    for blocked in SSRF_DOMAIN_BLOCKLIST:
        if target.lower() == blocked.lower() or blocked.lower() in target.lower():
            return f'目标被域名黑名单拦截: {blocked}'
    # IP 黑名单检查
    try:
        ip = ipaddress.ip_address(target)
        for cidr in SSRF_BLACKLIST:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return f'目标被 IP 黑名单拦截: {cidr}'
    except ValueError:
        # 不是 IP 地址，可能是主机名，跳过 IP 段检查
        pass
    return None


# ====== 端口字典 ======
TOP_100_PORTS = [
    21,22,23,25,53,80,81,110,111,135,139,143,161,389,443,445,465,500,514,
    587,631,636,873,902,989,993,995,1080,1099,1433,1521,1723,1883,2049,
    2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,2483,2484,3000,3001,
    3306,3389,3690,3749,4369,4444,4567,4848,5000,5001,5044,5432,5601,5900,
    5984,5985,5986,6379,6443,6666,7001,7002,7474,8000,8001,8008,8009,8080,
    8081,8083,8086,8088,8089,8090,8091,8443,8500,8888,9000,9001,9042,9090,
    9092,9200,9300,9418,9443,11211,15672,16010,18080,27017,28017,50000
]

# 知名服务签名
SERVICE_SIGNS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
    587: 'SMTP-TLS', 631: 'IPP', 873: 'rsync', 902: 'VMware',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1099: 'RMI',
    1433: 'MSSQL', 1521: 'Oracle', 1883: 'MQTT', 2049: 'NFS',
    2375: 'Docker-API', 2376: 'Docker-API-TLS',
    3306: 'MySQL', 3389: 'RDP', 3690: 'SVN',
    4444: 'Metasploit', 5000: 'Flask', 5432: 'PostgreSQL',
    5601: 'Kibana', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 6443: 'Kubernetes-API',
    7001: 'WebLogic', 7474: 'Neo4j', 8000: 'HTTP-Alt',
    8001: 'HTTP-Alt', 8008: 'HTTP-Alt', 8009: 'Tomcat-AJP',
    8080: 'HTTP-Tomcat/Jetty', 8081: 'HTTP-Alt',
    8083: 'InfluxDB', 8086: 'InfluxDB-HTTP',
    8088: 'HTTP-Alt', 8089: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 8500: 'Consul',
    8888: 'Jupyter/HTTP-Alt', 9000: 'PHP-FPM/HTTP-Alt',
    9001: 'Supervisor/HTTP', 9042: 'Cassandra',
    9090: 'Prometheus/Cockpit', 9092: 'Kafka',
    9200: 'Elasticsearch', 9300: 'Elasticsearch',
    9418: 'Git', 11211: 'Memcached',
    15672: 'RabbitMQ-Mgmt', 27017: 'MongoDB',
    28017: 'MongoDB-Web', 50000: 'SAP'
}


class PortScanner:
    """TCP 端口扫描器（基于 socket）"""

    def __init__(self, timeout: float = 0.5, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []

    def scan_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """扫描单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start = time.time()
            result = sock.connect_ex((ip, port))
            elapsed = time.time() - start
            if result == 0:
                # 端口开放，尝试抓 banner
                banner = None
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                finally:
                    sock.close()

                return {
                    'port': port,
                    'state': 'open',
                    'service': SERVICE_SIGNS.get(port, 'unknown'),
                    'banner': banner,
                    'response_time_ms': round(elapsed * 1000, 1)
                }
            sock.close()
            return None
        except (socket.timeout, OSError):
            return None

    def scan(self, ip: str, ports: List[int] = None, progress_cb=None) -> List[Dict[str, Any]]:
        """扫描 IP 的多个端口"""
        ports = ports or TOP_100_PORTS
        open_ports = []
        total = len(ports)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_port, ip, p): p for p in ports}
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result:
                    open_ports.append(result)
                if progress_cb and (i + 1) % 10 == 0:
                    progress_cb(i + 1, total)

        # 按端口号排序
        open_ports.sort(key=lambda x: x['port'])
        return open_ports


class ServiceIdentifier:
    """服务识别（HTTP 头 + 路径探测）"""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        try:
            import requests
            self.requests = requests
        except ImportError:
            self.requests = None

    def identify_http(self, ip: str, port: int, scheme: str = None) -> Optional[Dict[str, Any]]:
        """HTTP 服务识别"""
        if not self.requests:
            return None

        if scheme is None:
            scheme = 'https' if port in (443, 8443, 9443) else 'http'

        url = f'{scheme}://{ip}:{port}'
        try:
            r = self.requests.get(url, timeout=self.timeout, verify=False,
                                   allow_redirects=True, headers={'User-Agent': 'SOC-Scanner/1.0'})
            headers = dict(r.headers)

            # 提取服务器信息
            server = headers.get('Server', headers.get('server', ''))
            powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))

            # 检测技术栈
            tech_stack = []
            if 'nginx' in server.lower():
                tech_stack.append('Nginx')
            if 'apache' in server.lower():
                tech_stack.append('Apache')
            if 'tomcat' in (server + powered_by).lower():
                tech_stack.append('Tomcat')
            if 'iis' in server.lower():
                tech_stack.append('IIS')
            if 'express' in powered_by.lower():
                tech_stack.append('Express')
            if 'php' in powered_by.lower():
                tech_stack.append('PHP')
            if 'asp.net' in powered_by.lower() or 'aspnet' in powered_by.lower():
                tech_stack.append('ASP.NET')
            if 'python' in headers.get('Server', '').lower():
                tech_stack.append('Python')

            # 检查响应内容里的标志
            body = r.text[:5000] if hasattr(r, 'text') else ''
            if 'wordpress' in body.lower():
                tech_stack.append('WordPress')
            if 'jenkins' in body.lower():
                tech_stack.append('Jenkins')
            if 'grafana' in body.lower():
                tech_stack.append('Grafana')
            if 'kibana' in body.lower():
                tech_stack.append('Kibana')

            # 路径探测
            paths = self._probe_paths(url) if self.requests else {}

            return {
                'url': url,
                'scheme': scheme,
                'status_code': r.status_code,
                'headers': {k: v for k, v in headers.items()},
                'server': server,
                'powered_by': powered_by,
                'tech_stack': tech_stack or ['unknown'],
                'content_length': len(body),
                'title': self._extract_title(body),
                'paths_found': paths
            }
        except Exception as e:
            return {'url': url, 'error': str(e)[:100]}

    def _extract_title(self, html: str) -> str:
        m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:100] if m else ''

    def _probe_paths(self, base_url: str) -> Dict[str, int]:
        """探测常见路径"""
        paths = {
            '/.env': 'env_file', '/admin': 'admin_panel', '/login': 'login_page',
            '/wp-admin': 'wordpress', '/phpmyadmin': 'phpmyadmin',
            '/manager/html': 'tomcat_manager', '/jenkins': 'jenkins',
            '/actuator': 'spring_actuator', '/swagger': 'swagger_api',
            '/api': 'api_root', '/api/v1': 'api_v1',
            '/robots.txt': 'robots', '/sitemap.xml': 'sitemap',
            '/.git/HEAD': 'git_exposed', '/.svn/entries': 'svn_exposed',
            '/console': 'console',
            '/server-status': 'apache_status', '/status': 'status_page',
            '/health': 'health_endpoint', '/metrics': 'metrics'
        }
        found = {}
        for path, label in paths.items():
            try:
                r = self.requests.get(base_url + path, timeout=2, verify=False,
                                       allow_redirects=False, headers={'User-Agent': 'SOC-Scanner/1.0'})
                if r.status_code in (200, 301, 302, 401, 403):
                    found[path] = {'label': label, 'status': r.status_code}
            except Exception:
                continue
        return found


class AssetScanner:
    """资产生命周期管理"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     'data', 'scan_results.json')
        self.db_path = db_path
        # 后端预留（nmap/nuclei）
        self.backend = 'python-builtin'
        self.tools_available = self._detect_tools()

    def _detect_tools(self) -> Dict[str, bool]:
        """检测可用工具（为预留下个阶段用）"""
        import shutil
        tools = {'nmap': False, 'nuclei': False, 'sqlmap': False}
        for tool in tools:
            try:
                if shutil.which(tool):
                    tools[tool] = True
            except Exception:
                pass
        return tools

    def scan_target(self, target: Dict[str, Any],
                     enable_service_id: bool = True,
                     progress_cb=None) -> Dict[str, Any]:
        """扫描单个资产"""
        start = time.time()
        ip = target['ip_address']
        hostname = target.get('hostname', ip)

        result = {
            'target_id': target.get('id'),
            'hostname': hostname,
            'ip_address': ip,
            'criticality': target.get('criticality', 'medium'),
            'owner': target.get('owner', 'unknown'),
            'scan_start': datetime.now().isoformat(),
            'scan_backend': self.backend,
            'tools_available': self.tools_available,
            'ports_open': [],
            'services': [],
            'recommendations': []
        }

        # 1. 端口扫描
        scanner = PortScanner()
        ports = scanner.scan(ip, progress_cb=progress_cb)
        result['ports_open'] = ports
        result['port_count'] = len(ports)

        # 2. 服务识别（仅对 HTTP/HTTPS）
        if enable_service_id and self.tools_available.get('python') != False:
            service_id = ServiceIdentifier()
            for port_info in ports:
                port = port_info['port']
                if port in (80, 443, 8080, 8443, 8000, 8001, 8888, 9000) or port_info['service'].startswith('HTTP'):
                    info = service_id.identify_http(ip, port)
                    if info:
                        # 简化 headers（避免太多字段）
                        info['headers'] = {k: v for k, v in list(info.get('headers', {}).items())[:10]}
                        result['services'].append({
                            'port': port,
                            **info
                        })

        # 3. 风险评估
        result['risk_score'] = self._assess_risk(result)
        result['recommendations'] = self._generate_recommendations(result)
        result['scan_duration'] = round(time.time() - start, 2)
        result['scan_end'] = datetime.now().isoformat()

        return result

    def _assess_risk(self, result: Dict[str, Any]) -> int:
        """基于扫描结果计算风险分（0-100）"""
        risk = 0
        open_ports = result['ports_open']

        # 风险端口加分
        high_risk_ports = {
            22: 10, 23: 25, 3389: 15, 5900: 15,  # 远程管理
            21: 5, 445: 15, 139: 10,  # 文件共享
            3306: 15, 5432: 15, 6379: 20, 27017: 15,  # 数据库
            2375: 25, 9200: 20, 11211: 15,  # 无认证服务
            25: 5,  # SMTP 开放
        }
        for port_info in open_ports:
            port = port_info['port']
            risk += high_risk_ports.get(port, 2)

        # 暴露的危险路径
        dangerous_paths = {'/.env': 25, '/phpmyadmin': 20, '/jenkins': 15,
                           '/manager/html': 25, '/.git/HEAD': 20, '/actuator': 15,
                           '/swagger': 10, '/api': 5}
        for service in result.get('services', []):
            for path in service.get('paths_found', {}):
                label = service['paths_found'][path].get('label', '')
                for dp, score in dangerous_paths.items():
                    if label in dp:
                        risk += score // 2

        # 资产重要性加成
        criticality = result.get('criticality', 'medium')
        if criticality == 'critical':
            risk += 20
        elif criticality == 'high':
            risk += 10

        return min(risk, 100)

    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """生成修复建议"""
        recs = []
        ports = {p['port']: p['service'] for p in result['ports_open']}

        port_recs = {
            23: '⚠️ Telnet 明文传输，建议禁用并使用 SSH',
            21: '⚠️ FTP 明文，建议改用 SFTP/FTPS',
            3389: '🔒 RDP 暴露公网风险高，建议限制源 IP + 启用 NLA',
            5900: '🔒 VNC 弱认证常见，建议改用 SSH 隧道',
            6379: '🚨 Redis 无密码风险极高，立即设置 requirepass',
            2375: '🚨 Docker API 未授权访问，立即关闭或启用 TLS',
            9200: '🔒 Elasticsearch 暴露，执行 security.yml 启用认证',
            11211: '🚨 Memcached 无认证，可被用于 DDoS 放大攻击',
            27017: '🔒 MongoDB 暴露，启用 --auth',
        }
        for port, msg in port_recs.items():
            if port in ports:
                recs.append(f'[{port}/{ports[port]}] {msg}')

        # 检查暴露的危险路径
        for service in result.get('services', []):
            paths = service.get('paths_found', {})
            if '.env' in paths:
                recs.append('🚨 /.env 文件暴露，立即移除并轮换密钥')
            if 'phpmyadmin' in str(paths):
                recs.append('🔒 phpMyAdmin 暴露，限制访问 IP')
            if 'jenkins' in str(paths):
                recs.append('🔒 Jenkins 控制台暴露，启用认证 + 限制 IP')
            if 'tomcat_manager' in str(paths):
                recs.append('🚨 Tomcat Manager 暴露，立即禁用或重命名')

        if not recs:
            recs.append('✅ 扫描未发现明显风险')

        return recs

    def save_result(self, result: Dict[str, Any]):
        """保存扫描结果到 SQLite"""
        task_id = result.get('task_id', '')
        target_ip = result.get('ip_address', '')
        hostname = result.get('hostname', '')
        risk_score = result.get('risk_score', 0)
        risk_level = 'critical' if risk_score >= 60 else 'high' if risk_score >= 30 else 'medium' if risk_score >= 10 else 'low'
        port_count = len(result.get('ports_open', []))
        result_json = json.dumps(result, ensure_ascii=False, default=str)

        from web.admin.db import get_db
        with get_db() as conn:
            existing = conn.execute("SELECT id FROM scan_results WHERE task_id=?", (task_id,)).fetchone()
            if existing:
                conn.execute("""
                    UPDATE scan_results SET target_ip=?, hostname=?, risk_score=?,
                        risk_level=?, port_count=?, result_json=?
                    WHERE task_id=?
                """, (target_ip, hostname, risk_score, risk_level, port_count, result_json, task_id))
            else:
                conn.execute("""
                    INSERT INTO scan_results (task_id, target_ip, hostname, risk_score, risk_level, port_count, result_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (task_id, target_ip, hostname, risk_score, risk_level, port_count, result_json))
            conn.commit()

    def list_results(self, limit: int = 50) -> List[Dict[str, Any]]:
        """列出最近的扫描结果"""
        from web.admin.db import get_db
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_results ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get('result_json'):
                try:
                    full = json.loads(d['result_json'])
                    d.update(full)
                except Exception:
                    pass
                d.pop('result_json', None)
            results.append(d)
        return results

    def get_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """获取指定扫描结果"""
        from web.admin.db import get_db
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM scan_results WHERE task_id=?", (scan_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get('result_json'):
            try:
                full = json.loads(d['result_json'])
                d.update(full)
            except Exception:
                pass
            d.pop('result_json', None)
        return d


def is_target_authorized(target_ip: str, whitelist: List[str] = None) -> bool:
    """检查目标是否在白名单内（合规检查）"""
    if whitelist is None:
        return False
    try:
        target = ipaddress.ip_address(target_ip)
        for allowed in whitelist:
            try:
                if '/' in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if target in network:
                        return True
                else:
                    if str(target) == allowed:
                        return True
            except Exception:
                continue
    except Exception:
        return False
    return False


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help='IP to scan')
    parser.add_argument('--ports', type=str, help='Comma-separated ports (default: top 100)')
    parser.add_argument('--no-service-id', action='store_true')
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(',')] if args.ports else None
    scanner = PortScanner()
    print(f'Scanning {args.target}...')
    results = scanner.scan(args.target, ports)
    print(json.dumps(results, ensure_ascii=False, indent=2))
#!/usr/bin/env python3
"""
轻量级 Web 漏洞扫描器
- 常见 Web 漏洞检测（SQL 注入 / XSS / 路径遍历 / SSRF / 弱密码）
- 敏感信息泄漏检测
- 已知漏洞指纹
- 预留 nuclei 接口
"""

import os
import sys
import json
import re
import socket
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional


class WebVulnerabilityScanner:
    """Web 漏洞扫描器"""

    # 风险 Payload 库（仅用于检测，不利用）
    PAYLOADS = {
        'sqli_error': [
            "'", "''", "';--", "' OR '1'='1", "' UNION SELECT NULL--",
            "1' ORDER BY 1--", "1' ORDER BY 10--"
        ],
        'sqli_time': [
            "1' AND SLEEP(3)--", "1; WAITFOR DELAY '0:0:3'--",
            "1' AND BENCHMARK(1000000,MD5(1))--"
        ],
        'xss': [
            "<script>alert(1)</script>",
            "\"><svg onload=alert(1)>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>"
        ],
        'path_traversal': [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ],
        'ssrf': [
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:6379",
            "file:///etc/passwd"
        ],
        'command_injection': [
            "; ls -la", "| cat /etc/passwd",
            "$(id)", "`id`", "&& whoami"
        ]
    }

    # SQL 错误签名
    SQL_ERROR_SIGNATURES = [
        r'you have an error in your sql syntax',
        r'warning.*mysql_',
        r'mysqlclient\.py',
        r'pg_query\(\)',
        r'psycopg2',
        r'sqlite3\.operationalerror',
        r'microsoft.*sql server.*error',
        r'ora-\d+',
        r'quoted string not properly terminated',
        r'unclosed quotation mark',
        r'syntax error.*sql'
    ]

    # 敏感信息签名
    SENSITIVE_SIGNATURES = {
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'github_token': r'ghp_[0-9a-zA-Z]{36}',
        'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'api_key_generic': r'(?i)api[_-]?key[\'":\s]+[A-Za-z0-9]{20,}',
        'password_field': r'(?i)password\s*[:=]\s*[\'"]?[^\s\'"]+',
    }

    # 弱密码字典（仅检测常见弱密码，不暴力破解）
    COMMON_PASSWORDS = [
        'admin', '123456', 'password', 'admin123', 'root', '12345678',
        'qwerty', '123456789', '111111', '1234567', 'abc123',
        'test', 'test123', 'guest', 'master', 'administrator'
    ]

    COMMON_USERS = ['admin', 'root', 'test', 'guest', 'user', 'administrator']

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        try:
            import requests
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': 'SOC-VulnScanner/1.0'})
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.requests = requests
        except ImportError:
            self.requests = None
        self.findings = []

    def is_available(self) -> bool:
        return self.requests is not None

    def scan_url(self, target_url: str) -> Dict[str, Any]:
        """扫描单个 URL"""
        result = {
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'findings': [],
            'risk_score': 0,
            'risk_level': 'low',
            'tests_performed': []
        }

        # 1. 敏感信息泄漏
        result = self._check_sensitive_exposure(target_url, result)
        result['tests_performed'].append('sensitive_exposure')

        # 2. SQL 注入探测（GET 参数）
        result = self._check_sqli(target_url, result)
        result['tests_performed'].append('sqli')

        # 3. XSS 检测（GET 参数反射）
        result = self._check_xss(target_url, result)
        result['tests_performed'].append('xss')

        # 4. 路径遍历
        result = self._check_path_traversal(target_url, result)
        result['tests_performed'].append('path_traversal')

        # 5. HTTP 安全头
        result = self._check_security_headers(target_url, result)
        result['tests_performed'].append('security_headers')

        # 6. 已知路径/敏感文件
        result = self._check_exposed_files(target_url, result)
        result['tests_performed'].append('exposed_files')

        # 7. 弱密码检测（仅在登录页面检测）
        result = self._check_weak_passwords(target_url, result)
        result['tests_performed'].append('weak_passwords')

        # 汇总风险
        result['risk_score'] = sum(f.get('severity_score', 0) for f in result['findings'])
        if result['risk_score'] >= 30:
            result['risk_level'] = 'critical'
        elif result['risk_score'] >= 15:
            result['risk_level'] = 'high'
        elif result['risk_score'] >= 5:
            result['risk_level'] = 'medium'

        return result

    def _check_sensitive_exposure(self, url: str, result: Dict) -> Dict:
        """检测敏感信息泄漏"""
        sensitive_files = [
            '/.env', '/.git/config', '/.svn/entries', '/.DS_Store',
            '/backup.sql', '/database.sql', '/db.sql', '/dump.sql',
            '/config.php.bak', '/web.config', '/.htaccess',
            '/phpinfo.php', '/info.php', '/server-status',
            '/crossdomain.xml', '/.well-known/security.txt'
        ]
        for path in sensitive_files:
            try:
                r = self.session.get(url.rstrip('/') + path, timeout=self.timeout, verify=False,
                                      allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    body = r.text
                    findings = []
                    for sig_name, sig_pattern in self.SENSITIVE_SIGNATURES.items():
                        if re.search(sig_pattern, body):
                            findings.append(sig_name)
                    if findings:
                        result['findings'].append({
                            'type': 'sensitive_exposure',
                            'severity': 'critical',
                            'severity_score': 30,
                            'path': path,
                            'findings': findings,
                            'details': f'在 {path} 中发现敏感字段: {", ".join(findings)}',
                            'recommendation': '立即移除该文件并轮换泄漏的密钥'
                        })
            except Exception:
                continue
        return result

    def _check_sqli(self, url: str, result: Dict) -> Dict:
        """SQL 注入检测"""
        if '?' not in url:
            return result
        try:
            parsed = urllib.parse.urlparse(url)
            base_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
            params = urllib.parse.parse_qs(parsed.query)
            if not params:
                return result
            for param_name in list(params.keys())[:3]:  # 只测前 3 个参数
                for payload in self.PAYLOADS['sqli_error']:
                    test_params = dict(params)
                    test_params[param_name] = [str(params[param_name][0]) + payload]
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    r = self.session.get(f'{base_url}?{test_query}', timeout=self.timeout, verify=False)
                    for sig in self.SQL_ERROR_SIGNATURES:
                        if re.search(sig, r.text, re.IGNORECASE):
                            result['findings'].append({
                                'type': 'sql_injection',
                                'severity': 'critical',
                                'severity_score': 25,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': re.search(sig, r.text, re.IGNORECASE).group(0)[:100],
                                'recommendation': '使用参数化查询或 ORM，禁止字符串拼接 SQL'
                            })
                            return result
        except Exception:
            pass
        return result

    def _check_xss(self, url: str, result: Dict) -> Dict:
        """XSS 反射检测"""
        if '?' not in url:
            return result
        try:
            parsed = urllib.parse.urlparse(url)
            base_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
            params = urllib.parse.parse_qs(parsed.query)
            if not params:
                return result
            for param_name in list(params.keys())[:3]:
                for payload in self.PAYLOADS['xss']:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    r = self.session.get(f'{base_url}?{test_query}', timeout=self.timeout, verify=False)
                    if payload in r.text:
                        result['findings'].append({
                            'type': 'reflected_xss',
                            'severity': 'high',
                            'severity_score': 15,
                            'parameter': param_name,
                            'payload': payload[:50],
                            'recommendation': '对输出做 HTML 转义，使用 CSP 头'
                        })
                        return result
        except Exception:
            pass
        return result

    def _check_path_traversal(self, url: str, result: Dict) -> Dict:
        """路径遍历检测"""
        try:
            parsed = urllib.parse.urlparse(url)
            base_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
            for payload in self.PAYLOADS['path_traversal']:
                test_url = base_url + payload
                try:
                    r = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    body = r.text.lower()
                    if 'root:' in body or '[extensions]' in body:
                        result['findings'].append({
                            'type': 'path_traversal',
                            'severity': 'critical',
                            'severity_score': 25,
                            'payload': payload,
                            'evidence': '泄漏系统文件内容',
                            'recommendation': '过滤 .. 序列，使用白名单或规范化路径'
                        })
                        return result
                except Exception:
                    continue
        except Exception:
            pass
        return result

    def _check_security_headers(self, url: str, result: Dict) -> Dict:
        """HTTP 安全头检查"""
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            missing_headers = []
            headers_lower = {k.lower(): v for k, v in r.headers.items()}

            checks = {
                'strict-transport-security': 'HSTS 缺失',
                'x-frame-options': 'X-Frame-Options 缺失（点击劫持风险）',
                'x-content-type-options': 'X-Content-Type-Options 缺失（MIME 嗅探风险）',
                'content-security-policy': 'CSP 缺失（XSS 防御弱）',
                'x-xss-protection': 'XSS-Protection 缺失',
                'referrer-policy': 'Referrer-Policy 缺失'
            }
            for header, msg in checks.items():
                if header not in headers_lower:
                    missing_headers.append(msg)

            if missing_headers:
                result['findings'].append({
                    'type': 'missing_security_headers',
                    'severity': 'low',
                    'severity_score': 2,
                    'missing': missing_headers,
                    'recommendation': '在 Nginx/Apache/IIS 配置中添加缺失的安全头'
                })
        except Exception:
            pass
        return result

    def _check_exposed_files(self, url: str, result: Dict) -> Dict:
        """暴露文件/路径检测"""
        exposed_paths = [
            ('/.env', 'env_file', 'critical'),
            ('/.git/HEAD', 'git_repo', 'high'),
            ('/.svn/entries', 'svn_repo', 'high'),
            ('/backup.zip', 'backup_file', 'high'),
            ('/phpmyadmin/', 'phpmyadmin', 'critical'),
            ('/jenkins/', 'jenkins', 'high'),
            ('/actuator/env', 'spring_actuator', 'high'),
            ('/api/swagger-ui.html', 'swagger', 'medium'),
            ('/api-docs', 'api_docs', 'medium'),
            ('/console', 'console', 'high'),
            ('/index.php?page=phpinfo', 'phpinfo', 'medium'),
            ('/uploads/', 'uploads_dir', 'medium'),
            ('/admin/', 'admin_dir', 'medium'),
        ]
        base_url = url.rstrip('/')
        for path, label, severity in exposed_paths:
            try:
                r = self.session.get(f'{base_url}{path}', timeout=self.timeout, verify=False, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    score = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2}.get(severity, 5)
                    result['findings'].append({
                        'type': 'exposed_path',
                        'severity': severity,
                        'severity_score': score,
                        'path': path,
                        'label': label,
                        'status': r.status_code,
                        'recommendation': f'访问受限或移除 {path}'
                    })
            except Exception:
                continue
        return result

    def _check_weak_passwords(self, url: str, result: Dict) -> Dict:
        """弱密码检测（仅在检测到登录页面时执行）"""
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            body = r.text.lower()
            # 检测登录页面
            login_indicators = ['<input type="password"', 'name="password"', 'name="user"',
                                'name="login"', 'name="username"']
            has_login = any(ind in body for ind in login_indicators)

            if has_login and 'action=' in body:
                # 只在登录页尝试 5 个最常见弱密码（不做暴力）
                soup_links = re.findall(r'action="([^"]+)"', body)
                if soup_links:
                    login_url = soup_links[0]
                    if not login_url.startswith('http'):
                        login_url = urllib.parse.urljoin(url, login_url)
                    for user in ['admin']:  # 只测 admin 账号
                        for pwd in self.COMMON_PASSWORDS[:5]:
                            try:
                                test_resp = self.session.post(login_url, data={
                                    'username': user, 'user': user, 'login': user,
                                    'password': pwd, 'pwd': pwd
                                }, timeout=self.timeout, verify=False, allow_redirects=False)
                                # 检测是否登录成功（200/302 跳转到非登录页）
                                if test_resp.status_code in (302, 303) and 'login' not in test_resp.headers.get('Location', '').lower():
                                    result['findings'].append({
                                        'type': 'weak_password',
                                        'severity': 'critical',
                                        'severity_score': 30,
                                        'username': user,
                                        'password': pwd,
                                        'recommendation': '立即修改密码，并启用账户锁定策略'
                                    })
                                    return result
                            except Exception:
                                continue
        except Exception:
            pass
        return result


class NucleiBridge:
    """预留 nuclei 接入点（未实现，下个阶段激活）"""

    def __init__(self, nuclei_path: str = '/usr/local/bin/nuclei'):
        self.nuclei_path = nuclei_path
        self.templates_dir = os.path.expanduser('~/.nuclei/templates')

    def is_available(self) -> bool:
        return os.path.exists(self.nuclei_path)

    def get_command(self, target_url: str) -> List[str]:
        return [
            self.nuclei_path,
            '-u', target_url,
            '-t', self.templates_dir,
            '-json-export', '-',
            '-silent'
        ]

    def parse_output(self, json_lines: List[str]) -> List[Dict[str, Any]]:
        results = []
        for line in json_lines:
            try:
                findings = json.loads(line)
                results.append({
                    'template_id': findings.get('template-id'),
                    'name': findings.get('info', {}).get('name'),
                    'severity': findings.get('info', {}).get('severity'),
                    'matched_at': findings.get('matched-at'),
                    'type': findings.get('type'),
                    'host': findings.get('host')
                })
            except Exception:
                continue
        return results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    args = parser.parse_args()

    scanner = WebVulnerabilityScanner()
    if not scanner.is_available():
        print('requests 库未安装')
        sys.exit(1)
    result = scanner.scan_url(args.url)
    print(json.dumps(result, ensure_ascii=False, indent=2))
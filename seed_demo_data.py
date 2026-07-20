#!/usr/bin/env python3
"""
灌测试数据脚本 - 让 SOC 仪表盘看起来真实
- 200+ incidents（覆盖 7 天）
- 20+ scan_tasks（不同 risk_level）
- 真实感攻击类型 / 源 IP / 优先级分布
"""

import sys
import os
import json
import random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web', 'admin'))

import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'admin.db')

# 固定随机种子，让结果可复现
random.seed(42)

# ============ 数据池 ============

ATTACK_TYPES = [
    ('SQL Injection', 22, 'critical', 'P1', 'T1190'),
    ('Brute Force Login', 35, 'high', 'P2', 'T1110'),
    ('Phishing Email', 28, 'high', 'P2', 'T1566'),
    ('C2 Communication', 15, 'critical', 'P1', 'T1071'),
    ('Privilege Escalation', 12, 'critical', 'P1', 'T1068'),
    ('XSS Attack', 18, 'medium', 'P3', 'T1059'),
    ('Malware Detected', 14, 'critical', 'P1', 'T1204'),
    ('DNS Tunneling', 8, 'high', 'P2', 'T1071'),
    ('Data Exfiltration', 6, 'critical', 'P1', 'T1041'),
    ('Lateral Movement', 10, 'high', 'P2', 'T1021'),
    ('Ransomware Behavior', 3, 'critical', 'P1', 'T1486'),
    ('Port Scan', 42, 'low', 'P4', 'T1046'),
    ('Suspicious PowerShell', 18, 'medium', 'P3', 'T1059'),
    ('Unauthorized Access', 24, 'high', 'P2', 'T1078'),
    ('DDoS Attempt', 9, 'high', 'P2', 'T1498'),
    ('Web Shell Upload', 5, 'critical', 'P1', 'T1505'),
    ('Credential Dump', 7, 'critical', 'P1', 'T1003'),
    ('Process Injection', 11, 'high', 'P2', 'T1055'),
    ('Registry Persistence', 8, 'medium', 'P3', 'T1547'),
    ('Scheduled Task Abuse', 6, 'medium', 'P3', 'T1053'),
]

# 攻击源 IP（涵盖主要攻击来源国）
SOURCE_IPS = [
    ('203.0.113.45', 'CN', 'AS4134'),     # 中国电信
    ('198.51.100.20', 'US', 'AS15169'),   # Google
    ('192.0.2.88', 'RU', 'AS12389'),      # 俄罗斯
    ('203.0.113.99', 'CN', 'AS9808'),     # 中国移动
    ('198.51.100.55', 'NL', 'AS60781'),   # 荷兰
    ('185.220.101.32', 'DE', 'AS208294'), # 德国 Tor 出口
    ('45.33.32.156', 'US', 'AS63949'),    # Linode
    ('91.219.236.222', 'RU', 'AS49505'),  # 俄罗斯 Selectel
    ('103.25.61.110', 'KR', 'AS4766'),    # 韩国
    ('194.5.249.180', 'IR', 'AS44244'),   # 伊朗
    ('5.188.10.156', 'BG', 'AS204957'),   # 保加利亚
    ('162.247.74.7', 'US', 'AS19752'),    # 美国 Hurricane Electric
    ('23.129.64.130', 'US', 'AS396507'),  # 美国 Emerald Onion
    ('171.25.193.20', 'SE', 'AS198093'),  # 瑞典 Forskningsnätet
]

# 资产主机名
HOSTNAMES = [
    ('web-prod-01', 'web', 'production', 'core', 'ecommerce'),
    ('web-prod-02', 'web', 'production', 'core', 'ecommerce'),
    ('api-gateway', 'api', 'production', 'critical', 'platform'),
    ('db-master-01', 'db', 'production', 'critical', 'data'),
    ('db-replica-01', 'db', 'production', 'high', 'data'),
    ('cache-redis-01', 'cache', 'production', 'high', 'platform'),
    ('k8s-worker-01', 'container', 'production', 'core', 'platform'),
    ('k8s-worker-02', 'container', 'production', 'core', 'platform'),
    ('jenkins-ci', 'ci-cd', 'production', 'high', 'engineering'),
    ('gitlab-01', 'ci-cd', 'production', 'high', 'engineering'),
    ('mail-server', 'mail', 'production', 'medium', 'corporate'),
    ('vpn-gateway', 'network', 'production', 'critical', 'it'),
    ('file-server', 'storage', 'production', 'high', 'corporate'),
    ('dev-laptop-04', 'endpoint', 'office', 'medium', 'engineering'),
    ('sales-laptop-12', 'endpoint', 'office', 'medium', 'sales'),
    ('finance-laptop-03', 'endpoint', 'office', 'high', 'finance'),
    ('office-printer-02', 'iot', 'office', 'low', 'corporate'),
    ('camera-lobby', 'iot', 'office', 'low', 'facilities'),
]

OWNERS = ['张伟', '李娜', '王芳', '刘洋', '陈静', 'Budi', 'Sari', 'Andi', '王明', '李强', '陈华']

DESCRIPTIONS = [
    'Detected suspicious outbound connection to known C2 server',
    'Multiple failed login attempts within short timeframe',
    'SQL injection pattern detected in HTTP request body',
    'Phishing email with malicious attachment quarantined',
    'Privilege escalation attempt via sudoers file modification',
    'Encoded PowerShell command executed by office macro',
    'DNS queries to suspicious TLD (.top, .xyz)',
    'Large data transfer to external IP detected',
    'PsExec execution detected between workstations',
    'Ransomware signature matched in file entropy analysis',
    'TCP SYN scan from external host detected',
    'Suspicious base64 encoded command line arguments',
    'Unauthorized user added to local administrators group',
    'Volumetric traffic anomaly from single source IP',
    'Web shell file uploaded to /uploads/ directory',
    'LSASS memory dump attempt blocked by EDR',
    'Process hollowing technique detected',
    'Registry Run key persistence mechanism established',
    'New scheduled task created with suspicious binary path',
]


def gen_incident(ts: datetime, idx: int):
    """生成单个 incident"""
    atype, count_hint, severity, priority, mitre = random.choices(
        ATTACK_TYPES, weights=[t[1] for t in ATTACK_TYPES]
    )[0]
    src_ip, country, asn = random.choice(SOURCE_IPS)
    hostname, _, _, _, bu = random.choice(HOSTNAMES)
    owner = random.choice(OWNERS)
    desc = random.choice(DESCRIPTIONS)

    # 风险分按优先级
    base_score = {'P1': 85, 'P2': 65, 'P3': 45, 'P4': 20}[priority]
    risk_score = max(0, min(100, base_score + random.randint(-10, 10)))

    return {
        'alert_id': f'INC-2026-{idx:05d}',
        'timestamp': ts.isoformat(timespec='seconds'),
        'source_ip': src_ip,
        'dest_ip': f'10.0.{random.randint(1,254)}.{random.randint(1,254)}',
        'alert_type': atype,
        'severity': severity,
        'priority': priority,
        'risk_score': risk_score,
        'hostname': hostname,
        'owner': owner,
        'mitre_technique': mitre,
        'confidence': random.randint(70, 99),
        'description': desc,
        'status': random.choices(['open', 'investigating', 'contained', 'closed'],
                                  weights=[40, 25, 20, 15])[0],
        'tenant_id': 1,
    }


def gen_incidents_for_timespan(start: datetime, end: datetime, count: int):
    """在指定时间范围内生成 incident（业务时间加权）"""
    incidents = []
    total_seconds = int((end - start).total_seconds())
    for i in range(count):
        # 时间分布：业务时间(8-20)更密集
        offset_seconds = random.randint(0, total_seconds)
        ts = start + timedelta(seconds=offset_seconds)
        hour = ts.hour

        # 夜间稍微加权（攻击者活动）
        if hour in [2, 3, 4, 22, 23]:
            if random.random() > 0.3:  # 30% 跳过，保留业务时间数据
                continue

        incidents.append(gen_incident(ts, i + 1))
    return incidents


def main():
    if not os.path.exists(DB_PATH):
        print(f'❌ 数据库不存在: {DB_PATH}')
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 1. 清空并重建 incidents 表
    cur.execute("DROP TABLE IF EXISTS incidents")
    print('✓ 已清空 incidents 表')

    # 重建表（与 db.py 保持一致）
    cur.execute("""
        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            dest_ip TEXT,
            alert_type TEXT,
            severity TEXT,
            priority TEXT,
            risk_score INTEGER DEFAULT 0,
            hostname TEXT,
            owner TEXT,
            mitre_technique TEXT,
            confidence INTEGER DEFAULT 0,
            description TEXT,
            status TEXT DEFAULT 'open',
            tenant_id INTEGER DEFAULT 1
        )
    """)
    cur.execute("CREATE INDEX idx_incidents_timestamp ON incidents(timestamp)")
    cur.execute("CREATE INDEX idx_incidents_priority ON incidents(priority)")
    cur.execute("CREATE INDEX idx_incidents_severity ON incidents(severity)")

    # 2. 灌 7 天数据 (240+ 条)
    end = datetime.now()
    start = end - timedelta(days=7)
    incidents = gen_incidents_for_timespan(start, end, 280)
    for inc in incidents:
        cur.execute("""
            INSERT INTO incidents (alert_id, timestamp, source_ip, dest_ip, alert_type,
                                    severity, priority, risk_score, hostname, owner,
                                    mitre_technique, confidence, description, status, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (inc['alert_id'], inc['timestamp'], inc['source_ip'], inc['dest_ip'],
              inc['alert_type'], inc['severity'], inc['priority'], inc['risk_score'],
              inc['hostname'], inc['owner'], inc['mitre_technique'], inc['confidence'],
              inc['description'], inc['status'], inc['tenant_id']))

    print(f'✓ 灌入 {len(incidents)} 条 incidents')

    # 3. 优先级分布统计
    cur.execute("SELECT priority, COUNT(*) FROM incidents GROUP BY priority ORDER BY priority")
    print('\n  优先级分布:')
    for r in cur.fetchall():
        print(f'    {r[0]}: {r[1]}')

    # 4. 严重度分布
    cur.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity ORDER BY severity")
    print('\n  严重度分布:')
    for r in cur.fetchall():
        print(f'    {r[0]}: {r[1]}')

    # 5. 攻击类型 Top 5
    cur.execute("""
        SELECT alert_type, COUNT(*) as cnt FROM incidents
        WHERE alert_type IS NOT NULL
        GROUP BY alert_type ORDER BY cnt DESC LIMIT 5
    """)
    print('\n  攻击类型 Top 5:')
    for r in cur.fetchall():
        print(f'    {r[0]}: {r[1]}')

    conn.commit()

    # ============ 补充 scan_tasks 多样化 ============
    print('\n--- 补充 scan_tasks ---')
    cur.execute("DELETE FROM scan_tasks WHERE target_ip='127.0.0.1'")

    # 添加 20 条多 IP 多 risk_level 的扫描记录
    sample_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30', '10.0.0.5', '10.0.0.8',
                  '10.0.0.15', '10.0.0.22', '172.16.5.5', '172.16.5.10', '172.16.8.3']
    for i, ip in enumerate(sample_ips * 2):  # 20 条
        ts = end - timedelta(hours=random.randint(0, 168))
        risk_score = random.choice([15, 18, 22, 25, 38, 42, 55, 68, 78, 85, 92])
        risk_level = 'critical' if risk_score >= 80 else 'high' if risk_score >= 60 else 'medium' if risk_score >= 30 else 'low'
        cur.execute("""
            INSERT INTO scan_tasks (task_id, target_ip, target_hostname, scan_type,
                                    enable_web_scan, authorized, status, started_at,
                                    completed_at, risk_score, risk_level, ports_open,
                                    summary, triggered_by)
            VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f'SCAN-{ts.strftime("%Y%m%d")}-{i:04d}',
            ip,
            f'server-{i:02d}.corp.local',
            'asset',
            random.choice(['completed', 'completed', 'completed', 'failed']),
            ts.isoformat(timespec='seconds'),
            (ts + timedelta(seconds=random.randint(30, 240))).isoformat(timespec='seconds'),
            risk_score,
            risk_level,
            random.randint(1, 15),
            f'发现 {random.randint(1, 8)} 个开放端口 / {random.randint(0, 3)} 个 Web 服务',
            'admin',
        ))

    cur.execute("SELECT COUNT(*) FROM scan_tasks")
    print(f'✓ scan_tasks 共 {cur.fetchone()[0]} 条')

    # ============ 补充 target_assets 多样化 ============
    print('\n--- 补充 target_assets ---')
    cur.execute("DELETE FROM target_assets WHERE ip_address='127.0.0.1'")

    sample_targets = [
        ('web-prod-01.corp.local', '10.10.1.10', 'server', 'web', 'production', 'critical', 'ecommerce'),
        ('web-prod-02.corp.local', '10.10.1.11', 'server', 'web', 'production', 'critical', 'ecommerce'),
        ('api-gateway.corp.local', '10.10.2.5', 'server', 'api', 'production', 'critical', 'platform'),
        ('db-master-01.corp.local', '10.10.3.10', 'server', 'database', 'production', 'critical', 'data'),
        ('db-replica-01.corp.local', '10.10.3.11', 'server', 'database', 'production', 'high', 'data'),
        ('cache-redis-01.corp.local', '10.10.4.5', 'server', 'cache', 'production', 'high', 'platform'),
        ('k8s-master-01.corp.local', '10.10.5.10', 'server', 'kubernetes', 'production', 'critical', 'platform'),
        ('k8s-worker-01.corp.local', '10.10.5.20', 'server', 'kubernetes', 'production', 'core', 'platform'),
        ('k8s-worker-02.corp.local', '10.10.5.21', 'server', 'kubernetes', 'production', 'core', 'platform'),
        ('jenkins-ci.corp.local', '10.10.6.5', 'server', 'ci-cd', 'production', 'high', 'engineering'),
        ('gitlab-01.corp.local', '10.10.6.10', 'server', 'ci-cd', 'production', 'high', 'engineering'),
        ('mail-server.corp.local', '10.10.7.5', 'server', 'mail', 'production', 'medium', 'corporate'),
        ('vpn-gateway.corp.local', '10.10.8.1', 'network', 'firewall', 'production', 'critical', 'it'),
        ('file-server.corp.local', '10.10.9.5', 'server', 'storage', 'production', 'high', 'corporate'),
        ('office-printer-02', '10.10.20.20', 'iot', 'printer', 'office', 'low', 'corporate'),
        ('camera-lobby', '10.10.20.30', 'iot', 'camera', 'office', 'low', 'facilities'),
    ]

    for hn, ip, atype, role, bu, crit, _ in sample_targets:
        cur.execute("""
            INSERT INTO target_assets (hostname, ip_address, asset_type, role, business_unit,
                                       criticality, owner, enabled, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)
        """, (hn, ip, atype, role, bu, crit, random.choice(OWNERS)))

    cur.execute("SELECT COUNT(*) FROM target_assets")
    print(f'✓ target_assets 共 {cur.fetchone()[0]} 条')

    # ============ 补充 data_sources 多样化 ============
    print('\n--- 补充 data_sources ---')
    cur.execute("DELETE FROM data_sources")

    sources = [
        ('CloudTrail - AWS Production', 'cloud_audit', json.dumps({'region': 'ap-southeast-1', 'bucket': 'soc-cloudtrail-prod'}), 1, 'success', None),
        ('Office 365 Audit Logs', 'cloud_audit', json.dumps({'tenant_id': 'o365-corp', 'subscription': 'premium'}), 1, 'success', None),
        ('Osquery EDR - Production Fleet', 'edr', json.dumps({'server': 'https://edr.corp.local:9000', 'fleet_size': 120}), 1, 'success', None),
        ('WAF - Web Application Firewall', 'waf', json.dumps({'endpoint': 'https://waf.corp.local/api/events', 'vendor': 'modsecurity'}), 1, 'success', None),
        ('CrowdStrike Falcon', 'edr', json.dumps({'api_url': 'https://api.crowdstrike.com', 'customer_id': 'corp-prod'}), 1, 'success', None),
        ('Splunk SIEM', 'siem', json.dumps({'endpoint': 'https://splunk.corp.local:8089', 'index': 'main'}), 1, 'success', None),
        ('Firewall - Palo Alto', 'firewall', json.dumps({'host': '10.10.8.1', 'api_port': 443, 'vendor': 'paloalto'}), 1, 'success', None),
        ('Nessus Vulnerability Scanner', 'vuln_scan', json.dumps({'host': '10.10.6.20', 'port': 8834}), 1, 'success', None),
        ('GitHub Audit Log', 'cloud_audit', json.dumps({'org': 'corp-eng', 'webhook_url': 'https://hooks.soc.local/github'}), 1, 'success', None),
        ('Active Directory - LDAP', 'identity', json.dumps({'host': '10.10.1.100', 'base_dn': 'dc=corp,dc=local'}), 0, 'error', 'Connection timeout after 30s'),
    ]

    for name, stype, cfg, enabled, status, err in sources:
        cur.execute("""
            INSERT INTO data_sources (name, type, config_json, enabled, last_sync,
                                      last_status, last_error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (name, stype, cfg, enabled,
              (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(timespec='seconds'),
              status, err))

    cur.execute("SELECT COUNT(*) FROM data_sources")
    print(f'✓ data_sources 共 {cur.fetchone()[0]} 条')

    # ============ 补充 agent 性能 audit_logs ============
    print('\n--- 补充 agent 执行审计日志 ---')

    agent_names = ['triage', 'hunting', 'response', 'vuln', 'forensics', 'threat_intel']
    actions = [
        ('agent.execute', 'success', 1200, 4500),
        ('agent.execute', 'success', 800, 3200),
        ('agent.execute', 'failed', 5000, 8000),
        ('agent.test', 'success', 200, 800),
        ('agent.pipeline_run', 'success', 3500, 12000),
    ]

    log_count = 0
    for _ in range(80):
        ag = random.choice(agent_names)
        mod, result, lat_min, lat_max = random.choice(actions)
        ts = end - timedelta(hours=random.randint(0, 168))
        cur.execute("""
            INSERT INTO audit_logs (timestamp, username, action, module, target, details,
                                    ip_address, result, duration_ms, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts.isoformat(timespec='seconds'),
            'admin',
            f'{ag}.execute',
            mod.split('.')[0],
            f'{ag}-agent-v2',
            f'Executed task with {random.randint(3, 12)} subtasks',
            '127.0.0.1',
            result,
            random.randint(lat_min, lat_max),
            1,
        ))
        log_count += 1

    print(f'✓ 新增 {log_count} 条 agent 执行审计日志')

    conn.commit()
    conn.close()

    print('\n🎉 全部测试数据已就位！')
    print('\n下一步: 重启 Gunicorn 让 db.py 加载 incidents 表')


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
SOC 管理后台 - 数据库初始化
SQLite 单文件存储
"""

import sqlite3
import os
import bcrypt
import atexit
from datetime import datetime
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'admin.db')
_init_lockfile = DB_PATH + '.init.lock'


def _acquire_init_lock():
    """防止多个 Gunicorn worker 同时执行 init_db"""
    import fcntl
    try:
        fd = os.open(_init_lockfile, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (IOError, OSError):
        return None


def _release_init_lock(fd):
    if fd is not None:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


_init_lock_owner = False
_global_init_fd = None


def init_db(lock=True):
    """初始化数据库表结构（支持 Gunicorn 多进程并发安全）"""
    global _init_lock_owner, _global_init_fd
    
    fd = None
    if lock:
        fd = _acquire_init_lock()
        if fd is None:
            # 另一个 worker 正在初始化，等待它完成
            import time
            for _ in range(30):
                time.sleep(0.1)
                fd2 = _acquire_init_lock()
                if fd2 is not None:
                    fd = fd2
                    break
            if fd is None:
                # 超时回退：直接尝试连接
                pass
    
    _global_init_fd = fd
    if fd is not None:
        _init_lock_owner = True
        
        try:
            _do_init()
        finally:
            _release_init_lock(fd)
            _init_lock_owner = False
            _global_init_fd = None
    else:
        _do_init()


def _do_init():
    """实际初始化逻辑"""
    conn = get_db()
    cur = conn.cursor()

    # 1. 用户表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            full_name TEXT,
            role TEXT NOT NULL DEFAULT 'analyst',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            api_token TEXT
        )
    """)

    # 2. 数据源表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS data_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            config_json TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_sync TEXT,
            last_status TEXT,
            last_error TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Agent 配置表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_name TEXT UNIQUE NOT NULL,
            config_json TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT
        )
    """)

    # 4. Playbook 表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS playbooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            yaml_content TEXT NOT NULL,
            trigger_alert_type TEXT,
            trigger_severity TEXT,
            enabled INTEGER DEFAULT 1,
            version INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT
        )
    """)

    # 5. 系统设置表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            category TEXT DEFAULT 'general',
            encrypted INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 6. 审计日志表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT NOT NULL,
            module TEXT NOT NULL,
            target TEXT,
            details TEXT,
            ip_address TEXT,
            result TEXT DEFAULT 'success'
        )
    """)

    # 7. 扫描目标资产表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS target_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            ip_address TEXT,
            asset_type TEXT,
            role TEXT,
            business_unit TEXT,
            criticality TEXT DEFAULT 'medium',
            owner TEXT,
            tags TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 8. Agent 注册表（动态 Agent 模板）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            icon TEXT DEFAULT '🤖',
            system_prompt TEXT NOT NULL,
            input_schema TEXT,
            output_schema TEXT,
            tools TEXT,
            config_json TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            is_builtin INTEGER DEFAULT 0,
            usage_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT
        )
    """)

    # 9. 扫描结果表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT UNIQUE,
            target_ip TEXT,
            hostname TEXT,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'low',
            port_count INTEGER DEFAULT 0,
            result_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 10. 扫描白名单与任务（轻量级预留）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_or_cidr TEXT UNIQUE NOT NULL,
            label TEXT,
            scope TEXT DEFAULT 'authorized',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT UNIQUE NOT NULL,
            target_id INTEGER,
            target_ip TEXT NOT NULL,
            target_hostname TEXT,
            scan_type TEXT DEFAULT 'asset',
            enable_web_scan INTEGER DEFAULT 1,
            authorized INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'low',
            ports_open INTEGER DEFAULT 0,
            summary TEXT,
            triggered_by TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
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
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_priority_timestamp ON incidents(priority, timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity_timestamp ON incidents(severity, timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_alert_type ON incidents(alert_type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_module ON audit_logs(module)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_risk ON scan_results(risk_score, risk_level)")

    # 初始化默认数据
    # 默认管理员 admin/admin123
    if not cur.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        pw_hash = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
        cur.execute("""
            INSERT INTO users (username, password_hash, email, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        """, ('admin', pw_hash, 'admin@soc.local', '系统管理员', 'admin'))

    # 默认 Analyst 用户
    if not cur.execute("SELECT id FROM users WHERE username='analyst'").fetchone():
        pw_hash = bcrypt.hashpw('analyst123'.encode(), bcrypt.gensalt()).decode()
        cur.execute("""
            INSERT INTO users (username, password_hash, email, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        """, ('analyst', pw_hash, 'analyst@soc.local', '安全分析师', 'analyst'))

    # 默认 Agent 配置
    default_agent_configs = {
        'triage': {
            'risk_thresholds': {'P1': 80, 'P2': 60, 'P3': 40, 'P4': 0},
            'ai_model': 'deepseek-v3',
            'temperature': 0.2,
            'timeout_seconds': 30,
            'rule_engine_weight': 0.3,
            'auto_close_threshold': 20,
            'enable_ai_analysis': True
        },
        'hunting': {
            'min_risk_score': 50,
            'max_queries_per_hunt': 10,
            'time_window_hours': 24,
            'enable_chain_analysis': True,
            'enable_ioc_correlation': True
        },
        'response': {
            'enable_auto_response': False,
            'auto_response_priority': ['P1'],
            'require_approval_for': ['isolate_host', 'disable_user'],
            'notification_channels': ['feishu', 'email']
        },
        'vuln': {
            'cvss_critical_threshold': 9.0,
            'auto_calculate_priority': True,
            'include_mitigations': True
        }
    }

    for name, cfg in default_agent_configs.items():
        if not cur.execute("SELECT id FROM agent_configs WHERE agent_name=?", (name,)).fetchone():
            import json
            cur.execute("""
                INSERT INTO agent_configs (agent_name, config_json)
                VALUES (?, ?)
            """, (name, json.dumps(cfg, ensure_ascii=False)))

    # 默认系统设置
    default_settings = [
        ('site.name', 'SOC Multi-Agent 管理后台', 'general', 0),
        ('site.timezone', 'Asia/Shanghai', 'general', 0),
        ('site.language', 'zh-CN', 'general', 0),
        ('api.deepseek_key', '', 'api_keys', 1),
        ('api.deepseek_base_url', 'https://api.siliconflow.cn/v1', 'api_keys', 0),
        ('api.kimi_key', '', 'api_keys', 1),
        ('notification.feishu_webhook', '', 'notifications', 0),
        ('notification.email_smtp', '', 'notifications', 0),
        ('storage.report_retention_days', '90', 'storage', 0),
        ('security.session_timeout_minutes', '60', 'security', 0),
        ('security.password_min_length', '8', 'security', 0),
    ]

    for key, value, cat, enc in default_settings:
        if not cur.execute("SELECT key FROM settings WHERE key=?", (key,)).fetchone():
            cur.execute("""
                INSERT INTO settings (key, value, category, encrypted)
                VALUES (?, ?, ?, ?)
            """, (key, value, cat, enc))

    # 默认 Playbook (复制现有 yml)
    import json
    playbooks_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'playbooks')
    if os.path.exists(playbooks_dir):
        for yml_file in os.listdir(playbooks_dir):
            if yml_file.endswith('.yml'):
                file_path = os.path.join(playbooks_dir, yml_file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                pb_id = yml_file.replace('.yml', '')

                # 简单解析 frontmatter
                name = pb_id.replace('_', ' ').title()
                alert_type = pb_id
                severity = '["high", "critical"]'

                if not cur.execute("SELECT id FROM playbooks WHERE playbook_id=?", (pb_id,)).fetchone():
                    cur.execute("""
                        INSERT INTO playbooks (playbook_id, name, yaml_content, trigger_alert_type, trigger_severity)
                        VALUES (?, ?, ?, ?, ?)
                    """, (pb_id, name, yaml_content, alert_type, severity))

    # 默认示例资产
    sample_assets = [
        ('prod-web-01', '10.0.0.10', 'server', 'web-server', '电商', 'critical', 'ops-team', 'production,internet-facing'),
        ('prod-db-01', '10.0.0.20', 'server', 'database', '电商', 'critical', 'dba-team', 'production,pii'),
        ('office-pc-01', '10.1.0.100', 'workstation', 'workstation', '行政', 'low', 'it-team', 'office'),
        ('app-server-03', '10.0.0.30', 'server', 'application-server', '金融', 'high', 'devops-team', 'production'),
    ]
    for asset in sample_assets:
        if not cur.execute("SELECT id FROM target_assets WHERE hostname=?", (asset[0],)).fetchone():
            cur.execute("""
                INSERT INTO target_assets (hostname, ip_address, asset_type, role, business_unit, criticality, owner, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, asset)

    # 6 个内置 Agent 模板
    builtin_agents = [
        ('phishing_triage', '钓鱼邮件分流器', 'phishing',
         '自动识别钓鱼邮件，判断风险等级，提取 IOC',
         '🎣',
         '''你是 SOC 钓鱼邮件分析专家。请按以下步骤分析邮件：

1. **发件人检查**：域名信誉、SPF/DKIM/DMARC 验证、显示名伪装
2. **内容分析**：话术紧迫感、异常链接、可疑附件、社会工程学痕迹
3. **URL/Hash 提取**：所有可疑 URL、附件 Hash、邮箱地址
4. **风险评级**：高/中/低
5. **处置建议**：隔离/通知用户/加黑名单/工单

严格返回 JSON：
{
  "verdict": "phishing|spam|legitimate|uncertain",
  "risk_level": "high|medium|low",
  "confidence": 0-100,
  "indicators": ["i1", "i2"],
  "sender_analysis": "...",
  "url_analysis": "...",
  "iocs": {"urls": [], "hashes": [], "emails": []},
  "recommended_actions": ["action1"],
  "reasoning": "..."
}''',
         '{"subject":"string","sender":"string","body":"string","headers":"object","attachments":"array"}',
         '{"verdict":"string","risk_level":"string","confidence":"number","indicators":"array","sender_analysis":"string","url_analysis":"string","iocs":"object","recommended_actions":"array","reasoning":"string"}',
         '["threat_intel_lookup","email_quarantine"]'),

        ('log_anomaly', '日志异常检测', 'detection',
         '从大量日志中识别异常行为模式，发现潜在威胁',
         '📊',
         '''你是 SOC 日志分析专家。给定一段日志样本，请识别异常模式：

1. **基线偏离**：与正常模式的偏差（如时间、频率、来源）
2. **攻击指示器**：已知 IOC 匹配、TTP 模式
3. **异常关联**：多条日志组合形成的攻击链
4. **风险评级**：0-100

返回 JSON：
{
  "anomaly_detected": true|false,
  "anomaly_score": 0-100,
  "patterns": [{"name":"...","severity":"...","evidence":["..."]}],
  "potential_attack": "...",
  "affected_entities": ["ip|user|host"],
  "recommended_investigation": "...",
  "reasoning": "..."
}''',
         '{"log_sample":"string","source":"string","time_range":"string"}',
         '{"anomaly_detected":"boolean","anomaly_score":"number","patterns":"array","potential_attack":"string","affected_entities":"array","recommended_investigation":"string","reasoning":"string"}',
         '["siem_query","log_search"]'),

        ('ioc_enrichment', 'IOC 情报增强', 'intel',
         '对 IP/域名/Hash 进行威胁情报富化，输出关联威胁',
         '🔍',
         '''你是威胁情报分析师。对给定 IOC 进行多维度情报富化：

1. **信誉查询**：VirusTotal、AbuseIPDB、ThreatFox 等公开情报源
2. **历史关联**：该 IOC 是否与历史攻击事件关联
3. **TTP 映射**：对应的 MITRE ATT&CK 技术
4. **关联实体**：同家族 IOC、关联攻击组织

返回 JSON：
{
  "ioc_type": "ip|domain|hash|url|email",
  "ioc_value": "...",
  "reputation": "malicious|suspicious|clean|unknown",
  "confidence": 0-100,
  "sources": ["VirusTotal", "AbuseIPDB"],
  "first_seen": "YYYY-MM-DD",
  "last_seen": "YYYY-MM-DD",
  "associated_threats": ["APT29", "Emotet"],
  "mitre_techniques": ["T1566.001"],
  "related_iocs": ["..."],
  "recommended_action": "block|monitor|investigate|ignore",
  "reasoning": "..."
}''',
         '{"ioc":"string","ioc_type":"string"}',
         '{"ioc_type":"string","ioc_value":"string","reputation":"string","confidence":"number","sources":"array","first_seen":"string","last_seen":"string","associated_threats":"array","mitre_techniques":"array","related_iocs":"array","recommended_action":"string","reasoning":"string"}',
         '["threat_intel_lookup","geoip_lookup"]'),

        ('vuln_prioritizer', '漏洞优先级排序', 'vulnerability',
         '基于资产、暴露面、威胁情报综合排序漏洞修复优先级',
         '🛡️',
         '''你是漏洞管理专家。基于以下输入输出修复优先级建议：

1. **CVSS + EPSS**：结合基础评分和实际利用概率
2. **资产重要性**：关键资产/普通资产差异化
3. **暴露面**：公网/内网/隔离
4. **是否有补丁**：补丁可用性
5. **威胁情报**：是否被 APT/僵尸网络利用

返回 JSON：
{
  "prioritized_cves": [{
    "cve_id": "CVE-XXXX-XXXXX",
    "cvss": 0-10,
    "epss": 0-1,
    "priority": "P0|P1|P2|P3|P4",
    "patch_available": true|false,
    "exploitation_in_wild": true|false,
    "affected_assets": ["..."],
    "remediation_steps": ["..."],
    "remediation_eta": "..."
  }],
  "summary": "..."
}''',
         '{"cve_list":"array","asset_inventory":"object","threat_intel":"object"}',
         '{"prioritized_cves":"array","summary":"string"}',
         '["cve_lookup","asset_query"]'),

        ('malware_classifier', '恶意软件分类', 'malware',
         '根据行为、样本信息对恶意软件进行分类和家族识别',
         '🦠',
         '''你是恶意软件分析师。根据样本信息进行分类：

1. **类型识别**：木马/蠕虫/勒索/挖矿/间谍/银行/APT植入
2. **家族归属**：Emotet/Conti/Agent Tesla/PlugX 等
3. **行为能力**：持久化/横向移动/数据窃取/加密/通信
4. **影响范围**：基于 IOC 评估扩散情况
5. **清除难度**：1-10

返回 JSON：
{
  "family": "string",
  "type": "trojan|worm|ransomware|miner|spyware|banker|rat|other",
  "severity": "critical|high|medium|low",
  "capabilities": ["persistence", "lateral_movement", "data_exfil"],
  "persistence_mechanisms": ["registry", "service", "scheduled_task"],
  "network_indicators": {"c2_servers": [], "protocols": []},
  "estimated_infection_count": 0,
  "removal_difficulty": 1-10,
  "recommended_response": ["..."],
  "reasoning": "..."
}''',
         '{"file_hash":"string","behavior_logs":"string","sample_metadata":"object"}',
         '{"family":"string","type":"string","severity":"string","capabilities":"array","persistence_mechanisms":"array","network_indicators":"object","estimated_infection_count":"number","removal_difficulty":"number","recommended_response":"array","reasoning":"string"}',
         '["hash_lookup","sandbox_lookup"]'),

        ('threat_intel_summary', '威胁情报摘要', 'intel',
         '将原始威胁情报报告提炼成结构化的可操作摘要',
         '📰',
         '''你是威胁情报摘要专家。读取原始报告，输出结构化情报卡：

1. **威胁概述**：1-2 句话总结威胁本质
2. **影响范围**：行业/地区/产品/版本
3. **TTP**：MITRE ATT&CK 技术列表
4. **IOC**：提取所有 IOC（IP/域名/Hash/邮箱/工具）
5. **防御建议**：检测规则、加固措施、应急动作
6. **关联威胁**：该威胁与其他已知威胁的关联

返回 JSON：
{
  "title": "...",
  "threat_actor": "...",
  "summary": "...",
  "severity": "critical|high|medium|low",
  "ttps": ["T1566.001"],
  "iocs": {"ips": [], "domains": [], "hashes": [], "tools": []},
  "affected_sectors": ["..."],
  "detection_signatures": ["..."],
  "mitigation_actions": ["..."],
  "related_campaigns": ["..."],
  "references": ["url"]
}''',
         '{"report_content":"string","source":"string"}',
         '{"title":"string","threat_actor":"string","summary":"string","severity":"string","ttps":"array","iocs":"object","affected_sectors":"array","detection_signatures":"array","mitigation_actions":"array","related_campaigns":"array","references":"array"}',
         '["threat_intel_lookup","ttp_lookup"]'),
    ]

    for key, name, cat, desc, icon, prompt, in_schema, out_schema, tools in builtin_agents:
        if not cur.execute("SELECT id FROM agent_registry WHERE agent_key=?", (key,)).fetchone():
            cur.execute("""
                INSERT INTO agent_registry
                (agent_key, name, category, description, icon, system_prompt, input_schema, output_schema, tools, is_builtin, enabled, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'system')
            """, (key, name, cat, desc, icon, prompt, in_schema, out_schema, tools))

    # 默认扫描白名单（仅 RFC 1918 私网 + 常见演示目标）
    default_whitelist = [
        ('10.0.0.0/8', '内网A段', 'internal'),
        ('172.16.0.0/12', '内网B段', 'internal'),
        ('192.168.0.0/16', '内网C段', 'internal'),
        ('127.0.0.0/8', '本机回环', 'local'),
        ('scanme.nmap.org', 'Nmap 官方演示目标', 'authorized_demo'),
    ]
    for ip, label, scope in default_whitelist:
        if not cur.execute("SELECT id FROM scan_whitelist WHERE ip_or_cidr=?", (ip,)).fetchone():
            cur.execute("""
                INSERT INTO scan_whitelist (ip_or_cidr, label, scope, created_by)
                VALUES (?, ?, ?, 'system')
            """, (ip, label, scope))

    # ====== 产品化扩展：多租户 + 通知 + 品牌 ======

    # 10. 租户表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            contact_email TEXT,
            plan TEXT NOT NULL DEFAULT 'free',
            is_active INTEGER DEFAULT 1,
            max_users INTEGER DEFAULT 10,
            max_assets INTEGER DEFAULT 100,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT
        )
    """)

    # 给 users 表加 tenant_id（ALTER TABLE IF NOT EXISTS 不支持，用 try）
    try:
        cur.execute("ALTER TABLE users ADD COLUMN tenant_id INTEGER DEFAULT 1 REFERENCES tenants(id)")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN wechat TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN tenant_id INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN duration_ms INTEGER")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE target_assets ADD COLUMN tenant_id INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE playbooks ADD COLUMN tenant_id INTEGER DEFAULT 1")
    except Exception:
        pass

    # 11. 通知渠道配置表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER DEFAULT 1,
            name TEXT NOT NULL,
            channel TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            test_result TEXT,
            last_tested_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 12. 通知模板表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notification_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER DEFAULT 1,
            name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            title_template TEXT NOT NULL,
            body_template TEXT NOT NULL,
            channels TEXT DEFAULT '[]',
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 13. 品牌/Logo 配置表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS branding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER UNIQUE DEFAULT 1,
            site_name TEXT DEFAULT 'SOC 控制台',
            logo_url TEXT,
            favicon_url TEXT,
            primary_color TEXT DEFAULT '#6366f1',
            footer_text TEXT,
            custom_css TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ====== 初始种子数据 ======

    # 默认租户
    if not cur.execute("SELECT id FROM tenants WHERE tenant_key='default'").fetchone():
        cur.execute("""
            INSERT INTO tenants (tenant_key, name, contact_email, plan, max_users, max_assets)
            VALUES ('default', '默认租户', 'admin@soc.local', 'enterprise', 100, 1000)
        """)

    # 默认品牌配置
    if not cur.execute("SELECT id FROM branding WHERE tenant_id=1").fetchone():
        cur.execute("""
            INSERT INTO branding (tenant_id, site_name, primary_color, footer_text)
            VALUES (1, 'SOC 控制台', '#6366f1', 'Powered by SOC Agent v2.0')
        """)

    # 默认通知模板
    default_templates = [
        ('高危告警通知', 'alert_critical',
         '🚨 [高风险] {{alert.severity}} - {{alert.title}}',
         '**告警详情**\n- 来源: {{alert.source_ip}}\n- 目标: {{alert.dest_ip}}\n- 时间: {{alert.timestamp}}\n- 优先级: {{alert.priority}}\n- 描述: {{alert.description}}\n\n{{alert.recommendation or ""}}'),
        ('扫描结果报告', 'scan_completed',
         '📋 扫描报告 - {{scan.hostname}} ({{scan.ip_address}})',
         '**扫描结果**\n- 风险等级: {{scan.risk_level}} ({{scan.risk_score}}/100)\n- 开放端口: {{scan.port_count}} 个\n- 开始时间: {{scan.scan_start}}\n- 耗时: {{scan.scan_duration}}s\n\n**修复建议**:\n{{scan.recommendations | join("\n")}}'),
        ('调度任务超阈值', 'schedule_alert',
         '⚠️ [扫描调度] {{schedule.name}} - 风险分 {{score}}',
         '**调度任务告警**\n- 任务: {{schedule.name}}\n- 目标: {{schedule.target_ips | join(", ")}}\n- 风险分: {{score}}（阈值: {{threshold}}）\n- 时间: {{timestamp}}\n\n**建议**: 立即检查目标资产安全状态'),
    ]
    for tpl_name, event_type, title_tpl, body_tpl in default_templates:
        if not cur.execute("""SELECT id FROM notification_templates WHERE tenant_id=1 AND event_type=?
                           AND name=?""", (event_type, tpl_name)).fetchone():
            cur.execute("""INSERT INTO notification_templates
                (tenant_id, name, event_type, title_template, body_template)
                VALUES (1, ?, ?, ?, ?)""", (tpl_name, event_type, title_tpl, body_tpl))

    conn.commit()
    conn.close()
    print(f"✓ 数据库初始化完成: {DB_PATH}")


if __name__ == '__main__':
    init_db()
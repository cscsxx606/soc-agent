#!/usr/bin/env python3
"""
SOC Multi-Agent System - 主程序入口
完整实现 Phase 1-4:
  1. 告警智能分流 (Alert Triage)
  2. 主动威胁狩猎 (Threat Hunting)  
  3. 应急响应处置 (Incident Response)
  4. 漏洞智能评估 (Vulnerability Assessment)

用法:
  python main.py                    # 运行完整流水线
  python main.py --phase triage     # 仅运行告警分流
  python main.py --phase vuln       # 仅运行漏洞评估
  python main.py --demo             # 使用演示数据
"""

import sys
import os
import json
import argparse

# 确保能导入本地模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

# 加载配置
env_path = os.path.join(os.path.dirname(__file__), 'config', '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)

from orchestrator import SOCOrchestrator


def load_sample_alerts() -> list:
    """加载示例告警数据"""
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'sample_alerts.json')
    if os.path.exists(data_path):
        with open(data_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    # 内建演示数据
    return [
        {
            "id": "ALERT-2026-001",
            "timestamp": "2026-07-16T09:15:00Z",
            "source_ip": "203.0.113.45",
            "dest_ip": "10.0.0.50",
            "alert_type": "brute_force_ssh",
            "severity": "high",
            "description": "检测到 203.0.113.45 对 10.0.0.50 进行 SSH 暴力破解，5分钟内失败登录 47 次",
            "raw_log": "Jul 16 09:15:01 server-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 54321 ssh2",
            "asset_info": {"hostname": "server-01", "role": "web-server", "criticality": "high", "owner": "ops-team"}
        },
        {
            "id": "ALERT-2026-002",
            "timestamp": "2026-07-16T09:20:00Z",
            "source_ip": "172.16.0.88",
            "dest_ip": "8.8.8.8",
            "alert_type": "suspicious_dns_query",
            "severity": "medium",
            "description": "主机 172.16.0.88 频繁查询已知恶意域名 evil-c2.example.com",
            "raw_log": "Jul 16 09:20:15 workstation-03 dnsmasq[5678]: query[A] evil-c2.example.com from 172.16.0.88",
            "asset_info": {"hostname": "workstation-03", "role": "developer-workstation", "criticality": "medium", "owner": "dev-team"}
        },
        {
            "id": "ALERT-2026-003",
            "timestamp": "2026-07-16T09:25:00Z",
            "source_ip": "10.0.0.15",
            "dest_ip": "8.8.8.8",
            "alert_type": "outbound_connection",
            "severity": "low",
            "description": "服务器 10.0.0.15 非工作时间连接外部 DNS",
            "raw_log": "Jul 16 09:25:30 db-server-02 kernel: OUTBOUND TCP 10.0.0.15:45678 -> 8.8.8.8:53 SYN",
            "asset_info": {"hostname": "db-server-02", "role": "database-server", "criticality": "high", "owner": "dba-team"}
        },
        {
            "id": "ALERT-2026-004",
            "timestamp": "2026-07-16T09:30:00Z",
            "source_ip": "203.0.113.100",
            "dest_ip": "10.0.0.50",
            "alert_type": "web_attack_sql_injection",
            "severity": "critical",
            "description": "WAF 检测到 SQL 注入攻击: /api/v1/users?id=1' OR '1'='1",
            "raw_log": "ModSecurity: SQL Injection Attack Detected from 203.0.113.100",
            "asset_info": {"hostname": "web-server-prod", "role": "web-server", "criticality": "critical", "owner": "security-team"}
        },
        {
            "id": "ALERT-2026-005",
            "timestamp": "2026-07-16T09:35:00Z",
            "source_ip": "10.0.0.22",
            "dest_ip": "10.0.0.50",
            "alert_type": "privilege_escalation",
            "severity": "high",
            "description": "用户 zhangsan 执行 sudo su - 切换到 root",
            "raw_log": "app-server-03 sudo: zhangsan : USER=root ; COMMAND=/bin/su -",
            "asset_info": {"hostname": "app-server-03", "role": "application-server", "criticality": "high", "owner": "devops-team"}
        }
    ]


def main():
    parser = argparse.ArgumentParser(description='SOC Multi-Agent System')
    parser.add_argument('--phase', choices=['triage', 'hunting', 'response', 'vuln', 'full'],
                       default='full', help='选择执行阶段 (默认: full)')
    parser.add_argument('--demo', action='store_true', help='使用演示模式')
    parser.add_argument('--input', type=str, help='输入告警文件 (JSON)')
    args = parser.parse_args()

    print("🔒 SOC Multi-Agent System")
    print(f"   Model: DeepSeek V4 Flash")
    print(f"   Phases: 1-Triage | 2-Hunting | 3-Response | 4-Vuln\n")

    # 加载告警
    if args.input and os.path.exists(args.input):
        with open(args.input, 'r', encoding='utf-8') as f:
            alerts = json.load(f)
    else:
        alerts = load_sample_alerts()

    print(f"📥 已加载 {len(alerts)} 条告警数据\n")

    # 创建编排器并执行
    orchestrator = SOCOrchestrator()
    
    if args.phase == 'full':
        report = orchestrator.run_full_pipeline(alerts)
    else:
        # 单阶段执行
        if args.phase == 'triage':
            from agents.triage_agent import AlertTriageAgent
            agent = AlertTriageAgent()
            results = agent.execute(alerts)
            print(f"\n✅ 分流完成: {len(results)} 条告警")
            for r in results:
                a = r.get('ai_analysis', {})
                print(f"  {r['id']}: 评分={a.get('risk_score')}, 优先级={a.get('priority')}")
        
        elif args.phase == 'vuln':
            from agents.vuln_agent import VulnAssessmentAgent
            agent = VulnAssessmentAgent()
            vulns = agent.generate_sample_vulns()
            report = agent.execute(vulns)
            print(f"\n✅ 漏洞评估完成")
            print(f"  Critical: {report['vuln_summary']['critical']}")
            print(f"  High: {report['vuln_summary']['high']}")

    print("\n🏁 执行完成!")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Phase 2: 威胁狩猎 Agent (Threat Hunting Agent)
功能：基于告警进行主动威胁狩猎，发现隐藏威胁
"""

from typing import Dict, Any, List
from datetime import datetime, timedelta
from core.agent_base import BaseAgent


class ThreatHuntingAgent(BaseAgent):
    """威胁狩猎 Agent"""

    def __init__(self):
        super().__init__(
            name="HuntingAgent",
            description="主动威胁狩猎与攻击链还原"
        )
        self.hunt_prompt = """你是一名高级威胁狩猎分析师（GCTI/GCFA 认证），擅长通过单点告警发现整个攻击链。

任务：基于给定的告警，设计并执行威胁狩猎查询，发现：
1. 同一攻击者的其他活动（横向移动、权限提升）
2. 历史攻击痕迹（过去 7-30 天）
3. 关联的 IOC 和 TTP
4. 攻击链完整时间线
5. 受影响的资产范围

输出 JSON 格式：
{
  "hunt_id": "HUNT-XXXX",
  "hypothesis": "狩猎假设",
  "hunt_queries": [
    {
      "query_name": "查询名称",
      "query_logic": "SIEM/EDR 查询语句",
      "data_source": "数据来源",
      "time_range": "时间范围"
    }
  ],
  "findings": [
    {
      "finding_type": "发现类型",
      "description": "描述",
      "confidence": "高/中/低",
      "severity": "严重/高/中/低"
    }
  ],
  "attack_chain": {
    "initial_access": "初始访问方式",
    "persistence": "持久化手段",
    "privilege_escalation": "权限提升",
    "lateral_movement": "横向移动",
    "exfiltration": "数据窃取"
  },
  "affected_assets": ["资产1", "资产2"],
  "recommended_hunts": ["后续建议的狩猎方向"],
  "hunt_summary": "狩猎总结"
}"""

    def execute(self, triaged_alert: Dict) -> Dict:
        """
        执行威胁狩猎
        输入: 已分流的告警
        输出: 威胁狩猎报告
        """
        alert_id = triaged_alert.get('id', 'unknown')
        risk_score = triaged_alert.get('ai_analysis', {}).get('risk_score', 0)

        # 只对中高风险的告警进行狩猎
        if risk_score < 50:
            self.log(f"告警 {alert_id} 风险评分 {risk_score} < 50，跳过狩猎")
            return {
                'alert_id': alert_id,
                'hunt_status': 'skipped',
                'reason': '风险评分过低'
            }

        self.log(f"开始对告警 {alert_id} 进行威胁狩猎")

        # 构建狩猎查询
        user_prompt = self._build_hunt_prompt(triaged_alert)

        # AI 狩猎分析
        hunt_result = self.llm.analyze_json(self.hunt_prompt, user_prompt)

        if hunt_result:
            self.log(f"  ✓ 威胁狩猎完成，发现 {len(hunt_result.get('findings', []))} 个线索")
            self.update_stats(success=True)
        else:
            self.log(f"  ⚠ AI 狩猎分析失败，使用内置模板")
            hunt_result = self._template_hunt(triaged_alert)
            self.update_stats(success=False)

        return {
            'alert_id': alert_id,
            'hunt_status': 'completed',
            'hunt_time': datetime.now().isoformat(),
            'trigger_risk_score': risk_score,
            'hunt_result': hunt_result,
            'hunt_agent': self.name
        }

    def _build_hunt_prompt(self, alert: Dict) -> str:
        """构建狩猎查询"""
        analysis = alert.get('ai_analysis', {})
        enrichment = alert.get('enrichment', {})

        return f"""基于以下安全告警，设计威胁狩猎方案：

【触发告警】
ID: {alert.get('id')}
类型: {alert.get('alert_type')}
攻击类型: {analysis.get('attack_type')}
MITRE: {analysis.get('mitre_technique_id')} - {analysis.get('mitre_technique_name')}
源 IP: {alert.get('source_ip')}
目标资产: {alert.get('asset_info', {}).get('hostname')} ({alert.get('asset_info', {}).get('role')})
时间: {alert.get('timestamp')}

【已知信息】
{analysis.get('reasoning', '无')}

请设计具体的 SIEM/EDR 查询语句，并推测可能的攻击链。"""

    def _template_hunt(self, alert: Dict) -> Dict:
        """内置狩猎模板（AI 失败时使用）"""
        alert_type = alert.get('alert_type', '')
        source_ip = alert.get('source_ip', '')
        hostname = alert.get('asset_info', {}).get('hostname', '')

        # 基于告警类型的标准狩猎查询
        queries = []

        if alert_type == 'brute_force_ssh':
            queries = [
                {
                    'query_name': '同一源 IP 的其他登录尝试',
                    'query_logic': f'source_ip={source_ip} AND (event_type=auth OR event_type=login) | stats count by dest_ip, user',
                    'data_source': 'SIEM-Auth-Logs',
                    'time_range': 'last_7d'
                },
                {
                    'query_name': '成功登录后活动',
                    'query_logic': f'hostname={hostname} AND event_type=process_start AND user!=root | stats count by process_name',
                    'data_source': 'EDR-Process-Logs',
                    'time_range': 'last_24h'
                }
            ]
        elif alert_type == 'web_attack_sql_injection':
            queries = [
                {
                    'query_name': '相同攻击者的其他 Web 攻击',
                    'query_logic': f'source_ip={source_ip} AND (url=*union* OR url=*select* OR url=*drop*) | stats count by url',
                    'data_source': 'WAF-Logs',
                    'time_range': 'last_7d'
                },
                {
                    'query_name': '数据库异常查询',
                    'query_logic': f'hostname={hostname} AND database_query=*union* | stats count by query_pattern',
                    'data_source': 'DB-Audit-Logs',
                    'time_range': 'last_24h'
                }
            ]

        return {
            'hunt_id': f"HUNT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'hypothesis': f"基于 {alert_type} 告警，攻击者可能已完成初始访问并尝试横向移动",
            'hunt_queries': queries,
            'findings': [],
            'attack_chain': {
                'initial_access': '待确认',
                'persistence': '待确认',
                'privilege_escalation': '待确认',
                'lateral_movement': '待确认',
                'exfiltration': '待确认'
            },
            'affected_assets': [hostname],
            'recommended_hunts': ['检查同一源 IP 的其他活动', '检查目标资产的异常进程'],
            'hunt_summary': '基于模板的初始狩猎查询已生成，需人工执行查询并分析结果'
        }

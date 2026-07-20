#!/usr/bin/env python3
"""
Phase 1: 告警分流 Agent (Alert Triage Agent)
功能：告警丰富化、AI 风险分析、自动分流
"""

from typing import Dict, Any, List
from core.agent_base import BaseAgent


class AlertTriageAgent(BaseAgent):
    """告警智能分流 Agent"""

    def __init__(self):
        super().__init__(
            name="TriageAgent",
            description="告警智能分流与风险评估"
        )
        self.system_prompt = """你是一名资深 SOC 分析师（CISSP/GCIA 认证），拥有10年+安全运营经验。
你的任务是对安全告警进行专业分析，输出严格的 JSON 格式结果。

分析要求：
1. 攻击类型识别：映射到 MITRE ATT&CK 框架
2. 风险评分：0-100（综合资产重要性、攻击严重性、暴露面）
3. 置信度：高/中/低
4. 影响分析：业务影响 + 数据影响
5. 处置建议：立即处置(P1) / 调查跟进(P2) / 观察记录(P3) / 自动关闭(P4)
6. 是否需要人工确认

评分规则：
- 90-100: 紧急（核心业务受威胁，需立即处置）
- 80-89: 高危（重要资产受攻击，需快速响应）
- 60-79: 中危（需调查确认）
- 40-59: 低危（观察记录）
- 0-39: 信息（可自动关闭）

输出严格 JSON 格式：
{
  "attack_type": "攻击类型",
  "mitre_technique_id": "TXXXX",
  "mitre_technique_name": "技术名称",
  "risk_score": 85,
  "confidence": "高",
  "business_impact": "业务影响描述",
  "data_impact": "数据影响描述",
  "recommended_action": "立即处置/调查跟进/观察记录/自动关闭",
  "priority": "P1/P2/P3/P4",
  "key_indicators": ["指标1", "指标2"],
  "human_verification_needed": true,
  "reasoning": "详细推理过程",
  "playbook_suggestion": "建议执行的处置预案"
}"""

    def _enrich_alert(self, alert: Dict) -> Dict:
        """告警丰富化"""
        source_ip = alert.get('source_ip', '')

        # 简单 IP 信誉判断
        if not source_ip.startswith(('10.', '172.16.', '172.17.', '172.18.', 
                                      '172.19.', '172.20.', '172.21.', '172.22.',
                                      '172.23.', '172.24.', '172.25.', '172.26.',
                                      '172.27.', '172.28.', '172.29.', '172.30.',
                                      '172.31.', '192.168.')):
            ip_reputation = 'external/potentially_malicious'
        else:
            ip_reputation = 'internal'

        alert['enrichment'] = {
            'source_ip_reputation': ip_reputation,
            'asset_criticality_score': {
                'critical': 100, 'high': 75, 'medium': 50, 'low': 25
            }.get(alert.get('asset_info', {}).get('criticality', 'medium'), 50),
            'alert_family': self._classify_alert_family(alert.get('alert_type', '')),
            'triage_time': __import__('datetime').datetime.now().isoformat()
        }
        return alert

    def _classify_alert_family(self, alert_type: str) -> str:
        """告警分类"""
        families = {
            'brute_force_ssh': 'intrusion_attempt',
            'web_attack_sql_injection': 'web_attack',
            'privilege_escalation': 'lateral_movement',
            'suspicious_dns_query': 'command_and_control',
            'outbound_connection': 'exfiltration',
            'malware_detected': 'malware',
            'phishing_email': 'social_engineering'
        }
        return families.get(alert_type, 'unknown')

    def _rule_fallback(self, alert: Dict) -> Dict:
        """规则引擎 fallback"""
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'medium')
        criticality = alert.get('asset_info', {}).get('criticality', 'medium')
        enrichment = alert.get('enrichment', {})
        is_external = enrichment.get('source_ip_reputation', '').startswith('external')

        # 基础评分
        score_map = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30}
        base_score = score_map.get(severity, 50)

        # 资产调整
        asset_mult = {'critical': 1.0, 'high': 0.9, 'medium': 0.8, 'low': 0.7}
        score = int(base_score * asset_mult.get(criticality, 0.8))

        # 攻击类型调整
        type_adj = {
            'web_attack_sql_injection': 10,
            'privilege_escalation': 8,
            'brute_force_ssh': 5,
            'suspicious_dns_query': 3,
            'outbound_connection': -5
        }
        score = min(100, score + type_adj.get(alert_type, 0))

        # 外网源加分
        if is_external:
            score = min(100, score + 10)

        # 优先级
        if score >= 80:
            priority, action = 'P1', '立即处置'
        elif score >= 60:
            priority, action = 'P2', '调查跟进'
        elif score >= 40:
            priority, action = 'P3', '观察记录'
        else:
            priority, action = 'P4', '自动关闭'

        mitre_map = {
            'brute_force_ssh': ('T1110', 'Brute Force'),
            'suspicious_dns_query': ('T1071.004', 'Application Layer Protocol: DNS'),
            'web_attack_sql_injection': ('T1190', 'Exploit Public-Facing Application'),
            'privilege_escalation': ('T1068', 'Exploitation for Privilege Escalation'),
            'outbound_connection': ('T1041', 'Exfiltration Over C2 Channel')
        }
        tid, tname = mitre_map.get(alert_type, ('T0000', 'Unknown'))

        return {
            'attack_type': tname,
            'mitre_technique_id': tid,
            'mitre_technique_name': tname,
            'risk_score': score,
            'confidence': '中',
            'business_impact': f'影响{criticality}级别资产',
            'data_impact': '待评估',
            'recommended_action': action,
            'priority': priority,
            'key_indicators': [alert_type, f'资产:{criticality}', f'源IP:{enrichment.get("source_ip_reputation", "unknown")}'],
            'human_verification_needed': score >= 70,
            'reasoning': f'规则引擎: 严重度{severity} × 资产{criticality} + 类型调整 + 外网{is_external} = {score}',
            'playbook_suggestion': f'{alert_type}_response'
        }

    def execute(self, alerts: List[Dict]) -> List[Dict]:
        """
        执行告警分流
        输入: 告警列表
        输出: 带 AI 分析的分流结果
        """
        self.log(f"开始处理 {len(alerts)} 条告警")
        results = []

        for idx, alert in enumerate(alerts, 1):
            self.log(f"[{idx}/{len(alerts)}] 分析告警: {alert.get('id', 'unknown')}")

            # Step 1: 丰富化
            enriched = self._enrich_alert(alert)

            # Step 2: AI 分析 - 过三层护栏 (PromptGuard + ModelACL)
            user_prompt = self._format_alert_for_analysis(enriched)
            analysis = self.safe_llm_call(
                self.system_prompt,
                user_prompt,
                model='deepseek-chat',
                estimated_tokens=len(user_prompt + self.system_prompt) // 4,
            )

            if analysis:
                self.log(f"  ✓ AI 分析完成，风险评分: {analysis.get('risk_score', 'N/A')}")
                self.update_stats(success=True)
            else:
                self.log(f"  ⚠ AI 分析失败 / 被护栏拦截，使用规则引擎")
                analysis = self._rule_fallback(enriched)
                self.update_stats(success=False)

            # 合并结果
            triaged = {
                **enriched,
                'ai_analysis': analysis,
                'triage_agent': self.name,
                'triage_version': '2.0'
            }
            results.append(triaged)

            # 记忆
            self.remember('triage_result', {
                'alert_id': alert.get('id'),
                'risk_score': analysis.get('risk_score', 0),
                'priority': analysis.get('priority', 'P4')
            })

        self.log(f"分流完成: {len(results)} 条告警")
        return results

    def _format_alert_for_analysis(self, alert: Dict) -> str:
        """格式化告警给 LLM 分析"""
        enrichment = alert.get('enrichment', {})
        return f"""请分析以下安全告警：

【告警基本信息】
ID: {alert.get('id')}
时间: {alert.get('timestamp')}
类型: {alert.get('alert_type')}
原始严重级别: {alert.get('severity')}
源 IP: {alert.get('source_ip')} (信誉: {enrichment.get('source_ip_reputation', 'unknown')})
目标 IP: {alert.get('dest_ip')}
描述: {alert.get('description')}

【资产信息】
主机名: {alert.get('asset_info', {}).get('hostname')}
角色: {alert.get('asset_info', {}).get('role')}
重要性: {alert.get('asset_info', {}).get('criticality')}
负责团队: {alert.get('asset_info', {}).get('owner')}

【原始日志】
{alert.get('raw_log', 'N/A')[:2000]}

请输出 JSON 格式的分析结果。"""

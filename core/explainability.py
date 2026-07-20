#!/usr/bin/env python3
"""
AegisGuard · Layer 3 · Explainability
======================================

AI 决策可解释性。每个 SOC AI 决策都可追溯、可解释、可证明。

用法::

    from core.explainability import DecisionExplainer
    
    explainer = DecisionExplainer()
    
    explanation = explainer.explain_incident_triage({
        'incident_id': 'INC-001',
        'alert_type': 'brute_force_ssh',
        'severity': 'high',
        'asset_info': {'criticality': 'critical'},
        'source_ip': '8.8.8.8',
        'enrichment': {...},
        'ai_analysis': {
            'priority': 'P1',
            'risk_score': 85,
            'reasoning': '...',
            'mitre_technique_id': 'T1110',
            ...
        }
    })
    
    print(explanation.summary)
    for evidence in explanation.evidence:
        print(f'  - {evidence}')
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time


class ExplanationType(str, Enum):
    TRIAGE = "triage"
    HUNTING = "hunting"
    RESPONSE = "response"
    VULN = "vuln"
    TOOL_ACL = "tool_acl"
    MODEL_QUOTA = "model_quota"


# ============ 数据结构 ============

@dataclass
class Evidence:
    """决策依据"""
    source: str           # 'alert', 'asset', 'enrichment', 'history', 'rule_engine'
    field: str            # 'source_ip', 'criticality', etc.
    value: Any            # 实际值
    impact: str           # 'positive' (推高风险) / 'negative' (降低) / 'neutral'
    weight: float         # 0-1 权重
    note: str = ""        # 补充说明


@dataclass
class AlternativeAction:
    """备选方案"""
    action: str
    priority: str
    pros: List[str] = field(default_factory=list)
    cons: List[str] = field(default_factory=list)


@dataclass
class Explanation:
    """决策解释报告"""
    decision_id: str
    decision_type: str
    summary: str                  # 一句话总结
    reasoning: str                # 推理链
    evidence: List[Evidence]      # 证据列表
    confidence: float             # 0-1
    risk_factors: List[str]       # 风险因素
    alternative_actions: List[AlternativeAction] = field(default_factory=list)
    audit_trail: List[str] = field(default_factory=list)  # 引用 audit_chain
    timestamp: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d

    def to_human_readable(self) -> str:
        """人类可读格式"""
        lines = [
            f"## 决策解释报告 ({self.decision_type})",
            f"决策 ID: {self.decision_id}",
            f"时间: {self.timestamp}",
            "",
            f"### 摘要",
            self.summary,
            "",
            f"### 推理",
            self.reasoning,
            "",
            f"### 置信度",
            f"{self.confidence * 100:.1f}%",
            "",
            f"### 证据",
        ]
        for ev in self.evidence:
            impact_icon = "⬆️" if ev.impact == 'positive' else "⬇️" if ev.impact == 'negative' else "➡️"
            lines.append(f"  {impact_icon} [{ev.source}] {ev.field} = {ev.value} (权重 {ev.weight})")
            if ev.note:
                lines.append(f"     {ev.note}")

        lines.append("")
        lines.append("### 风险因素")
        for rf in self.risk_factors:
            lines.append(f"  ⚠️ {rf}")

        if self.alternative_actions:
            lines.append("")
            lines.append("### 备选方案")
            for alt in self.alternative_actions:
                lines.append(f"  - [{alt.priority}] {alt.action}")
                for p in alt.pros:
                    lines.append(f"    + {p}")
                for c in alt.cons:
                    lines.append(f"    - {c}")

        if self.audit_trail:
            lines.append("")
            lines.append("### 审计追溯")
            for ref in self.audit_trail:
                lines.append(f"  → {ref}")

        return "\n".join(lines)


# ============ DecisionExplainer ============

class DecisionExplainer:
    """AI 决策解释器"""

    def __init__(self):
        self.explanations: List[Explanation] = []

    def explain_incident_triage(self, incident: Dict) -> Explanation:
        """解释告警分流决策"""
        decision_id = f'triage-{incident.get("incident_id", "unknown")}'
        ai = incident.get('ai_analysis', {})
        enrichment = incident.get('enrichment', {})
        asset = incident.get('asset_info', {})

        evidence = []
        risk_factors = []

        # ============ 收集证据 ============

        # 1. 攻击类型
        alert_type = incident.get('alert_type', 'unknown')
        evidence.append(Evidence(
            source='alert', field='alert_type', value=alert_type,
            impact='positive' if self._is_high_risk_type(alert_type) else 'neutral',
            weight=0.8,
            note=self._describe_alert_type(alert_type),
        ))

        # 2. 源 IP
        source_ip = incident.get('source_ip', '')
        ip_rep = enrichment.get('source_ip_reputation', 'unknown')
        is_external = ip_rep.startswith('external')
        evidence.append(Evidence(
            source='enrichment', field='source_ip_reputation', value=ip_rep,
            impact='positive' if is_external else 'negative',
            weight=0.6,
            note='外网 IP' if is_external else '内网 IP',
        ))

        # 3. 资产重要性
        criticality = asset.get('criticality', 'medium')
        crit_weight = {'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.2}.get(criticality, 0.4)
        evidence.append(Evidence(
            source='asset', field='criticality', value=criticality,
            impact='positive' if crit_weight >= 0.5 else 'neutral',
            weight=crit_weight,
            note=f'{criticality} 级资产',
        ))

        # 4. 严重度
        severity = incident.get('severity', 'medium')
        sev_weight = {'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.2}.get(severity, 0.4)
        evidence.append(Evidence(
            source='alert', field='severity', value=severity,
            impact='positive' if sev_weight >= 0.5 else 'neutral',
            weight=sev_weight,
        ))

        # ============ 风险因素 ============
        if is_external and criticality == 'critical':
            risk_factors.append('外部 IP 攻击 critical 级资产')
        if self._is_high_risk_type(alert_type):
            risk_factors.append(f'攻击类型 {alert_type} 属于高风险家族')
        if severity == 'critical':
            risk_factors.append('严重度 critical')

        # ============ 备选方案 ============
        priority = ai.get('priority', 'P3')
        alternatives = self._generate_alternatives(alert_type, criticality, priority)

        # ============ 摘要 ============
        risk_score = ai.get('risk_score', 0)
        summary = f'{priority} 优先级 (风险评分 {risk_score}): {alert_type} 攻击 {criticality} 资产'
        if is_external:
            summary += ', 来自外部 IP'

        # ============ 推理 ============
        reasoning = ai.get('reasoning', '') or self._generate_reasoning(evidence, priority)

        explanation = Explanation(
            decision_id=decision_id,
            decision_type=ExplanationType.TRIAGE.value,
            summary=summary,
            reasoning=reasoning,
            evidence=evidence,
            confidence=min(1.0, sum(e.weight for e in evidence) / len(evidence) / 1.0),
            risk_factors=risk_factors,
            alternative_actions=alternatives,
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
        )

        self.explanations.append(explanation)
        return explanation

    def explain_response_action(self, action: Dict) -> Explanation:
        """解释响应动作"""
        decision_id = f'response-{action.get("action_id", "unknown")}'
        target = action.get('target', 'unknown')
        action_type = action.get('action_type', 'unknown')

        evidence = [
            Evidence('incident', 'incident_id', action.get('incident_id', ''), 'neutral', 0.5),
            Evidence('target', 'target_host', target, 'positive', 0.8),
            Evidence('action', 'action_type', action_type, 'positive', 0.7,
                     note=f'自动化动作: {action_type}'),
        ]

        risk_factors = [f'执行自动化动作: {action_type}']
        if 'disable_user' in action_type:
            risk_factors.append('用户账号被禁用 - 影响范围评估')
        if 'isolate_host' in action_type:
            risk_factors.append('主机被隔离 - 业务连续性影响')

        summary = f'执行 {action_type} 针对 {target}'

        return Explanation(
            decision_id=decision_id,
            decision_type=ExplanationType.RESPONSE.value,
            summary=summary,
            reasoning=f'基于 Incident {action.get("incident_id", "")} 的自动化响应动作。\n'
                      f'目标: {target}\n动作: {action_type}\n'
                      f'触发条件: {action.get("trigger", "高风险告警")}',
            evidence=evidence,
            confidence=0.85,
            risk_factors=risk_factors,
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
        )

    def explain_tool_acl_deny(self, event: Dict) -> Explanation:
        """解释工具 ACL 拒绝事件"""
        decision_id = f'acl-{event.get("event_hash", "unknown")}'
        agent = event.get('agent_name', '')
        action = event.get('action', '')
        resource = event.get('resource', '')

        evidence = [
            Evidence('acl', 'agent', agent, 'neutral', 0.5),
            Evidence('acl', 'action', action, 'neutral', 0.5),
            Evidence('acl', 'resource', resource, 'neutral', 0.5),
        ]

        summary = f'{agent} 被拒绝执行 {action} {resource}'
        risk_factors = ['Agent 越权尝试', '潜在攻击或配置错误']

        alternatives = [
            AlternativeAction(
                action='使用其他有权限的 agent',
                priority='P2',
                pros=['安全合规', '权限隔离生效'],
                cons=['需要人工协调'],
            ),
            AlternativeAction(
                action='提升 agent 权限（需审批）',
                priority='P3',
                pros=['自动化继续', '审计可追溯'],
                cons=['需 CISO 审批', '扩大攻击面'],
            ),
        ]

        return Explanation(
            decision_id=decision_id,
            decision_type=ExplanationType.TOOL_ACL.value,
            summary=summary,
            reasoning=f'Agent {agent} 尝试 {action} 操作 {resource}, '
                      f'但 ACL 配置禁止此操作。这表明权限隔离机制正常工作。',
            evidence=evidence,
            confidence=1.0,
            risk_factors=risk_factors,
            alternative_actions=alternatives,
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
        )

    def _is_high_risk_type(self, alert_type: str) -> bool:
        return alert_type in (
            'web_attack_sql_injection', 'privilege_escalation',
            'malware_detected', 'data_exfiltration',
        )

    def _describe_alert_type(self, alert_type: str) -> str:
        descriptions = {
            'brute_force_ssh': 'SSH 暴力破解',
            'web_attack_sql_injection': 'SQL 注入攻击',
            'privilege_escalation': '权限提升',
            'suspicious_dns_query': '可疑 DNS 查询（可能 C2）',
            'malware_detected': '恶意软件检出',
            'data_exfiltration': '数据外泄',
        }
        return descriptions.get(alert_type, '未知类型')

    def _generate_reasoning(self, evidence: List[Evidence], priority: str) -> str:
        """根据证据生成推理链"""
        positive = [e for e in evidence if e.impact == 'positive']
        negative = [e for e in evidence if e.impact == 'negative']
        parts = [
            f"决策: {priority} 优先级。",
            f"正因素 ({len(positive)}):",
        ]
        for e in positive:
            parts.append(f'  - {e.field} = {e.value} (权重 {e.weight})')
        if negative:
            parts.append(f"负因素 ({len(negative)}):")
            for e in negative:
                parts.append(f'  - {e.field} = {e.value} (权重 {e.weight})')
        return "\n".join(parts)

    def _generate_alternatives(
        self,
        alert_type: str,
        criticality: str,
        chosen_priority: str,
    ) -> List[AlternativeAction]:
        """生成备选方案"""
        if chosen_priority == 'P1':
            return [
                AlternativeAction(
                    action='立即自动隔离 + 触发应急响应',
                    priority='P1',
                    pros=['快速遏制', '减少损失'],
                    cons=['可能影响业务', '需人工确认'],
                ),
                AlternativeAction(
                    action='仅告警 + 等待人工确认',
                    priority='P2',
                    pros=['保守', '避免误杀'],
                    cons=['响应延迟', '攻击可能继续'],
                ),
            ]
        elif chosen_priority == 'P4':
            return [
                AlternativeAction(
                    action='自动关闭（当前选择）',
                    priority='P4',
                    pros=['减少噪音', '节省资源'],
                    cons=['可能漏掉真实威胁'],
                ),
                AlternativeAction(
                    action='观察记录',
                    priority='P3',
                    pros=['保留证据', '便于复盘'],
                    cons=['占存储'],
                ),
            ]
        return []

    def get_explanations(self) -> List[Explanation]:
        return self.explanations
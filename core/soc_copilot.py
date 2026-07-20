#!/usr/bin/env python3
"""
AegisGuard · Layer 1 · SOCCopilot
=====================================

SOC 分析师实时 AI 助手。

功能:
1. 根据当前 incident/action 推荐下一步操作
2. 自动起草事件报告
3. 解释历史 AI 决策
4. 分析 Incident 趋势

用法::

    from core.soc_copilot import SOCCopilot

    copilot = SOCCopilot()

    # 推荐下一步
    suggestions = copilot.suggest_next_action(incident_data)

    # 起草报告
    report = copilot.auto_draft_report(incident_data)
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import time


# ============ 数据结构 ============

@dataclass
class CopilotSuggestion:
    """Copilot 推荐"""
    action: str
    priority: str
    description: str
    icon: str = "💡"                    # emoji
    reasoning: str = ""                  # 为什么推荐
    estimated_time: str = ""             # 预估耗时
    auto_executable: bool = False        # 能否自动化执行
    requires_approval: bool = True


@dataclass
class IncidentSummary:
    """事件摘要"""
    incident_id: str
    summary: str
    priority: str
    risk_score: int
    attack_type: str
    status: str


# ============ SOCCopilot ============

class SOCCopilot:
    """SOC 分析师实时助手"""

    def __init__(self):
        self.suggestions_history: List[CopilotSuggestion] = []
        self.stats = {
            'suggestions_given': 0,
            'reports_drafted': 0,
            'trends_analyzed': 0,
        }

    # ============ 下一步推荐 ============

    def suggest_next_action(self, incident: Dict) -> List[CopilotSuggestion]:
        """根据当前 incident 状态推荐下一步"""
        suggestions = []

        priority = incident.get('ai_analysis', {}).get('priority', 'P3')
        risk_score = incident.get('ai_analysis', {}).get('risk_score', 0)
        alert_type = incident.get('alert_type', 'unknown')
        source_ip = incident.get('source_ip', '')
        hostname = incident.get('asset_info', {}).get('hostname', '')

        # P1/P2 - 高优先级
        if priority in ('P1', 'P2') or risk_score >= 60:
            if source_ip:
                suggestions.append(CopilotSuggestion(
                    action=f'source_ip_lookup:{source_ip}',
                    priority='P1' if priority == 'P1' else 'P2',
                    description=f'查询源IP {source_ip} 的历史告警与情报',
                    icon='🔍',
                    reasoning=f'{priority} 告警，外部 IP 需立即排查',
                    estimated_time='2-5 分钟',
                    auto_executable=True,
                    requires_approval=False,
                ))
            if hostname:
                suggestions.append(CopilotSuggestion(
                    action=f'host_investigation:{hostname}',
                    priority='P1' if priority == 'P1' else 'P2',
                    description=f'检查 {hostname} 的运行状态与进程行为',
                    icon='🖥️',
                    reasoning='资产可能已被入侵',
                    estimated_time='5-10 分钟',
                    auto_executable=True,
                    requires_approval=False,
                ))
            suggestions.append(CopilotSuggestion(
                action=f'automated_response:{incident.get("incident_id", "")}',
                priority=priority,
                description=f'执行自动化响应，基于 {alert_type} playbook',
                icon='⚡',
                reasoning='高风险告警应立即启动响应流程',
                estimated_time='1-3 分钟',
                auto_executable=True,
                requires_approval=True,
            ))

        # 中等优先级
        if priority in ('P2', 'P3'):
            suggestions.append(CopilotSuggestion(
                action=f'siem_query:{alert_type}',
                priority=priority,
                description=f'在 SIEM 中搜索同类 {alert_type} 告警 (过去 24h)',
                icon='📊',
                reasoning='判断是否为批量攻击的一部分',
                estimated_time='3 分钟',
                auto_executable=True,
                requires_approval=False,
            ))
            suggestions.append(CopilotSuggestion(
                action=f'draft_incident_report:{incident.get("incident_id", "")}',
                priority=priority,
                description='自动起草事件调查报告初稿',
                icon='📝',
                reasoning='提前准备报告，减少事后工作量',
                estimated_time='30 秒',
                auto_executable=True,
                requires_approval=False,
            ))

        # 低优先级
        if priority == 'P4':
            suggestions.append(CopilotSuggestion(
                action='auto_close',
                priority='P4',
                description='自动关闭：低风险信息事件',
                icon='✅',
                reasoning='风险评分低，可自动归档',
                estimated_time='即时',
                auto_executable=True,
                requires_approval=False,
            ))
            suggestions.append(CopilotSuggestion(
                action='add_to_watchlist',
                priority='P4',
                description='将源 IP 加入观察名单',
                icon='👁️',
                reasoning='低风险但值得关注',
                estimated_time='即时',
                auto_executable=True,
                requires_approval=False,
            ))

        # 通用推荐
        if source_ip:
            suggestions.append(CopilotSuggestion(
                action='add_to_threat_intel',
                priority='P3',
                description=f'向威胁情报库提交 {source_ip} 看是否已知 IoC',
                icon='🌐',
                reasoning='关联外部威胁情报',
                estimated_time='10 秒',
                auto_executable=True,
                requires_approval=False,
            ))

        self.suggestions_history.extend(suggestions)
        self.stats['suggestions_given'] += len(suggestions)

        return suggestions

    # ============ 报告起草 ============

    def auto_draft_report(self, incident: Dict) -> str:
        """自动起草事件报告初稿（基于规则 + LLM 可选的 template）"""
        self.stats['reports_drafted'] += 1

        ai = incident.get('ai_analysis', {})
        asset = incident.get('asset_info', {})
        enrichment = incident.get('enrichment', {})

        lines = [
            "# 事件调查报告（初稿）",
            "",
            f"## 基本信息",
            f"- 事件 ID: {incident.get('incident_id', 'N/A')}",
            f"- 告警类型: {incident.get('alert_type', 'N/A')}",
            f"- 时间: {incident.get('timestamp', 'N/A')}",
            f"- 优先级: {ai.get('priority', 'N/A')}",
            f"- 风险评分: {ai.get('risk_score', 'N/A')}",
            "",
            f"## 源头分析",
            f"- 源 IP: {incident.get('source_ip', 'N/A')} (信誉: {enrichment.get('source_ip_reputation', 'N/A')})",
            f"- 目标: {incident.get('dest_ip', 'N/A')} ({asset.get('hostname', 'N/A')})",
            "",
            f"## MITRE ATT&CK",
            f"- 技术 ID: {ai.get('mitre_technique_id', 'N/A')}",
            f"- 技术名称: {ai.get('mitre_technique_name', 'N/A')}",
            "",
            f"## AI 分析摘要",
            ai.get('reasoning', 'N/A'),
            "",
            f"## 建议动作",
            ai.get('recommended_action', 'N/A'),
            "",
            f"## 处置建议 (需人工确认)",
            f"- Playbook: {ai.get('playbook_suggestion', 'N/A')}",
            f"- 是否需要人工验证: {ai.get('human_verification_needed', True)}",
            "",
            "---",
            "*该报告由 AegisGuard Copilot 自动生成，需分析师审核后正式提交。*",
        ]
        return "\n".join(lines)

    # ============ 趋势分析 ============

    def analyze_trend(self, incidents: List[Dict], time_window_hours: int = 24) -> Dict:
        """分析告警趋势"""
        self.stats['trends_analyzed'] += 1

        if not incidents:
            return {'total': 0, 'by_priority': {}, 'by_type': {}, 'p1_spike': False}

        total = len(incidents)
        by_priority = {}
        by_type = {}
        external_count = 0

        for inc in incidents:
            p = inc.get('ai_analysis', {}).get('priority', 'P4')
            t = inc.get('alert_type', 'unknown')
            ip = inc.get('source_ip', '')
            rep = inc.get('enrichment', {}).get('source_ip_reputation', '')

            by_priority[p] = by_priority.get(p, 0) + 1
            by_type[t] = by_type.get(t, 0) + 1
            if rep.startswith('external'):
                external_count += 1

        p1_count = by_priority.get('P1', 0)

        return {
            'total': total,
            'by_priority': by_priority,
            'by_type': by_type,
            'p1_spike': p1_count >= 3,
            'external_pct': round(external_count / total * 100, 1) if total > 0 else 0,
            'time_window_hours': time_window_hours,
        }

    # ============ 决策解释 ============

    def explain_decision(self, incident: Dict) -> str:
        """用人类语言解释 AI 决策"""
        ai = incident.get('ai_analysis', {})

        priority = ai.get('priority', 'P3')
        risk_score = ai.get('risk_score', 0)
        reasoning = ai.get('reasoning', '')
        confidence = ai.get('confidence', '中')
        mitre_tech = ai.get('mitre_technique_id', 'T0000')

        if risk_score >= 80:
            why = '高风险'
        elif risk_score >= 60:
            why = '中风险'
        else:
            why = '低风险'

        lines = [
            f"## 决策解释",
            f"### 为什么是 {priority}?",
            f"AI 对此告警评分为 {risk_score}/100，属于 {why}。",
            f"置信度: {confidence}",
            f"",
            f"### 基于 MITRE ATT&CK {mitre_tech}",
            reasoning if reasoning else '规则引擎判定',
            f"",
            f"### 建议",
            ai.get('recommended_action', '观察记录'),
        ]
        return "\n".join(lines)

    def get_stats(self) -> Dict:
        return {**self.stats}
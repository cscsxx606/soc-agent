#!/usr/bin/env python3
"""
Phase 3: 应急响应 Agent (Incident Response Agent)
功能：自动化响应处置、遏制、根除、恢复
"""

from typing import Dict, Any, List
from datetime import datetime
from core.agent_base import BaseAgent


class ResponseAgent(BaseAgent):
    """应急响应 Agent"""

    def __init__(self):
        super().__init__(
            name="ResponseAgent",
            description="自动化应急响应与处置"
        )
        self.response_prompt = """你是一名应急响应专家（GCIH/GCFA 认证），负责制定和执行事件响应方案。

任务：基于威胁分析结果，制定详细的响应处置方案，包括：
1. 遏制措施（Containment）- 短期和长期
2. 根除措施（Eradication）- 清除威胁
3. 恢复措施（Recovery）- 恢复业务
4. 证据保全
5. 沟通计划

输出 JSON 格式：
{
  "incident_id": "INC-XXXX",
  "severity": "P1/P2/P3/P4",
  "containment": {
    "immediate_actions": ["立即执行的遏制措施"],
    "short_term": ["短期遏制（24-48小时）"],
    "long_term": ["长期遏制（1-2周）"]
  },
  "eradication": {
    "steps": ["根除步骤"],
    "verification": ["验证方法"]
  },
  "recovery": {
    "priority_systems": ["优先恢复系统"],
    "recovery_steps": ["恢复步骤"],
    "validation_tests": ["验证测试"]
  },
  "evidence_preservation": {
    "memory_dump": true/false,
    "disk_forensics": true/false,
    "log_collection": ["需要收集的日志"],
    "chain_of_custody": "证据链说明"
  },
  "communication_plan": {
    "internal_notify": ["内部通知对象"],
    "external_notify": ["外部通知对象"],
    "regulatory_requirements": ["合规要求"]
  },
  "playbook_actions": [
    {
      "action_id": "ACT-001",
      "action_type": "isolate_host/block_ip/disable_account",
      "target": "目标资产",
      "automation_level": "fully_automated/manual_approval/manual_only",
      "estimated_time": "预计执行时间",
      "rollback_plan": "回滚方案"
    }
  ],
  "response_summary": "响应总结"
}"""

    def execute(self, triaged_alert: Dict, hunt_result: Dict = None) -> Dict:
        """
        执行应急响应
        输入: 已分流告警 + 可选的狩猎结果
        输出: 响应处置方案
        """
        alert_id = triaged_alert.get('id', 'unknown')
        analysis = triaged_alert.get('ai_analysis', {})
        priority = analysis.get('priority', 'P4')

        # 只对 P1/P2 执行响应
        if priority in ['P3', 'P4']:
            self.log(f"告警 {alert_id} 优先级 {priority}，仅生成观察建议")
            return self._generate_observation(triaged_alert)

        self.log(f"开始为告警 {alert_id} 制定响应方案 (优先级: {priority})")

        # AI 生成响应方案
        user_prompt = self._build_response_prompt(triaged_alert, hunt_result)
        response_plan = self.llm.analyze_json(self.response_prompt, user_prompt)

        if response_plan:
            self.log(f"  ✓ 响应方案生成完成，包含 {len(response_plan.get('playbook_actions', []))} 个处置动作")
            self.update_stats(success=True)
        else:
            self.log(f"  ⚠ AI 响应方案生成失败，使用模板")
            response_plan = self._template_response(triaged_alert, hunt_result)
            self.update_stats(success=False)

        # 执行自动化动作（仅 fully_automated 且启用自动响应）
        executed_actions = []
        if __import__('os').getenv('ENABLE_AUTO_RESPONSE', 'false').lower() == 'true':
            executed_actions = self._execute_auto_actions(response_plan)

        return {
            'alert_id': alert_id,
            'incident_id': response_plan.get('incident_id', f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
            'response_time': datetime.now().isoformat(),
            'priority': priority,
            'response_plan': response_plan,
            'executed_actions': executed_actions,
            'pending_approvals': [a for a in response_plan.get('playbook_actions', []) 
                                  if a.get('automation_level') == 'manual_approval'],
            'response_agent': self.name
        }

    def _generate_observation(self, alert: Dict) -> Dict:
        """生成观察建议（低优先级）"""
        return {
            'alert_id': alert.get('id'),
            'response_time': datetime.now().isoformat(),
            'priority': alert.get('ai_analysis', {}).get('priority', 'P4'),
            'action': 'observe',
            'recommendations': [
                '持续监控该资产的异常活动',
                '检查同一源 IP 的其他告警',
                f"建议观察期: {7 if alert.get('ai_analysis', {}).get('priority') == 'P3' else 1} 天"
            ],
            'response_agent': self.name
        }

    def _build_response_prompt(self, alert: Dict, hunt_result: Dict = None) -> str:
        """构建响应提示"""
        analysis = alert.get('ai_analysis', {})
        hunt_findings = hunt_result.get('hunt_result', {}) if hunt_result else {}

        return f"""基于以下安全事件，制定应急响应方案：

【事件信息】
告警 ID: {alert.get('id')}
攻击类型: {analysis.get('attack_type')}
MITRE 技术: {analysis.get('mitre_technique_id')} - {analysis.get('mitre_technique_name')}
风险评分: {analysis.get('risk_score')}
影响: {analysis.get('business_impact')}

【受影响资产】
主机: {alert.get('asset_info', {}).get('hostname')}
角色: {alert.get('asset_info', {}).get('role')}
重要性: {alert.get('asset_info', {}).get('criticality')}
团队: {alert.get('asset_info', {}).get('owner')}

【威胁情报】
{hunt_findings.get('hunt_summary', '无额外威胁情报')}

请制定详细的响应处置方案。"""

    def _template_response(self, alert: Dict, hunt_result: Dict = None) -> Dict:
        """响应模板"""
        alert_type = alert.get('alert_type', '')
        hostname = alert.get('asset_info', {}).get('hostname', '')
        source_ip = alert.get('source_ip', '')

        # 自动化动作
        auto_actions = []

        if alert_type == 'brute_force_ssh':
            auto_actions = [
                {
                    'action_id': 'ACT-001',
                    'action_type': 'block_ip',
                    'target': source_ip,
                    'automation_level': 'fully_automated',
                    'estimated_time': '30秒',
                    'rollback_plan': '从防火墙黑名单移除该 IP'
                },
                {
                    'action_id': 'ACT-002',
                    'action_type': 'isolate_host',
                    'target': hostname,
                    'automation_level': 'manual_approval',
                    'estimated_time': '2分钟',
                    'rollback_plan': '恢复主机网络连接'
                }
            ]
        elif alert_type == 'web_attack_sql_injection':
            auto_actions = [
                {
                    'action_id': 'ACT-001',
                    'action_type': 'block_ip',
                    'target': source_ip,
                    'automation_level': 'fully_automated',
                    'estimated_time': '30秒',
                    'rollback_plan': '从 WAF 黑名单移除'
                },
                {
                    'action_id': 'ACT-002',
                    'action_type': 'collect_logs',
                    'target': hostname,
                    'automation_level': 'fully_automated',
                    'estimated_time': '5分钟',
                    'rollback_plan': 'N/A'
                }
            ]
        elif alert_type == 'privilege_escalation':
            auto_actions = [
                {
                    'action_id': 'ACT-001',
                    'action_type': 'disable_account',
                    'target': '涉事用户账号',
                    'automation_level': 'manual_approval',
                    'estimated_time': '1分钟',
                    'rollback_plan': '重新启用账号并强制改密'
                },
                {
                    'action_id': 'ACT-002',
                    'action_type': 'isolate_host',
                    'target': hostname,
                    'automation_level': 'manual_approval',
                    'estimated_time': '2分钟',
                    'rollback_plan': '恢复网络连接并深度排查'
                }
            ]

        return {
            'incident_id': f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'severity': alert.get('ai_analysis', {}).get('priority', 'P2'),
            'containment': {
                'immediate_actions': [f'阻断攻击源 IP: {source_ip}'],
                'short_term': [f'隔离受影响主机: {hostname}', '收集相关日志'],
                'long_term': ['漏洞修复', '安全加固', '复盘改进']
            },
            'eradication': {
                'steps': ['清除恶意进程', '删除恶意文件', '修复漏洞', '重置凭据'],
                'verification': ['恶意代码扫描', '漏洞复测', '行为基线对比']
            },
            'recovery': {
                'priority_systems': [hostname],
                'recovery_steps': ['确认威胁已清除', '逐步恢复网络', '监控异常行为'],
                'validation_tests': ['功能测试', '安全测试']
            },
            'evidence_preservation': {
                'memory_dump': True,
                'disk_forensics': True,
                'log_collection': ['auth.log', 'access.log', 'audit.log'],
                'chain_of_custody': f'事件从 {alert.get("timestamp")} 开始收集证据'
            },
            'communication_plan': {
                'internal_notify': ['安全团队', '运维团队', alert.get('asset_info', {}).get('owner', '业务团队')],
                'external_notify': [],
                'regulatory_requirements': ['如确认数据泄露，需按法规报告']
            },
            'playbook_actions': auto_actions,
            'response_summary': f'基于 {alert_type} 的标准响应模板已生成，包含 {len(auto_actions)} 个处置动作'
        }

    def _execute_auto_actions(self, response_plan: Dict) -> List[Dict]:
        """执行自动化动作（模拟）"""
        executed = []
        for action in response_plan.get('playbook_actions', []):
            if action.get('automation_level') == 'fully_automated':
                # 模拟执行
                executed.append({
                    'action_id': action['action_id'],
                    'action_type': action['action_type'],
                    'target': action['target'],
                    'status': 'simulated_success',
                    'execution_time': datetime.now().isoformat(),
                    'note': '此为模拟执行，实际环境需对接 EDR/防火墙 API'
                })
        return executed

"""
AegisGuard - AI SOC Operations Platform
=====================================

让企业放心用 AI 做安全。

架构分为 3 层:
- LAYER 1 (aegis.ai_for_sec):   用 AI 做事 - Triage/Hunting/Response/Vuln Agents
- LAYER 2 (aegis.sec_for_ai):  护 AI 不出事 - PromptGuard/ToolACL/ModelQuota
- LAYER 3 (aegis.ops_trust):   合规可信 - Explainability/AuditChain/Compliance

使用示例::

    # 1. 保护 LLM 调用
    from aegis.sec_for_ai.guard import PromptGuard
    guard = PromptGuard()
    safe_input, verdict = guard.sanitize(user_input)

    # 2. 跑 SOC Agent
    from aegis.ai_for_sec.agents import AlertTriageAgent
    triage = AlertTriageAgent()
    results = triage.execute([alert])

    # 3. 解释 AI 决策
    from aegis.ops_trust.explainability import DecisionExplainer
    explainer = DecisionExplainer()
    explanation = explainer.explain_incident_triage(results[0]['id'])
"""

__version__ = "1.0.0"
__author__ = "AegisGuard Team"
__license__ = "MIT"
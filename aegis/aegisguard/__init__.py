"""
AegisGuard 公开 API
===================

高层 import 接口，让用户只需::

    from aegisguard import (
        AlertTriageAgent,
        PromptGuard,
        DecisionExplainer,
    )

不要用::

    from core.agent_base import BaseAgent  # 旧路径（保留兼容）
    from aegis.ai_for_sec.core.agent_base import BaseAgent  # 新路径

Phase 5 之后，这些公开 API 会逐步稳定。
"""

# === Layer 1: AI for Security ===
from agents.triage_agent import AlertTriageAgent
from agents.hunting_agent import ThreatHuntingAgent
from agents.response_agent import ResponseAgent
from agents.vuln_agent import VulnAssessmentAgent

# === Layer 2: Security for AI ===
from core.guard import PromptGuard, GuardVerdict, RiskLevel, GuardAction
from core.tool_acl import ToolACL, check_permission, require_permission, PermissionDenied
from core.model_acl import ModelACL, QuotaExceeded, MODEL_PRICING, AGENT_QUOTAS

# === Layer 3: Ops & Trust ===
from core.explainability import DecisionExplainer, Explanation, Evidence

from core.audit_chain import AuditChain
from core.soc_copilot import SOCCopilot, CopilotSuggestion

# === Metadata ===
__version__ = "1.0.0"
__all__ = [
    # Layer 1
    "AlertTriageAgent",
    "ThreatHuntingAgent",
    "ResponseAgent",
    "VulnAssessmentAgent",
    # Layer 2 - 核心护城河
    "PromptGuard", "GuardVerdict", "RiskLevel", "GuardAction",
    "ToolACL", "check_permission", "require_permission", "PermissionDenied",
    "ModelACL", "QuotaExceeded", "MODEL_PRICING", "AGENT_QUOTAS",
    # Layer 3
    "DecisionExplainer", "Explanation", "Evidence",
    "AuditChain",
    # Layer 1 扩展
    "SOCCopilot", "CopilotSuggestion",
]
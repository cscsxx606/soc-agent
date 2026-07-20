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
try:
    from core.guard import PromptGuard, GuardVerdict
except ImportError:
    PromptGuard = None
    GuardVerdict = None

try:
    from core.tool_acl import ToolACL, check_permission
except ImportError:
    ToolACL = None
    check_permission = None

try:
    from core.model_acl import ModelACL, QuotaExceeded
except ImportError:
    ModelACL = None
    QuotaExceeded = None

# === Layer 3: Ops & Trust ===
try:
    from core.explainability import DecisionExplainer, Explanation
except ImportError:
    DecisionExplainer = None
    Explanation = None

try:
    from core.audit_chain import AuditChain
except ImportError:
    AuditChain = None

# === Metadata ===
__version__ = "1.0.0"
__all__ = [
    # Layer 1
    "AlertTriageAgent",
    "ThreatHuntingAgent",
    "ResponseAgent",
    "VulnAssessmentAgent",
    # Layer 2
    "PromptGuard", "GuardVerdict",
    "ToolACL", "check_permission",
    "ModelACL", "QuotaExceeded",
    # Layer 3
    "DecisionExplainer", "Explanation",
    "AuditChain",
]
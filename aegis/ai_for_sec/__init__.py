"""
LAYER 1 · AI for Security
========================

用 AI 把安全做对：告警分流、威胁狩猎、应急响应、漏洞评估。

子模块:
- agents:    4 个业务 Agent (Triage/Hunting/Response/Vuln)
- copilot:   SOC 分析师实时 AI 助手 (Phase 5+)
- core:      AI 引擎基础（继承自原 core/）
"""

# 兼容旧 import: from core.agent_base import BaseAgent
# 推荐新 import: from aegis.ai_for_sec.core.agent_base import BaseAgent
from .. import _compat  # noqa: F401

__version__ = "1.0.0"
__layer__ = "Layer 1 · AI for Security"
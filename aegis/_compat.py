"""
AegisGuard 兼容层
==================

让现有的代码（agents/, web/, core/, tests/）能在新 aegis/ 包下继续工作，
同时提供新的导入路径: from aegis.ai_for_sec.agents import TriageAgent

设计:
- aegis.ai_for_sec.core  -> 软链到 /core/
- aegis.ai_for_sec.agents -> 软链到 /agents/
- aegis.ai_for_sec.playbooks -> 软链到 /playbooks/

这样做的好处:
1. 不破坏现有 110 个测试
2. 不破坏 web/admin 代码 (仍然 from core.llm_client import DeepSeekClient)
3. 渐进式迁移：先建立新架构边界，未来把 core/agents/ 内容物理移到 aegis/ 下
"""

import sys
import os
from pathlib import Path

# 把项目根目录加到 sys.path，让 core/agents 等能被 import
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

__all__ = []
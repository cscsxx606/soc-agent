#!/usr/bin/env python3
"""
SOC Agent 基类

集成 Layer 2 护栏 (Phase 6):
- PromptGuard: 调 LLM 前检查输入
- ToolACL: tool 调用前检查权限
- ModelACL: 调 LLM 前检查配额
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from core.llm_client import DeepSeekClient
from core.guard import PromptGuard, GuardVerdict
from core.tool_acl import ToolACL, PermissionDenied
from core.model_acl import ModelACL, QuotaExceeded


class BaseAgent(ABC):
    """SOC Agent 基类"""

    def __init__(
        self,
        name: str,
        description: str,
        guard: Optional[PromptGuard] = None,
        tool_acl: Optional[ToolACL] = None,
        model_acl: Optional[ModelACL] = None,
    ):
        self.name = name
        self.description = description
        self.llm = DeepSeekClient()
        self.memory = []  # 短期记忆
        self.stats = {
            'executions': 0,
            'success': 0,
            'failed': 0,
            'total_tokens': 0,
            'blocked_inputs': 0,    # 被 Guard 拦截的输入数
            'acl_denies': 0,        # ACL 拒绝次数
            'quota_denies': 0,      # 配额超限次数
        }

        # Layer 2 护栏 - 可由外部传入，也可使用全局默认
        self.guard = guard or PromptGuard()
        self.tool_acl = tool_acl or ToolACL()
        self.model_acl = model_acl or ModelACL()

    def log(self, message: str, level: str = 'info'):
        """记录 Agent 日志"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] [{self.name}] {message}")

    # ============ Layer 2 护栏调用方法 ============

    def safe_llm_call(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = 'deepseek-chat',
        estimated_tokens: int = 0,
    ) -> Optional[Dict]:
        """
        安全的 LLM 调用 - 过三层护栏后才调 LLM

        流程:
        1. PromptGuard 检查 user_prompt (block → 返回 None)
        2. ModelACL 检查配额 (超限 → 返回 None)
        3. 调 LLM
        4. 记录实际用量
        """
        # 1. PromptGuard 检查 user_prompt
        verdict = self.guard.check(user_prompt)
        if not verdict.safe:
            self.stats['blocked_inputs'] += 1
            self.log(f"  🛡️ PromptGuard 拦截: {verdict.reason} (risk={verdict.risk_level})")
            return None

        # 2. ModelACL 检查配额
        try:
            self.model_acl.check_quota(
                self.name,
                estimated_tokens=estimated_tokens or len(user_prompt) // 4,
                model=model,
            )
        except QuotaExceeded as e:
            self.stats['quota_denies'] += 1
            self.log(f"  💸 配额超限: {e.message}")
            return None

        # 3. 调 LLM (使用净化后的输入)
        result = self.llm.analyze_json(system_prompt, verdict.sanitized_input)

        # 4. 记录用量（估算）
        if result:
            # 粗略估算 token 数 (实际应该从 LLM 返回获取)
            est_input = len(system_prompt + verdict.sanitized_input) // 4
            est_output = len(json.dumps(result, ensure_ascii=False)) // 4
            self.model_acl.record_usage(self.name, est_input, est_output, model)
            self.stats['total_tokens'] += est_input + est_output

        return result

    def safe_tool_call(self, action: str, resource: str, executor: callable):
        """
        安全的 tool 调用 - ACL 检查后才执行

        用法:
            result = self.safe_tool_call('write', 'incidents.triage_result',
                                          lambda: db.update(...))
        """
        if not self.tool_acl.is_allowed(self.name, action, resource):
            self.stats['acl_denies'] += 1
            self.log(f"  🚫 ACL 拒绝: {self.name} {action} {resource}")
            return None
        return executor()

    def safe_acl_check(self, action: str, resource: str) -> bool:
        """快速 ACL check (不执行)"""
        return self.tool_acl.is_allowed(self.name, action, resource)

    @abstractmethod
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行 Agent 核心任务"""
        pass

    def update_stats(self, success: bool, tokens: int = 0):
        """更新统计"""
        self.stats['executions'] += 1
        if success:
            self.stats['success'] += 1
        else:
            self.stats['failed'] += 1
        self.stats['total_tokens'] += tokens

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            'success_rate': round(self.stats['success'] / max(self.stats['executions'], 1) * 100, 1)
        }

    def remember(self, key: str, value: Any):
        """记录到短期记忆"""
        self.memory.append({
            'timestamp': datetime.now().isoformat(),
            'key': key,
            'value': value
        })
        # 保留最近 50 条
        if len(self.memory) > 50:
            self.memory = self.memory[-50:]

    def recall(self, key: str = None) -> List[Dict]:
        """回忆记忆"""
        if key:
            return [m for m in self.memory if m['key'] == key]
        return self.memory

    def to_json(self) -> str:
        """序列化状态"""
        return json.dumps({
            'name': self.name,
            'description': self.description,
            'stats': self.stats,
            'memory_count': len(self.memory)
        }, ensure_ascii=False)

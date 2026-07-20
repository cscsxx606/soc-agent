#!/usr/bin/env python3
"""
AegisGuard · Layer 2 · ModelACL
==============================

模型调用配额系统。防止单个 Agent 跑飞导致账单爆掉。

每个 Agent 有:
- TPM (Tokens Per Minute) 上限
- Daily Token 配额
- Daily Cost USD 上限
- 每次调用最大 token

用法::

    from core.model_acl import ModelACL, QuotaExceeded
    
    acl = ModelACL()
    
    if not acl.check_quota('triage_agent', estimated_tokens=2000):
        raise QuotaExceeded('triage_agent 已达 TPM 上限')
    
    # 调用 LLM
    response = llm.chat(...)
    
    # 记录实际用量
    acl.record_usage('triage_agent', prompt_tokens=500, completion_tokens=200, model='deepseek-chat')
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import threading


class ModelProvider(str, Enum):
    DEEPSEEK = "deepseek"
    KIMI = "kimi"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    QWEN = "qwen"


# 模型定价 (USD per 1M tokens) - 2026-07 数据
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    'deepseek-chat': {'input': 0.14, 'output': 0.28},
    'deepseek-v3': {'input': 0.27, 'output': 1.10},
    'deepseek-v4-pro': {'input': 0.55, 'output': 2.19},
    'deepseek-v4-flash': {'input': 0.14, 'output': 0.28},
    'kimi-k2.7': {'input': 0.30, 'output': 0.60},
    'kimi-code': {'input': 0.15, 'output': 0.30},
    'gpt-4o': {'input': 2.50, 'output': 10.00},
    'gpt-4o-mini': {'input': 0.15, 'output': 0.60},
    'claude-sonnet-4': {'input': 3.00, 'output': 15.00},
    'qwen3.5-plus': {'input': 0.20, 'output': 0.60},
}

# Agent 配额配置
AGENT_QUOTAS: Dict[str, Dict[str, Any]] = {
    'triage_agent': {
        'tpm': 100_000,
        'daily_tokens': 5_000_000,
        'daily_cost_usd': 5.0,
        'max_per_call_tokens': 8000,
    },
    'hunting_agent': {
        'tpm': 200_000,
        'daily_tokens': 10_000_000,
        'daily_cost_usd': 10.0,
        'max_per_call_tokens': 16_000,
    },
    'response_agent': {
        'tpm': 50_000,
        'daily_tokens': 2_000_000,
        'daily_cost_usd': 2.0,
        'max_per_call_tokens': 4000,
    },
    'vuln_agent': {
        'tpm': 300_000,
        'daily_tokens': 15_000_000,
        'daily_cost_usd': 15.0,
        'max_per_call_tokens': 32_000,
    },
    'soc_copilot': {
        'tpm': 80_000,
        'daily_tokens': 3_000_000,
        'daily_cost_usd': 3.0,
        'max_per_call_tokens': 8000,
    },
}


# ============ 异常 ============

class QuotaExceeded(Exception):
    """配额超限"""
    def __init__(self, agent_name: str, quota_type: str, message: str):
        self.agent_name = agent_name
        self.quota_type = quota_type
        self.message = message
        super().__init__(message)


# ============ 使用记录 ============

@dataclass
class UsageRecord:
    """单次使用记录"""
    agent_name: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    timestamp: str

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


# ============ ModelACL ============

class ModelACL:
    """模型调用配额管理"""

    def __init__(
        self,
        quotas: Optional[Dict[str, Dict[str, Any]]] = None,
        pricing: Optional[Dict[str, Dict[str, float]]] = None,
    ):
        self.quotas = quotas or AGENT_QUOTAS
        self.pricing = pricing or MODEL_PRICING

        # 滑动窗口: {agent_name: [(timestamp, tokens), ...]}
        self._minute_windows: Dict[str, List[tuple]] = {}

        # 累计: {agent_name: {date_str: {tokens, cost}}}
        self._daily_usage: Dict[str, Dict[str, Dict[str, float]]] = {}

        # 完整记录（审计用）
        self.records: List[UsageRecord] = []

        self._lock = threading.Lock()

        self.stats = {
            'checks': 0,
            'allowed': 0,
            'denied': 0,
        }

    def estimate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """估算 USD 成本"""
        pricing = self.pricing.get(model, {'input': 1.0, 'output': 2.0})  # 未知模型默认高
        input_cost = prompt_tokens / 1_000_000 * pricing['input']
        output_cost = completion_tokens / 1_000_000 * pricing['output']
        return round(input_cost + output_cost, 6)

    def check_quota(
        self,
        agent_name: str,
        estimated_tokens: int = 0,
        estimated_cost_usd: float = 0.0,
        model: str = 'deepseek-chat',
    ) -> bool:
        """检查配额（不消耗，只是 check）"""
        with self._lock:
            self.stats['checks'] += 1
            quota = self.quotas.get(agent_name)
            if quota is None:
                # 未知 agent → 默认放行但记录
                self.stats['allowed'] += 1
                return True

            # 1. 单次调用上限
            max_per_call = quota.get('max_per_call_tokens', 100_000)
            if estimated_tokens > max_per_call:
                self.stats['denied'] += 1
                raise QuotaExceeded(
                    agent_name, 'per_call',
                    f'{agent_name} 单次调用超过 {max_per_call} tokens (估 {estimated_tokens})'
                )

            # 2. TPM 检查
            current_minute_tokens = self._get_minute_tokens(agent_name)
            tpm_limit = quota.get('tpm', 200_000)
            if current_minute_tokens + estimated_tokens > tpm_limit:
                self.stats['denied'] += 1
                raise QuotaExceeded(
                    agent_name, 'tpm',
                    f'{agent_name} TPM 超限 (当前 {current_minute_tokens}/{tpm_limit})'
                )

            # 3. Daily Token
            daily_tokens = self._get_daily_tokens(agent_name)
            daily_token_limit = quota.get('daily_tokens', 10_000_000)
            if daily_tokens + estimated_tokens > daily_token_limit:
                self.stats['denied'] += 1
                raise QuotaExceeded(
                    agent_name, 'daily_tokens',
                    f'{agent_name} 日 token 超限 (当前 {daily_tokens}/{daily_token_limit})'
                )

            # 4. Daily Cost
            daily_cost = self._get_daily_cost(agent_name)
            daily_cost_limit = quota.get('daily_cost_usd', 100.0)
            estimated_total_cost = daily_cost + estimated_cost_usd
            if estimated_total_cost > daily_cost_limit:
                self.stats['denied'] += 1
                raise QuotaExceeded(
                    agent_name, 'daily_cost',
                    f'{agent_name} 日花费超限 (${daily_cost:.2f}/${daily_cost_limit:.2f})'
                )

            self.stats['allowed'] += 1
            return True

    def record_usage(
        self,
        agent_name: str,
        prompt_tokens: int,
        completion_tokens: int,
        model: str = 'deepseek-chat',
    ) -> UsageRecord:
        """记录实际用量"""
        with self._lock:
            cost = self.estimate_cost(model, prompt_tokens, completion_tokens)
            now = time.time()
            today = time.strftime('%Y-%m-%d')

            # 添加到 minute window
            if agent_name not in self._minute_windows:
                self._minute_windows[agent_name] = []
            self._minute_windows[agent_name].append((now, prompt_tokens + completion_tokens))

            # 清理 60s 之前
            cutoff = now - 60
            self._minute_windows[agent_name] = [
                (t, tok) for t, tok in self._minute_windows[agent_name] if t >= cutoff
            ]

            # 添加到 daily
            if agent_name not in self._daily_usage:
                self._daily_usage[agent_name] = {}
            if today not in self._daily_usage[agent_name]:
                self._daily_usage[agent_name][today] = {'tokens': 0, 'cost': 0.0}

            self._daily_usage[agent_name][today]['tokens'] += prompt_tokens + completion_tokens
            self._daily_usage[agent_name][today]['cost'] += cost

            # 记录
            record = UsageRecord(
                agent_name=agent_name,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost,
                timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
            )
            self.records.append(record)
            return record

    def _get_minute_tokens(self, agent_name: str) -> int:
        now = time.time()
        cutoff = now - 60
        window = self._minute_windows.get(agent_name, [])
        return sum(tok for t, tok in window if t >= cutoff)

    def _get_daily_tokens(self, agent_name: str) -> int:
        today = time.strftime('%Y-%m-%d')
        usage = self._daily_usage.get(agent_name, {}).get(today, {'tokens': 0})
        return int(usage.get('tokens', 0))

    def _get_daily_cost(self, agent_name: str) -> float:
        today = time.strftime('%Y-%m-%d')
        usage = self._daily_usage.get(agent_name, {}).get(today, {'cost': 0.0})
        return float(usage.get('cost', 0.0))

    def get_usage_report(self, agent_name: str = None) -> Dict:
        """获取用量报告"""
        today = time.strftime('%Y-%m-%d')
        if agent_name:
            quota = self.quotas.get(agent_name, {})
            daily = self._daily_usage.get(agent_name, {}).get(today, {'tokens': 0, 'cost': 0.0})
            return {
                'agent': agent_name,
                'daily_tokens_used': daily['tokens'],
                'daily_tokens_limit': quota.get('daily_tokens', 0),
                'daily_tokens_pct': round(daily['tokens'] / max(quota.get('daily_tokens', 1), 1) * 100, 2),
                'daily_cost_usd': round(daily['cost'], 4),
                'daily_cost_limit': quota.get('daily_cost_usd', 0),
                'tpm_current': self._get_minute_tokens(agent_name),
                'tpm_limit': quota.get('tpm', 0),
            }
        # 全 agent
        return {agent: self.get_usage_report(agent) for agent in self.quotas}

    def get_stats(self) -> Dict:
        return {**self.stats,
                'deny_rate': round(self.stats['denied'] / max(self.stats['checks'], 1) * 100, 2)}
#!/usr/bin/env python3
"""
SOC Agent 基类
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from datetime import datetime
import json

from core.llm_client import DeepSeekClient


class BaseAgent(ABC):
    """SOC Agent 基类"""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.llm = DeepSeekClient()
        self.memory = []  # 短期记忆
        self.stats = {
            'executions': 0,
            'success': 0,
            'failed': 0,
            'total_tokens': 0
        }

    def log(self, message: str, level: str = 'info'):
        """记录 Agent 日志"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] [{self.name}] {message}")

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

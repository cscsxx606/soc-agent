#!/usr/bin/env python3
"""
AegisGuard · Layer 3 · AuditChain
==================================

Hash 链式审计日志。每条日志包含前一条的 hash，形成不可篡改的链。

特性:
- sha256 哈希链，任何修改变会导致链断裂
- 支持单条验证和全库扫描
- 与 ACL / ModelQuota / Explainability 集成
- 数据库无关（内存 + 可落盘）

用法::

    from core.audit_chain import AuditChain

    chain = AuditChain()

    # 记录操作
    chain.log('triage_agent', 'read', {'resource': 'incidents'}, 'allow')
    chain.log('triage_agent', 'write', {'resource': 'incidents'}, 'deny')

    # 验证完整性
    result = chain.verify()
    # → 返回 {'valid': True, 'count': 10, ...}
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


GENESIS_HASH = '0' * 64


@dataclass
class AuditEntry:
    """审计条目"""
    index: int
    prev_hash: str
    current_hash: str
    actor: str
    action: str
    params: Dict[str, Any]
    result: str
    timestamp: str

    def to_dict(self) -> Dict:
        return asdict(self)

    def verify(self) -> bool:
        """验证本条 hash 是否匹配"""
        expected = self._compute_hash()
        return expected == self.current_hash

    def _compute_hash(self) -> str:
        raw = f"{self.index}|{self.prev_hash}|{self.actor}|{self.action}|{json.dumps(self.params, sort_keys=True)}|{self.result}|{self.timestamp}"
        return hashlib.sha256(raw.encode()).hexdigest()


class AuditChain:
    """Hash 链式审计日志"""

    def __init__(self):
        self.entries: List[AuditEntry] = []
        self._index = 0
        self._last_hash = GENESIS_HASH

        # 统计
        self.stats = {
            'entries': 0,
            'verifications': 0,
            'violations': 0,
        }

    def log(
        self,
        actor: str,
        action: str,
        params: Dict[str, Any] = None,
        result: str = '',
    ) -> AuditEntry:
        """记录一条审计日志"""
        entry = self._create_entry(actor, action, params or {}, result)
        self.entries.append(entry)
        self._index = entry.index + 1
        self._last_hash = entry.current_hash
        self.stats['entries'] += 1
        return entry

    def _create_entry(
        self,
        actor: str,
        action: str,
        params: Dict[str, Any],
        result: str,
    ) -> AuditEntry:
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
        raw = f"{self._index}|{self._last_hash}|{actor}|{action}|{json.dumps(params, sort_keys=True)}|{result}|{timestamp}"
        current_hash = hashlib.sha256(raw.encode()).hexdigest()
        return AuditEntry(
            index=self._index,
            prev_hash=self._last_hash,
            current_hash=current_hash,
            actor=actor,
            action=action,
            params=params,
            result=result,
            timestamp=timestamp,
        )

    def verify(self, from_index: int = 0) -> Dict:
        """
        完整性扫描。返回:
        - valid: 是否完整
        - count: 已检查条数
        - violations: 发现篡改的索引列表
        """
        self.stats['verifications'] += 1
        violations = []

        if not self.entries:
            return {'valid': True, 'count': 0, 'violations': [], 'genesis_ok': True}

        # 检查第一条的 prev_hash 必须是 GENESIS
        first = self.entries[0]
        if first.prev_hash != GENESIS_HASH:
            violations.append(0)

        # 逐条验证 hash 链
        for i in range(max(1, from_index), len(self.entries)):
            entry = self.entries[i]
            prev = self.entries[i - 1]

            if not entry.verify():
                violations.append(entry.index)

            if entry.prev_hash != prev.current_hash:
                violations.append(entry.index)

        if violations:
            self.stats['violations'] += 1

        return {
            'valid': len(violations) == 0,
            'count': len(self.entries),
            'violations': violations,
            'genesis_ok': first.index == 0 and first.prev_hash == GENESIS_HASH,
        }

    def search(self, actor: str = None, action: str = None, limit: int = 20) -> List[AuditEntry]:
        """搜索审计日志"""
        result = self.entries
        if actor:
            result = [e for e in result if e.actor == actor]
        if action:
            result = [e for e in result if e.action == action]
        return result[-limit:]

    def export(self, format: str = 'json') -> str:
        """导出全部日志"""
        if format == 'json':
            items = [e.to_dict() for e in self.entries]
            return json.dumps(items, ensure_ascii=False, indent=2)
        # text
        lines = []
        for e in self.entries:
            lines.append(f"[{e.timestamp}] {e.actor}: {e.action} → {e.result}")
        return "\n".join(lines)

    def get_stats(self) -> Dict:
        return {**self.stats}

    def __len__(self) -> int:
        return len(self.entries)
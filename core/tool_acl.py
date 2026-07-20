#!/usr/bin/env python3
"""
AegisGuard · Layer 2 · ToolACL
===============================

Agent 工具调用 RBAC。每个 Agent 在调 LLM 前必须 check_permission。

防止:
- Triage Agent 误删 user 表
- Hunting Agent 改了 Playbook
- Response Agent 给自己提权
- Vuln Agent 直接执行系统命令

设计:
- ACL 用声明式 dict 表达 (action_type × resource_pattern → allow/deny)
- 4 个 SOC Agent 各有独立 ACL
- 每次 check 调用都写入 audit log (hash chain)
- 默认 deny (白名单机制)

用法::

    from core.tool_acl import ToolACL, check_permission
    
    if not check_permission('triage_agent', 'write', 'incidents.update'):
        raise PermissionDenied('Triage Agent 禁止修改 incidents')
    
    # 或者自己拿 ACL 对象
    acl = ToolACL()
    if not acl.is_allowed('response_agent', 'write', 'users.delete'):
        return 'denied'
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
import fnmatch
import time
import hashlib


class ActionType(str, Enum):
    """操作类型"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"     # 执行外部命令


class ResourceType(str, Enum):
    """资源类型"""
    INCIDENTS = "incidents"
    PLAYBOOKS = "playbooks"
    USERS = "users"
    ROLES = "roles"
    SETTINGS = "settings"
    DATA_SOURCES = "data_sources"
    TARGETS = "target_assets"
    AUDIT_LOGS = "audit_logs"
    AGENTS_REGISTRY = "agent_configs"
    SCAN_TASKS = "scan_tasks"
    NOTIFICATIONS = "notifications"
    SYSTEM = "system"        # 系统命令


# ============ ACL 配置（声明式） ============

# 每个 Agent 允许的操作
# key = agent_name
# value = {action_type: set of resource_patterns (glob), '*' = all}
TOOL_ACL_CONFIG: Dict[str, Dict[str, Set[str]]] = {
    'triage_agent': {
        # 只读 + 写 incidents（加 triage 字段）
        ActionType.READ: {ResourceType.INCIDENTS.value, ResourceType.TARGETS.value,
                          ResourceType.AUDIT_LOGS.value, ResourceType.AGENTS_REGISTRY.value},
        ActionType.WRITE: {'incidents.triage_result', 'incidents.priority', 'incidents.status'},
        ActionType.DELETE: set(),  # 完全禁止
        ActionType.EXECUTE: set(),
    },
    'hunting_agent': {
        ActionType.READ: {'*'},  # 调查需要看所有
        ActionType.WRITE: {'incidents.hunt_result', 'incidents.ioc',
                           'audit_logs', 'hunt_results'},
        ActionType.DELETE: set(),
        ActionType.EXECUTE: {'siem_query.*', 'edr_query.*'},  # 只能执行查询
    },
    'response_agent': {
        ActionType.READ: {ResourceType.INCIDENTS.value, ResourceType.PLAYBOOKS.value,
                          ResourceType.TARGETS.value, ResourceType.AGENTS_REGISTRY.value},
        ActionType.WRITE: {'incidents.response_action', 'incidents.status',
                           'response_actions', 'audit_logs'},
        ActionType.DELETE: set(),  # 严禁删任何东西
        ActionType.EXECUTE: {'isolate_host.*', 'block_ip.*', 'disable_user.*',
                              'revoke_token.*'},  # 应急响应动作
    },
    'vuln_agent': {
        ActionType.READ: {'*'},
        ActionType.WRITE: {'vuln_scans', 'vuln_reports', 'incidents.vuln_link'},
        ActionType.DELETE: set(),
        ActionType.EXECUTE: {'scan.*', 'nmap.*', 'nessus.*'},
    },
    'soc_copilot': {
        ActionType.READ: {'*'},
        ActionType.WRITE: {'copilot_suggestions', 'incidents.notes'},
        ActionType.DELETE: set(),
        ActionType.EXECUTE: set(),
    },
}


# ============ 异常 ============

class PermissionDenied(Exception):
    """Agent 越权"""
    def __init__(self, agent_name: str, action: str, resource: str, reason: str = ''):
        self.agent_name = agent_name
        self.action = action
        self.resource = resource
        self.reason = reason or f'{agent_name} 禁止 {action} {resource}'
        super().__init__(self.reason)


# ============ 决策记录 ============

@dataclass
class ACLEvent:
    """ACL 检查事件"""
    agent_name: str
    action: str
    resource: str
    allowed: bool
    reason: str
    timestamp: str
    event_hash: str

    def to_dict(self) -> Dict:
        return {
            'agent_name': self.agent_name,
            'action': self.action,
            'resource': self.resource,
            'allowed': self.allowed,
            'reason': self.reason,
            'timestamp': self.timestamp,
            'event_hash': self.event_hash,
        }


# ============ ToolACL ============

class ToolACL:
    """Agent 工具调用 RBAC 引擎"""

    def __init__(
        self,
        config: Optional[Dict[str, Dict[str, Set[str]]]] = None,
        audit_chain: Optional[Any] = None,  # AuditChain 实例 (可选)
    ):
        self.config = config or TOOL_ACL_CONFIG
        self.audit_chain = audit_chain
        self.events: List[ACLEvent] = []
        self.stats = {
            'checks': 0,
            'allows': 0,
            'denies': 0,
        }

    def is_allowed(self, agent_name: str, action: str, resource: str) -> bool:
        """检查 Agent 是否允许对 resource 做 action"""
        verdict = self.check(agent_name, action, resource)
        return verdict.allowed

    def check(self, agent_name: str, action: str, resource: str) -> ACLEvent:
        """检查并返回 ACLEvent（带审计记录）"""
        self.stats['checks'] += 1
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
        content = f'{agent_name}|{action}|{resource}|{timestamp}'

        # 1. 查 agent ACL
        agent_acl = self.config.get(agent_name)
        if agent_acl is None:
            event = self._record_event(agent_name, action, resource, False,
                                       f'未知 agent: {agent_name}', timestamp, content)
            return event

        # 2. 查 action 资源列表
        allowed_resources = agent_acl.get(action, set())
        if not allowed_resources:
            event = self._record_event(agent_name, action, resource, False,
                                       f'{agent_name} 没有任何 {action} 权限', timestamp, content)
            return event

        # 3. 通配符匹配
        matched = False
        for pattern in allowed_resources:
            if pattern == '*' or pattern == f'{resource.split(".")[0]}.*':
                matched = True
                break
            if fnmatch.fnmatch(resource, pattern):
                matched = True
                break

        if matched:
            event = self._record_event(agent_name, action, resource, True, '允许', timestamp, content)
            return event

        # 4. 显式 deny（黑名单）
        event = self._record_event(agent_name, action, resource, False,
                                   f'{agent_name} 不允许 {action} {resource}', timestamp, content)
        return event

    def require(self, agent_name: str, action: str, resource: str):
        """check + raise (DSL 风格)"""
        verdict = self.check(agent_name, action, resource)
        if not verdict.allowed:
            raise PermissionDenied(agent_name, action, resource, verdict.reason)
        return True

    def _record_event(
        self,
        agent_name: str,
        action: str,
        resource: str,
        allowed: bool,
        reason: str,
        timestamp: str,
        content: str,
    ) -> ACLEvent:
        """记录事件 + 写入 audit_chain（如果提供）"""
        event_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        if allowed:
            self.stats['allows'] += 1
        else:
            self.stats['denies'] += 1

        event = ACLEvent(
            agent_name=agent_name,
            action=action,
            resource=resource,
            allowed=allowed,
            reason=reason,
            timestamp=timestamp,
            event_hash=event_hash,
        )

        self.events.append(event)

        # 写入 hash chain (如果存在)
        if self.audit_chain is not None:
            try:
                self.audit_chain.log(
                    actor=agent_name,
                    action=f'acl.{action}',
                    params={'resource': resource, 'allowed': allowed},
                    result='allow' if allowed else 'deny',
                )
            except Exception:
                pass  # 审计失败不阻断主流程

        return event

    def get_events(self, only_denies: bool = False) -> List[ACLEvent]:
        if only_denies:
            return [e for e in self.events if not e.allowed]
        return self.events

    def get_stats(self) -> Dict:
        return {**self.stats,
                'deny_rate': round(self.stats['denies'] / max(self.stats['checks'], 1) * 100, 2)}


# ============ 便利函数 ============

# 全局默认 ACL（单例模式）
_default_acl: Optional[ToolACL] = None


def get_default_acl() -> ToolACL:
    """获取默认 ACL 实例"""
    global _default_acl
    if _default_acl is None:
        _default_acl = ToolACL()
    return _default_acl


def check_permission(agent_name: str, action: str, resource: str) -> bool:
    """快速检查（使用默认 ACL）"""
    return get_default_acl().is_allowed(agent_name, action, resource)


def require_permission(agent_name: str, action: str, resource: str):
    """快速检查 + raise（DSL）"""
    get_default_acl().require(agent_name, action, resource)
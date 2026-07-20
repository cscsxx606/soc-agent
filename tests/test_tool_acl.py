#!/usr/bin/env python3
"""
SOC Agent ToolACL 单元测试
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.tool_acl import (
    ToolACL, check_permission, require_permission,
    PermissionDenied, ACLEvent, ActionType, ResourceType,
    TOOL_ACL_CONFIG,
)


class TestBasicCheck(unittest.TestCase):
    """基础权限检查"""

    def setUp(self):
        self.acl = ToolACL()

    def test_triage_read_incidents(self):
        """triage 可以读 incidents"""
        self.assertTrue(self.acl.is_allowed('triage_agent', 'read', 'incidents'))

    def test_triage_read_targets(self):
        self.assertTrue(self.acl.is_allowed('triage_agent', 'read', 'target_assets'))

    def test_triage_write_incidents_triage(self):
        """triage 可以写 incidents.triage_result"""
        self.assertTrue(self.acl.is_allowed('triage_agent', 'write', 'incidents.triage_result'))

    def test_triage_delete_users_denied(self):
        """triage 禁止删 users"""
        self.assertFalse(self.acl.is_allowed('triage_agent', 'delete', 'users'))

    def test_triage_write_users_denied(self):
        """triage 禁止写 users"""
        self.assertFalse(self.acl.is_allowed('triage_agent', 'write', 'users'))


class TestWildcard(unittest.TestCase):
    """通配符匹配"""

    def setUp(self):
        self.acl = ToolACL()

    def test_hunting_read_all(self):
        """hunting 可以读所有"""
        for resource in ['incidents', 'users', 'settings', 'audit_logs', 'playbooks']:
            self.assertTrue(self.acl.is_allowed('hunting_agent', 'read', resource))

    def test_vuln_execute_scan(self):
        """vuln 可以执行 scan.*"""
        self.assertTrue(self.acl.is_allowed('vuln_agent', 'execute', 'scan.nmap'))
        self.assertTrue(self.acl.is_allowed('vuln_agent', 'execute', 'scan.nessus'))

    def test_vuln_execute_blocked(self):
        """vuln 禁止执行无关命令"""
        self.assertFalse(self.acl.is_allowed('vuln_agent', 'execute', 'rm'))

    def test_response_execute_isolate_host(self):
        """response 可以隔离主机"""
        self.assertTrue(self.acl.is_allowed('response_agent', 'execute', 'isolate_host.web-01'))

    def test_response_execute_drop_table_denied(self):
        """response 不能执行 SQL 命令"""
        self.assertFalse(self.acl.is_allowed('response_agent', 'execute', 'sql.drop_table'))


class TestDeny(unittest.TestCase):
    """禁止场景"""

    def setUp(self):
        self.acl = ToolACL()

    def test_no_delete_for_any_agent(self):
        """所有 agent 都不允许 delete 资源"""
        for agent in ['triage_agent', 'hunting_agent', 'response_agent', 'vuln_agent']:
            for resource in ['incidents', 'users', 'playbooks']:
                self.assertFalse(
                    self.acl.is_allowed(agent, 'delete', resource),
                    f'{agent} 删 {resource} 必须 deny'
                )

    def test_unknown_agent_denied(self):
        """未知 agent 全部拒绝"""
        verdict = self.acl.check('rogue_agent', 'read', 'incidents')
        self.assertFalse(verdict.allowed)

    def test_response_no_read_settings(self):
        """response 不能读 settings"""
        self.assertFalse(self.acl.is_allowed('response_agent', 'read', 'settings'))


class TestACLEvent(unittest.TestCase):
    """事件结构"""

    def setUp(self):
        self.acl = ToolACL()

    def test_event_recorded(self):
        verdict = self.acl.check('triage_agent', 'read', 'incidents')
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.agent_name, 'triage_agent')
        self.assertEqual(verdict.action, 'read')
        self.assertEqual(verdict.resource, 'incidents')

    def test_event_hash(self):
        """每次 event 有唯一 hash"""
        v1 = self.acl.check('triage_agent', 'read', 'incidents')
        v2 = self.acl.check('triage_agent', 'read', 'incidents')
        # 不同时刻 hash 不同
        self.assertEqual(len(v1.event_hash), 16)
        self.assertEqual(len(v2.event_hash), 16)

    def test_event_to_dict(self):
        verdict = self.acl.check('triage_agent', 'write', 'incidents.triage_result')
        d = verdict.to_dict()
        for key in ['agent_name', 'action', 'resource', 'allowed', 'reason', 'timestamp', 'event_hash']:
            self.assertIn(key, d)


class TestRequire(unittest.TestCase):
    """require 模式"""

    def setUp(self):
        self.acl = ToolACL()

    def test_require_allows(self):
        """允许时无异常"""
        try:
            self.acl.require('triage_agent', 'read', 'incidents')
        except PermissionDenied:
            self.fail('允许操作不应该 raise')

    def test_require_raises_on_deny(self):
        """拒绝时 raise PermissionDenied"""
        with self.assertRaises(PermissionDenied) as ctx:
            self.acl.require('triage_agent', 'delete', 'users')
        self.assertEqual(ctx.exception.agent_name, 'triage_agent')
        self.assertEqual(ctx.exception.action, 'delete')
        self.assertEqual(ctx.exception.resource, 'users')


class TestConvenienceFunctions(unittest.TestCase):
    """便利函数"""

    def test_check_permission_global(self):
        self.assertTrue(check_permission('triage_agent', 'read', 'incidents'))
        self.assertFalse(check_permission('triage_agent', 'delete', 'users'))

    def test_require_permission_global(self):
        try:
            require_permission('triage_agent', 'read', 'incidents')
        except PermissionDenied:
            self.fail('应该允许')

        with self.assertRaises(PermissionDenied):
            require_permission('triage_agent', 'delete', 'users')


class TestStats(unittest.TestCase):
    """统计"""

    def test_stats_init(self):
        acl = ToolACL()
        stats = acl.get_stats()
        self.assertEqual(stats['checks'], 0)

    def test_stats_increment(self):
        acl = ToolACL()
        acl.check('triage_agent', 'read', 'incidents')   # allow
        acl.check('triage_agent', 'delete', 'users')     # deny
        acl.check('triage_agent', 'read', 'users')       # deny
        stats = acl.get_stats()
        self.assertEqual(stats['checks'], 3)
        self.assertEqual(stats['allows'], 1)
        self.assertEqual(stats['denies'], 2)
        self.assertGreater(stats['deny_rate'], 0)


class TestEventsHistory(unittest.TestCase):
    """事件历史"""

    def setUp(self):
        self.acl = ToolACL()

    def test_events_recorded(self):
        self.acl.check('triage_agent', 'read', 'incidents')
        self.acl.check('triage_agent', 'delete', 'users')
        events = self.acl.get_events()
        self.assertEqual(len(events), 2)

    def test_only_denies(self):
        self.acl.check('triage_agent', 'read', 'incidents')
        self.acl.check('triage_agent', 'delete', 'users')
        denies = self.acl.get_events(only_denies=True)
        self.assertEqual(len(denies), 1)
        self.assertFalse(denies[0].allowed)


class TestAuditChainIntegration(unittest.TestCase):
    """与 audit_chain 集成"""

    def test_audit_chain_called(self):
        """提供 audit_chain 时 deny 会写入"""
        class MockAuditChain:
            def __init__(self):
                self.logs = []
            def log(self, actor, action, params, result):
                self.logs.append((actor, action, params, result))

        ac = MockAuditChain()
        acl = ToolACL(audit_chain=ac)
        acl.check('triage_agent', 'delete', 'users')
        self.assertEqual(len(ac.logs), 1)
        self.assertEqual(ac.logs[0][0], 'triage_agent')
        self.assertEqual(ac.logs[0][1], 'acl.delete')
        self.assertFalse(ac.logs[0][3] == 'allow')


class TestRealWorldScenarios(unittest.TestCase):
    """真实场景"""

    def setUp(self):
        self.acl = ToolACL()

    def test_triage_full_workflow(self):
        """triage 完整工作流的允许链"""
        # 读 incident
        self.assertTrue(self.acl.is_allowed('triage_agent', 'read', 'incidents'))
        # 读 target 资产
        self.assertTrue(self.acl.is_allowed('triage_agent', 'read', 'target_assets'))
        # 写 triage result
        self.assertTrue(self.acl.is_allowed('triage_agent', 'write', 'incidents.triage_result'))
        # 尝试越权 (写 settings) → deny
        self.assertFalse(self.acl.is_allowed('triage_agent', 'write', 'settings'))

    def test_response_isolate_attack(self):
        """response agent 隔离攻击主机"""
        self.assertTrue(self.acl.is_allowed('response_agent', 'execute', 'isolate_host.attacker-vm'))
        self.assertTrue(self.acl.is_allowed('response_agent', 'execute', 'block_ip.1.2.3.4'))
        self.assertTrue(self.acl.is_allowed('response_agent', 'execute', 'disable_user.suspicious'))

    def test_response_cant_modify_users_table(self):
        """response 不能动 users 表"""
        self.assertFalse(self.acl.is_allowed('response_agent', 'write', 'users.delete'))
        self.assertFalse(self.acl.is_allowed('response_agent', 'delete', 'users'))

    def test_vuln_scan_target(self):
        """vuln 扫描目标"""
        self.assertTrue(self.acl.is_allowed('vuln_agent', 'execute', 'nmap.target-01'))
        self.assertTrue(self.acl.is_allowed('vuln_agent', 'execute', 'nessus.scan-001'))
        self.assertTrue(self.acl.is_allowed('vuln_agent', 'write', 'vuln_reports'))

    def test_attacker_compromised_triage(self):
        """假设 triage agent 被劫持，攻击者试图删数据"""
        # 应该全部 deny
        for action in ['delete', 'write']:
            for resource in ['users', 'settings', 'playbooks', 'audit_logs']:
                self.assertFalse(
                    self.acl.is_allowed('triage_agent', action, resource),
                    f'被劫持的 triage 居然能 {action} {resource}'
                )


if __name__ == '__main__':
    unittest.main(verbosity=2)
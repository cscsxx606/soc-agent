#!/usr/bin/env python3
"""
SOC Agent AuditChain 单元测试
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.audit_chain import AuditChain, AuditEntry, GENESIS_HASH


class TestBasicLogging(unittest.TestCase):
    """基础审计日志"""

    def setUp(self):
        self.chain = AuditChain()

    def test_log_returns_entry(self):
        entry = self.chain.log('triage_agent', 'read', {'resource': 'incidents'}, 'allow')
        self.assertIsInstance(entry, AuditEntry)
        self.assertEqual(entry.index, 0)
        self.assertEqual(entry.actor, 'triage_agent')

    def test_log_auto_increment(self):
        e1 = self.chain.log('a1', 'read', {}, 'ok')
        e2 = self.chain.log('a2', 'write', {}, 'ok')
        self.assertEqual(e1.index, 0)
        self.assertEqual(e2.index, 1)

    def test_entry_has_hash(self):
        entry = self.chain.log('agent', 'action', {}, 'ok')
        self.assertEqual(len(entry.current_hash), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in entry.current_hash))

    def test_first_entry_uses_genesis(self):
        entry = self.chain.log('agent', 'action', {}, 'ok')
        self.assertEqual(entry.prev_hash, GENESIS_HASH)


class TestHashChain(unittest.TestCase):
    """Hash 链"""

    def setUp(self):
        self.chain = AuditChain()

    def test_hash_links(self):
        e1 = self.chain.log('a', 'read', {}, 'ok')
        e2 = self.chain.log('a', 'write', {}, 'ok')
        # e2 的 prev_hash = e1 的 current_hash
        self.assertEqual(e2.prev_hash, e1.current_hash)

    def test_hash_uses_actor(self):
        """不同 actor → hash 不同"""
        chain = AuditChain()
        e1 = chain.log('actor_a', 'action', {}, 'ok')
        e2 = chain.log('actor_b', 'action', {}, 'ok')
        self.assertNotEqual(e1.current_hash, e2.current_hash)


class TestVerification(unittest.TestCase):
    """完整性校验"""

    def setUp(self):
        self.chain = AuditChain()
        self.chain.log('triage', 'read', {'resource': 'incidents'}, 'allow')
        self.chain.log('triage', 'write', {'resource': 'result'}, 'allow')
        self.chain.log('response', 'execute', {'cmd': 'block_ip'}, 'allow')

    def test_verify_clean(self):
        result = self.chain.verify()
        self.assertTrue(result['valid'])
        self.assertEqual(result['count'], 3)
        self.assertEqual(len(result['violations']), 0)

    def test_verify_empty_chain(self):
        c = AuditChain()
        result = c.verify()
        self.assertTrue(result['valid'])
        self.assertEqual(result['count'], 0)

    def test_detect_tampered_hash(self):
        """篡改 hash → 检测到"""
        orig = self.chain.entries[1].current_hash
        self.chain.entries[1].current_hash = '0000000000000000000000000000000000000000000000000000000000000001'
        result = self.chain.verify()
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['violations']), 0)
        # 恢复
        self.chain.entries[1].current_hash = orig

    def test_detect_broken_chain(self):
        """断裂的 prev_hash → 检测到"""
        orig = self.chain.entries[2].prev_hash
        self.chain.entries[2].prev_hash = 'x' * 64
        result = self.chain.verify()
        self.assertFalse(result['valid'])
        self.chain.entries[2].prev_hash = orig

    def test_genesis_check(self):
        self.chain.entries[0].prev_hash = 'x' * 64
        result = self.chain.verify()
        self.assertFalse(result['valid'])
        self.chain.entries[0].prev_hash = GENESIS_HASH


class TestEntryVerification(unittest.TestCase):
    """单条校验"""

    def test_entry_self_verify(self):
        chain = AuditChain()
        entry = chain.log('a', 'action', {}, 'ok')
        self.assertTrue(entry.verify())

    def test_entry_tampered(self):
        chain = AuditChain()
        entry = chain.log('a', 'action', {}, 'ok')
        entry.result = 'hacked'
        self.assertFalse(entry.verify())


class TestSearch(unittest.TestCase):
    """搜索"""

    def setUp(self):
        self.chain = AuditChain()
        self.chain.log('triage', 'read', {}, 'allow')
        self.chain.log('response', 'execute', {}, 'deny')
        self.chain.log('triage', 'write', {}, 'allow')

    def test_search_by_actor(self):
        results = self.chain.search(actor='triage')
        self.assertEqual(len(results), 2)

    def test_search_by_action(self):
        results = self.chain.search(action='execute')
        self.assertEqual(len(results), 1)

    def test_search_limit(self):
        results = self.chain.search(limit=1)
        self.assertEqual(len(results), 1)


class TestExport(unittest.TestCase):
    """导出"""

    def setUp(self):
        self.chain = AuditChain()
        self.chain.log('agent', 'action', {}, 'ok')

    def test_export_json(self):
        out = self.chain.export('json')
        self.assertIn('"actor"', out)

    def test_export_text(self):
        out = self.chain.export('text')
        self.assertIn('agent: action', out)


class TestStats(unittest.TestCase):
    """统计"""

    def test_stats_init(self):
        c = AuditChain()
        self.assertEqual(c.get_stats()['entries'], 0)

    def test_stats_increment(self):
        c = AuditChain()
        c.log('a', 'action', {}, 'ok')
        c.log('b', 'action', {}, 'ok')
        self.assertEqual(c.get_stats()['entries'], 2)

    def test_stats_verification(self):
        c = AuditChain()
        c.verify()
        self.assertEqual(c.get_stats()['verifications'], 1)


class TestEmptyEdgeCase(unittest.TestCase):
    """空链边界"""

    def test_empty_len(self):
        c = AuditChain()
        self.assertEqual(len(c), 0)

    def test_search_empty(self):
        c = AuditChain()
        self.assertEqual(len(c.search(actor='test')), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
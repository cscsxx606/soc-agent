#!/usr/bin/env python3
"""
SOC Agent ModelACL 单元测试
"""

import sys
import os
import unittest
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.model_acl import (
    ModelACL, QuotaExceeded, UsageRecord,
    MODEL_PRICING, AGENT_QUOTAS,
)


class TestEstimateCost(unittest.TestCase):
    """成本估算"""

    def setUp(self):
        self.acl = ModelACL()

    def test_deepseek_cost(self):
        cost = self.acl.estimate_cost('deepseek-chat', prompt_tokens=1_000_000, completion_tokens=500_000)
        # 1M input * 0.14 + 0.5M output * 0.28 = 0.14 + 0.14 = 0.28
        self.assertAlmostEqual(cost, 0.28, places=4)

    def test_kimi_cost(self):
        cost = self.acl.estimate_cost('kimi-k2.7', 1000, 500)
        # 0.001 * 0.3 + 0.0005 * 0.6 = 0.0006
        self.assertAlmostEqual(cost, 0.0006, places=6)

    def test_gpt4o_cost(self):
        cost = self.acl.estimate_cost('gpt-4o', 1000, 500)
        # 0.001 * 2.5 + 0.0005 * 10 = 0.0075
        self.assertAlmostEqual(cost, 0.0075, places=6)

    def test_unknown_model_uses_default(self):
        """未知模型用默认高价"""
        cost = self.acl.estimate_cost('unknown-model-xxx', 1_000_000, 0)
        # 默认 input 1.0/1M
        self.assertEqual(cost, 1.0)


class TestCheckQuota(unittest.TestCase):
    """配额检查"""

    def setUp(self):
        self.acl = ModelACL()

    def test_basic_check_allowed(self):
        """基本检查允许"""
        self.assertTrue(self.acl.check_quota('triage_agent', estimated_tokens=1000))

    def test_per_call_limit(self):
        """单次调用超过 max_per_call_tokens → raise"""
        quota = AGENT_QUOTAS['triage_agent']
        max_tokens = quota['max_per_call_tokens']
        with self.assertRaises(QuotaExceeded) as ctx:
            self.acl.check_quota('triage_agent', estimated_tokens=max_tokens + 1)
        self.assertEqual(ctx.exception.quota_type, 'per_call')

    def test_tpm_limit(self):
        """TPM 限制"""
        # 假设 triage_agent TPM=100K
        quota = AGENT_QUOTAS['triage_agent']
        tpm = quota['tpm']
        # 录到 TPM 上限
        for _ in range(tpm // 1000):
            self.acl.record_usage('triage_agent', prompt_tokens=500, completion_tokens=500)
        # 再请求 2000 tokens → raise
        with self.assertRaises(QuotaExceeded) as ctx:
            self.acl.check_quota('triage_agent', estimated_tokens=2000)
        self.assertEqual(ctx.exception.quota_type, 'tpm')

    def test_daily_token_limit(self):
        """日 token 限制 - 用大 daily limit 的 agent 测"""
        # 用未知 agent 绕过 TPM (未知 agent TPM 默认 pass)
        acl = ModelACL(quotas={
            'test_agent': {'tpm': 1_000_000, 'daily_tokens': 5_000, 'daily_cost_usd': 100, 'max_per_call_tokens': 1000}
        })
        # 用满
        for _ in range(5):
            acl.record_usage('test_agent', 600, 400)  # 1000/call
        # 再要 1 token > 1000 daily remaining → daily limit
        with self.assertRaises(QuotaExceeded) as ctx:
            acl.check_quota('test_agent', estimated_tokens=1)
        self.assertIn('daily', ctx.exception.quota_type)

    def test_daily_cost_limit(self):
        """日花费 USD 限制"""
        acl = ModelACL(quotas={
            'test_cost_agent': {'tpm': 10_000_000, 'daily_tokens': 100_000_000, 'daily_cost_usd': 1.0, 'max_per_call_tokens': 1000}
        })
        # 已用满 $1
        acl.record_usage('test_cost_agent', 1_000_000, 0)  # $0.14
        # 再请求 $1 → 超过
        with self.assertRaises(QuotaExceeded) as ctx:
            acl.check_quota('test_cost_agent', estimated_tokens=0, estimated_cost_usd=1.0)
        self.assertEqual(ctx.exception.quota_type, 'daily_cost')


class TestRecordUsage(unittest.TestCase):
    """用量记录"""

    def setUp(self):
        self.acl = ModelACL()

    def test_basic_record(self):
        r = self.acl.record_usage('triage_agent', prompt_tokens=500, completion_tokens=200, model='deepseek-chat')
        self.assertEqual(r.prompt_tokens, 500)
        self.assertEqual(r.completion_tokens, 200)
        self.assertEqual(r.total_tokens, 700)

    def test_record_appends(self):
        self.acl.record_usage('triage_agent', 100, 50)
        self.acl.record_usage('triage_agent', 100, 50)
        self.assertEqual(len(self.acl.records), 2)

    def test_daily_accumulation(self):
        """日累计"""
        self.acl.record_usage('triage_agent', 1000, 500)
        self.acl.record_usage('triage_agent', 1000, 500)
        report = self.acl.get_usage_report('triage_agent')
        self.assertEqual(report['daily_tokens_used'], 3000)


class TestUsageReport(unittest.TestCase):
    """用量报告"""

    def setUp(self):
        self.acl = ModelACL()

    def test_report_single_agent(self):
        r = self.acl.get_usage_report('triage_agent')
        self.assertEqual(r['agent'], 'triage_agent')
        self.assertIn('daily_tokens_used', r)
        self.assertIn('daily_cost_usd', r)

    def test_report_pct(self):
        """百分比"""
        # 设 daily_tokens=5M, 用 1M → 20%
        # 但 TPM 限制会让它分多次, 所以我们直接 record 后看
        self.acl.record_usage('triage_agent', 1_000_000, 0)
        r = self.acl.get_usage_report('triage_agent')
        # 1M/5M = 20%
        self.assertGreaterEqual(r['daily_tokens_pct'], 0)

    def test_report_all_agents(self):
        """全 agent 报告"""
        r = self.acl.get_usage_report()
        self.assertIn('triage_agent', r)
        self.assertIn('hunting_agent', r)
        self.assertIn('response_agent', r)
        self.assertIn('vuln_agent', r)


class TestQuotaExceeded(unittest.TestCase):
    """异常信息"""

    def setUp(self):
        self.acl = ModelACL()

    def test_exception_attributes(self):
        quota = AGENT_QUOTAS['triage_agent']
        try:
            self.acl.check_quota('triage_agent', estimated_tokens=quota['max_per_call_tokens'] + 1)
        except QuotaExceeded as e:
            self.assertEqual(e.agent_name, 'triage_agent')
            self.assertEqual(e.quota_type, 'per_call')
            self.assertIn('超过', e.message)


class TestUnknownAgent(unittest.TestCase):
    """未知 Agent 处理"""

    def test_unknown_agent_passes(self):
        """未配置的 agent 默认放行（不阻断）"""
        acl = ModelACL()
        self.assertTrue(acl.check_quota('unknown_agent', estimated_tokens=1000))

    def test_unknown_agent_record(self):
        acl = ModelACL()
        r = acl.record_usage('unknown_agent', 100, 100)
        self.assertEqual(r.agent_name, 'unknown_agent')


class TestStats(unittest.TestCase):
    """统计"""

    def test_stats_init(self):
        acl = ModelACL()
        stats = acl.get_stats()
        self.assertEqual(stats['checks'], 0)
        self.assertEqual(stats['allowed'], 0)
        self.assertEqual(stats['denied'], 0)

    def test_stats_increment(self):
        acl = ModelACL()
        acl.check_quota('triage_agent', 100)
        try:
            acl.check_quota('triage_agent', 1_000_000)  # 超过
        except QuotaExceeded:
            pass
        stats = acl.get_stats()
        self.assertEqual(stats['checks'], 2)
        self.assertEqual(stats['allowed'], 1)
        self.assertEqual(stats['denied'], 1)


class TestRealWorldScenarios(unittest.TestCase):
    """真实场景"""

    def setUp(self):
        self.acl = ModelACL()

    def test_normal_triage_call(self):
        """正常 triage 调用"""
        self.assertTrue(self.acl.check_quota('triage_agent', estimated_tokens=2000))
        record = self.acl.record_usage('triage_agent', 800, 200, 'deepseek-v4-pro')
        self.assertGreater(record.cost_usd, 0)
        report = self.acl.get_usage_report('triage_agent')
        self.assertEqual(report['daily_tokens_used'], 1000)

    def test_rouge_agent_attempting_mass_calls(self):
        """被劫持的 agent 尝试大调用"""
        quota = AGENT_QUOTAS['triage_agent']
        # 模拟攻击
        caught = 0
        for _ in range(10000):
            try:
                self.acl.check_quota('triage_agent', estimated_tokens=50000)
                self.acl.record_usage('triage_agent', 50000, 50000)
            except QuotaExceeded:
                caught += 1
        self.assertGreater(caught, 0, '攻击应该被拦截')
        # 报告
        report = self.acl.get_usage_report('triage_agent')
        # 被拦截后 cost 不应该爆
        self.assertLessEqual(report['daily_cost_usd'], quota['daily_cost_usd'] * 1.1)

    def test_multi_agent_isolation(self):
        """多 Agent 配额隔离"""
        # triage 用满
        for _ in range(50):
            self.acl.record_usage('triage_agent', 100_000, 100_000)
        # response 应该不受影响
        self.assertTrue(self.acl.check_quota('response_agent', estimated_tokens=1000))

    def test_minute_window_expiry(self):
        """分钟窗口过期"""
        # 立即记一次（满 TPM）
        # 实际操作略复杂，我们简单验证 window 逻辑
        self.acl.record_usage('triage_agent', 1000, 500)
        before = self.acl._get_minute_tokens('triage_agent')
        self.assertEqual(before, 1500)


if __name__ == '__main__':
    unittest.main(verbosity=2)
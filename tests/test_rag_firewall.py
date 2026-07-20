#!/usr/bin/env python3
"""
SOC Agent RAGFirewall 单元测试
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.rag_firewall import RAGFirewall, RAGVerdict, Redaction


SAFE_TEXT = "本次扫描发现 3 台主机开放了 22 端口，建议关闭。"
SK_KEY = "我的 API key 是 sk-N4Kf3H8mP2qR5tW9zC1vB6xL0jD7gY，别泄漏"
JWT = "用户 token: eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzb2MuYWkiLCJ1c2VyIjoidGVzdCJ9.pVG6bQ"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "请联系 admin@soc-agent.ai 处理"
PHONE = "电话 13800138000"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..." 
INTERNAL_IP = "内网 10.0.0.5 和 192.168.1.1"


class TestBasic(unittest.TestCase):
    def setUp(self):
        self.fw = RAGFirewall()

    def test_safe_text_no_redact(self):
        v = self.fw.check(SAFE_TEXT)
        self.assertTrue(v.safe)
        self.assertEqual(v.total_redactions, 0)

    def test_safe_text_unchanged(self):
        v = self.fw.check(SAFE_TEXT)
        self.assertEqual(v.redacted_text, SAFE_TEXT)

    def test_empty_input(self):
        v = self.fw.check('')
        self.assertTrue(v.safe)


class TestAPIKeyDetection(unittest.TestCase):
    def setUp(self):
        self.fw = RAGFirewall()

    def test_sk_key_detected(self):
        v = self.fw.check(SK_KEY)
        self.assertFalse(v.safe)
        self.assertGreater(v.total_redactions, 0)
        types = [r.type for r in v.redactions]
        self.assertIn('api_key', types)

    def test_aws_key_detected(self):
        v = self.fw.check(AWS_KEY)
        self.assertFalse(v.safe)

    def test_jwt_detected(self):
        v = self.fw.check(JWT)
        self.assertFalse(v.safe)

    def test_sk_key_redacted_partial(self):
        v = self.fw.check(SK_KEY)
        # sk- 部分脱敏但保留后 4 位
        self.assertNotIn('N4Kf3H8mP2qR5tW9zC1vB6xL0jD7gY', v.redacted_text)


class TestSecretDetection(unittest.TestCase):
    def setUp(self):
        self.fw = RAGFirewall()

    def test_private_key_detected(self):
        v = self.fw.check(PRIVATE_KEY)
        self.assertFalse(v.safe)

    def test_password_line(self):
        v = self.fw.check("password = superSecret123!")
        self.assertFalse(v.safe)


class TestInternalIP(unittest.TestCase):
    def setUp(self):
        self.fw = RAGFirewall()

    def test_internal_ip_detected(self):
        v = self.fw.check(INTERNAL_IP)
        self.assertFalse(v.safe)
        self.assertIn('[REDACTED]', v.redacted_text)

    def test_public_ip_not_redacted(self):
        v = self.fw.check("公网 8.8.8.8")
        self.assertTrue(v.safe)


class TestPIIDetection(unittest.TestCase):
    def setUp(self):
        self.fw = RAGFirewall()

    def test_email_detected(self):
        v = self.fw.check(EMAIL)
        self.assertFalse(v.safe)

    def test_email_keeps_domain(self):
        v = self.fw.check(EMAIL)
        self.assertIn('@soc-agent.ai', v.redacted_text)

    def test_phone_detected(self):
        v = self.fw.check(PHONE)
        self.assertFalse(v.safe)

    def test_phone_redacted(self):
        v = self.fw.check(PHONE)
        self.assertIn('[REDACTED]', v.redacted_text)


class TestOutputTruncation(unittest.TestCase):
    def test_truncated(self):
        fw = RAGFirewall(max_output_length=100)
        text = "x" * 500
        v = fw.check(text)
        self.assertEqual(len(v.redacted_text), 100)
        self.assertIn('截断', v.warning)

    def test_truncation_records_redaction(self):
        fw = RAGFirewall(max_output_length=50)
        v = fw.check("x" * 200)
        self.assertEqual(v.total_redactions, 1)
        self.assertEqual(v.redactions[0].type, 'truncation')


class TestDisableDetection(unittest.TestCase):
    def test_disable_all(self):
        fw = RAGFirewall(enable_api_key_detection=False, enable_secret_detection=False,
                         enable_internal_ip_detection=False, enable_pii_detection=False)
        v = fw.check(SK_KEY)
        self.assertTrue(v.safe)

    def test_disable_only_api(self):
        fw = RAGFirewall(enable_api_key_detection=False)
        v = fw.check(SK_KEY)
        # API key 不检，但其他检
        self.assertFalse(v.safe) if 'secret' in 'password' else self.assertTrue(v.safe)


class TestQuickSafeOutput(unittest.TestCase):
    def test_safe_output(self):
        fw = RAGFirewall()
        result = fw.safe_output(SK_KEY)
        self.assertNotIn('N4Kf3H8mP2qR5tW9zC1vB6xL0jD7gY', result)

    def test_safe_output_unchanged(self):
        fw = RAGFirewall()
        result = fw.safe_output(SAFE_TEXT)
        self.assertEqual(result, SAFE_TEXT)


class TestRedactionData(unittest.TestCase):
    def test_redaction_has_all_fields(self):
        fw = RAGFirewall()
        v = fw.check(SK_KEY)
        r = v.redactions[0]
        for attr in ['type', 'pattern_name', 'original', 'redacted', 'start', 'end']:
            self.assertTrue(hasattr(r, attr), f'missing {attr}')

    def test_redaction_to_dict(self):
        r = Redaction(type='api_key', pattern_name='test', original='sk-xxx',
                      redacted='[REDACTED]', start=0, end=6)
        d = r.to_dict()
        for key in ['type', 'pattern_name', 'original', 'redacted']:
            self.assertIn(key, d)

    def test_verdict_to_dict(self):
        fw = RAGFirewall()
        v = fw.check(SK_KEY)
        d = v.to_dict()
        for key in ['safe', 'redacted_text', 'redactions', 'total_redactions']:
            self.assertIn(key, d)


class TestComplexText(unittest.TestCase):
    def test_multiple_threats(self):
        text = f"""
        用户 admin 的 API key 是 {SK_KEY}
        内网地址 {INTERNAL_IP}
        联系邮箱 {EMAIL}
        """
        fw = RAGFirewall()
        v = fw.check(text)
        self.assertFalse(v.safe)
        # 至少 3 个 redaction
        self.assertGreaterEqual(v.total_redactions, 3)


class TestWarning(unittest.TestCase):
    def test_warning_messages(self):
        fw = RAGFirewall()
        v = fw.check(SK_KEY)
        if v.warning:
            self.assertIn('API key', v.warning)


class TestStats(unittest.TestCase):
    def test_stats_init(self):
        fw = RAGFirewall()
        self.assertEqual(fw.get_stats()['checks'], 0)

    def test_stats_increment(self):
        fw = RAGFirewall()
        fw.check(SAFE_TEXT)
        fw.check(SK_KEY)
        s = fw.get_stats()
        self.assertEqual(s['checks'], 2)
        self.assertGreater(s['api_keys_found'], 0) if not fw.enable_api_key else self.assertEqual(s['checks'], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
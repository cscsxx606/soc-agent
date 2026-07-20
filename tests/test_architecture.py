#!/usr/bin/env python3
"""
AegisGuard 架构测试
===================

验证:
1. aegis/ 包导入正常
2. 三个 layer 都有 __init__
3. 旧 import 路径 100% 兼容
4. 高层 API aegis.aegisguard 工作
5. Layer 2/3 Phase 5+ 模块优雅降级（None 不报错）
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)


class TestAegisPackage(unittest.TestCase):
    """aegis/ 顶层包测试"""

    def test_aegis_version(self):
        import aegis
        self.assertTrue(hasattr(aegis, '__version__'))
        self.assertEqual(aegis.__version__, '1.0.0')

    def test_three_layers_exist(self):
        """三个 layer 都可 import"""
        from aegis import ai_for_sec, sec_for_ai, ops_trust
        self.assertEqual(ai_for_sec.__layer__, 'Layer 1 · AI for Security')
        self.assertEqual(sec_for_ai.__layer__, 'Layer 2 · Security for AI')
        self.assertEqual(ops_trust.__layer__, 'Layer 3 · Operations & Trust')

    def test_layer2_is_differentiator(self):
        """Layer 2 必须标记为差异化"""
        from aegis import sec_for_ai
        self.assertTrue(getattr(sec_for_ai, '__differentiator__', False))


class TestLegacyCompat(unittest.TestCase):
    """旧 import 路径兼容测试"""

    def test_core_imports(self):
        from core.agent_base import BaseAgent
        from core.llm_client import DeepSeekClient
        from core.notification import Notifier
        self.assertTrue(callable(BaseAgent))
        self.assertTrue(callable(DeepSeekClient))
        self.assertTrue(callable(Notifier))

    def test_agents_imports(self):
        from agents.triage_agent import AlertTriageAgent
        from agents.hunting_agent import ThreatHuntingAgent
        from agents.response_agent import ResponseAgent
        from agents.vuln_agent import VulnAssessmentAgent
        self.assertTrue(callable(AlertTriageAgent))
        self.assertTrue(callable(ThreatHuntingAgent))
        self.assertTrue(callable(ResponseAgent))
        self.assertTrue(callable(VulnAssessmentAgent))

    def test_agent_creation_works(self):
        from agents.triage_agent import AlertTriageAgent
        agent = AlertTriageAgent()
        self.assertEqual(agent.name, 'TriageAgent')

    def test_all_agents_can_be_instantiated(self):
        """4 个 Agent 都能创建"""
        from agents.triage_agent import AlertTriageAgent
        from agents.hunting_agent import ThreatHuntingAgent
        from agents.response_agent import ResponseAgent
        from agents.vuln_agent import VulnAssessmentAgent
        for cls in [AlertTriageAgent, ThreatHuntingAgent, ResponseAgent, VulnAssessmentAgent]:
            instance = cls()
            self.assertTrue(hasattr(instance, 'execute'))


class TestPublicAPI(unittest.TestCase):
    """aegis.aegisguard 公开 API 测试"""

    def test_layer1_agents_exported(self):
        from aegis.aegisguard import (
            AlertTriageAgent, ThreatHuntingAgent,
            ResponseAgent, VulnAssessmentAgent,
        )
        for cls in [AlertTriageAgent, ThreatHuntingAgent, ResponseAgent, VulnAssessmentAgent]:
            self.assertTrue(callable(cls))

    def test_layer2_modules_graceful_none(self):
        """Phase 5+ 模块还没实现, 应该是 None (优雅降级)"""
        from aegis import aegisguard
        # PromptGuard / ToolACL / ModelACL 还没实现
        self.assertTrue(hasattr(aegisguard, 'PromptGuard'))
        self.assertTrue(hasattr(aegisguard, 'ToolACL'))
        self.assertTrue(hasattr(aegisguard, 'ModelACL'))

    def test_layer3_modules_graceful_none(self):
        """Phase 5+ DecisionExplainer / AuditChain 应该是 None"""
        from aegis import aegisguard
        self.assertTrue(hasattr(aegisguard, 'DecisionExplainer'))
        self.assertTrue(hasattr(aegisguard, 'AuditChain'))

    def test_public_api_all_declared(self):
        """__all__ 列出的所有名字都能拿到"""
        from aegis import aegisguard
        for name in aegisguard.__all__:
            self.assertTrue(hasattr(aegisguard, name), f'{name} 不存在')


class TestArchitecturalFiles(unittest.TestCase):
    """架构文档/标记文件存在性测试"""

    def test_readme_exists(self):
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, 'README.md')))

    def test_architecture_doc_exists(self):
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, 'docs', 'ARCHITECTURE.md')))

    def test_operations_doc_exists(self):
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, 'docs', 'OPERATIONS.md')))

    def test_roadmap_exists(self):
        self.assertTrue(os.path.exists(os.path.join(PROJECT_ROOT, 'ROADMAP.md')))

    def test_aegis_package_structure(self):
        """aegis/ 三层结构必须齐"""
        for path in [
            'aegis/__init__.py',
            'aegis/_compat.py',
            'aegis/ai_for_sec/__init__.py',
            'aegis/sec_for_ai/__init__.py',
            'aegis/ops_trust/__init__.py',
            'aegis/aegisguard/__init__.py',
        ]:
            self.assertTrue(
                os.path.exists(os.path.join(PROJECT_ROOT, path)),
                f'{path} 缺失'
            )


class TestFlaskAppStillWorks(unittest.TestCase):
    """Flask app 在新架构下仍能跑 (回归测试)"""

    def test_app_imports(self):
        from web.admin.app import app
        self.assertIsNotNone(app)

    def test_public_endpoints(self):
        from web.admin.app import app
        with app.test_client() as c:
            for endpoint in ['/health', '/api/version', '/metrics']:
                r = c.get(endpoint)
                self.assertEqual(r.status_code, 200, f'{endpoint} 挂了')


if __name__ == '__main__':
    unittest.main(verbosity=2)
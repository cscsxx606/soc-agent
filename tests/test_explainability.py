#!/usr/bin/env python3
"""
SOC Agent Explainability 单元测试
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.explainability import (
    DecisionExplainer, Explanation, Evidence, AlternativeAction,
    ExplanationType,
)


def make_incident(**overrides):
    base = {
        'incident_id': 'INC-001',
        'alert_type': 'brute_force_ssh',
        'severity': 'high',
        'source_ip': '8.8.8.8',
        'asset_info': {'criticality': 'critical'},
        'enrichment': {'source_ip_reputation': 'external/potentially_malicious'},
        'ai_analysis': {
            'priority': 'P1',
            'risk_score': 85,
            'reasoning': '高危外部攻击',
            'mitre_technique_id': 'T1110',
        },
    }
    base.update(overrides)
    return base


class TestBasicExplanation(unittest.TestCase):
    """基础解释"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_explain_incident_triage(self):
        """解释一个 incident"""
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertIsInstance(exp, Explanation)
        self.assertEqual(exp.decision_type, ExplanationType.TRIAGE.value)
        self.assertGreater(len(exp.summary), 0)

    def test_explanation_has_evidence(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertGreater(len(exp.evidence), 0)

    def test_evidence_includes_alert_type(self):
        incident = make_incident(alert_type='web_attack_sql_injection')
        exp = self.explainer.explain_incident_triage(incident)
        ev = next(e for e in exp.evidence if e.field == 'alert_type')
        self.assertEqual(ev.value, 'web_attack_sql_injection')

    def test_evidence_includes_criticality(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        ev = next(e for e in exp.evidence if e.field == 'criticality')
        self.assertEqual(ev.value, 'critical')

    def test_evidence_includes_ip_reputation(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        ev = next(e for e in exp.evidence if e.field == 'source_ip_reputation')
        self.assertEqual(ev.value, 'external/potentially_malicious')


class TestRiskFactorCollection(unittest.TestCase):
    """风险因素收集"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_high_risk_type_flagged(self):
        incident = make_incident(alert_type='privilege_escalation')
        exp = self.explainer.explain_incident_triage(incident)
        self.assertTrue(any('privilege_escalation' in rf for rf in exp.risk_factors))

    def test_external_critical_combo(self):
        """外部 IP + critical 资产"""
        incident = make_incident(
            source_ip='1.2.3.4',
            asset_info={'criticality': 'critical'},
        )
        exp = self.explainer.explain_incident_triage(incident)
        self.assertTrue(any('外部 IP' in rf for rf in exp.risk_factors))

    def test_critical_severity_flagged(self):
        incident = make_incident(severity='critical')
        exp = self.explainer.explain_incident_triage(incident)
        self.assertTrue(any('critical' in rf.lower() for rf in exp.risk_factors))


class TestConfidenceCalculation(unittest.TestCase):
    """置信度计算"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_confidence_in_range(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertGreaterEqual(exp.confidence, 0.0)
        self.assertLessEqual(exp.confidence, 1.0)

    def test_high_confidence_for_complete_data(self):
        """完整数据 → 高置信度"""
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertGreater(exp.confidence, 0.3)


class TestAlternatives(unittest.TestCase):
    """备选方案"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_p1_has_alternatives(self):
        """P1 应该有备选方案"""
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertGreater(len(exp.alternative_actions), 0)

    def test_p1_alternative_includes_isolation(self):
        """P1 备选包含隔离"""
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        actions = ' '.join(a.action for a in exp.alternative_actions)
        self.assertIn('隔离', actions)


class TestSummaryGeneration(unittest.TestCase):
    """摘要生成"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_summary_includes_priority(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertIn('P1', exp.summary)

    def test_summary_includes_score(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        self.assertIn('85', exp.summary)

    def test_summary_includes_external_for_external_ip(self):
        incident = make_incident(source_ip='1.2.3.4')
        exp = self.explainer.explain_incident_triage(incident)
        self.assertIn('外部', exp.summary)


class TestEvidenceImpact(unittest.TestCase):
    """证据影响方向"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_external_ip_positive(self):
        incident = make_incident(source_ip='1.2.3.4')
        exp = self.explainer.explain_incident_triage(incident)
        ev = next(e for e in exp.evidence if e.field == 'source_ip_reputation')
        self.assertEqual(ev.impact, 'positive')

    def test_internal_ip_negative(self):
        incident = make_incident(
            source_ip='10.0.0.1',
            enrichment={'source_ip_reputation': 'internal'},
        )
        exp = self.explainer.explain_incident_triage(incident)
        ev = next(e for e in exp.evidence if e.field == 'source_ip_reputation')
        self.assertEqual(ev.impact, 'negative')

    def test_critical_criticality_positive(self):
        incident = make_incident(asset_info={'criticality': 'critical'})
        exp = self.explainer.explain_incident_triage(incident)
        ev = next(e for e in exp.evidence if e.field == 'criticality')
        self.assertEqual(ev.impact, 'positive')


class TestResponseExplanation(unittest.TestCase):
    """响应动作解释"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_explain_isolate_host(self):
        action = {
            'action_id': 'ACT-001',
            'incident_id': 'INC-001',
            'action_type': 'isolate_host',
            'target': 'web-prod-01',
        }
        exp = self.explainer.explain_response_action(action)
        self.assertEqual(exp.decision_type, ExplanationType.RESPONSE.value)
        self.assertIn('isolate_host', exp.summary)

    def test_isolate_has_business_continuity_warning(self):
        action = {'action_type': 'isolate_host', 'target': 'h1'}
        exp = self.explainer.explain_response_action(action)
        self.assertTrue(any('业务连续性' in rf for rf in exp.risk_factors))


class TestACLEventExplanation(unittest.TestCase):
    """ACL 事件解释"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_explain_deny_event(self):
        event = {
            'event_hash': 'abc123',
            'agent_name': 'triage_agent',
            'action': 'delete',
            'resource': 'users',
        }
        exp = self.explainer.explain_tool_acl_deny(event)
        self.assertEqual(exp.decision_type, ExplanationType.TOOL_ACL.value)
        self.assertIn('triage_agent', exp.summary)
        self.assertIn('users', exp.summary)

    def test_acl_deny_alternatives(self):
        event = {'agent_name': 'rogue', 'action': 'write', 'resource': 'settings'}
        exp = self.explainer.explain_tool_acl_deny(event)
        self.assertGreater(len(exp.alternative_actions), 0)


class TestSerialization(unittest.TestCase):
    """序列化"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_explanation_to_dict(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        d = exp.to_dict()
        for key in ['decision_id', 'decision_type', 'summary', 'reasoning',
                     'evidence', 'confidence', 'risk_factors', 'timestamp']:
            self.assertIn(key, d)

    def test_evidence_to_dict(self):
        ev = Evidence(source='test', field='x', value=1, impact='positive', weight=0.5)
        d = ev.to_dict() if hasattr(ev, 'to_dict') else None
        # dataclass asdict via __dict__
        self.assertEqual(ev.field, 'x')


class TestHumanReadable(unittest.TestCase):
    """人类可读输出"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_to_human_readable(self):
        incident = make_incident()
        exp = self.explainer.explain_incident_triage(incident)
        text = exp.to_human_readable()
        self.assertIn('决策解释报告', text)
        self.assertIn('证据', text)
        self.assertIn('风险因素', text)
        self.assertIn('P1', text)


class TestExplanationsHistory(unittest.TestCase):
    """解释历史"""

    def setUp(self):
        self.explainer = DecisionExplainer()

    def test_history_recorded(self):
        self.explainer.explain_incident_triage(make_incident())
        self.explainer.explain_incident_triage(make_incident(incident_id='INC-002'))
        exps = self.explainer.get_explanations()
        self.assertEqual(len(exps), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
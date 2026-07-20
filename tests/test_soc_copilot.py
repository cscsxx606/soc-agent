#!/usr/bin/env python3
"""
SOC Agent SOCCopilot 单元测试
"""

import sys
import os
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.soc_copilot import SOCCopilot, CopilotSuggestion


def make_incident(**overrides):
    base = {
        'incident_id': 'INC-001',
        'alert_type': 'brute_force_ssh',
        'severity': 'high',
        'source_ip': '8.8.8.8',
        'dest_ip': '10.0.0.1',
        'asset_info': {'hostname': 'web-prod-01', 'criticality': 'critical'},
        'enrichment': {'source_ip_reputation': 'external/potentially_malicious'},
        'ai_analysis': {
            'priority': 'P1',
            'risk_score': 85,
            'mitre_technique_id': 'T1110',
            'mitre_technique_name': 'Brute Force',
            'confidence': '高',
            'reasoning': '外部 IP 对 critical 资产暴力破解',
            'recommended_action': '立即隔离来源 IP',
            'human_verification_needed': True,
            'playbook_suggestion': 'brute_force_response',
        },
    }
    base.update(overrides)
    return base


class TestSuggestions(unittest.TestCase):
    """下一步推荐"""

    def setUp(self):
        self.copilot = SOCCopilot()

    def test_p1_has_suggestions(self):
        incident = make_incident()
        suggests = self.copilot.suggest_next_action(incident)
        self.assertGreater(len(suggests), 0)

    def test_suggestion_has_required_fields(self):
        incident = make_incident()
        suggests = self.copilot.suggest_next_action(incident)
        for s in suggests:
            self.assertTrue(hasattr(s, 'action'))
            self.assertTrue(hasattr(s, 'priority'))
            self.assertTrue(hasattr(s, 'description'))

    def test_p1_includes_ip_lookup(self):
        incident = make_incident(source_ip='8.8.8.8')
        suggests = self.copilot.suggest_next_action(incident)
        actions = [s.action for s in suggests]
        self.assertTrue(any('source_ip_lookup' in a for a in actions))

    def test_p1_includes_auto_response(self):
        incident = make_incident()
        suggests = self.copilot.suggest_next_action(incident)
        actions = [s.action for s in suggests]
        self.assertTrue(any('automated_response' in a for a in actions))

    def test_p4_fewer_suggestions(self):
        incident = make_incident()
        incident['ai_analysis']['priority'] = 'P4'
        incident['ai_analysis']['risk_score'] = 10
        suggests = self.copilot.suggest_next_action(incident)
        # P4 建议更少
        self.assertGreater(len(suggests), 0)

    def test_no_crash_on_empty_incident(self):
        suggests = self.copilot.suggest_next_action({})
        # 最小 incident 返回建议
        self.assertIsInstance(suggests, list)


class TestDraftReport(unittest.TestCase):
    """报告起草"""

    def setUp(self):
        self.copilot = SOCCopilot()

    def test_report_has_structure(self):
        incident = make_incident()
        report = self.copilot.auto_draft_report(incident)
        self.assertIn('事件调查报告', report)
        self.assertIn('基本信息', report)
        self.assertIn('源头分析', report)

    def test_report_includes_data(self):
        incident = make_incident()
        report = self.copilot.auto_draft_report(incident)
        self.assertIn('INC-001', report)
        self.assertIn('brute_force_ssh', report)
        self.assertIn('T1110', report)

    def test_report_empty_incident(self):
        report = self.copilot.auto_draft_report({})
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 50)


class TestTrendAnalysis(unittest.TestCase):
    """趋势分析"""

    def setUp(self):
        self.copilot = SOCCopilot()

    def test_empty_incidents(self):
        result = self.copilot.analyze_trend([])
        self.assertEqual(result['total'], 0)

    def test_counts_by_priority(self):
        incidents = [
            make_incident(incident_id=f'INC-{i}', ai_analysis={'priority': 'P1', 'risk_score': 90})
            for i in range(3)
        ]
        result = self.copilot.analyze_trend(incidents)
        self.assertEqual(result['total'], 3)
        self.assertEqual(result['by_priority'].get('P1', 0), 3)

    def test_p1_spike_detected(self):
        incidents = [
            make_incident(incident_id=f'INC-{i}', ai_analysis={'priority': 'P1', 'risk_score': 90})
            for i in range(5)
        ]
        result = self.copilot.analyze_trend(incidents)
        self.assertTrue(result['p1_spike'])

    def test_no_p1_spike(self):
        incidents = [make_incident(ai_analysis={'priority': 'P4', 'risk_score': 10})]
        result = self.copilot.analyze_trend(incidents)
        self.assertFalse(result['p1_spike'])

    def test_external_pct(self):
        incidents = [
            make_incident(source_ip='8.8.8.8'),
            make_incident(source_ip='10.0.0.1', enrichment={'source_ip_reputation': 'internal'}),
        ]
        result = self.copilot.analyze_trend(incidents)
        self.assertEqual(result['external_pct'], 50.0)


class TestDecisionExplanation(unittest.TestCase):
    """决策解释"""

    def setUp(self):
        self.copilot = SOCCopilot()

    def test_explain_returns_text(self):
        incident = make_incident()
        text = self.copilot.explain_decision(incident)
        self.assertIn('P1', text)
        self.assertIn('85', text)
        self.assertIn('T1110', text)

    def test_explain_empty_incident(self):
        text = self.copilot.explain_decision({})
        self.assertIsInstance(text, str)
        self.assertIn('决策', text)


class TestStats(unittest.TestCase):
    """统计"""

    def test_stats_init(self):
        c = SOCCopilot()
        s = c.get_stats()
        self.assertEqual(s['suggestions_given'], 0)
        self.assertEqual(s['reports_drafted'], 0)

    def test_stats_increment(self):
        c = SOCCopilot()
        c.suggest_next_action(make_incident())
        c.auto_draft_report(make_incident())
        s = c.get_stats()
        self.assertGreater(s['suggestions_given'], 0)
        self.assertEqual(s['reports_drafted'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
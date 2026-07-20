#!/usr/bin/env python3
"""
SOC Agent AlertTriageAgent 单元测试
"""

import sys
import os
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from agents.triage_agent import AlertTriageAgent


def make_alert(**overrides):
    base = {
        'id': 'ALT-001',
        'timestamp': '2026-07-20T15:00:00',
        'alert_type': 'brute_force_ssh',
        'severity': 'high',
        'source_ip': '8.8.8.8',
        'dest_ip': '10.0.0.1',
        'description': 'SSH brute force attempt',
        'asset_info': {'hostname': 'web-prod-01', 'role': 'web_server', 'criticality': 'critical', 'owner': 'ops-team'},
        'raw_log': 'Failed password for root from 8.8.8.8 port 12345 ssh2',
    }
    base.update(overrides)
    return base


def mock_llm_analyzer(json_response):
    def _side_effect(*args, **kwargs):
        return json_response
    return _side_effect


class TestEnrichAlert(unittest.TestCase):
    def setUp(self):
        self.agent = AlertTriageAgent()

    def test_external_ip_marked(self):
        alert = make_alert(source_ip='8.8.8.8')
        result = self.agent._enrich_alert(alert)
        self.assertIn('external', result['enrichment']['source_ip_reputation'])

    def test_internal_ip_marked(self):
        for ip in ['10.0.0.1', '172.16.0.1', '192.168.1.1']:
            alert = make_alert(source_ip=ip)
            self.assertEqual(self.agent._enrich_alert(alert)['enrichment']['source_ip_reputation'], 'internal', f'{ip} should be internal')

    def test_asset_criticality_score(self):
        for level, expected in [('critical', 100), ('high', 75), ('medium', 50), ('low', 25)]:
            alert = make_alert(asset_info={'criticality': level})
            self.assertEqual(self.agent._enrich_alert(alert)['enrichment']['asset_criticality_score'], expected)

    def test_unknown_criticality_defaults(self):
        alert = make_alert(asset_info={'criticality': 'unknown'})
        self.assertEqual(self.agent._enrich_alert(alert)['enrichment']['asset_criticality_score'], 50)

    def test_classify_alert_family(self):
        self.assertEqual(self.agent._classify_alert_family('brute_force_ssh'), 'intrusion_attempt')
        self.assertEqual(self.agent._classify_alert_family('web_attack_sql_injection'), 'web_attack')
        self.assertEqual(self.agent._classify_alert_family('privilege_escalation'), 'lateral_movement')
        self.assertEqual(self.agent._classify_alert_family('suspicious_dns_query'), 'command_and_control')
        self.assertEqual(self.agent._classify_alert_family('unknown_xxx'), 'unknown')

    def test_triage_time_set(self):
        result = self.agent._enrich_alert(make_alert())
        self.assertIn('triage_time', result['enrichment'])


class TestRuleFallback(unittest.TestCase):
    def setUp(self):
        self.agent = AlertTriageAgent()

    def test_critical_high_priority(self):
        alert = self.agent._enrich_alert(make_alert(
            severity='critical',
            asset_info={'criticality': 'critical'},
            source_ip='8.8.8.8',
            alert_type='web_attack_sql_injection'
        ))
        result = self.agent._rule_fallback(alert)
        self.assertEqual(result['priority'], 'P1')
        self.assertEqual(result['recommended_action'], '立即处置')
        self.assertGreaterEqual(result['risk_score'], 80)
        self.assertEqual(result['mitre_technique_id'], 'T1190')

    def test_low_priority_autoclose(self):
        alert = self.agent._enrich_alert(make_alert(severity='low', asset_info={'criticality': 'low'}, source_ip='10.0.0.5'))
        result = self.agent._rule_fallback(alert)
        self.assertEqual(result['priority'], 'P4')
        self.assertEqual(result['recommended_action'], '自动关闭')

    def test_external_ip_bonus(self):
        ext = self.agent._rule_fallback(self.agent._enrich_alert(make_alert(source_ip='1.2.3.4', severity='medium')))
        int_ = self.agent._rule_fallback(self.agent._enrich_alert(make_alert(source_ip='10.0.0.5', severity='medium')))
        self.assertGreater(ext['risk_score'], int_['risk_score'])

    def test_mitre_technique_mapping(self):
        for atype, tid in [('brute_force_ssh', 'T1110'), ('suspicious_dns_query', 'T1071.004'), ('privilege_escalation', 'T1068')]:
            alert = self.agent._enrich_alert(make_alert(alert_type=atype))
            self.assertEqual(self.agent._rule_fallback(alert)['mitre_technique_id'], tid)

    def test_unknown_alert_type_default(self):
        alert = self.agent._enrich_alert(make_alert(alert_type='foo_bar'))
        result = self.agent._rule_fallback(alert)
        self.assertEqual(result['mitre_technique_id'], 'T0000')

    def test_score_capped_at_100(self):
        alert = self.agent._enrich_alert(make_alert(severity='critical', asset_info={'criticality': 'critical'}, source_ip='1.2.3.4', alert_type='web_attack_sql_injection'))
        self.assertLessEqual(self.agent._rule_fallback(alert)['risk_score'], 100)

    def test_human_verification_needed_at_high_score(self):
        alert = self.agent._enrich_alert(make_alert(severity='critical', asset_info={'criticality': 'critical'}, source_ip='1.2.3.4', alert_type='web_attack_sql_injection'))
        self.assertTrue(self.agent._rule_fallback(alert)['human_verification_needed'])


class TestExecuteFlow(unittest.TestCase):
    def setUp(self):
        self.agent = AlertTriageAgent()

    def test_ai_path_succeeds(self):
        ai_response = {'attack_type': 'Brute Force', 'mitre_technique_id': 'T1110', 'risk_score': 85, 'priority': 'P1', 'recommended_action': '立即处置'}
        with patch('core.agent_base.DeepSeekClient') as MockClient:
            mock_client = MockClient.return_value
            mock_client.analyze_json.side_effect = mock_llm_analyzer(ai_response)
            agent = AlertTriageAgent()
            results = agent.execute([make_alert()])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['ai_analysis']['risk_score'], 85)
            self.assertEqual(results[0]['triage_agent'], 'TriageAgent')
            stats = agent.get_stats()
            self.assertEqual(stats['executions'], 1)
            self.assertEqual(stats['success'], 1)

    def test_ai_path_fallback_on_none(self):
        with patch('core.agent_base.DeepSeekClient') as MockClient:
            mock_client = MockClient.return_value
            mock_client.analyze_json.return_value = None
            agent = AlertTriageAgent()
            results = agent.execute([make_alert()])
            self.assertEqual(len(results), 1)
            self.assertIn('risk_score', results[0]['ai_analysis'])
            self.assertEqual(agent.get_stats()['failed'], 1)

    def test_multiple_alerts_stats_accumulate(self):
        with patch('core.agent_base.DeepSeekClient') as MockClient:
            mock_client = MockClient.return_value
            mock_client.analyze_json.return_value = None
            agent = AlertTriageAgent()
            alerts = [make_alert(id=f'ALT-{i}', alert_type=t) for i, t in enumerate(['brute_force_ssh', 'web_attack_sql_injection', 'privilege_escalation'])]
            results = agent.execute(alerts)
            self.assertEqual(len(results), 3)
            self.assertEqual(agent.get_stats()['executions'], 3)

    def test_memory_records_triage(self):
        with patch('core.agent_base.DeepSeekClient') as MockClient:
            mock_client = MockClient.return_value
            mock_client.analyze_json.return_value = {'risk_score': 90, 'priority': 'P1', 'attack_type': 'X', 'mitre_technique_id': 'T1110', 'mitre_technique_name': 'X', 'confidence': '高', 'business_impact': '', 'data_impact': '', 'recommended_action': '立即处置', 'key_indicators': [], 'human_verification_needed': True, 'reasoning': '', 'playbook_suggestion': ''}
            agent = AlertTriageAgent()
            agent.execute([make_alert(id='ALT-X')])
            mem = agent.recall('triage_result')
            self.assertEqual(len(mem), 1)
            self.assertEqual(mem[0]['value']['alert_id'], 'ALT-X')


class TestAgentStats(unittest.TestCase):
    def setUp(self):
        self.agent = AlertTriageAgent()

    def test_update_stats_success(self):
        self.agent.update_stats(success=True, tokens=100)
        self.assertEqual(self.agent.stats['success'], 1)
        self.assertEqual(self.agent.stats['total_tokens'], 100)

    def test_update_stats_failure(self):
        self.agent.update_stats(success=False)
        self.assertEqual(self.agent.stats['failed'], 1)
        self.assertEqual(self.agent.stats['executions'], 1)

    def test_success_rate_zero(self):
        self.assertEqual(self.agent.get_stats()['success_rate'], 0.0)

    def test_success_rate_calculated(self):
        self.agent.update_stats(success=True)
        self.agent.update_stats(success=True)
        self.agent.update_stats(success=False)
        self.assertEqual(self.agent.get_stats()['success_rate'], 66.7)

    def test_memory_capped_at_50(self):
        for i in range(60):
            self.agent.remember('x', i)
        self.assertEqual(len(self.agent.memory), 50)
        self.assertEqual(self.agent.memory[-1]['value'], 59)

    def test_recall_by_key(self):
        self.agent.remember('triage_result', {'a': 1})
        self.agent.remember('other', {'b': 2})
        self.agent.remember('triage_result', {'c': 3})
        self.assertEqual(len(self.agent.recall('triage_result')), 2)

    def test_to_json(self):
        import json
        self.agent.update_stats(success=True)
        parsed = json.loads(self.agent.to_json())
        self.assertEqual(parsed['name'], 'TriageAgent')
        self.assertEqual(parsed['stats']['success'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
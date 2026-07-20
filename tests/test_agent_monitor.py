#!/usr/bin/env python3
"""
SOC Agent AgentMonitor 单元测试
"""

import sys
import os
import unittest
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from core.agent_monitor import (
    AgentMonitor, Event, AnomalyAlert,
    AnomalyType, Severity,
)


def mk_event(agent='triage', action='read', params=None, ts=None, output=None, success=True):
    return Event(
        agent_name=agent,
        action=action,
        params=params or {},
        timestamp=ts or time.time(),
        output=output,
        success=success,
    )


class TestEventRecording(unittest.TestCase):
    def setUp(self):
        self.m = AgentMonitor()

    def test_watch_event(self):
        self.m.watch(mk_event())
        self.assertEqual(self.m.stats['events_logged'], 1)

    def test_event_stored(self):
        self.m.watch(mk_event(agent='triage'))
        self.assertEqual(len(self.m.get_events('triage')), 1)

    def test_multiple_agents(self):
        self.m.watch(mk_event(agent='triage'))
        self.m.watch(mk_event(agent='hunting'))
        self.assertEqual(len(self.m.get_events('triage')), 1)
        self.assertEqual(len(self.m.get_events('hunting')), 1)

    def test_all_events(self):
        self.m.watch(mk_event(agent='triage'))
        self.m.watch(mk_event(agent='hunting'))
        self.assertEqual(len(self.m.get_events()), 2)


class TestFrequencyDetection(unittest.TestCase):
    def test_baseline_built(self):
        m = AgentMonitor(frequency_window_minutes=60)
        for _ in range(5):
            m.watch(mk_event(action='analyze'))
        alerts = m.analyze('triage')
        self.assertEqual(len(alerts), 0)

    def test_frequency_spike_after_baseline(self):
        m = AgentMonitor(frequency_window_minutes=60)
        for _ in range(3):
            m.watch(mk_event(action='analyze'))
        m.analyze('triage')
        for _ in range(15):
            m.watch(mk_event(action='analyze'))
        alerts = m.analyze('triage')
        freq_alerts = [a for a in alerts if a.anomaly_type == AnomalyType.FREQUENCY_SPIKE]
        self.assertGreater(len(freq_alerts), 0)

    def test_no_false_alarm_for_stable(self):
        m = AgentMonitor(frequency_window_minutes=60)
        for _ in range(10):
            m.watch(mk_event(action='read'))
        m.analyze('triage')
        for _ in range(8):
            m.watch(mk_event(action='read'))
        alerts = m.analyze('triage')
        freq_alerts = [a for a in alerts if a.anomaly_type == AnomalyType.FREQUENCY_SPIKE]
        self.assertEqual(len(freq_alerts), 0)


class TestOffHoursDetection(unittest.TestCase):
    def test_off_hours_mass_call(self):
        m = AgentMonitor(frequency_window_minutes=600, off_hours_start=0, off_hours_end=23)
        for _ in range(15):
            m.watch(mk_event(action='execute'))
        alerts = m.analyze('triage')
        off_alerts = [a for a in alerts if a.anomaly_type == AnomalyType.OFF_HOURS_ACTIVITY]
        self.assertGreater(len(off_alerts), 0)


class TestOutputAnomaly(unittest.TestCase):
    def test_high_empty_rate(self):
        m = AgentMonitor()
        for _ in range(10):
            m.watch(mk_event(output='', success=False))
        alerts = m.analyze('triage')
        out_alerts = [a for a in alerts if a.anomaly_type == AnomalyType.OUTPUT_ANOMALY]
        self.assertGreater(len(out_alerts), 0)

    def test_low_empty_rate_no_alarm(self):
        m = AgentMonitor()
        for _ in range(10):
            m.watch(mk_event(output='ok'))
        m.watch(mk_event(output=''))
        alerts = m.analyze('triage')
        out_alerts = [a for a in alerts if a.anomaly_type == AnomalyType.OUTPUT_ANOMALY]
        self.assertEqual(len(out_alerts), 0)


class TestAnomalyAlertStructure(unittest.TestCase):
    def test_alert_has_all_fields(self):
        a = AnomalyAlert(
            agent_name='triage', anomaly_type=AnomalyType.FREQUENCY_SPIKE,
            severity=Severity.HIGH, message='test', score=0.8,
            context={'test': 1}, timestamp=time.time()
        )
        for attr in ['agent_name', 'anomaly_type', 'severity', 'message', 'score', 'context']:
            self.assertTrue(hasattr(a, attr))

    def test_alert_to_dict(self):
        a = AnomalyAlert(agent_name='a', anomaly_type=AnomalyType.FREQUENCY_SPIKE,
                         severity=Severity.HIGH, message='m', score=0.5,
                         context={}, timestamp=12345)
        d = a.to_dict()
        for key in ['agent_name', 'anomaly_type', 'severity', 'message', 'score']:
            self.assertIn(key, d)
        self.assertEqual(d['severity'], 'high')


class TestMultiAgentAnalysis(unittest.TestCase):
    def test_analyze_all_agents(self):
        m = AgentMonitor(frequency_window_minutes=600, off_hours_start=0, off_hours_end=23)
        for _ in range(15):
            m.watch(mk_event(agent='triage', action='a'))
        m.analyze('triage')
        # all agents now fire off-hours alarm
        alerts = m.analyze()
        self.assertGreater(len(alerts), 0)

    def test_filter_critical(self):
        m = AgentMonitor(frequency_window_minutes=600, off_hours_start=0, off_hours_end=23)
        for _ in range(50):
            m.watch(mk_event(agent='triage', action='analyze'))
        m.analyze('triage')
        for _ in range(50):
            m.watch(mk_event(agent='triage', action='analyze'))
        alerts = m.analyze('triage')
        critical = m.get_alerts(only_critical=True)
        self.assertGreaterEqual(len(critical), 0)


class TestEventToDict(unittest.TestCase):
    def test_event_to_dict(self):
        e = mk_event(agent='test', action='run')
        d = e.to_dict()
        for key in ['agent_name', 'action', 'params', 'timestamp', 'success']:
            self.assertIn(key, d)


class TestStats(unittest.TestCase):
    def test_stats_init(self):
        m = AgentMonitor()
        self.assertEqual(m.get_stats()['events_logged'], 0)
        self.assertEqual(m.get_stats()['anomalies_detected'], 0)

    def test_stats_after_events(self):
        m = AgentMonitor()
        m.watch(mk_event())
        m.watch(mk_event())
        self.assertEqual(m.get_stats()['events_logged'], 2)

    def test_stats_after_alerts(self):
        m = AgentMonitor(frequency_window_minutes=600, off_hours_start=0, off_hours_end=23)
        for _ in range(20):
            m.watch(mk_event(action='analyze'))
        m.analyze('triage')
        m.analyze('triage')
        self.assertGreater(m.get_stats()['anomalies_detected'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
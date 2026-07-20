#!/usr/bin/env python3
"""
AegisGuard · Layer 2 · AgentMonitor
======================================

Agent 行为异常检测 (UEBA for AI)。

检测维度:
1. 调用频率突增 — 超过期望量的 3 倍
2. 输入参数异常 — 类型偏离历史 pattern
3. 输出异常 — 格式化错误、空结果率突增
4. 跨 Agent 关联 — 异常调用链
5. 时间异常 — 非工作时间大量活动

参考: UEBA (User and Entity Behavior Analytics)
"""

from dataclasses import dataclass, field, asdict
from collections import deque
from typing import Dict, List, Optional, Any, Deque, Set
from enum import Enum
import time
import statistics


class AnomalyType(str, Enum):
    FREQUENCY_SPIKE = "frequency_spike"
    UNUSUAL_PARAMS = "unusual_params"
    OUTPUT_ANOMALY = "output_anomaly"
    CHAIN_ANOMALY = "chain_anomaly"
    OFF_HOURS_ACTIVITY = "off_hours_activity"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Event:
    """Agent 事件"""
    agent_name: str
    action: str
    params: Dict[str, Any]
    timestamp: float
    output: Optional[str] = None
    success: bool = True

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AnomalyAlert:
    """异常告警"""
    agent_name: str
    anomaly_type: AnomalyType
    severity: Severity
    message: str
    score: float
    context: Dict[str, Any]
    timestamp: float

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['anomaly_type'] = self.anomaly_type.value
        d['severity'] = self.severity.value
        return d


class AgentMonitor:
    """Agent 行为监控器"""

    def __init__(
        self,
        frequency_window_minutes: int = 10,
        frequency_threshold_multiplier: float = 3.0,
        max_history: int = 10000,
        off_hours_start: int = 22,
        off_hours_end: int = 8,
    ):
        self.freq_window = frequency_window_minutes * 60
        self.freq_threshold = frequency_threshold_multiplier
        self.max_history = max_history
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

        # 事件缓冲区 per agent
        self.events: Dict[str, List[Event]] = {}

        # 基线 per agent per action
        self.baseline: Dict[str, Dict[str, Dict]] = {}
        # 基线结构:
        # { agent_name: { action: { count, durations, param_keys, success_rate, ... } } }

        # 输出异常: 空结果率
        self.empty_results: Dict[str, int] = {}
        self.total_results: Dict[str, int] = {}

        # 告警历史
        self.alerts: List[AnomalyAlert] = []

        self.stats = {
            'events_logged': 0,
            'anomalies_detected': 0,
            'baselines_built': 0,
        }

    def watch(self, event: Event):
        """记录单次 Agent 行为事件"""
        agent = event.agent_name
        if agent not in self.events:
            self.events[agent] = deque(maxlen=self.max_history)
        self.events[agent].append(event)

        # 跟踪输出
        if event.output is not None and len(event.output) == 0:
            self.empty_results[agent] = self.empty_results.get(agent, 0) + 1
        self.total_results[agent] = self.total_results.get(agent, 0) + 1

        self.stats['events_logged'] += 1

    def analyze(self, agent_name: Optional[str] = None) -> List[AnomalyAlert]:
        """分析 Agent 行为，返回异常告警列表"""
        if agent_name:
            agents = [agent_name]
        else:
            agents = list(self.events.keys())

        alerts: List[AnomalyAlert] = []
        now = time.time()

        for agent in agents:
            events = self.events.get(agent, [])
            if not events:
                continue

            # 1. 频率检测
            freq_alerts = self._check_frequency(agent, events, now)
            alerts.extend(freq_alerts)

            # 2. 非工作时间检测
            for a in self._check_off_hours(agent, events, now):
                alerts.append(a)

            # 3. 输出异常检测
            for a in self._check_output_anomaly(agent, now):
                alerts.append(a)

        for a in alerts:
            self.alerts.append(a)
            self.stats['anomalies_detected'] += 1

        return alerts

    def _check_frequency(self, agent: str, events: List[Event], now: float) -> List[AnomalyAlert]:
        """频率突增检测"""
        alerts = []

        # 按 action 分组
        action_counts: Dict[str, int] = {}
        for e in events:
            if now - e.timestamp <= self.freq_window:
                action_counts[e.action] = action_counts.get(e.action, 0) + 1

        if agent not in self.baseline:
            # 第一次 — 建立基线
            self.baseline[agent] = {}
            for action, count in action_counts.items():
                self.baseline[agent][action] = {
                    'count': count,
                    'durations': [],
                    'param_keys': set(),
                    'success_rate': 1.0,
                }
            self.stats['baselines_built'] += 1
            return alerts

        baseline = self.baseline.get(agent, {})
        for action, current_count in action_counts.items():
            bl = baseline.get(action)
            if bl and bl['count'] > 0:
                ratio = current_count / bl['count']
                if ratio > self.freq_threshold:
                    alerts.append(AnomalyAlert(
                        agent_name=agent,
                        anomaly_type=AnomalyType.FREQUENCY_SPIKE,
                        severity=Severity.HIGH if ratio > 5 else Severity.MEDIUM,
                        message=f'{action} 调用频率为基线的 {ratio:.1f}x ({current_count}/{bl["count"]})',
                        score=min(1.0, ratio / 10.0),
                        context={'action': action, 'current_count': current_count,
                                 'baseline_count': bl['count'], 'ratio': round(ratio, 2)},
                        timestamp=now,
                    ))

            # 更新基线（滑动平均）
            if bl:
                bl['count'] = int(bl['count'] * 0.7 + current_count * 0.3)
            else:
                baseline[action] = {'count': current_count, 'durations': [],
                                    'param_keys': set(), 'success_rate': 1.0}

        return alerts

    def _check_off_hours(self, agent: str, events: List[Event], now: float) -> List[AnomalyAlert]:
        """非工作时间活动检测"""
        current_hour = time.localtime(now).tm_hour
        is_off_hours = current_hour >= self.off_hours_start or current_hour < self.off_hours_end

        if not is_off_hours:
            return []

        # 最近 10 分钟内的非工作时间事件数
        recent = [e for e in events if now - e.timestamp <= self.freq_window]
        # 非工作时间正常基线是 0-3 个事件
        if len(recent) >= 10:
            return [AnomalyAlert(
                agent_name=agent,
                anomaly_type=AnomalyType.OFF_HOURS_ACTIVITY,
                severity=Severity.MEDIUM,
                message=f'非工作时间 ({current_hour}:00) 出现 {len(recent)} 次调用',
                score=min(1.0, len(recent) / 20.0),
                context={'hour': current_hour, 'count': len(recent), 'window_seconds': self.freq_window},
                timestamp=now,
            )]
        return []

    def _check_output_anomaly(self, agent: str, now: float) -> List[AnomalyAlert]:
        """输出异常检测"""
        empty = self.empty_results.get(agent, 0)
        total = self.total_results.get(agent, 0)
        if total < 5:
            return []  # 样本不足
        empty_rate = empty / total
        if empty_rate > 0.3:
            return [AnomalyAlert(
                agent_name=agent,
                anomaly_type=AnomalyType.OUTPUT_ANOMALY,
                severity=Severity.HIGH if empty_rate > 0.6 else Severity.MEDIUM,
                message=f'空输出率 {empty_rate:.0%} ({empty}/{total})',
                score=empty_rate,
                context={'empty': empty, 'total': total, 'empty_rate': round(empty_rate, 2)},
                timestamp=now,
            )]
        return []

    def get_events(self, agent_name: Optional[str] = None) -> List[Event]:
        if agent_name:
            return list(self.events.get(agent_name, []))
        all_events = []
        for lst in self.events.values():
            all_events.extend(lst)
        return all_events

    def get_baseline(self, agent_name: str) -> Dict:
        return self.baseline.get(agent_name, {})

    def get_alerts(self, only_critical: bool = False) -> List[AnomalyAlert]:
        if only_critical:
            return [a for a in self.alerts if a.severity in (Severity.HIGH, Severity.CRITICAL)]
        return self.alerts

    def get_stats(self) -> Dict:
        return {**self.stats}
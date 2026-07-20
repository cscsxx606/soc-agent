#!/usr/bin/env python3
"""
扫描调度器
- cron 表达式（5 字段：分 时 日 月 周）
- 调度表 + 历史执行记录
- 后台线程调度（无需外部 cron）
- 风险阈值告警
"""

import os
import re
import sys
import json
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CronParser:
    """简单 cron 表达式解析器（5 字段：分 时 日 月 周）"""

    @staticmethod
    def parse_field(field: str, min_val: int, max_val: int) -> List[int]:
        """解析单个字段"""
        values = set()
        for part in field.split(','):
            # 步长 */n 或 a-b/n
            step = 1
            if '/' in part:
                range_part, step_str = part.split('/', 1)
                step = int(step_str)
            else:
                range_part = part
            # 范围 a-b
            if range_part == '*':
                start, end = min_val, max_val
            elif '-' in range_part:
                start, end = range_part.split('-', 1)
                start, end = int(start), int(end)
            else:
                start = end = int(range_part)
            values.update(range(start, end + 1, step))
        return sorted(values)

    @staticmethod
    def parse(expr: str) -> Dict[str, set]:
        """解析 5 字段 cron 表达式"""
        expr = expr.strip()
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError(f'cron 表达式必须是 5 字段（分 时 日 月 周），收到 {len(parts)} 字段')
        return {
            'minute': set(CronParser.parse_field(parts[0], 0, 59)),
            'hour': set(CronParser.parse_field(parts[1], 0, 23)),
            'day': set(CronParser.parse_field(parts[2], 1, 31)),
            'month': set(CronParser.parse_field(parts[3], 1, 12)),
            'weekday': set(CronParser.parse_field(parts[4], 0, 6)),  # 0=Sunday
        }

    @staticmethod
    def next_fire_time(expr: str, after: datetime = None) -> Optional[datetime]:
        """计算下一次触发时间"""
        try:
            spec = CronParser.parse(expr)
        except Exception:
            return None
        if after is None:
            after = datetime.now()
        # 最多找未来 366 天
        # cron: 0=Sun, 1=Mon, ..., 6=Sat
        # Python weekday(): 0=Mon, 1=Tue, ..., 6=Sun
        # Mapping: cron_dow = (python_weekday() + 1) % 7
        py_to_cron = {(i + 1) % 7 for i in range(7)}
        for i in range(366 * 24 * 60):
            candidate = after + timedelta(minutes=i)
            cron_dow = (candidate.weekday() + 1) % 7
            if (candidate.minute in spec['minute'] and
                candidate.hour in spec['hour'] and
                candidate.day in spec['day'] and
                candidate.month in spec['month'] and
                cron_dow in spec['weekday']):
                return candidate
        return None

    @staticmethod
    def describe(expr: str) -> str:
        """人类可读描述"""
        try:
            spec = CronParser.parse(expr)
        except Exception as e:
            return f'❌ 解析失败: {e}'

        parts = expr.split()

        def fmt(vals: List[int], full_range: range) -> str:
            if set(vals) == set(full_range):
                return '每'
            if len(vals) == 1:
                return str(vals[0])
            return ','.join(str(v) for v in vals)

        minute_desc = fmt(sorted(spec['minute']), range(60))
        hour_desc = fmt(sorted(spec['hour']), range(24))

        # 处理「每 N 分钟」(*/N * * * *)
        if parts[0].startswith('*/') and parts[1] == '*' and parts[2] == '*' and parts[3] == '*' and parts[4] == '*':
            return f'每 {parts[0].split("/")[1]} 分钟'
        # 处理「每 N 小时」(0 */N * * *)
        if parts[0] == '0' and parts[1].startswith('*/') and parts[2] == '*' and parts[3] == '*' and parts[4] == '*':
            return f'每 {parts[1].split("/")[1]} 小时'

        if parts[2] == '*' and parts[3] == '*' and parts[4] == '*':
            if parts[1] == '*':
                return f'每分钟'
            elif '/' in parts[1]:
                return f'每小时第 {parts[1].split("/")[-1]} 分钟（{parts[1].split("/")[0]}{"=" if "/" not in parts[1].replace("*/","") else "起"}）'
            else:
                return f'每天 {parts[1]}:{parts[0].zfill(2)}'
        if parts[4] != '*':
            weekday_names = {0: '周日', 1: '周一', 2: '周二', 3: '周三', 4: '周四', 5: '周五', 6: '周六'}
            wd = ','.join(weekday_names.get(d, str(d)) for d in sorted(spec['weekday']))
            return f'每{wd} {parts[1]}:{parts[0].zfill(2)}'
        return f'每月 {parts[2]} 日 {parts[1]}:{parts[0].zfill(2)}'


class ScanScheduler:
    """扫描调度器 - 后台线程 + cron 触发"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = None):
        # 避免重复初始化
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        self.running = False
        self.thread = None
        self._callbacks: List[Callable] = []
        # 调度数据保存路径
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     'data', 'scheduler.json')
        self.db_path = db_path
        self._init_storage()

    def _init_storage(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w') as f:
                json.dump({'schedules': [], 'history': []}, f)

    def _read(self) -> Dict:
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {'schedules': [], 'history': []}

    def _write(self, data: Dict):
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)

    # ====== 调度 CRUD ======

    def add_schedule(self, name: str, cron_expr: str,
                     target_ids: List[int] = None,
                     target_ips: List[str] = None,
                     enable_web_scan: bool = True,
                     risk_alert_threshold: int = 30,
                     notify_channel: str = 'log',
                     created_by: str = 'admin') -> Dict[str, Any]:
        """添加调度任务"""
        try:
            CronParser.parse(cron_expr)
        except Exception as e:
            return {'success': False, 'error': f'cron 表达式错误: {e}'}

        schedule_id = f'SCH-{uuid.uuid4().hex[:8].upper()}'
        next_run = CronParser.next_fire_time(cron_expr)

        schedule = {
            'schedule_id': schedule_id,
            'name': name,
            'cron_expr': cron_expr,
            'description': CronParser.describe(cron_expr),
            'target_ids': target_ids or [],
            'target_ips': target_ips or [],
            'enable_web_scan': enable_web_scan,
            'risk_alert_threshold': risk_alert_threshold,
            'notify_channel': notify_channel,
            'enabled': True,
            'created_by': created_by,
            'created_at': datetime.now().isoformat(),
            'last_run': None,
            'next_run': next_run.isoformat() if next_run else None,
            'run_count': 0,
            'success_count': 0,
            'fail_count': 0
        }
        data = self._read()
        data['schedules'].append(schedule)
        self._write(data)
        return {'success': True, 'schedule': schedule}

    def list_schedules(self) -> List[Dict]:
        """列出所有调度"""
        data = self._read()
        # 更新下次运行时间
        for s in data['schedules']:
            try:
                next_run = CronParser.next_fire_time(s['cron_expr'])
                s['next_run'] = next_run.isoformat() if next_run else None
            except Exception:
                s['next_run'] = None
        return data['schedules']

    def get_schedule(self, schedule_id: str) -> Optional[Dict]:
        for s in self._read()['schedules']:
            if s['schedule_id'] == schedule_id:
                return s
        return None

    def toggle_schedule(self, schedule_id: str, enabled: bool) -> bool:
        data = self._read()
        for s in data['schedules']:
            if s['schedule_id'] == schedule_id:
                s['enabled'] = enabled
                self._write(data)
                return True
        return False

    def delete_schedule(self, schedule_id: str) -> bool:
        data = self._read()
        before = len(data['schedules'])
        data['schedules'] = [s for s in data['schedules'] if s['schedule_id'] != schedule_id]
        if len(data['schedules']) < before:
            self._write(data)
            return True
        return False

    def get_history(self, limit: int = 50) -> List[Dict]:
        """获取执行历史"""
        data = self._read()
        return data['history'][-limit:][::-1]

    # ====== 后台调度线程 ======

    def start(self):
        """启动调度器后台线程"""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True, name='ScanScheduler')
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        """主循环：每 30s 检查一次"""
        last_check = datetime.now().replace(second=0, microsecond=0)
        while self.running:
            try:
                now = datetime.now().replace(second=0, microsecond=0)
                if now > last_check:
                    self._check_triggers(now)
                    last_check = now
            except Exception as e:
                print(f'[Scheduler] loop error: {e}', file=sys.stderr)
            time.sleep(20)

    def _check_triggers(self, now: datetime):
        """检查并触发到期任务"""
        data = self._read()
        for s in data['schedules']:
            if not s.get('enabled', True):
                continue
            try:
                spec = CronParser.parse(s['cron_expr'])
            except Exception:
                continue
            cron_dow = (now.weekday() + 1) % 7
            if (now.minute in spec['minute'] and
                now.hour in spec['hour'] and
                now.day in spec['day'] and
                now.month in spec['month'] and
                cron_dow in spec['weekday']):
                # 检查是否最近已触发过（防止重复）
                last_run = s.get('last_run')
                if last_run:
                    try:
                        lr = datetime.fromisoformat(last_run)
                        if (now - lr).total_seconds() < 60:
                            continue
                    except Exception:
                        pass
                # 触发
                self._execute(s)
                s['last_run'] = now.isoformat()
                s['run_count'] = s.get('run_count', 0) + 1
        self._write(data)

    def _execute(self, schedule: Dict):
        """执行调度任务"""
        from core.scanner import AssetScanner
        from core.web_vuln_scanner import WebVulnerabilityScanner

        targets_to_scan = []
        # 收集目标
        if schedule.get('target_ips'):
            for ip in schedule['target_ips']:
                targets_to_scan.append({
                    'id': None,
                    'ip_address': ip,
                    'hostname': ip,
                    'criticality': 'medium',
                    'owner': 'scheduled'
                })

        scanner = AssetScanner()
        results = []
        for target in targets_to_scan:
            try:
                result = scanner.scan_target(target, enable_service_id=schedule.get('enable_web_scan', True))
                results.append(result)
                # 更新任务计数
                data = self._read()
                for s in data['schedules']:
                    if s['schedule_id'] == schedule['schedule_id']:
                        if 'risk_score' in result and result['risk_score'] >= s.get('risk_alert_threshold', 999):
                            self._alert(schedule, result)
                        break
            except Exception as e:
                results.append({'target_ip': target['ip_address'], 'error': str(e)})

        # 记录历史
        history_entry = {
            'history_id': f'HIS-{uuid.uuid4().hex[:8].upper()}',
            'schedule_id': schedule['schedule_id'],
            'schedule_name': schedule['name'],
            'started_at': datetime.now().isoformat(),
            'completed_at': datetime.now().isoformat(),
            'target_count': len(targets_to_scan),
            'success_count': sum(1 for r in results if 'risk_score' in r),
            'fail_count': sum(1 for r in results if 'error' in r),
            'max_risk_score': max((r.get('risk_score', 0) for r in results), default=0),
            'results': results
        }
        data = self._read()
        data['history'].append(history_entry)
        # 限制历史 500 条
        data['history'] = data['history'][-500:]
        self._write(data)
        # 调用回调
        for cb in self._callbacks:
            try:
                cb(schedule, history_entry)
            except Exception as e:
                print(f'[Scheduler] callback error: {e}', file=sys.stderr)

    def _alert(self, schedule: Dict, result: Dict):
        """风险告警（写入历史 + 简单日志）"""
        alert = {
            'type': 'risk_alert',
            'schedule_id': schedule['schedule_id'],
            'schedule_name': schedule['name'],
            'target_ip': result.get('ip_address'),
            'risk_score': result.get('risk_score'),
            'risk_level': 'critical' if result.get('risk_score', 0) >= 60 else 'high',
            'threshold': schedule.get('risk_alert_threshold'),
            'timestamp': datetime.now().isoformat(),
            'recommendations': result.get('recommendations', [])[:5]
        }
        # 简单实现：写入调度器历史
        print(f'[Scheduler ALERT] {alert}', file=sys.stderr)

    def register_callback(self, cb: Callable):
        """注册执行回调"""
        self._callbacks.append(cb)

    # ====== 常用 cron 预设 ======

    PRESETS = {
        '每天凌晨': '0 2 * * *',
        '每周一早8点': '0 8 * * 1',
        '每周日晚2点': '0 2 * * 0',
        '每6小时': '0 */6 * * *',
        '每30分钟': '*/30 * * * *',
        '每月1号凌晨3点': '0 3 1 * *',
    }


if __name__ == '__main__':
    # 测试
    print('Cron 表达式解析测试:')
    print('  "0 2 * * *" ->', CronParser.describe('0 2 * * *'))
    print('  "0 8 * * 1" ->', CronParser.describe('0 8 * * 1'))
    print('  "*/30 * * * *" ->', CronParser.describe('*/30 * * * *'))
    print('  "0 0 1 * *" ->', CronParser.describe('0 0 1 * *'))

    next_run = CronParser.next_fire_time('0 2 * * *')
    print(f'\n下次 0 2 * * * 触发: {next_run}')

    print('\n调度器测试:')
    sched = ScanScheduler()
    res = sched.add_schedule(
        name='关键资产周扫',
        cron_expr='0 2 * * 1',
        target_ips=['10.0.0.10', '10.0.0.11'],
        enable_web_scan=True,
        risk_alert_threshold=30
    )
    print(f'  添加: {res["success"]}, ID: {res.get("schedule", {}).get("schedule_id")}')
    print(f'  调度数: {len(sched.list_schedules())}')
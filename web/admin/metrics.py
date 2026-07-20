#!/usr/bin/env python3
"""
SOC Agent Prometheus 指标
- /metrics 端点暴露 text/plain 格式
- 默认注册系统指标（CPU、内存）
- 业务指标：请求总数、请求时长（每个 endpoint+method 一组）

依赖（已包含在 requirements.txt）:
- prometheus_client
"""

import time
import psutil

from prometheus_client import (
    Counter, Histogram, Gauge, generate_latest, REGISTRY,
    CONTENT_TYPE_LATEST, CollectorRegistry, multiprocess,
)

# ============ 业务指标定义 ============

# 请求总数（按 endpoint + method 维度）
REQUEST_COUNT = Counter(
    'soc_http_requests_total',
    'HTTP 请求总数',
    ['method', 'endpoint', 'status']
)

# 请求时长直方图
REQUEST_LATENCY = Histogram(
    'soc_http_request_duration_seconds',
    'HTTP 请求耗时（秒）',
    ['method', 'endpoint']
)

# 当前活跃请求数
IN_FLIGHT = Gauge(
    'soc_http_requests_in_flight',
    '当前正在处理的 HTTP 请求数'
)

# 业务事件统计
INCIDENTS_TOTAL = Counter(
    'soc_incidents_total',
    'Incident 事件总数',
    ['priority', 'severity']
)
PIPELINE_RUNS = Counter(
    'soc_pipeline_runs_total',
    'Pipeline 执行总数',
    ['phase', 'status']
)

# 系统指标（每隔 N 秒采样一次）
LAST_CPU_PCT = Gauge(
    'soc_system_cpu_percent',
    '最近一次 CPU 使用率采样（%）'
)
LAST_MEM_PCT = Gauge(
    'soc_system_memory_percent',
    '最近一次内存使用率采样（%）'
)
LAST_DISK_PCT = Gauge(
    'soc_system_disk_percent',
    '最近一次根分区使用率采样（%）'
)

# ============ 工具函数 ============

def sample_system_metrics():
    """采样系统指标（每次 /metrics 调用前）"""
    LAST_CPU_PCT.set(psutil.cpu_percent(interval=None))
    LAST_MEM_PCT.set(psutil.virtual_memory().percent)
    LAST_DISK_PCT.set(psutil.disk_usage('/').percent)


def normalize_endpoint(endpoint: str) -> str:
    """归一化 endpoint（避免高基数）"""
    # UUID/int 参数替换为 :id
    import re
    endpoint = re.sub(r'/\d+', '/:id', endpoint)
    endpoint = re.sub(r'/[a-f0-9-]{16,}', '/:uuid', endpoint)
    return endpoint


def before_request_hook():
    """每个请求开始时调用"""
    IN_FLIGHT.inc()
    from flask import request, g
    g._start_time = time.time()


def after_request_hook(response):
    """每个请求结束时调用 (Flask after_request)"""
    from flask import request
    IN_FLIGHT.dec()

    # 抓指标
    method = request.method
    endpoint = normalize_endpoint(request.path or 'unknown')
    status = str(response.status_code)

    REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()

    if hasattr(g := request.environ.get('werkzeug.request'), '_start_time'):
        elapsed = time.time() - request.environ['_start_time']
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(elapsed)

    return response


# ============ /metrics endpoint ============

def register(app):
    """注册 metrics 端点"""

    # 在 app 上绑 before/after_request
    app.before_request(before_request_hook)
    app.after_request(after_request_hook)

    @app.route('/metrics')
    def metrics():
        """Prometheus scrape target"""
        sample_system_metrics()
        return generate_latest(REGISTRY), 200, {'Content-Type': CONTENT_TYPE_LATEST}

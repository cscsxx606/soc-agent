#!/usr/bin/env python3
"""
SOC Agent 数据源适配器
从多种来源拉取告警数据：Splunk/ELK/Wazuh/syslog/本地文件/API
"""

import json
import os
import sys
import requests
from typing import List, Dict, Any
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DataSource(ABC):
    """数据源基类"""

    @abstractmethod
    def fetch_alerts(self, **kwargs) -> List[Dict[str, Any]]:
        """拉取告警数据"""
        pass


class FileSource(DataSource):
    """从本地 JSON 文件读取告警"""

    def __init__(self, file_path: str):
        self.file_path = file_path

    def fetch_alerts(self, **kwargs) -> List[Dict[str, Any]]:
        if not os.path.exists(self.file_path):
            print(f"⚠ 文件不存在: {self.file_path}")
            return []

        with open(self.file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'alerts' in data:
                return data['alerts']
            return []


class SplunkSource(DataSource):
    """从 Splunk 拉取告警（REST API）"""

    def __init__(self, host: str, port: int, token: str):
        self.base_url = f"https://{host}:{port}"
        self.headers = {"Authorization": f"Bearer {token}"}

    def fetch_alerts(self, search_query: str = 'index=security severity IN ("high","critical") earliest=-1h', **kwargs) -> List[Dict]:
        try:
            # 1. 启动搜索
            resp = requests.post(
                f"{self.base_url}/services/search/jobs",
                headers=self.headers,
                data={"search": search_query, "output_mode": "json"},
                verify=False
            )
            resp.raise_for_status()
            sid = resp.json()['sid']

            # 2. 等待完成
            import time
            for _ in range(30):
                status = requests.get(
                    f"{self.base_url}/services/search/jobs/{sid}",
                    headers=self.headers,
                    params={"output_mode": "json"},
                    verify=False
                ).json()
                if status['entry'][0]['content']['isDone']:
                    break
                time.sleep(1)

            # 3. 获取结果
            results = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                headers=self.headers,
                params={"output_mode": "json", "count": 1000},
                verify=False
            ).json()

            # 4. 转换为 SOC Agent 告警格式
            return [self._normalize(r) for r in results.get('results', [])]

        except Exception as e:
            print(f"✗ Splunk 拉取失败: {e}")
            return []

    def _normalize(self, splunk_event: Dict) -> Dict:
        """Splunk 事件 → SOC 告警格式"""
        return {
            "id": splunk_event.get('event_id', f"SPLK-{datetime.now().timestamp()}"),
            "timestamp": splunk_event.get('_time', datetime.now().isoformat()),
            "source_ip": splunk_event.get('src_ip', '0.0.0.0'),
            "dest_ip": splunk_event.get('dest_ip', '0.0.0.0'),
            "alert_type": splunk_event.get('alert_type', 'unknown'),
            "severity": splunk_event.get('severity', 'medium'),
            "description": splunk_event.get('description', splunk_event.get('raw', '')),
            "raw_log": splunk_event.get('raw', ''),
            "asset_info": {
                "hostname": splunk_event.get('host', 'unknown'),
                "role": splunk_event.get('asset_role', 'unknown'),
                "criticality": splunk_event.get('asset_criticality', 'medium'),
                "owner": splunk_event.get('asset_owner', 'unassigned')
            }
        }


class ElasticsearchSource(DataSource):
    """从 Elasticsearch / ELK 拉取告警"""

    def __init__(self, host: str, port: int, username: str = None, password: str = None):
        self.base_url = f"http://{host}:{port}"
        self.auth = (username, password) if username else None

    def fetch_alerts(self, index: str = "alerts-*", time_range: str = "now-1h", **kwargs) -> List[Dict]:
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": time_range}}}
                        ]
                    }
                },
                "size": kwargs.get('size', 100),
                "sort": [{"@timestamp": {"order": "desc"}}]
            }

            resp = requests.post(
                f"{self.base_url}/{index}/_search",
                json=query,
                auth=self.auth,
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()

            hits = resp.json().get('hits', {}).get('hits', [])
            return [self._normalize(h['_source']) for h in hits]

        except Exception as e:
            print(f"✗ ELK 拉取失败: {e}")
            return []

    def _normalize(self, es_doc: Dict) -> Dict:
        return {
            "id": es_doc.get('alert_id', f"ES-{datetime.now().timestamp()}"),
            "timestamp": es_doc.get('@timestamp', datetime.now().isoformat()),
            "source_ip": es_doc.get('source', {}).get('ip', '0.0.0.0'),
            "dest_ip": es_doc.get('destination', {}).get('ip', '0.0.0.0'),
            "alert_type": es_doc.get('event', {}).get('category', 'unknown'),
            "severity": es_doc.get('event', {}).get('severity', 'medium'),
            "description": es_doc.get('event', {}).get('description', ''),
            "raw_log": json.dumps(es_doc),
            "asset_info": {
                "hostname": es_doc.get('host', {}).get('name', 'unknown'),
                "role": es_doc.get('host', {}).get('role', 'unknown'),
                "criticality": es_doc.get('host', {}).get('criticality', 'medium'),
                "owner": es_doc.get('host', {}).get('owner', 'unassigned')
            }
        }


class WazuhSource(DataSource):
    """从 Wazuh Manager API 拉取告警"""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.base_url = f"https://{host}:{port}"
        self.auth = requests.auth.HTTPBasicAuth(username, password)
        self.token = None

    def _authenticate(self):
        resp = requests.post(
            f"{self.base_url}/security/user/authenticate",
            auth=self.auth,
            verify=False
        )
        self.token = resp.json()['data']['token']
        return self.token

    def fetch_alerts(self, time_range: str = "1d", level_min: int = 7, **kwargs) -> List[Dict]:
        try:
            if not self.token:
                self._authenticate()

            headers = {"Authorization": f"Bearer {self.token}"}
            resp = requests.get(
                f"{self.base_url}/alerts",
                headers=headers,
                params={"limit": 100, "sort": "-timestamp"},
                verify=False
            )
            resp.raise_for_status()

            alerts = resp.json()['data']['affected_items']
            # 过滤告警级别
            alerts = [a for a in alerts if int(a.get('rule', {}).get('level', 0)) >= level_min]
            return [self._normalize(a) for a in alerts]

        except Exception as e:
            print(f"✗ Wazuh 拉取失败: {e}")
            return []

    def _normalize(self, wazuh_alert: Dict) -> Dict:
        rule = wazuh_alert.get('rule', {})
        agent = wazuh_alert.get('agent', {})
        return {
            "id": wazuh_alert.get('id', f"WAZUH-{datetime.now().timestamp()}"),
            "timestamp": wazuh_alert.get('timestamp', datetime.now().isoformat()),
            "source_ip": wazuh_alert.get('data', {}).get('srcip', '0.0.0.0'),
            "dest_ip": agent.get('ip', '0.0.0.0'),
            "alert_type": rule.get('description', 'unknown'),
            "severity": 'critical' if rule.get('level', 0) >= 12 else 'high' if rule.get('level', 0) >= 8 else 'medium',
            "description": rule.get('description', ''),
            "raw_log": wazuh_alert.get('full_log', ''),
            "asset_info": {
                "hostname": agent.get('name', 'unknown'),
                "role": agent.get('labels', {}).get('role', 'unknown'),
                "criticality": agent.get('labels', {}).get('criticality', 'medium'),
                "owner": agent.get('labels', {}).get('owner', 'unassigned')
            }
        }


class CloudSIEMSource(DataSource):
    """通用云 SIEM 适配器（阿里云/腾讯云/华为云）"""

    def __init__(self, provider: str, access_key: str, secret_key: str, region: str = "cn-hangzhou"):
        self.provider = provider
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region

    def fetch_alerts(self, hours: int = 1, severity: str = "high", **kwargs) -> List[Dict]:
        """需要根据具体云厂商实现 SDK 调用"""
        print(f"⚠ {self.provider} 适配器需要根据官方 SDK 实现")
        return []


# ============ 工厂方法 ============

def create_source(source_type: str, **config) -> DataSource:
    """创建数据源实例"""
    sources = {
        'file': FileSource,
        'splunk': SplunkSource,
        'elk': ElasticsearchSource,
        'elasticsearch': ElasticsearchSource,
        'wazuh': WazuhSource,
        'cloud': CloudSIEMSource,
    }

    cls = sources.get(source_type.lower())
    if not cls:
        raise ValueError(f"不支持的数据源: {source_type}，可选: {list(sources.keys())}")

    return cls(**config)


# ============ CLI ============

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='SOC Agent 数据源拉取工具')
    parser.add_argument('--source', required=True, choices=['file', 'splunk', 'elk', 'wazuh'],
                       help='数据源类型')
    parser.add_argument('--output', default='alerts.json', help='输出文件')
    parser.add_argument('--hours', type=int, default=1, help='拉取时间范围（小时）')

    # 各数据源参数
    parser.add_argument('--file', help='文件路径 (file)')
    parser.add_argument('--splunk-host', help='Splunk host')
    parser.add_argument('--splunk-port', type=int, default=8089)
    parser.add_argument('--splunk-token', help='Splunk token')

    parser.add_argument('--elk-host', help='Elasticsearch host')
    parser.add_argument('--elk-port', type=int, default=9200)
    parser.add_argument('--elk-user', help='ELK username')
    parser.add_argument('--elk-pass', help='ELK password')

    parser.add_argument('--wazuh-host', help='Wazuh host')
    parser.add_argument('--wazuh-port', type=int, default=55000)
    parser.add_argument('--wazuh-user', help='Wazuh username')
    parser.add_argument('--wazuh-pass', help='Wazuh password')

    args = parser.parse_args()

    # 构建数据源
    if args.source == 'file':
        source = FileSource(args.file)
    elif args.source == 'splunk':
        source = SplunkSource(args.splunk_host, args.splunk_port, args.splunk_token)
    elif args.source in ['elk', 'elasticsearch']:
        source = ElasticsearchSource(args.elk_host, args.elk_port, args.elk_user, args.elk_pass)
    elif args.source == 'wazuh':
        source = WazuhSource(args.wazuh_host, args.wazuh_port, args.wazuh_user, args.wazuh_pass)

    # 拉取告警
    print(f"📥 从 {args.source} 拉取告警...")
    alerts = source.fetch_alerts(hours=args.hours)

    # 保存到文件
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"✓ 已拉取 {len(alerts)} 条告警，保存到 {args.output}")
    print(f"\n使用示例：python3 start.py cli --input {args.output}")
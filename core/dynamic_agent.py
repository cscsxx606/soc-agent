#!/usr/bin/env python3
"""动态 Agent 加载器 - 从数据库配置创建 Agent 实例"""

import os
import sys
import json
import time
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent_base import BaseAgent
from core.llm_client import DeepSeekClient


class DynamicAgent(BaseAgent):
    """从配置动态生成的 Agent（无需写代码）"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name=config.get('name', config.get('agent_key', 'DynamicAgent')),
            description=config.get('description', '')
        )
        self.agent_key = config.get('agent_key', '')
        self.category = config.get('category', 'general')
        self.icon = config.get('icon', '🤖')
        self.system_prompt = config.get('system_prompt', '')
        self.tools = config.get('tools', [])
        self.input_schema = config.get('input_schema', {})
        self.output_schema = config.get('output_schema', {})

        # LLM 配置（独立于全局）
        llm_cfg = config.get('config_json', {})
        if isinstance(llm_cfg, str):
            try:
                llm_cfg = json.loads(llm_cfg)
            except Exception:
                llm_cfg = {}
        self.config = llm_cfg  # 保存整个 config 以便 execute() 读取 engine/pipeline
        self.temperature = llm_cfg.get('temperature', 0.2)
        self.max_tokens = llm_cfg.get('max_tokens', 4000)
        self.model = llm_cfg.get('model', '')
        self.fallback_enabled = llm_cfg.get('fallback_enabled', True)

        # 每次创建独立 LLM client（如有定制 model）
        if self.model:
            self.llm = DeepSeekClient(model_override=self.model)

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行 Agent 任务（支持 LLM / 管线两种引擎）"""
        # 检查是否配置为管线模式
        engine = self.config.get('engine', 'llm')
        pipeline_id = self.config.get('pipeline', '')

        if engine == 'pipeline' and pipeline_id:
            return self._execute_pipeline(input_data, pipeline_id)

        return self._execute_llm(input_data)

    def _execute_pipeline(self, input_data: Dict[str, Any], pipeline_id: str) -> Dict[str, Any]:
        """管线模式执行"""
        start = time.time()
        self.log(f"🧠 管线模式 | pipeline={pipeline_id}")
        try:
            from core.task_pipeline import TaskPipeline
            pipe = TaskPipeline(self.llm)
            parallel = self.config.get('parallel', True)
            if parallel:
                result = pipe.run_parallel(pipeline_id, json.dumps(input_data, ensure_ascii=False))
            else:
                result = pipe.run(pipeline_id, json.dumps(input_data, ensure_ascii=False))
            result['agent'] = self.name
            result['agent_key'] = self.agent_key
            return result
        except Exception as e:
            elapsed = time.time() - start
            self.log(f"❌ 管线失败 | {e}", level='error')
            return {
                'success': False, 'agent': self.name, 'agent_key': self.agent_key,
                'engine': 'pipeline', 'error': str(e), 'elapsed_seconds': round(time.time()-start, 2),
                'fallback': True
            }

    def _execute_llm(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 模式执行（原有逻辑）"""
        start = time.time()
        self.log(f"🤖 开始执行 | 输入 keys: {list(input_data.keys())}")

        try:
            # 构建 user prompt
            user_prompt = self._build_user_prompt(input_data)

            # 调用 LLM
            response = self.llm.chat(
                system_prompt=self.system_prompt,
                user_prompt=user_prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )

            elapsed = time.time() - start
            content = response.get('content', '') or ''
            tokens = response.get('tokens', 0)

            # LLM 不可用 → fallback 到规则引擎
            if not content:
                self.log(f"⚠️ LLM 返回空，启用规则 fallback")
                fallback_out = self._rule_based_fallback(input_data)
                self.update_stats(True, 0)
                return {
                    'success': True,
                    'agent': self.name,
                    'agent_key': self.agent_key,
                    'output': fallback_out,
                    'elapsed_seconds': round(elapsed, 2),
                    'tokens': 0,
                    'raw_content': '',
                    'fallback': True,
                    'llm_error': response.get('error', 'unknown')
                }

            # 解析输出
            output = self._parse_output(content)

            self.update_stats(True, tokens)
            self.log(f"✅ 完成 | 耗时 {elapsed:.2f}s | tokens {tokens}")
            return {
                'success': True,
                'agent': self.name,
                'agent_key': self.agent_key,
                'output': output,
                'elapsed_seconds': round(elapsed, 2),
                'tokens': tokens,
                'raw_content': content
            }

        except Exception as e:
            elapsed = time.time() - start
            self.update_stats(False)
            self.log(f"❌ 失败 | 耗时 {elapsed:.2f}s | 错误: {e}", level='error')
            return {
                'success': False,
                'agent': self.name,
                'agent_key': self.agent_key,
                'error': str(e),
                'elapsed_seconds': round(elapsed, 2)
            }

    def _rule_based_fallback(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """规则引擎 fallback（LLM 不可用时）"""
        if 'ioc' in input_data and 'ioc_type' in input_data:
            ioc = input_data.get('ioc', '')
            ioc_type = input_data.get('ioc_type', '')
            return {
                'ioc_type': ioc_type,
                'ioc_value': ioc,
                'reputation': 'unknown',
                'confidence': 0,
                'sources': [],
                'associated_threats': [],
                'mitre_techniques': [],
                'recommended_action': 'investigate',
                'reasoning': '[规则引擎] LLM 不可用，建议人工调查该 IOC。'
            }
        elif 'subject' in input_data or 'sender' in input_data:
            return {
                'verdict': 'uncertain',
                'risk_level': 'medium',
                'confidence': 0,
                'indicators': [],
                'iocs': {'urls': [], 'hashes': [], 'emails': []},
                'recommended_actions': ['manual_review'],
                'reasoning': '[规则引擎] LLM 不可用，建议人工审查邮件。'
            }
        elif 'log_sample' in input_data:
            return {
                'anomaly_detected': False,
                'anomaly_score': 0,
                'patterns': [],
                'potential_attack': '',
                'affected_entities': [],
                'recommended_investigation': '[规则引擎] LLM 不可用，建议 SIEM 人工分析',
                'reasoning': 'fallback'
            }
        elif 'file_hash' in input_data or 'behavior_logs' in input_data:
            return {
                'family': 'unknown',
                'type': 'other',
                'severity': 'medium',
                'capabilities': [],
                'persistence_mechanisms': [],
                'network_indicators': {'c2_servers': [], 'protocols': []},
                'estimated_infection_count': 0,
                'removal_difficulty': 5,
                'recommended_response': ['manual_analysis'],
                'reasoning': '[规则引擎] LLM 不可用，建议上传沙箱分析'
            }
        elif 'cve_list' in input_data:
            return {
                'prioritized_cves': [],
                'summary': '[规则引擎] LLM 不可用，按 CVSS 降序手动排序'
            }
        elif 'report_content' in input_data:
            return {
                'title': '[规则引擎] 未命名情报报告',
                'summary': 'LLM 不可用，原始报告需人工摘要',
                'severity': 'medium',
                'ttps': [],
                'iocs': {'ips': [], 'domains': [], 'hashes': [], 'tools': []},
                'mitigation_actions': ['manual_review'],
                'reasoning': 'fallback'
            }
        return {'reasoning': '[规则引擎] LLM 不可用，输出默认结构', 'fallback': True}

    def _build_user_prompt(self, input_data: Dict[str, Any]) -> str:
        """构造 user prompt"""
        parts = ["## 输入数据\n"]
        for k, v in input_data.items():
            if isinstance(v, (dict, list)):
                parts.append(f"**{k}**: ```json\n{json.dumps(v, ensure_ascii=False, indent=2)}\n```")
            else:
                parts.append(f"**{k}**: {v}")
        parts.append("\n## 要求\n请按系统提示的 JSON schema 输出结果。")
        return '\n'.join(parts)

    def _parse_output(self, content: str) -> Any:
        """解析 LLM 输出为 JSON"""
        content = content.strip()

        # 去除 markdown 包裹
        if content.startswith('```'):
            lines = content.split('\n')
            # 跳过第一行 ```json 或 ```
            start = 1
            end = len(lines)
            for i in range(1, len(lines)):
                if lines[i].strip().startswith('```'):
                    end = i
                    break
            content = '\n'.join(lines[start:end])

        try:
            return json.loads(content)
        except Exception:
            # 尝试找到 JSON 块
            import re
            m = re.search(r'\{[\s\S]*\}', content)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    pass
            # 返回原文
            return {'raw_text': content}


class AgentRegistry:
    """Agent 注册表 - 从数据库加载 Agent"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'data', 'admin.db'
            )
        self.db_path = db_path
        self._cache = {}

    def _conn(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def list_enabled(self, category: str = None) -> list:
        """列出所有启用的 Agent"""
        conn = self._conn()
        if category:
            rows = conn.execute(
                "SELECT * FROM agent_registry WHERE enabled=1 AND category=? ORDER BY usage_count DESC",
                (category,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM agent_registry WHERE enabled=1 ORDER BY usage_count DESC"
            ).fetchall()
        conn.close()
        return [self._row_to_config(r) for r in rows]

    def list_all(self) -> list:
        """列出所有 Agent（含未启用）"""
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM agent_registry ORDER BY is_builtin DESC, name"
        ).fetchall()
        conn.close()
        return [self._row_to_config(r) for r in rows]

    def get(self, agent_key: str) -> Optional[Dict[str, Any]]:
        """获取单个 Agent 配置"""
        if agent_key in self._cache:
            return self._cache[agent_key]
        conn = self._conn()
        row = conn.execute(
            "SELECT * FROM agent_registry WHERE agent_key=?", (agent_key,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        cfg = self._row_to_config(row)
        self._cache[agent_key] = cfg
        return cfg

    def instantiate(self, agent_key: str) -> Optional[DynamicAgent]:
        """实例化一个动态 Agent"""
        cfg = self.get(agent_key)
        if not cfg:
            return None
        if not cfg.get('enabled'):
            return None
        return DynamicAgent(cfg)

    def run(self, agent_key: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """直接执行 Agent"""
        agent = self.instantiate(agent_key)
        if not agent:
            return {'success': False, 'error': f'Agent {agent_key} 未找到或未启用'}
        result = agent.execute(input_data)
        # 增加使用计数
        if result.get('success'):
            self._inc_usage(agent_key)
        return result

    def _inc_usage(self, agent_key: str):
        conn = self._conn()
        conn.execute(
            "UPDATE agent_registry SET usage_count = usage_count + 1 WHERE agent_key=?",
            (agent_key,)
        )
        conn.commit()
        conn.close()

    def _row_to_config(self, row) -> Dict[str, Any]:
        """DB row → config dict"""
        # 兼容 sqlite3.Row 和 tuple
        if hasattr(row, 'keys'):
            d = {k: row[k] for k in row.keys()}
        else:
            d = dict(row)
        # 解析 JSON 字段
        for key in ('input_schema', 'output_schema', 'tools', 'config_json'):
            val = d.get(key)
            if isinstance(val, str):
                try:
                    d[key] = json.loads(val)
                except Exception:
                    pass
        if isinstance(d.get('tools'), str):
            try:
                d['tools'] = json.loads(d['tools'])
            except Exception:
                d['tools'] = []
        return d


# CLI 快速测试
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true', help='列出所有启用的 Agent')
    parser.add_argument('--agent', type=str, help='Agent key')
    parser.add_argument('--input', type=str, help='JSON 输入')
    args = parser.parse_args()

    reg = AgentRegistry()

    if args.list:
        for a in reg.list_enabled():
            print(f"  {a['icon']} {a['agent_key']:<25} {a['name']:<14} [{a['category']}]")
    elif args.agent:
        input_data = json.loads(args.input) if args.input else {'sample': 'test'}
        result = reg.run(args.agent, input_data)
        print(json.dumps(result, ensure_ascii=False, indent=2))
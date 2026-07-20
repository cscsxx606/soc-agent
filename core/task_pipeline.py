#!/usr/bin/env python3
"""轻量任务管线 - 自研多 Agent 协作引擎，无需 CrewAI"""

import os, sys, json, time, re
from typing import Dict, List, Any, Callable
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TaskPipeline:
    """轻量任务管线 - 分解 → 并行执行 → 聚合"""

    def __init__(self, llm_client=None):
        self.llm = llm_client
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._step_results = []

    # ====== 预设管线 ======

    PIPELINE_PHISHING = {
        'name': '钓鱼邮件深度分析',
        'steps': [
            {
                'id': 'header_analysis',
                'name': '邮件头分析',
                'prompt': '分析以下邮件的发件人、域名、SPF/DKIM/DMARC 信息，判断是否有伪装：\\n\\n{input}',
                'output_key': 'header_analysis'
            },
            {
                'id': 'content_analysis',
                'name': '内容分析',
                'prompt': '分析以下邮件正文的话术套路、紧迫感、语法错误、社会工程学特征：\\n\\n{input}',
                'output_key': 'content_analysis'
            },
            {
                'id': 'url_analysis',
                'name': '链接/附件分析',
                'prompt': '列出邮件中所有 URL 和附件，判断每个的可疑程度：\\n\\n{input}',
                'output_key': 'url_analysis'
            },
            {
                'id': 'final_verdict',
                'name': '综合研判',
                'prompt': '综合以下分析结果，输出 JSON 格式的最终判决：\\n头部分析：{header_analysis}\\n内容分析：{content_analysis}\\n链接分析：{url_analysis}\\n\\n返回 JSON：{"verdict":"phishing|spam|legitimate|uncertain", "risk_level":"high|medium|low", "confidence":0-100, "indicators":[], "recommended_actions":[], "reasoning":""}',
                'output_key': 'final_verdict',
                'is_final': True
            }
        ]
    }

    PIPELINE_THREAT_HUNT = {
        'name': '威胁狩猎',
        'steps': [
            {
                'id': 'pattern_analysis',
                'name': '异常模式识别',
                'prompt': '从以下日志中识别异常模式（暴力破解、横向移动、数据外泄等），逐条标注可疑程度：\\n\\n{input}',
                'output_key': 'pattern_analysis'
            },
            {
                'id': 'chain_reconstruction',
                'name': '攻击链重建',
                'prompt': '基于以下异常分析结果，重建攻击链，关联 IOCs，标注 MITRE ATT&CK 技术编号：\\n\\n{pattern_analysis}',
                'output_key': 'chain_analysis',
                'is_final': True
            }
        ]
    }

    PIPELINE_INCIDENT_REPORT = {
        'name': '事件报告生成',
        'steps': [
            {
                'id': 'timeline',
                'name': '时间线整理',
                'prompt': '从以下事件信息中提取时间线，按时间顺序排列：\\n\\n{input}',
                'output_key': 'timeline'
            },
            {
                'id': 'impact_assessment',
                'name': '影响评估',
                'prompt': '评估以下安全事件的影响范围、数据泄露程度、业务影响：\\n\\n{input}',
                'output_key': 'impact'
            },
            {
                'id': 'report_writing',
                'name': '报告撰写',
                'prompt': '基于以下信息撰写出结构化的安全事件报告（中文），包含：事件概要、时间线、影响评估、处置措施、根因分析、改进建议：\\n\\n原始数据：{input}\\n时间线：{timeline}\\n影响：{impact}',
                'output_key': 'report',
                'is_final': True
            }
        ]
    }

    # ====== 管线执行 ======

    def run(self, pipeline_name: str, input_data: Any, context: Dict = None) -> Dict:
        """运行指定管线"""
        pipeline = getattr(self, f'PIPELINE_{pipeline_name.upper()}', None)
        if not pipeline:
            return {'success': False, 'error': f'未知管线: {pipeline_name}'}

        if not self.llm:
            return {'success': False, 'error': 'LLM 客户端未配置', 'fallback': True}

        start = time.time()
        results = {}
        step_details = []

        for step in pipeline['steps']:
            step_start = time.time()
            # 渲染 prompt（替换变量）
            prompt = step['prompt']
            for key, val in {**results, 'input': input_data, **(context or {})}.items():
                val_str = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val)
                prompt = prompt.replace(f'{{{key}}}', val_str)

            try:
                res = self.llm.chat(system_prompt='', user_prompt=prompt)
                step_success = True
                step_output = res.get('content', '') if isinstance(res, dict) else str(res)
            except Exception as e:
                step_success = False
                step_output = str(e)

            results[step['output_key']] = step_output
            step_details.append({
                'step_id': step['id'],
                'step_name': step['name'],
                'duration_seconds': round(time.time() - step_start, 2),
                'success': step_success,
                'is_final': step.get('is_final', False),
                'output_preview': str(step_output)[:200]
            })

        elapsed = time.time() - start
        return {
            'success': True,
            'pipeline': pipeline['name'],
            'pipeline_id': pipeline_name,
            'steps': len(pipeline['steps']),
            'duration_seconds': round(elapsed, 2),
            'step_details': step_details,
            'final_output': results.get('final_verdict') or results.get('chain_analysis') or results.get('report') or results,
            'all_results': results,
            'engine': 'pipeline',
            'fallback': False
        }

    def run_parallel(self, pipeline_name: str, input_data: Any, context: Dict = None) -> Dict:
        """并行执行可并行的步骤"""
        pipeline = getattr(self, f'PIPELINE_{pipeline_name.upper()}', None)
        if not pipeline:
            return {'success': False, 'error': f'未知管线: {pipeline_name}'}

        if not self.llm:
            return {'success': False, 'error': 'LLM 客户端未配置', 'fallback': True}

        start = time.time()
        results = {}
        step_details = []
        executed = set()

        # 第一轮：执行所有无依赖的步骤（并行）
        while len(executed) < len(pipeline['steps']):
            batch = []
            for i, step in enumerate(pipeline['steps']):
                if i in executed:
                    continue
                # 检查依赖是否满足
                deps = re.findall(r'\{(\w+)\}', step['prompt'])
                needed = [d for d in deps if d not in results and d != 'input']
                if not needed:
                    batch.append((i, step))

            if not batch:
                # 依赖未满足（循环引用或缺失），串行兜底
                for i, step in enumerate(pipeline['steps']):
                    if i not in executed:
                        batch.append((i, step))
                break

            # 并行执行批次
            futures = {}
            for idx, step in batch:
                prompt = step['prompt']
                for key, val in {**results, 'input': input_data, **(context or {})}.items():
                    val_str = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val)
                    prompt = prompt.replace(f'{{{key}}}', val_str)
                future = self.executor.submit(self._call_llm, prompt)
                futures[future] = (idx, step)

            for future in as_completed(futures):
                idx, step = futures[future]
                step_start = time.time()
                try:
                    output = future.result()
                    success = True
                except Exception as e:
                    output = str(e)
                    success = False
                results[step['output_key']] = output
                executed.add(idx)
                step_details.append({
                    'step_id': step['id'],
                    'step_name': step['name'],
                    'duration_seconds': round(time.time() - step_start, 2),
                    'success': success,
                    'is_final': step.get('is_final', False),
                    'output_preview': str(output)[:200]
                })

        elapsed = time.time() - start
        return {
            'success': True,
            'pipeline': pipeline['name'],
            'pipeline_id': pipeline_name,
            'steps': len(pipeline['steps']),
            'mode': 'parallel',
            'duration_seconds': round(elapsed, 2),
            'step_details': step_details,
            'final_output': results.get('final_verdict') or results.get('chain_analysis') or results.get('report') or results,
            'all_results': results,
            'engine': 'pipeline',
            'fallback': False
        }

    def _call_llm(self, prompt: str) -> str:
        """调用 LLM - 适配 DeepSeekClient 接口（接受 system + user 两个参数）"""
        try:
            # DeepSeekClient.chat(system_prompt, user_prompt)
            result = self.llm.chat(system_prompt='', user_prompt=prompt)
            return result.get('content', '') if isinstance(result, dict) else str(result)
        except Exception as e:
            return f'LLM 错误: {e}'


if __name__ == '__main__':
    # 测试（需要 LLM 客户端）
    import sys
    sys.path.insert(0, '.')
    from core.llm_client import DeepSeekClient
    llm = DeepSeekClient()
    pipe = TaskPipeline(llm)
    print('Pipeline module OK')
    print(f'Available pipelines: phishing, threat_hunt, incident_report')
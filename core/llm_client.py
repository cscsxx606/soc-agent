#!/usr/bin/env python3
"""
SOC Multi-Agent System - DeepSeek V4 Flash 驱动
核心 LLM 客户端
"""

import os
try:
    from dotenv import load_dotenv
    # 尝试加载项目根目录的 .env
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', '.env')
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except ImportError:
    pass

import os
import json
import time
from typing import Optional, Dict, Any
import requests


class DeepSeekClient:
    """DeepSeek V4 Flash 客户端 - 专为安全分析优化"""

    def __init__(self, model_override: str = None):
        self.api_key = os.getenv('API_KEY')
        self.base_url = os.getenv('BASE_URL', 'https://api.siliconflow.cn/v1')
        self.model = model_override or os.getenv('MODEL', 'deepseek-ai/DeepSeek-V3')
        self.timeout = 60

        # 多 API 备选
        self._backends = [
            {
                'base_url': self.base_url,
                'api_key': self.api_key,
                'model': self.model,
                'name': 'primary'
            },
            {
                'base_url': 'https://api.moonshot.cn/v1',
                'api_key': os.getenv('KIMI_API_KEY', ''),
                'model': 'kimi-k2.7',
                'name': 'kimi-fallback'
            }
        ]

    def chat(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, 
             max_tokens: int = 4000, response_format: Optional[Dict] = None) -> Dict[str, Any]:
        """
        调用大模型进行安全分析
        temperature=0.2 确保安全分析的稳定性
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }

        if response_format:
            payload["response_format"] = response_format

        # 逐个尝试后端
        for backend in self._backends:
            if not backend['api_key']:
                continue

            try:
                headers = {
                    "Authorization": f"Bearer {backend['api_key']}",
                    "Content-Type": "application/json"
                }

                response = requests.post(
                    f"{backend['base_url']}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=(10, self.timeout)
                )

                if response.status_code == 200:
                    result = response.json()
                    content = result['choices'][0]['message']['content']
                    usage = result.get('usage', {})
                    return {
                        'success': True,
                        'content': content,
                        'model': backend['model'],
                        'backend': backend['name'],
                        'prompt_tokens': usage.get('prompt_tokens', 0),
                        'completion_tokens': usage.get('completion_tokens', 0),
                        'total_tokens': usage.get('total_tokens', 0)
                    }

            except Exception as e:
                print(f"[LLM] {backend['name']} 失败: {e}")
                continue

        return {
            'success': False,
            'content': None,
            'error': '所有 API 后端均不可用'
        }

    def analyze_json(self, system_prompt: str, user_prompt: str) -> Optional[Dict]:
        """调用 LLM 并解析 JSON 输出"""
        result = self.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        if not result['success']:
            return None

        try:
            content = result['content'].strip()
            # 清理 markdown 代码块
            if content.startswith('```json'):
                content = content[7:]
            if content.startswith('```'):
                content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
            content = content.strip()
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"[LLM] JSON 解析失败: {e}")
            return None

    def batch_analyze(self, items: list, system_prompt: str, item_formatter, 
                      max_concurrent: int = 3) -> list:
        """批量分析（顺序执行，安全场景不适合并发）"""
        results = []
        for item in items:
            prompt = item_formatter(item)
            result = self.analyze_json(system_prompt, prompt)
            results.append(result or {})
            time.sleep(0.5)  # 控制速率
        return results

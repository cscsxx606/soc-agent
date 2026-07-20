#!/usr/bin/env python3
"""CrewAI 桥接层 - 将 CrewAI 多 Agent 协作引入 SOC 平台"""

import os, sys, json, time
from typing import Dict, List, Any, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CrewAIBridge:
    """CrewAI 引擎桥接 - 可在 Agent 配置中切换"""

    def __init__(self, model_name: str = None, temperature: float = 0.2):
        self.model_name = model_name or os.environ.get('MODEL', 'Qwen/Qwen2.5-7B-Instruct')
        self.temperature = temperature
        self.base_url = os.environ.get('BASE_URL', 'https://api.siliconflow.cn/v1')
        self.api_key = os.environ.get('API_KEY', '')

    def is_available(self) -> bool:
        """检查 CrewAI 和 API Key 是否可用"""
        try:
            import crewai
            return bool(self.api_key)
        except ImportError:
            return False

    def create_llm(self):
        """创建 CrewAI 兼容的 LLM 配置"""
        from crewai import LLM
        return LLM(
            model=self.model_name,
            temperature=self.temperature,
            base_url=self.base_url,
            api_key=self.api_key
        )

    def run_phishing_deep_analysis(self, email_data: Dict) -> Dict:
        """钓鱼邮件深度分析 - 3 Agent 协作"""
        if not self.is_available():
            return {'error': 'CrewAI 不可用', 'fallback': True}
        from crewai import Agent, Task, Crew, Process

        llm = self.create_llm()
        start = time.time()

        analyst = Agent(
            role='SOC 邮件安全分析师',
            goal='分析邮件内容、头部信息，判断是否为钓鱼邮件',
            backstory='你有 10 年邮件安全经验，擅长 SPF/DKIM/DMARC 验证和内容分析',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        investigator = Agent(
            role='威胁情报调查员',
            goal='对提取的 URL/Hash/IP 进行威胁情报查询',
            backstory='你熟悉 VirusTotal、AbuseIPDB 等情报源，能快速判断 IOC 信誉',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        coordinator = Agent(
            role='安全分析协调员',
            goal='综合分析师和调查员的结果，输出最终研判结论',
            backstory='你是团队负责人，擅长汇总多方信息形成最终判断',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        analyze_task = Task(
            description=f"""分析以下邮件内容，提取：
1. 发件人地址和域名
2. 邮件主题和正文中的紧迫感话术
3. 所有 URL 和附件信息
4. SPF/DKIM/DMARC 签名情况（如有）
5. 初始研判结论

邮件数据：{json.dumps(email_data, ensure_ascii=False)}""",
            expected_output='JSON 格式的分析结果，包含 sender_analysis、urls、verdict、confidence',
            agent=analyst
        )

        investigate_task = Task(
            description='根据分析师提取的 IOC（URL/域名/Hash），查询情报并判断信誉',
            expected_output='JSON 格式的情报查询结果，包含每个 IOC 的信誉评分',
            agent=investigator
        )

        conclusion_task = Task(
            description='综合以上结果，输出最终研判报告，包含：verdict、risk_level、confidence、recommended_actions、reasoning',
            expected_output='JSON 格式的最终报告',
            agent=coordinator
        )

        crew = Crew(
            agents=[analyst, investigator, coordinator],
            tasks=[analyze_task, investigate_task, conclusion_task],
            process=Process.sequential,
            verbose=False
        )

        result = crew.kickoff()
        elapsed = time.time() - start
        return {
            'engine': 'crewai',
            'model': self.model_name,
            'duration_seconds': round(elapsed, 2),
            'agents': 3,
            'tasks': 3,
            'process': 'sequential',
            'result': str(result),
            'fallback': False
        }

    def run_threat_hunt(self, logs: List[Dict]) -> Dict:
        """威胁狩猎 - 2 Agent 协作"""
        if not self.is_available():
            return {'error': 'CrewAI 不可用', 'fallback': True}
        from crewai import Agent, Task, Crew, Process

        llm = self.create_llm()
        start = time.time()

        hunter = Agent(
            role='威胁狩猎专家',
            goal='从日志中识别异常行为模式',
            backstory='你是 ATT&CK 框架专家，擅长从噪声中发现 APT 活动',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        analyst = Agent(
            role='安全分析师',
            goal='对狩猎发现进行优先级排序和攻击链重建',
            backstory='你有丰富的应急响应经验，能快速判断威胁严重程度',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        hunt_task = Task(
            description=f"""分析以下日志样本，识别：
1. 异常登录行为
2. 横向移动迹象
3. 数据外泄行为
4. 权限提升尝试
5. 持久化安装

日志：{json.dumps(logs, ensure_ascii=False)[:2000]}""",
            expected_output='JSON 格式的发现列表，包含 anomaly_score、patterns、affected_entities',
            agent=hunter
        )

        summary_task = Task(
            description='汇总狩猎发现，输出 JSON 报告：attack_chain、severity、affected_assets、recommended_actions、confidence_score',
            expected_output='JSON 格式的总结报告',
            agent=analyst
        )

        crew = Crew(
            agents=[hunter, analyst],
            tasks=[hunt_task, summary_task],
            process=Process.sequential,
            verbose=False
        )

        result = crew.kickoff()
        elapsed = time.time() - start
        return {
            'engine': 'crewai',
            'model': self.model_name,
            'duration_seconds': round(elapsed, 2),
            'agents': 2,
            'tasks': 2,
            'result': str(result),
            'fallback': False
        }

    def run_incident_report(self, incident_data: Dict) -> Dict:
        """事件报告生成 - 2 Agent 协作"""
        if not self.is_available():
            return {'error': 'CrewAI 不可用', 'fallback': True}
        from crewai import Agent, Task, Crew, Process

        llm = self.create_llm()
        start = time.time()

        writer = Agent(
            role='安全事件报告撰写员',
            goal='将原始告警和处置记录整理成结构化报告',
            backstory='你是专业的安全事件记录员，擅长按照行业标准格式编写报告',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        reviewer = Agent(
            role='报告审核员',
            goal='检查报告完整性、准确性和可操作性',
            backstory='你是 SOC 主管，确保每份报告达到交付标准',
            llm=llm,
            allow_delegation=False,
            verbose=False
        )

        write_task = Task(
            description=f"""基于以下事件信息撰写安全事件报告：
{json.dumps(incident_data, ensure_ascii=False)[:2000]}

报告需包含：事件概要、时间线、影响范围、处置措施、根因分析、改进建议""",
            expected_output='结构化文本报告',
            agent=writer
        )

        review_task = Task(
            description='审核报告质量，补充遗漏的关键信息，确保报告专业完整',
            expected_output='最终版结构化报告',
            agent=reviewer
        )

        crew = Crew(
            agents=[writer, reviewer],
            tasks=[write_task, review_task],
            process=Process.sequential,
            verbose=False
        )

        result = crew.kickoff()
        elapsed = time.time() - start
        return {
            'engine': 'crewai',
            'model': self.model_name,
            'duration_seconds': round(elapsed, 2),
            'agents': 2,
            'tasks': 2,
            'result': str(result),
            'fallback': False
        }


# 测试
if __name__ == '__main__':
    bridge = CrewAIBridge()
    print('Available:', bridge.is_available())
    if bridge.is_available():
        test_email = {
            'subject': '紧急：您的账户存在异常登录',
            'sender': 'security@bank-secure.xyz',
            'body': '尊敬的客户，您的银行账户在 2026-07-16 03:30 有异常登录，请立即点击以下链接验证：http://fake-bank-login.xyz/verify'
        }
        result = bridge.run_phishing_deep_analysis(test_email)
        print('Result:', json.dumps(result, ensure_ascii=False)[:300])
    else:
        print('Skipping real test (no API key configured or CrewAI not installed)')
#!/usr/bin/env python3
"""
SOC Multi-Agent Orchestrator - CrewAI 版
用 CrewAI 的多 Agent 协作引擎替代自研流水线
"""
import json, os, sys
from typing import Dict, Any, List
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.triage_agent import AlertTriageAgent
from agents.hunting_agent import ThreatHuntingAgent
from agents.response_agent import ResponseAgent
from agents.vuln_agent import VulnAssessmentAgent

console = Console()


class SOCOrchestrator:
    """SOC 多 Agent 编排器 - CrewAI 驱动"""

    def __init__(self, crewai_enabled: bool = None):
        """
        如果 crewai_enabled=None，自动从数据库读取
        如果 crewai_enabled=True/False，强制指定
        """
        self.triage = AlertTriageAgent()
        self.hunting = ThreatHuntingAgent()
        self.response = ResponseAgent()
        self.vuln = VulnAssessmentAgent()

        if crewai_enabled is not None:
            self.crewai_enabled = crewai_enabled and self._crewai_available()
        else:
            # 从数据库读取引擎配置
            self.crewai_enabled = self._read_engine_config() and self._crewai_available()
        self.execution_log = []

        if self.crewai_enabled:
            from crewai import LLM
            # CrewAI 1.15.x 需要 OPENAI_API_KEY 环境变量
            os.environ['OPENAI_API_KEY'] = os.getenv('API_KEY', '')
            os.environ['OPENAI_BASE_URL'] = os.getenv('BASE_URL', 'https://api.siliconflow.cn/v1')
            self.crewai_llm = LLM(
                model='gpt-4o',
                temperature=0.2
            )
            console.print("[green]✓ CrewAI 引擎已就绪[/green]")
        else:
            console.print("[yellow]⚠ CrewAI 不可用，使用自研引擎[/yellow]")

    def _crewai_available(self) -> bool:
        try:
            import crewai
            return bool(os.getenv('API_KEY'))
        except ImportError:
            return False

    def _read_engine_config(self) -> bool:
        """从数据库读取引擎配置"""
        try:
            db_path = os.path.join(os.path.dirname(__file__), 'data', 'admin.db')
            if not os.path.exists(db_path):
                return True  # 默认 CrewAI
            import sqlite3
            conn = sqlite3.connect(db_path)
            row = conn.execute(
                "SELECT value FROM settings WHERE key='engine.orchestrator'"
            ).fetchone()
            conn.close()
            if row:
                val = row[0]
                if val == 'crewai':
                    return True
                elif val == 'legacy':
                    return False
                elif val == 'auto':
                    return self._crewai_available()
            return True
        except Exception:
            return True

    def _crewai_agent(self, role: str, goal: str, backstory: str,
                      allow_delegation: bool = False,
                      verbose: bool = False):
        """创建 CrewAI Agent"""
        from crewai import Agent as CrewAgent
        return CrewAgent(
            role=role, goal=goal, backstory=backstory,
            llm=self.crewai_llm, allow_delegation=allow_delegation,
            verbose=verbose
        )

    def _crewai_task(self, description: str, expected_output: str, agent):
        """创建 CrewAI Task"""
        from crewai import Task
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent
        )

    def run_full_pipeline(self, alerts: List[Dict]) -> Dict:
        """
        运行完整 SOC 流水线（CrewAI 多 Agent 协作）
        Phase 1: 告警分流 → Phase 2: 威胁狩猎 → Phase 3: 应急响应 → Phase 4: 漏洞评估
        """
        console.print(Panel("[bold blue]SOC Multi-Agent System 启动 (CrewAI 引擎)[/bold blue]\n"
                           "[dim]Multi-Agent 协作模式[/dim]",
                           box=box.DOUBLE))

        start_time = datetime.now()

        # ===== Phase 1: 告警分流（自研 Agent + CrewAI 分析） =====
        console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]  Phase 1: 告警智能分流[/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")

        triaged = self.triage.execute(alerts)
        self._print_triage_summary(triaged)

        # ===== Phase 2: 威胁狩猎（CrewAI 多 Agent 协作） =====
        console.print("\n[bold yellow]═══════════════════════════════════════[/bold yellow]")
        console.print("[bold yellow]  Phase 2: 主动威胁狩猎 (CrewAI)[/bold yellow]")
        console.print("[bold yellow]═══════════════════════════════════════[/bold yellow]")

        high_risk = [a for a in triaged
                     if a.get('ai_analysis', {}).get('priority') in ['P1', 'P2']]
        hunt_results = []

        for alert in high_risk[:3]:
            if self.crewai_enabled:
                result = self._run_crewai_hunt(alert)
            else:
                result = self.hunting.execute(alert)
            hunt_results.append(result)
            console.print(f"  {'✓' if result.get('hunt_status') == 'completed' else '○'} "
                         f"{alert['id']} → 狩猎完成")

        # ===== Phase 3: 应急响应（CrewAI 多 Agent 协作） =====
        console.print("\n[bold red]═══════════════════════════════════════[/bold red]")
        console.print("[bold red]  Phase 3: 应急响应处置 (CrewAI)[/bold red]")
        console.print("[bold red]═══════════════════════════════════════[/bold red]")

        response_results = []
        for alert in high_risk:
            if self.crewai_enabled:
                result = self._run_crewai_response(alert, hunt_results)
            else:
                hunt = next((h for h in hunt_results if h['alert_id'] == alert['id']), None)
                result = self.response.execute(alert, hunt)
            response_results.append(result)

            priority = alert.get('ai_analysis', {}).get('priority', 'P4')
            color = 'red' if priority == 'P1' else 'yellow'
            incident_id = result.get('response_plan', {}).get('incident_id',
                           result.get('incident_id', 'N/A'))
            console.print(f"  [{color}]{'✓' if priority in ['P1', 'P2'] else '○'}[/{color}] "
                         f"{alert['id']} ({priority}) → {incident_id}")

        # ===== Phase 4: 漏洞评估（CrewAI 多 Agent 协作） =====
        console.print("\n[bold green]═══════════════════════════════════════[/bold green]")
        console.print("[bold green]  Phase 4: 漏洞智能评估 (CrewAI)[/bold green]")
        console.print("[bold green]═══════════════════════════════════════[/bold green]")

        sample_vulns = self.vuln.generate_sample_vulns()
        if self.crewai_enabled:
            vuln_report = self._run_crewai_vuln(sample_vulns)
        else:
            vuln_report = self.vuln.execute(sample_vulns)
        self._print_vuln_summary(vuln_report)

        # 汇总
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        final_report = {
            'execution_time': start_time.isoformat(),
            'duration_seconds': duration,
            'engine': 'crewai' if self.crewai_enabled else 'self_ruled',
            'phases': {
                'triage': {
                    'total_alerts': len(triaged),
                    'p1': len([a for a in triaged if a.get('ai_analysis', {}).get('priority') == 'P1']),
                    'p2': len([a for a in triaged if a.get('ai_analysis', {}).get('priority') == 'P2']),
                    'p3': len([a for a in triaged if a.get('ai_analysis', {}).get('priority') == 'P3']),
                    'p4': len([a for a in triaged if a.get('ai_analysis', {}).get('priority') == 'P4']),
                },
                'hunting': {
                    'hunts_executed': len(hunt_results),
                    'findings': sum(len(h.get('hunt_result', {}).get('findings', [])) for h in hunt_results)
                },
                'response': {
                    'incidents_created': len(response_results),
                    'auto_actions': sum(len(r.get('executed_actions', [])) for r in response_results)
                },
                'vuln': {
                    'total_vulns': vuln_report.get('vuln_summary', {}).get('total', 0),
                    'critical': vuln_report.get('vuln_summary', {}).get('critical', 0),
                    'high': vuln_report.get('vuln_summary', {}).get('high', 0)
                }
            },
            'agent_stats': {
                'triage': self.triage.get_stats(),
                'hunting': self.hunting.get_stats(),
                'response': self.response.get_stats(),
                'vuln': self.vuln.get_stats()
            }
        }

        self._print_final_summary(final_report)

        # 保存报告
        report_path = f"data/soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs('data', exist_ok=True)
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump({
                'summary': final_report,
                'triaged_alerts': triaged,
                'hunt_results': hunt_results,
                'response_results': response_results,
                'vuln_report': vuln_report
            }, f, ensure_ascii=False, indent=2)

        console.print(f"\n[dim]完整报告已保存: {report_path}[/dim]")
        return final_report

    # ==================== CrewAI 多 Agent 协作方法 ====================

    def _run_crewai_hunt(self, alert: Dict) -> Dict:
        """CrewAI 多 Agent 威胁狩猎 - 分析师 + 调查员 + 协调员"""
        from crewai import Crew, Process

        analysis = alert.get('ai_analysis', {})
        alert_desc = json.dumps({
            'id': alert.get('id'),
            'type': alert.get('alert_type'),
            'source_ip': alert.get('source_ip'),
            'attack': analysis.get('attack_type'),
            'score': analysis.get('risk_score'),
            'description': alert.get('description', '')
        }, ensure_ascii=False)

        hunter = self._crewai_agent(
            role='威胁狩猎专家',
            goal='从告警中还原攻击链，发现 IOC 和关联事件',
            backstory='你是 ATT&CK 框架专家，精通攻击链分析和威胁情报关联。'
                      '能从一条孤立告警中发现完整的攻击路径。'
        )

        investigator = self._crewai_agent(
            role='威胁情报调查员',
            goal='对 IOC 进行深度分析和情报关联',
            backstory='你熟悉多个威胁情报源，能判断 IOC 的信誉度、'
                      '所属恶意家族、活跃时间窗口等信息。'
        )

        coordinator = self._crewai_agent(
            role='安全事件协调员',
            goal='汇总狩猎结果，输出最终威胁评估报告',
            backstory='你是 SOC 团队负责人，擅长综合多方信息形成准确判断。'
        )

        hunt_task = self._crewai_task(
            description=f"""分析以下安全告警，完成威胁狩猎：

告警信息：{alert_desc}

狩猎要求：
1. 识别攻击者在 kill chain 中的当前阶段
2. 提取 IOC（IP/域名/Hash）
3. 还原可能的完整攻击路径
4. 评估是否有关联告警或相关主机
5. 给出置信度评分 (0-100)

输出 JSON 格式：findings（每个发现含 type/description/confidence）、
iocs（每个含 value/type/verdict）、attack_chain、hunt_summary""",
            expected_output='JSON 格式的完整狩猎报告',
            agent=hunter
        )

        investigate_task = self._crewai_task(
            description='对狩猎发现的 IOC 进行深度分析，判断每个 IOC 的信誉和可能关联的威胁',
            expected_output='JSON 格式的 IOC 分析报告',
            agent=investigator
        )

        summary_task = self._crewai_task(
            description='综合以上分析，输出最终威胁评估，包含攻击类型、危害等级、影响范围、处置优先级、关联事件',
            expected_output='JSON 格式的最终汇总',
            agent=coordinator
        )

        crew = Crew(
            agents=[hunter, investigator, coordinator],
            tasks=[hunt_task, investigate_task, summary_task],
            process=Process.sequential,
            verbose=False
        )

        try:
            result = crew.kickoff()
            return {
                'alert_id': alert.get('id'),
                'hunt_status': 'completed',
                'engine': 'crewai',
                'hunt_result': {'result': str(result), 'findings': []}
            }
        except Exception as e:
            console.print(f"[red]  CrewAI 狩猎失败: {e}，降级到自研[/red]")
            return self.hunting.execute(alert)

    def _run_crewai_response(self, alert: Dict, hunt_results: List[Dict]) -> Dict:
        """CrewAI 多 Agent 应急响应 - 遏制 + 根除 + 恢复 + 协调"""
        from crewai import Crew, Process

        analysis = alert.get('ai_analysis', {})
        alert_data = json.dumps({
            'id': alert.get('id'),
            'type': alert.get('alert_type'),
            'source_ip': alert.get('source_ip'),
            'hostname': alert.get('asset_info', {}).get('hostname', ''),
            'attack': analysis.get('attack_type'),
            'score': analysis.get('risk_score'),
            'mitre': f"{analysis.get('mitre_technique_id')} - {analysis.get('mitre_technique_name')}"
        }, ensure_ascii=False)

        containment_agent = self._crewai_agent(
            role='遏制专家',
            goal='制定快速有效的遏制措施，阻止威胁扩散',
            backstory='你有丰富的应急响应经验，精通网络隔离、访问控制、'
                      '主机阻断等遏制技术。'
        )

        eradication_agent = self._crewai_agent(
            role='根除专家',
            goal='制定彻底清除威胁的方案，确保威胁不会复发',
            backstory='你是恶意代码分析专家，擅长从系统深处清理威胁。'
        )

        recovery_agent = self._crewai_agent(
            role='恢复专家',
            goal='制定业务恢复计划，最小化影响',
            backstory='你擅长在安全与业务连续性之间找到平衡。'
        )

        coordinator = self._crewai_agent(
            role='应急响应指挥',
            goal='统筹整体响应方案，确保每一步都有回滚计划和验证方法',
            backstory='你是 SOC 应急响应团队的指挥官。'
        )

        tasks = [
            self._crewai_task(
                description=f'基于以下安全事件制定遏制方案：\n{alert_data}\n\n输出立即执行的遏制动作和短期遏制策略',
                expected_output='JSON 格式的遏制方案',
                agent=containment_agent
            ),
            self._crewai_task(
                description='制定根除方案，包括清除步骤和验证方法',
                expected_output='JSON 格式的根除方案',
                agent=eradication_agent
            ),
            self._crewai_task(
                description='制定恢复方案，包括优先级、恢复步骤和验证测试',
                expected_output='JSON 格式的恢复方案',
                agent=recovery_agent
            ),
            self._crewai_task(
                description=f'综合以上方案，输出完整的应急响应计划。\n告警: {alert_data}\n\n'
                           '包含：事件编号、严重级别、遏制/根除/恢复方案、'
                           '处置动作列表（每个动作含 action_id、类型、目标、自动化级别、回滚计划）、'
                           '沟通计划、证据保全措施',
                expected_output='JSON 格式的完整响应计划',
                agent=coordinator
            )
        ]

        crew = Crew(
            agents=[containment_agent, eradication_agent, recovery_agent, coordinator],
            tasks=tasks,
            process=Process.sequential,
            verbose=False
        )

        try:
            result = crew.kickoff()
            return {
                'alert_id': alert.get('id'),
                'incident_id': f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'response_time': datetime.now().isoformat(),
                'priority': analysis.get('priority', 'P4'),
                'engine': 'crewai',
                'response_plan': {
                    'result': str(result),
                    'playbook_actions': []
                },
                'executed_actions': [],
                'pending_approvals': []
            }
        except Exception as e:
            console.print(f"[red]  CrewAI 响应失败: {e}，降级到自研[/red]")
            hunt = next((h for h in hunt_results if h['alert_id'] == alert['id']), None)
            return self.response.execute(alert, hunt)

    def _run_crewai_vuln(self, vulns: List[Dict]) -> Dict:
        """CrewAI 多 Agent 漏洞评估 - 分析 + 利用性 + 修复专家"""
        from crewai import Crew, Process

        vuln_data = json.dumps(vulns, ensure_ascii=False)

        analyst = self._crewai_agent(
            role='漏洞分析专家',
            goal='对漏洞进行技术分析和 CVSS 评分调整',
            backstory='你是 OSCP 认证专家，精通 CVSS v3.1 评分系统和漏洞利用技术评估。'
        )

        exploitability_agent = self._crewai_agent(
            role='可利用性评估师',
            goal='评估漏洞的实际可利用性和暴露风险',
            backstory='你擅长判断漏洞是否有公开 EXP、是否被在野利用、是否需要紧急修复。'
        )

        fix_agent = self._crewai_agent(
            role='修复规划师',
            goal='制定具体的修复方案和优先级排序',
            backstory='你是资深运维安全工程师，精通各类系统的补丁管理和缓解措施。'
        )

        coordinator = self._crewai_agent(
            role='漏洞管理协调员',
            goal='汇总评估结果，输出完整的漏洞修复计划',
            backstory='你是安全主管，负责决策哪些漏洞优先修复。'
        )

        tasks = [
            self._crewai_task(
                description=f'分析以下漏洞数据，对每个漏洞进行技术评估：\n{vuln_data}\n\n'
                           '评估维度：攻击向量、攻击复杂度、所需权限、用户交互、影响范围',
                expected_output='JSON 格式的技术评估',
                agent=analyst
            ),
            self._crewai_task(
                description='评估每个漏洞的实际可利用性和暴露风险，包括：是否有公开 EXP、是否在野利用、资产暴露面影响',
                expected_output='JSON 格式的可利用性评估',
                agent=exploitability_agent
            ),
            self._crewai_task(
                description='为每个漏洞制定具体的修复方案，含临时缓解和长期修复',
                expected_output='JSON 格式的修复方案',
                agent=fix_agent
            ),
            self._crewai_task(
                description='综合以上分析，输出最终漏洞修复计划。包括漏洞分布统计、'
                           'Top 风险漏洞（含调整评分、修复优先级）、'
                           '修复时间表（24h/7天/30天）、补偿控制措施',
                expected_output='JSON 格式的完整漏洞评估报告',
                agent=coordinator
            )
        ]

        crew = Crew(
            agents=[analyst, exploitability_agent, fix_agent, coordinator],
            tasks=tasks,
            process=Process.sequential,
            verbose=False
        )

        try:
            result = crew.kickoff()
            return {
                'assessment_id': f"VA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'assessment_time': datetime.now().isoformat(),
                'engine': 'crewai',
                'vuln_summary': {'total': len(vulns), 'critical': 0, 'high': 0,
                                 'medium': 0, 'low': 0, 'info': 0},
                'top_risks': [],
                'remediation_plan': {},
                'crewai_result': str(result)
            }
        except Exception as e:
            console.print(f"[red]  CrewAI 漏洞评估失败: {e}，降级到自研[/red]")
            return self.vuln.execute(vulns)

    # ==================== 打印方法 ====================

    def _print_triage_summary(self, triaged: List[Dict]):
        table = Table(box=box.ROUNDED, show_header=True)
        table.add_column("告警ID", style="cyan")
        table.add_column("攻击类型", style="magenta")
        table.add_column("资产", style="blue")
        table.add_column("评分", justify="center")
        table.add_column("优先级", justify="center")
        table.add_column("处置", style="green")
        for a in triaged:
            analysis = a.get('ai_analysis', {})
            score = analysis.get('risk_score', 0)
            priority = analysis.get('priority', 'P4')
            color = 'red' if priority == 'P1' else 'yellow' if priority == 'P2' else 'green'
            table.add_row(
                a['id'], analysis.get('attack_type', 'N/A')[:25],
                a.get('asset_info', {}).get('hostname', 'N/A'),
                str(score), f"[{color}]{priority}[/{color}]",
                analysis.get('recommended_action', 'N/A')[:10])
        console.print(table)

    def _print_vuln_summary(self, report: Dict):
        summary = report.get('vuln_summary', {})
        console.print(f"  漏洞总数: {summary.get('total', 0)} | "
                     f"[red]Critical: {summary.get('critical', 0)}[/red] | "
                     f"[yellow]High: {summary.get('high', 0)}[/yellow] | "
                     f"Medium: {summary.get('medium', 0)} | Low: {summary.get('low', 0)}")

    def _print_final_summary(self, report: Dict):
        console.print("\n[bold blue]═══════════════════════════════════════[/bold blue]")
        engine = "CrewAI Multi-Agent" if self.crewai_enabled else "自研引擎"
        console.print(f"[bold blue]  SOC 多 Agent 系统执行完成 ({engine})[/bold blue]")
        console.print("[bold blue]═══════════════════════════════════════[/bold blue]")

        stats = Table.grid(padding=1)
        p = report['phases']
        stats.add_row(
            Panel(f"[bold]{p['triage']['total_alerts']}[/bold]\n[dim]告警处理[/dim]", border_style="cyan"),
            Panel(f"[bold red]{p['triage']['p1']}[/bold red] P1 / [bold yellow]{p['triage']['p2']}[/bold yellow] P2",
                  title="高危告警", border_style="red"),
            Panel(f"[bold]{p['hunting']['hunts_executed']}[/bold]\n[dim]威胁狩猎[/dim]", border_style="yellow"),
            Panel(f"[bold]{p['response']['incidents_created']}[/bold]\n[dim]事件响应[/dim]", border_style="red"),
            Panel(f"[bold red]{p['vuln']['critical']}[/bold red] Critical / [bold yellow]{p['vuln']['high']}[/bold yellow] High",
                  title="漏洞评估", border_style="green"))
        console.print(stats)
        console.print(f"\n[dim]执行耗时: {report['duration_seconds']:.1f} 秒 | 引擎: {engine}[/dim]")

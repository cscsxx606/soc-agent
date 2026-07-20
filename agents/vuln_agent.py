#!/usr/bin/env python3
"""
Phase 4: 漏洞评估 Agent (Vulnerability Assessment Agent)
功能：漏洞扫描结果分析、风险评估、修复建议
"""

from typing import Dict, Any, List
from datetime import datetime
from core.agent_base import BaseAgent


class VulnAssessmentAgent(BaseAgent):
    """漏洞评估 Agent"""

    def __init__(self):
        super().__init__(
            name="VulnAgent",
            description="漏洞智能评估与修复建议"
        )
        self.vuln_prompt = """你是一名漏洞管理专家（OSCP/GWAPT 认证），擅长漏洞评估和修复优先级排序。

任务：分析漏洞扫描结果，输出结构化的评估报告：
1. CVSS 评分复核（考虑实际环境因素）
2. 可利用性评估（是否有公开 EXP）
3. 修复优先级排序（综合风险 + 业务影响）
4. 修复建议（含具体命令/补丁）
5. 缓解措施（临时防护方案）

评分调整因素：
- 资产暴露面（公网/内网）
- 资产重要性
- 漏洞成熟度（是否有武器化 EXP）
- 现有补偿控制措施

输出 JSON 格式：
{
  "assessment_id": "VA-XXXX",
  "vuln_summary": {
    "total": 100,
    "critical": 5,
    "high": 20,
    "medium": 40,
    "low": 35
  },
  "top_risks": [
    {
      "vuln_id": "CVE-XXXX-XXXX",
      "title": "漏洞标题",
      "cvss_base": 9.8,
      "adjusted_score": 9.5,
      "epss_score": 0.95,
      "exploit_available": true,
      "asset_criticality": "critical",
      "exposure": "internet_facing",
      "priority": "P1",
      "fix_complexity": "简单/中等/复杂",
      "fix_estimate": "预计修复时间",
      "remediation": "具体修复步骤",
      "mitigation": "临时缓解措施",
      "verification": "验证方法"
    }
  ],
  "remediation_plan": {
    "immediate": ["需立即修复的漏洞"],
    "short_term": ["30天内修复"],
    "long_term": ["90天内修复"]
  },
  "compensating_controls": ["现有补偿控制措施"],
  "risk_acceptance": ["建议接受的风险及理由"]
}"""

    def execute(self, vuln_scan_results: List[Dict]) -> Dict:
        """
        执行漏洞评估
        输入: 漏洞扫描结果列表
        输出: 评估报告
        """
        self.log(f"开始评估 {len(vuln_scan_results)} 个漏洞")

        # 预处理：统计
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vuln_scan_results:
            sev = vuln.get('severity', 'medium').lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        self.log(f"漏洞分布: Critical={severity_counts['critical']}, High={severity_counts['high']}, "
                  f"Medium={severity_counts['medium']}, Low={severity_counts['low']}")

        # 对每个 Critical/High 漏洞进行 AI 深度分析
        top_vulns = [v for v in vuln_scan_results 
                     if v.get('severity', '').lower() in ['critical', 'high']]

        analyzed_vulns = []
        for vuln in top_vulns[:10]:  # 只分析前10个高危漏洞（控制 token 消耗）
            self.log(f"  分析漏洞: {vuln.get('cve_id', 'N/A')}")
            analysis = self._analyze_single_vuln(vuln)
            analyzed_vulns.append(analysis)

        # 生成修复计划
        remediation_plan = self._generate_remediation_plan(analyzed_vulns)

        return {
            'assessment_id': f"VA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'assessment_time': datetime.now().isoformat(),
            'vuln_summary': {
                'total': len(vuln_scan_results),
                **severity_counts
            },
            'top_risks': analyzed_vulns,
            'remediation_plan': remediation_plan,
            'vuln_agent': self.name
        }

    def _analyze_single_vuln(self, vuln: Dict) -> Dict:
        """分析单个漏洞"""
        user_prompt = f"""请分析以下漏洞：

漏洞 ID: {vuln.get('cve_id', 'N/A')}
标题: {vuln.get('title', 'N/A')}
CVSS 基础评分: {vuln.get('cvss_score', 'N/A')}
严重程度: {vuln.get('severity', 'N/A')}
资产: {vuln.get('asset', 'N/A')} ({vuln.get('asset_type', 'unknown')})
暴露面: {vuln.get('exposure', 'unknown')}
描述: {vuln.get('description', 'N/A')[:500]}

请评估实际风险并给出修复建议。"""

        result = self.safe_llm_call(self.vuln_prompt, user_prompt)

        if result:
            self.update_stats(success=True)
            # 合并原始漏洞信息
            return {**vuln, **result}
        else:
            self.update_stats(success=False)
            return self._template_vuln_analysis(vuln)

    def _template_vuln_analysis(self, vuln: Dict) -> Dict:
        """漏洞分析模板"""
        cvss = vuln.get('cvss_score', 5.0)
        severity = vuln.get('severity', 'medium').lower()
        exposure = vuln.get('exposure', 'internal')
        asset_type = vuln.get('asset_type', 'server')

        # 根据暴露面调整
        exposure_boost = {'internet_facing': 1.2, 'dmz': 1.1, 'internal': 1.0}.get(exposure, 1.0)
        adjusted_score = min(10.0, round(cvss * exposure_boost, 1))

        # 优先级
        if adjusted_score >= 9.0 or (severity == 'critical' and exposure == 'internet_facing'):
            priority = 'P1'
        elif adjusted_score >= 7.0:
            priority = 'P2'
        elif adjusted_score >= 4.0:
            priority = 'P3'
        else:
            priority = 'P4'

        return {
            **vuln,
            'adjusted_score': adjusted_score,
            'epss_score': 'unknown',
            'exploit_available': cvss > 8.0,
            'priority': priority,
            'fix_complexity': '中等',
            'fix_estimate': '2-4小时',
            'remediation': f'1. 确认漏洞影响版本\n2. 应用厂商补丁\n3. 如无法补丁，参考缓解措施\n4. 验证修复',
            'mitigation': f'1. 限制 {asset_type} 的网络访问\n2. 启用 WAF 规则\n3. 监控相关利用行为',
            'verification': '1. 重新扫描确认漏洞已修复\n2. 检查补丁是否成功应用'
        }

    def _generate_remediation_plan(self, analyzed_vulns: List[Dict]) -> Dict:
        """生成修复计划"""
        immediate = [v for v in analyzed_vulns if v.get('priority') == 'P1']
        short_term = [v for v in analyzed_vulns if v.get('priority') == 'P2']
        long_term = [v for v in analyzed_vulns if v.get('priority') in ['P3', 'P4']]

        return {
            'immediate': [f"{v.get('cve_id')}: {v.get('title', 'N/A')} (评分: {v.get('adjusted_score', 'N/A')})" 
                         for v in immediate],
            'short_term': [f"{v.get('cve_id')}: {v.get('title', 'N/A')}" for v in short_term],
            'long_term': [f"{v.get('cve_id')}: {v.get('title', 'N/A')}" for v in long_term],
            'estimated_effort': f"{len(immediate) * 4 + len(short_term) * 2} 小时",
            'recommended_window': 'P1漏洞: 24小时内 | P2漏洞: 7天内 | P3/P4: 30天内'
        }

    def generate_sample_vulns(self) -> List[Dict]:
        """生成示例漏洞数据（用于演示）"""
        return [
            {
                'cve_id': 'CVE-2024-21762',
                'title': 'Fortinet FortiOS SSL VPN 缓冲区溢出',
                'cvss_score': 9.8,
                'severity': 'critical',
                'asset': 'vpn-gateway-01',
                'asset_type': 'network_device',
                'exposure': 'internet_facing',
                'description': 'FortiOS SSL VPN 组件中存在缓冲区溢出漏洞，未经身份验证的攻击者可利用此漏洞远程执行代码。'
            },
            {
                'cve_id': 'CVE-2024-3400',
                'title': 'Palo Alto PAN-OS 命令注入',
                'cvss_score': 10.0,
                'severity': 'critical',
                'asset': 'firewall-01',
                'asset_type': 'network_device',
                'exposure': 'internet_facing',
                'description': 'PAN-OS 全局保护功能中存在命令注入漏洞，攻击者可在防火墙上以 root 权限执行任意命令。'
            },
            {
                'cve_id': 'CVE-2024-21626',
                'title': 'runc 文件描述符泄露',
                'cvss_score': 8.6,
                'severity': 'high',
                'asset': 'k8s-worker-03',
                'asset_type': 'container',
                'exposure': 'internal',
                'description': 'runc 容器运行时中存在文件描述符泄露漏洞，攻击者可逃逸容器获取主机访问权限。'
            },
            {
                'cve_id': 'CVE-2024-22243',
                'title': 'Spring Framework URL 解析绕过',
                'cvss_score': 7.5,
                'severity': 'high',
                'asset': 'app-server-02',
                'asset_type': 'application',
                'exposure': 'dmz',
                'description': 'Spring Framework 中存在 URL 解析差异，可能导致安全控制绕过。'
            },
            {
                'cve_id': 'CVE-2024-23334',
                'title': 'Node.js 路径遍历',
                'cvss_score': 5.3,
                'severity': 'medium',
                'asset': 'web-server-03',
                'asset_type': 'web_server',
                'exposure': 'internal',
                'description': 'Node.js 某些版本中存在路径遍历漏洞，可读取服务器上的任意文件。'
            }
        ]

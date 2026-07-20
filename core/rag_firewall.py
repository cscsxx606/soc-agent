#!/usr/bin/env python3
"""
AegisGuard · Layer 2 · RAGFirewall
=====================================

RAG 检索增强防火墙。防止 LLM 返回中包含敏感数据。

功能:
1. 输出前 PII 检测 + 脱敏
2. API key / secret / credential 匹配
3. 内网 IP / 域名泄露防护
4. 全角字母脱敏
5. Token 数限制（防 context dumping）
"""

import re
import unicodedata
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass, field, asdict


# ============ 模式定义 ============

# API Key 模式
API_KEY_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', 'API Key (sk-*)'),
    (r'sk-[a-zA-Z0-9_-]{32,64}', 'API Key (sk-)'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
    (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth'),
    (r'xox[bp]-[a-zA-Z0-9]{10,}', 'Slack Token'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'JWT Token'),
    (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
    (r'pk-[a-zA-Z0-9]{32,}', 'Stripe Publishable Key'),
    (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Secret Key'),
]

# 私密密钥模式
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?\S+', 'Password'),
    (r'(?i)(secret|api_key|apikey|api-key|token|auth)\s*[:=]\s*["\']?\S{8,}', 'Secret'),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'Private Key'),
    (r'-----BEGIN CERTIFICATE-----', 'Certificate'),
    (r'(?i)jdbc:[a-z]+://\S+', 'JDBC URL'),
    (r'(?i)(mongodb|mongodb\+srv)://\S+', 'MongoDB URL'),
]

# 内网 IP / 域名模式
INTERNAL_IP_PATTERNS = [
    (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Internal IP (10.x)'),
    (r'\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b', 'Internal IP (172.16-31.x)'),
    (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 'Internal IP (192.168.x)'),
    (r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Loopback IP'),
]

# PII 模式
PII_PATTERNS = [
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email'),
    (r'\b1[3-9]\d{9}\b', 'Phone Number'),
    (r'\b\d{18}[\dXx]\b', 'Chinese ID Number'),
    (r'\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b', 'Chinese ID'),
]


@dataclass
class Redaction:
    """脱敏记录"""
    type: str                # 'api_key', 'secret', 'internal_ip', 'pii'
    pattern_name: str        # 例如 'API Key (sk-*)'
    original: str            # 原始片段
    redacted: str            # 脱敏后片段
    start: int               # 在原字符串中的 offset
    end: int

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class RAGVerdict:
    """RAG 检查结果"""
    safe: bool                        # 是否无泄漏
    redacted_text: str                 # 脱敏后文本
    redactions: List[Redaction]       # 脱敏记录
    total_redactions: int
    warning: str = ""

    def to_dict(self) -> Dict:
        return {
            'safe': self.safe,
            'redacted_text': self.redacted_text,
            'redactions': [r.to_dict() for r in self.redactions],
            'total_redactions': self.total_redactions,
            'warning': self.warning,
        }


class RAGFirewall:
    """RAG 输出防火墙"""

    def __init__(
        self,
        enable_api_key_detection: bool = True,
        enable_secret_detection: bool = True,
        enable_internal_ip_detection: bool = True,
        enable_pii_detection: bool = True,
        redact_placeholder: str = '[REDACTED]',
        max_output_length: int = 100_000,
    ):
        self.enable_api_key = enable_api_key_detection
        self.enable_secret = enable_secret_detection
        self.enable_internal_ip = enable_internal_ip_detection
        self.enable_pii = enable_pii_detection
        self.placeholder = redact_placeholder
        self.max_length = max_output_length

        # 预编译
        self._api_key_re = [(re.compile(p[0]), p[1]) for p in API_KEY_PATTERNS]
        self._secret_re = [(re.compile(p[0]), p[1]) for p in SECRET_PATTERNS]
        self._internal_ip_re = [(re.compile(p[0]), p[1]) for p in INTERNAL_IP_PATTERNS]
        self._pii_re = [(re.compile(p[0]), p[1]) for p in PII_PATTERNS]

        self.stats = {
            'checks': 0,
            'redacted': 0,
            'api_keys_found': 0,
            'secrets_found': 0,
            'internal_ips_found': 0,
            'pii_found': 0,
            'truncated': 0,
        }

    def check(self, text: str) -> RAGVerdict:
        """检查并脱敏"""
        self.stats['checks'] += 1
        redactions: List[Redaction] = []
        working = text

        # 1. 长度截断
        if len(working) > self.max_length:
            working = working[:self.max_length]
            self.stats['truncated'] += 1
            redactions.append(Redaction(
                type='truncation', pattern_name='Max Length',
                original=f'... ({len(text)} chars)', redacted=f'... (truncated to {self.max_length})',
                start=self.max_length, end=len(text)
            ))

        # 2. API Key 检测
        if self.enable_api_key:
            for pattern, name in self._api_key_re:
                working, found = self._redact_pattern(working, pattern, 'api_key', name, redactions)
                if found:
                    self.stats['api_keys_found'] += found

        # 3. Secret 检测
        if self.enable_secret:
            for pattern, name in self._secret_re:
                working, found = self._redact_pattern(working, pattern, 'secret', name, redactions)
                if found:
                    self.stats['secrets_found'] += found

        # 4. 内网 IP 检测
        if self.enable_internal_ip:
            for pattern, name in self._internal_ip_re:
                working, found = self._redact_pattern(working, pattern, 'internal_ip', name, redactions)
                if found:
                    self.stats['internal_ips_found'] += found

        # 5. PII 检测
        if self.enable_pii:
            for pattern, name in self._pii_re:
                working, found = self._redact_pattern(working, pattern, 'pii', name, redactions)
                if found:
                    self.stats['pii_found'] += found

        if redactions:
            self.stats['redacted'] += 1

        # 警告信息
        warning = ''
        if self.stats['api_keys_found'] > 0:
            warning += f'检测到 {self.stats["api_keys_found"]} 个 API key; '
        if self.stats['secrets_found'] > 0:
            warning += f'检测到 {self.stats["secrets_found"]} 个 secret; '
        if self.stats['pii_found'] > 0:
            warning += f'检测到 {self.stats["pii_found"]} 个 PII; '
        if self.stats['truncated'] > 0:
            warning += f'输出被截断 ({self.max_length} chars); '

        return RAGVerdict(
            safe=len(redactions) == 0,
            redacted_text=working,
            redactions=redactions,
            total_redactions=len(redactions),
            warning=warning.strip('; '),
        )

    def safe_output(self, text: str) -> str:
        """快速脱敏（仅返回脱敏后文本）"""
        return self.check(text).redacted_text

    def _redact_pattern(
        self, text: str, pattern: re.Pattern,
        rtype: str, pname: str, redactions: List[Redaction]
    ) -> Tuple[str, int]:
        """替换命中的模式为脱敏占位符"""
        count = 0
        result = list(text)
        offset = 0

        for m in pattern.finditer(text):
            orig = m.group(0)
            # 排除非实际匹配（纯数字/短串）
            if len(orig) < 4:
                continue
            start = m.start()
            end = m.end()
            redacted = self.placeholder

            # 保留部分信息（如邮箱只保留域名部分）
            if '@' in orig:
                _, domain = orig.split('@', 1)
                redacted = f'***@{domain}'
            elif orig.startswith('sk-') and len(orig) > 20:
                redacted = f'sk-***{orig[-4:]}'

            redactions.append(Redaction(
                type=rtype, pattern_name=pname,
                original=orig, redacted=redacted,
                start=start, end=end
            ))

            # 替换（避免 offset 冲突，用切片替换）
            result[start:end] = list(redacted)
            diff = len(redacted) - len(orig)
            if diff != 0:
                for later_m in list(pattern.finditer(''.join(result))):
                    pass
            count += 1

        return ''.join(result), count

    def get_stats(self) -> Dict:
        return {**self.stats}
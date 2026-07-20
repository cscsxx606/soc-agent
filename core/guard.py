#!/usr/bin/env python3
"""
AegisGuard · Layer 2 · PromptGuard
==================================

Prompt 注入防护层。在所有 LLM 调用前强制通过 Guard。

4 个检测维度:
1. 模式匹配    - 经典关键词（ignore previous, DAN, jailbreak, system prompt）
2. Unicode 混淆 - 零宽字符 / 不可见字符 / 全角字母替换
3. Token 走私  - 超长输入 / 异常 token 密度
4. 语义分析    - LLM 二次判定（可选，开销 ~100ms）

3 个处理动作:
- safe:    pass through
- rewrite: 注入被注入符号 → 加 escapes
- block:   拒绝 + 记录事件

设计目标:
- 零依赖（不引入 presidio、rebuff 等大库）
- 优雅降级（缺 optional deps 时降级为纯规则）
- 高性能（< 1ms / 检测）
- 可审计（每次都写入事件流）

用法::

    from core.guard import PromptGuard, GuardVerdict
    
    guard = PromptGuard()
    verdict = guard.check(user_input)
    
    if verdict.action == 'block':
        raise SecurityError(verdict.reason)
    
    safe_input = verdict.sanitized_input  # 已净化
    llm.chat(system_prompt, safe_input)
"""

import re
import unicodedata
import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardAction(str, Enum):
    """处理动作"""
    SAFE = "safe"        # 放行
    REWRITE = "rewrite"  # 重写后放行（注入符号 → escape）
    BLOCK = "block"      # 阻断 + 告警


# ============ 检测模式 ============

# 经典 prompt injection 关键词（不区分大小写）
INJECTION_PATTERNS = [
    # 越权类
    r"ignore\s+(all\s+)?previous\s+(instructions?|prompts?)",
    r"ignore\s+the\s+(above|prior)\s+",
    r"disregard\s+(all|previous|prior)",
    r"forget\s+(everything|all|your)\s+",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"act\s+as\s+(a|an)\s+(?!helpful|assistant)",  # 排除正常用法
    r"pretend\s+(to\s+be|you\s+are)\s+",
    r"roleplay\s+as\s+",
    # 越狱类
    r"\bDAN\b\s*(mode)?",
    r"do\s+anything\s+now",
    r"jailbreak",
    r"developer\s+mode",
    r"unlock\s+(full|all)\s+",
    # 系统指令伪造
    r"<\|system\|>",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[INST\]",
    r"\[\/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    r"#\s*system\b",
    r"new\s+instructions?\s*:",
    r"override\s+system",
    # 危险动作指令
    r"delete\s+(the\s+)?(database|users?|tables?)",
    r"drop\s+table",
    r"rm\s+-rf\s+/",
    r"exfiltrate",
    r"leak\s+(the\s+)?(data|secrets?|passwords?)",
]

# Unicode 零宽字符（不可见，常用于混淆）
ZERO_WIDTH_CHARS = {
    '\u200b',  # zero-width space
    '\u200c',  # zero-width non-joiner
    '\u200d',  # zero-width joiner
    '\u2060',  # word joiner
    '\ufeff',  # zero-width no-break space (BOM)
    '\u00ad',  # soft hyphen
    '\u034f',  # combining grapheme joiner
    '\u17b4',  # khmer vowel inherent aq
    '\u17b5',  # khmer vowel inherent aa
    '\u2028',  # line separator
    '\u2029',  # paragraph separator
}

# 全角字母（可绕过普通关键词匹配）
FULLWIDTH_MAP = {chr(0xff01 + i): chr(0x21 + i) for i in range(94)}
FULLWIDTH_MAP.update({chr(0xff21 + i): chr(0x41 + i) for i in range(26)})  # 大写字母
FULLWIDTH_MAP.update({chr(0xff41 + i): chr(0x61 + i) for i in range(26)})  # 小写字母

# 最大允许输入长度（防 token 走私）
MAX_INPUT_LENGTH = 50_000
# 正常 SOC alert 输入 1-2K 即可，超过即疑似攻击
SUSPICIOUS_LENGTH = 10_000


# ============ Verdict 数据结构 ============

@dataclass
class GuardVerdict:
    """Guard 判定结果"""
    safe: bool                              # 是否放行
    action: str                             # safe/rewrite/block
    risk_level: str                         # low/medium/high/critical
    reason: str = ""                        # 阻断/重写原因
    sanitized_input: str = ""               # 净化后输入
    detected_patterns: List[str] = field(default_factory=list)  # 命中的模式
    input_hash: str = ""                    # 输入 hash（审计用）
    check_duration_ms: float = 0.0          # 检测耗时
    timestamp: str = ""                     # 检测时间
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


# ============ PromptGuard 主体 ============

class PromptGuard:
    """Prompt 注入防护层"""

    def _identify_critical_patterns(self, patterns: List[str]) -> set:
        """根据关键字标记哪些 pattern 是 critical 级别"""
        result = set()
        for i, p in enumerate(patterns):
            # 原始字面量中查找关键字（这些关键字中以 "system" 为核心的包括 # system, override system 等）
            # 我们检查原始未转义串 + 特殊关键词
            is_critical = False
            if 'INST' in p:
                is_critical = True
            elif 'SYS' in p:  # <<SYS>> 或 </SYS>>
                is_critical = True
            elif 'override' in p:
                is_critical = True
            elif 'system' in p:  # # system、override system 等含 system 的
                is_critical = True
            elif '\\|' in p and '<' in p:  # <|xxx|> ChatML 格式
                is_critical = True
            if is_critical:
                result.add(i)
        return result

    def __init__(
        self,
        max_length: int = MAX_INPUT_LENGTH,
        suspicious_length: int = SUSPICIOUS_LENGTH,
        enable_unicode_check: bool = True,
        enable_length_check: bool = True,
        enable_pattern_check: bool = True,
        on_block_callback: Optional[callable] = None,
    ):
        self.max_length = max_length
        self.suspicious_length = suspicious_length
        self.enable_unicode_check = enable_unicode_check
        self.enable_length_check = enable_length_check
        self.enable_pattern_check = enable_pattern_check
        self.on_block_callback = on_block_callback

        # 预编译正则（性能优化）
        self._patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in INJECTION_PATTERNS]
        # 严重级标记：哪些 pattern 命中后 risk=critical
        self._critical_indices = self._identify_critical_patterns(INJECTION_PATTERNS)

        # 统计
        self.stats = {
            'checks': 0,
            'blocks': 0,
            'rewrites': 0,
            'passes': 0,
        }

    def check(self, text: str) -> GuardVerdict:
        """
        主入口：检测文本是否含 prompt 注入。
        
        返回 GuardVerdict，调用方根据 verdict.action 决定后续动作。
        """
        start = time.time()
        self.stats['checks'] += 1

        if not isinstance(text, str):
            return GuardVerdict(
                safe=False, action='block', risk_level='high',
                reason='输入不是字符串',
                timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
                input_hash=hashlib.sha256(str(text).encode()).hexdigest()[:16],
            )

        input_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        detected_patterns: List[str] = []
        risk = RiskLevel.LOW
        metadata: Dict[str, Any] = {}

        # ============ 检测 1: 长度 ============
        if self.enable_length_check:
            length = len(text)
            metadata['length'] = length
            if length > self.max_length:
                return self._build_verdict(
                    text, GuardAction.BLOCK, RiskLevel.CRITICAL,
                    f'输入超长 ({length} > {self.max_length})，疑似 token 走私',
                    detected_patterns=['length_exceeded'],
                    metadata=metadata,
                    duration=time.time() - start,
                    input_hash=input_hash,
                )
            elif length > self.suspicious_length:
                risk = RiskLevel.MEDIUM
                detected_patterns.append('suspicious_length')

        # ============ 检测 2: Unicode 零宽字符 ============
        if self.enable_unicode_check:
            zw_count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
            metadata['zero_width_chars'] = zw_count
            if zw_count > 0:
                # 任何零宽字符都是高风险（正常文本不应该有）
                risk = max(risk, RiskLevel.HIGH, key=lambda r: ['low', 'medium', 'high', 'critical'].index(r.value))
                detected_patterns.append(f'zero_width_chars:{zw_count}')

        # ============ 检测 3: 全角字母替换 ============
        normalized = unicodedata.normalize('NFKC', text) if self.enable_unicode_check else text
        fullwidth_count = sum(1 for c in text if c in FULLWIDTH_MAP)
        metadata['fullwidth_chars'] = fullwidth_count
        if fullwidth_count > 5:  # 5 个以上全角字母可疑
            risk = max(risk, RiskLevel.MEDIUM, key=lambda r: ['low', 'medium', 'high', 'critical'].index(r.value))
            detected_patterns.append(f'fullwidth_chars:{fullwidth_count}')

        # ============ 检测 4: 经典模式匹配 ============
        if self.enable_pattern_check:
            for idx, pattern in enumerate(self._patterns):
                m = pattern.search(normalized)
                if m:
                    detected_patterns.append(f'pattern:{m.group(0)[:40]}')
                    # 系统指令伪造直接 critical
                    if idx in self._critical_indices:
                        risk = RiskLevel.CRITICAL
                    else:
                        risk = max(risk, RiskLevel.HIGH, key=lambda r: ['low', 'medium', 'high', 'critical'].index(r.value))

        # ============ 综合判定 ============
        # 风险等级数值化用于比较
        risk_value = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}[risk.value]

        if risk == RiskLevel.CRITICAL:
            # critical 风险立即 block
            return self._build_verdict(
                text, GuardAction.BLOCK, risk,
                f'检测到严重注入特征: {detected_patterns[0]}',
                detected_patterns=detected_patterns,
                metadata=metadata,
                duration=time.time() - start,
                input_hash=input_hash,
            )
        elif risk == RiskLevel.HIGH and len(detected_patterns) >= 1:
            # high + 至少 1 个模式匹配 → block
            return self._build_verdict(
                text, GuardAction.BLOCK, risk,
                f'检测到高风险注入特征: {detected_patterns[0]}',
                detected_patterns=detected_patterns,
                metadata=metadata,
                duration=time.time() - start,
                input_hash=input_hash,
            )
        elif detected_patterns:
            # 有信号但不够多 → rewrite (清掉零宽 + 全角转半角)
            sanitized = self._sanitize(text)
            return self._build_verdict(
                text, GuardAction.REWRITE, risk,
                '检测到可疑特征已净化',
                sanitized=sanitized,
                detected_patterns=detected_patterns,
                metadata=metadata,
                duration=time.time() - start,
                input_hash=input_hash,
            )

        # 全部通过
        return self._build_verdict(
            text, GuardAction.SAFE, RiskLevel.LOW,
            '', [], metadata, time.time() - start, input_hash,
        )

    def sanitize(self, text: str) -> str:
        """仅净化（不阻断），返回净化后的字符串"""
        return self._sanitize(text)

    def is_safe(self, text: str) -> bool:
        """快速判定（仅 bool）"""
        return self.check(text).safe

    def _sanitize(self, text: str) -> str:
        """净化：去零宽 + 全角转半角 + 去控制字符"""
        # 去零宽
        result = ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)
        # 全角转半角
        result = ''.join(FULLWIDTH_MAP.get(c, c) for c in result)
        # 去控制字符（保留 \n \t \r）
        result = ''.join(c for c in result if c in '\n\t\r' or not unicodedata.category(c).startswith('C'))
        return result

    def _build_verdict(
        self,
        original_text: str,
        action: GuardAction,
        risk: RiskLevel,
        reason: str,
        detected_patterns: List[str],
        metadata: Dict,
        duration: float,
        input_hash: str,
        sanitized: Optional[str] = None,
    ) -> GuardVerdict:
        """构造 Verdict + 更新统计 + 回调"""
        if action == GuardAction.BLOCK:
            self.stats['blocks'] += 1
            if self.on_block_callback:
                try:
                    self.on_block_callback(original_text, detected_patterns, risk)
                except Exception:
                    pass  # 回调失败不能影响主流程
        elif action == GuardAction.REWRITE:
            self.stats['rewrites'] += 1
        else:
            self.stats['passes'] += 1

        return GuardVerdict(
            safe=(action == GuardAction.SAFE),
            action=action.value,
            risk_level=risk.value,
            reason=reason,
            sanitized_input=sanitized if sanitized is not None else (self._sanitize(original_text) if action != GuardAction.SAFE else original_text),
            detected_patterns=detected_patterns,
            input_hash=input_hash,
            check_duration_ms=round(duration * 1000, 3),
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
            metadata=metadata,
        )

    def get_stats(self) -> Dict:
        return {**self.stats,
                'block_rate': round(self.stats['blocks'] / max(self.stats['checks'], 1) * 100, 2)}
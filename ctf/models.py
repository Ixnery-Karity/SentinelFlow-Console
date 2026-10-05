"""CTF Agent 的数据模型与通用判定工具。"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


# 常见 flag 形态：flag{...} / ctf{...} / xxx{...} / 32位十六进制串
_FLAG_PATTERNS = [
    re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\n]{1,120}\}"),
    re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])"),
]

# 明显不是 flag 的高频误报（编码后的二进制等）
_FLAG_DENY = re.compile(r"^(?:0{32}|f{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-)", re.I)


@dataclass
class Challenge:
    """一道待解的题。"""
    title: str = ""
    description: str = ""
    content: str = ""
    files: list[str] = field(default_factory=list)
    ctype: str = "unknown"          # web/crypto/misc/reverse/pwn
    tags: list[str] = field(default_factory=list)

    def blob(self) -> str:
        """题目全文，用于分类与检索。"""
        parts = [self.title, self.description, self.content]
        return "\n".join(p for p in parts if p)


@dataclass
class Step:
    """一次工具调用的记录（解题轨迹的基本单元）。"""
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    ok: bool = False
    outputs: list[str] = field(default_factory=list)
    note: str = ""
    elapsed_ms: int = 0


@dataclass
class SolveResult:
    """一次完整解题的结果。"""
    challenge: Challenge
    ctype: str = "unknown"
    status: str = "unsolved"        # solved / unsolved / error
    flag: str = ""
    flag_confidence: float = 0.0    # flag 可信度（用于区分真解出与编码误报）
    needs_review: bool = False      # 仅拿到低可信候选时置位，提示人工复核
    chain: list[str] = field(default_factory=list)   # 成功的工具链
    steps: list[Step] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)
    kb_hits: list[int] = field(default_factory=list)  # 命中的知识卡 id
    notes: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["challenge"] = asdict(self.challenge)
        return d


@dataclass
class KnowledgeCard:
    """知识卡：一次解题沉淀下来的可复用经验。"""
    title: str
    kind: str = "recipe"            # recipe / pitfall / tool / pattern
    challenge_type: str = "unknown"
    content: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    fingerprint: str = ""
    confidence: float = 0.5
    success_count: int = 0
    fail_count: int = 0
    card_id: int | None = None
    created_at: float = field(default_factory=time.time)


# ----------------------------------------------------------------------
# 判定与评分工具
# ----------------------------------------------------------------------
def find_flags(text: str) -> list[str]:
    """从任意文本中提取疑似 flag，按出现顺序去重。"""
    found: list[str] = []
    for pat in _FLAG_PATTERNS:
        for m in pat.finditer(text or ""):
            v = m.group(0)
            if _FLAG_DENY.match(v):
                continue
            if v not in found:
                found.append(v)
    return found


def looks_like_flag(text: str) -> bool:
    return bool(find_flags(text))


# 常见 CTF flag 前缀（命中即高可信）
KNOWN_PREFIXES = {
    "flag", "ctf", "flag_flag", "hctf", "hfctf", "actf", "nssctf", "buuctf",
    "moectf", "iscc", "qsnctf", "dasctf", "n1ctf", "de1ctf", "starctf",
    "geek", "xsctf", "ctfshow", "gift", "key", "answer",
}
HIGH_CONFIDENCE = 0.60


def flag_confidence(flag: str) -> float:
    """给候选 flag 打可信度（0~1），用于剔除编码误报。

    实战最常见的坑：ROT13 / 凯撒会把密文转成 ``vbqw{squiqh}`` 这种
    "长得像 flag、其实是乱码" 的串，必须靠前缀与可读性把它压下去。
    """
    if not flag:
        return 0.0
    score = 0.0
    has_brace = "{" in flag and flag.endswith("}")
    prefix = flag.split("{", 1)[0].lower() if "{" in flag else ""
    body = flag[flag.find("{") + 1:-1] if has_brace else ""

    if prefix in ("flag", "ctf"):
        score += 0.45
    elif prefix in KNOWN_PREFIXES or prefix.endswith("ctf"):
        score += 0.35
    elif prefix and prefix.isalpha():
        score += 0.05                      # 未知前缀几乎不加分

    if has_brace:
        score += 0.15
    else:
        score += 0.05                      # 裸串（如 32 位 hex）可信度天然低

    if body:
        if re.fullmatch(r"[\x20-\x7e]+", body):
            score += 0.25 * min(1.0, english_score(body) / 3.0)
        if re.fullmatch(r"[0-9a-fA-F]{16,}", body):
            score += 0.15
        if re.fullmatch(r"[A-Za-z0-9_\-]{2,}", body):
            score += 0.10
    return round(min(score, 1.0), 3)


def best_flag(candidates: list[str]) -> str:
    """从候选中挑可信度最高的 flag。"""
    if not candidates:
        return ""
    return max(candidates, key=flag_confidence)


_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def printable_ratio(data: bytes | str) -> float:
    """可打印字符占比，用于 XOR / 凯撒爆破打分。"""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    if not data:
        return 0.0
    good = sum(1 for b in data if b in _PRINTABLE) if data else 0
    # 中文字节按高位置 1 计，不算可打印但也不该判死
    return good / len(data)


_COMMON_WORDS = (
    "the", "and", "flag", "ctf", "this", "that", "with", "you", "for", "are",
    "is", "of", "to", "in", "a", "key", "secret", "hello", "world",
)
_FREQ = "etaoin shrdlu"


def english_score(text: str) -> float:
    """英文可读性打分：字母频率 + 常见词命中。分数越高越像明文。"""
    if not text:
        return 0.0
    low = text.lower()
    letters = [c for c in low if c.isalpha()]
    if not letters:
        return 0.0
    base = sum(_FREQ.find(c) >= 0 and (3.0 - _FREQ.index(c) * 0.1) or 0.0 for c in letters) / len(letters)
    hits = sum(1 for w in _COMMON_WORDS if w in low)
    ratio = printable_ratio(text)
    return base * ratio + hits * 1.5 + ratio


def best_by_score(items: Iterable[str], scorer=english_score) -> list[str]:
    """按分数降序返回。"""
    return sorted(items, key=scorer, reverse=True)


def guess_encoding_of_flag(flag: str) -> str:
    """粗略判断 flag 内部的编码形态，用于写知识卡。"""
    body = flag
    m = re.search(r"\{(.*)\}", flag)
    if m:
        body = m.group(1)
    if re.fullmatch(r"[0-9a-fA-F]+", body or "") and len(body) % 2 == 0:
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", body or ""):
        return "base64-like"
    if re.fullmatch(r"[\x20-\x7e]+", body or ""):
        return "plaintext"
    return "unknown"

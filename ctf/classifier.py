"""题型识别：把题目归到 web / crypto / misc / reverse / pwn，并给出工具建议。

纯启发式、离线可跑；LLM 可用时只作为**补充**，不作为唯一依据。
"""
from __future__ import annotations

import re
from typing import Any

# 关键词 → 题型权重
_KEYWORDS: dict[str, list[str]] = {
    "web": ["sql", "注入", "injection", "xss", "csrf", "ssrf", "rce", "文件包含",
            "upload", "上传", "cookie", "session", "jwt", "http", "url", "参数",
            "源码", ".git", "备份", "目录扫描", "php", "jsp", "asp", "flask",
            "反序列化", "逻辑漏洞", "越权"],
    "crypto": ["加密", "解密", "密文", "密钥", "key", "rsa", "aes", "des", "base64",
               "base32", "异或", "xor", "凯撒", "caesar", "维吉尼亚", "vigenere",
               "密码", "cipher", "哈希", "hash", "md5", "sha", "素数", "模数",
               "大数", "e=", "n=", "c="],
    "reverse": ["逆向", "反编译", "汇编", "ida", "jadx", "ghidra", "apk", "dex",
                "exe", "elf", "smali", "so文件", "伪代码", "脱壳", "crackme"],
    "pwn": ["溢出", "栈", "堆", "heap", "stack", "canary", "rop", "got", "plt",
            "libc", "shellcode", "格式化字符串", "uaf", "tcache", "pwn"],
    "misc": ["隐写", "stego", "图片", "音频", "视频", "二维码", "qr", "流量", "pcap",
             "压缩包", "zip", "rar", "编码", "解密文", "签到", "杂项", "取证",
             "日志", "内存镜像", "磁盘", "字体"],
}

_TOOLBOX_HINTS = {
    "web": ["url", "base64", "hex"],
    "crypto": ["base64", "hex", "caesar", "xor_brute", "atbash", "railfence",
               "hash_identify", "hash_weak", "binary", "ascii_dec"],
    "reverse": ["hex", "base64", "magic"],
    "pwn": ["hex", "base64"],
    "misc": ["magic", "flag_scan", "base64", "hex", "binary", "morse",
             "ascii_dec", "unicode_escape", "rot13", "reverse", "freq"],
    "unknown": ["base64", "hex", "morse", "binary", "ascii_dec", "caesar",
                "url", "rot13", "reverse", "xor_brute", "flag_scan"],
}

_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F\s]{16,}$")
_BIN_RE = re.compile(r"^[01\s]{16,}$")
_MORSE_RE = re.compile(r"^[.\-\s/·−—_]{6,}$")
_ASCII_RE = re.compile(r"^(?:\d{2,3}[\s,]+){3,}\d{2,3}$")


def classify(challenge: Any) -> dict[str, Any]:
    """返回 {ctype, scores, hints, suggested_tools, content_signals}。"""
    blob = challenge.blob() if hasattr(challenge, "blob") else str(challenge)
    content = getattr(challenge, "content", "") or blob
    low = blob.lower()

    scores = {k: 0 for k in _KEYWORDS}
    for ctype, words in _KEYWORDS.items():
        for w in words:
            if w in low:
                scores[ctype] += 2 if len(w) > 3 else 1

    # 内容形态的强信号
    stripped = content.strip()
    signals: list[str] = []
    if _BIN_RE.match(stripped):
        scores["misc"] += 4
        signals.append("疑似二进制串（0/1）")
    if _MORSE_RE.match(stripped):
        scores["misc"] += 4
        signals.append("疑似摩斯电码")
    if _ASCII_RE.match(stripped):
        scores["misc"] += 3
        signals.append("疑似十进制 ASCII 码")
    if _HEX_RE.match(stripped) and len(re.sub(r"\s", "", stripped)) >= 32:
        scores["crypto"] += 3
        signals.append("疑似十六进制串")
    if _B64_RE.match(stripped) and len(re.sub(r"\s", "", stripped)) >= 20:
        scores["crypto"] += 2
        signals.append("疑似 Base64")
    if re.search(r"(?i)\bflag\b|\bctf\b", blob):
        signals.append("题目文本中出现 flag 字样")

    ctype = max(scores, key=lambda k: scores[k]) if any(scores.values()) else "unknown"

    hints = _TOOLBOX_HINTS.get(ctype, _TOOLBOX_HINTS["unknown"])
    return {
        "ctype": ctype,
        "scores": scores,
        "hints": hints,
        "suggested_tools": list(hints),
        "content_signals": signals,
    }


def plan(ctype: str, content: str = "") -> list[list[str]]:
    """生成候选工具链（按优先级排列的多套方案），供 Agent 依次尝试。

    返回的是"链"而非单工具——因为实战里套娃编码很常见。
    顺序策略：先看题目形态（哈希 / 编码），再按题型的默认工具面展开。
    """
    base = _TOOLBOX_HINTS.get(ctype, _TOOLBOX_HINTS["unknown"])
    s = re.sub(r"\s+", "", content or "")

    plans: list[list[str]] = []
    # 形态优先：命中哈希形态时，识别 + 弱口令比对排在最前
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", s):
        plans += [["hash_identify"], ["hash_weak"]]

    plans.append(["auto_decode"])                      # 自动套娃解码，性价比最高
    plans.extend([[t] for t in base])
    if ctype in ("misc", "unknown", "crypto"):
        plans.append(["magic", "auto_decode"])
        plans.append(["flag_scan"])
        plans.append(["xor_brute"])
        plans.append(["caesar", "auto_decode"])
        plans.append(["reverse"])
        plans.append(["morse"])
        plans.append(["caesar", "reverse"])
    # 去重保序
    seen, out = set(), []
    for p in plans:
        key = ">".join(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out

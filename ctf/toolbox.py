"""离线解题工具箱：全部可在无网络、无大模型的环境下运行。

每个工具接收文本、返回若干候选字符串；统一登记在 ``TOOLS`` 里，
供解题 Agent 按题型检索与编排（这也是 Agent 的"工具面"）。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
import string
from typing import Any, Callable

from .models import english_score, printable_ratio

ToolFn = Callable[..., list[str]]

TOOLS: dict[str, dict[str, Any]] = {}


def tool(name: str, category: str, desc: str, needs: str = ""):
    """登记一个工具。"""
    def deco(fn: ToolFn) -> ToolFn:
        TOOLS[name] = {"name": name, "category": category, "desc": desc,
                       "needs": needs, "fn": fn}
        return fn
    return deco


# ======================================================================
# 一、编码类
# ======================================================================
@tool("base64", "encoding", "Base64 解码（自动补 padding）", "文本形如 A-Za-z0-9+/ 且长度多为 4 的倍数")
def t_base64(text: str, **_: Any) -> list[str]:
    out: list[str] = []
    s = re.sub(r"\s+", "", text)
    for cand in (s, s.replace("-", "+").replace("_", "/")):
        pad = "=" * (-len(cand) % 4)
        try:
            raw = base64.b64decode(cand + pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                v = raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
            if v and v not in out:
                out.append(v)
            break
    return out


@tool("base32", "encoding", "Base32 解码", "文本形如 A-Z2-7 且结尾多为 =")
def t_base32(text: str, **_: Any) -> list[str]:
    s = re.sub(r"\s+", "", text).upper()
    pad = "=" * (-len(s) % 8)
    try:
        return [base64.b32decode(s + pad).decode("utf-8", errors="replace")]
    except (binascii.Error, ValueError):
        return []


@tool("hex", "encoding", "十六进制转字节（可再按 utf-8/gbk 解码）", "成对十六进制字符")
def t_hex(text: str, **_: Any) -> list[str]:
    s = re.sub(r"(?i)0x|[\s,]", "", text)
    if not re.fullmatch(r"(?i)[0-9a-f]+", s) or len(s) % 2:
        return []
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return []
    out = []
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            v = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if v and v not in out:
            out.append(v)
        break
    if raw not in (b"",) and not out:
        out.append(raw.decode("latin-1"))
    return out


@tool("url", "encoding", "URL 百分号解码（%xx）")
def t_url(text: str, **_: Any) -> list[str]:
    from urllib.parse import unquote
    v = unquote(text)
    return [v] if v != text else []


@tool("rot13", "encoding", "ROT13 字母位移")
def t_rot13(text: str, **_: Any) -> list[str]:
    return [codecs.decode(text, "rot_13")]


@tool("morse", "encoding", "摩斯电码解码（支持 .- 与 ·−）", "由 . - 空格 / 组成")
def t_morse(text: str, **_: Any) -> list[str]:
    table = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
        "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
        "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
        "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
        "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
        "---..": "8", "----.": "9", "..--.-": "_", ".-.-.-": ".", "--..--": ",",
        "..--..": "?", "-..-.": "/", ".--.-.": "@",
    }
    s = text.replace("·", ".").replace("−", "-").replace("—", "-").replace("_", "-")
    parts = re.split(r"\s*/\s*|\s{2,}|\n", s.strip())
    out_chars: list[str] = []
    for token in parts:
        if not token.strip():
            out_chars.append(" ")
            continue
        letters = [table.get(c, "") for c in token.split()]
        if any(c == "" for c in letters):
            # 也可能是单空格分隔的连续摩斯
            letters = [table.get(c, "") for c in token.strip().split(" ")]
        if any(c == "" for c in letters):
            return []
        out_chars.append("".join(letters))
    res = "".join(out_chars).strip()
    return [res] if res else []


@tool("binary", "encoding", "二进制串转文本（8 位一组）", "只有 0/1 与空格")
def t_binary(text: str, **_: Any) -> list[str]:
    bits = re.sub(r"[^01]", "", text)
    if len(bits) < 8 or len(bits) % 8:
        return []
    try:
        raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    except ValueError:
        return []
    return [raw.decode("utf-8", errors="replace")]


@tool("ascii_dec", "encoding", "十进制 ASCII 码转字符", "由 32-126 的数字组成")
def t_ascii_dec(text: str, **_: Any) -> list[str]:
    nums = re.findall(r"\d{2,3}", text)
    if len(nums) < 3:
        return []
    try:
        vals = [int(n) for n in nums]
    except ValueError:
        return []
    if not all(0 < v < 0x110000 for v in vals):
        return []
    try:
        return ["".join(chr(v) for v in vals)]
    except ValueError:
        return []


@tool("unicode_escape", "encoding", "Unicode 转义解码（\\uXXXX）")
def t_unicode(text: str, **_: Any) -> list[str]:
    if not re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", text):
        return []
    try:
        return [codecs.decode(text, "unicode_escape")]
    except (UnicodeDecodeError, ValueError):
        return []


# ======================================================================
# 二、古典密码类
# ======================================================================
@tool("caesar", "classic", "凯撒密码爆破（枚举 26 个位移，按可读性排序）")
def t_caesar(text: str, **_: Any) -> list[str]:
    out: list[str] = []
    for shift in range(1, 26):
        buf = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                buf.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                buf.append(ch)
        out.append("".join(buf))
    return sorted(out, key=english_score, reverse=True)


@tool("atbash", "classic", "Atbash 字母反转（a<->z）")
def t_atbash(text: str, **_: Any) -> list[str]:
    tbl = str.maketrans(string.ascii_letters, string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1])
    return [text.translate(tbl)]


@tool("railfence", "classic", "栅栏密码爆破（枚举 2..8 栏）")
def t_railfence(text: str, max_rails: int = 8, **_: Any) -> list[str]:
    out: list[str] = []
    for rails in range(2, max_rails + 1):
        if rails >= len(text):
            break
        pattern, r, step = [], 0, 1
        for _ in range(len(text)):
            pattern.append(r)
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
        counts = [pattern.count(i) for i in range(rails)]
        buckets, idx = [], 0
        for c in counts:
            buckets.append(list(text[idx:idx + c]))
            idx += c
        ptr = [0] * rails
        buf = []
        for rr in pattern:
            buf.append(buckets[rr][ptr[rr]])
            ptr[rr] += 1
        out.append("".join(buf))
    return sorted(out, key=english_score, reverse=True)


@tool("reverse", "classic", "整体字符串倒序")
def t_reverse(text: str, **_: Any) -> list[str]:
    v = text[::-1]
    return [v] if v != text else []


# ======================================================================
# 三、异或 / 加密类
# ======================================================================
@tool("xor_brute", "crypto", "单字节 XOR 爆破（1..255，按可打印比例过滤）", "密文为十六进制或含不可见字符")
def t_xor_brute(text: str, min_ratio: float = 0.85, **_: Any) -> list[str]:
    raw: bytes | None = None
    s = re.sub(r"(?i)0x|[\s,]", "", text)
    if re.fullmatch(r"(?i)[0-9a-f]+", s) and len(s) % 2 == 0:
        try:
            raw = bytes.fromhex(s)
        except ValueError:
            raw = None
    if raw is None:
        raw = text.encode("utf-8", errors="ignore")
    out: list[str] = []
    for k in range(1, 256):
        dec = bytes(b ^ k for b in raw)
        if printable_ratio(dec) < min_ratio:
            continue
        try:
            out.append(dec.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return sorted(out, key=english_score, reverse=True)[:20]


# ======================================================================
# 四、哈希类
# ======================================================================
COMMON_WORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "admin", "root", "flag", "ctf", "hello", "world", "test", "guest",
]


@tool("hash_identify", "hash", "识别哈希类型（按长度与字符集）")
def t_hash_identify(text: str, **_: Any) -> list[str]:
    s = re.sub(r"\s+", "", text)
    out: list[str] = []
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        n = len(s)
        table = {32: "MD5 / NTLM", 40: "SHA-1", 56: "SHA-224",
                 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
        if n in table:
            out.append(f"疑似 {table[n]}（长度 {n}）")
    if re.fullmatch(r"(?i)\$2[aby]\$.{56}", s):
        out.append("疑似 bcrypt")
    if re.fullmatch(r"\$1\$[^$]+\$[^$]+", s):
        out.append("疑似 MD5-crypt")
    if re.fullmatch(r"\$6\$[^$]+\$[^$]+", s):
        out.append("疑似 SHA-512-crypt")
    return out


@tool("hash_weak", "hash", "弱口令字典比对（内置常见口令，覆盖 MD5/SHA1/SHA256）")
def t_hash_weak(text: str, **_: Any) -> list[str]:
    target = re.sub(r"\s+", "", text).lower()
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", target):
        return []
    algos = {32: hashlib.md5, 40: hashlib.sha1, 64: hashlib.sha256}
    fn = algos[len(target)]
    hits = [w for w in COMMON_WORDS
            if fn(w.encode()).hexdigest() == target]
    return [f"弱口令命中：{w}" for w in hits]


# ======================================================================
# 五、文件与杂项
# ======================================================================
MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG 图片"),
    (b"\xff\xd8\xff", "JPEG 图片"),
    (b"GIF8", "GIF 图片"),
    (b"PK\x03\x04", "ZIP（可能是 DOCX/XLSX/APK）"),
    (b"%PDF", "PDF"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\x7fELF", "ELF 可执行文件（Linux）"),
    (b"MZ", "PE 可执行文件（Windows）"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"RIFF", "RIFF（WAV/AVI/WebP）"),
    (b"OggS", "OGG 音频"),
    (b"ID3", "MP3 音频"),
    (b"\x42\x4d", "BMP 图片"),
    (b"ustar", "TAR 归档（偏移 257）"),
]


@tool("magic", "misc", "按文件头识别真实文件类型（对抗改后缀）", "需要提供文件名")
def t_magic(path: str, **_: Any) -> list[str]:
    try:
        with open(path, "rb") as fh:
            head = fh.read(300)
    except OSError:
        return []
    out: list[str] = []
    for sig, name in MAGIC:
        if head.startswith(sig) or (sig == b"ustar" and head[257:262] == b"ustar"):
            out.append(name)
    return out


@tool("flag_scan", "misc", "在文本中直接扫描 flag 形态")
def t_flag_scan(text: str, **_: Any) -> list[str]:
    from .models import find_flags
    return find_flags(text)


@tool("freq", "misc", "展示字符频率与可疑片段（辅助人工判断）")
def t_freq(text: str, **_: Any) -> list[str]:
    if not text:
        return []
    freq: dict[str, int] = {}
    for ch in text:
        if ch.isprintable() and not ch.isspace():
            freq[ch] = freq.get(ch, 0) + 1
    top = sorted(freq.items(), key=lambda kv: -kv[1])[:10]
    return ["字符频率 Top10：" + " ".join(f"{k}×{v}" for k, v in top)]


# ======================================================================
# 自动解码链（处理"套娃"编码）——这是解题 Agent 的主力
# ======================================================================
_AUTO_CHAIN = ["base64", "hex", "base32", "url", "rot13", "binary", "ascii_dec", "unicode_escape"]


def auto_decode_chain(text: str, depth: int = 3, beam: int = 5,
                      max_nodes: int = 160, max_repeat: int = 2) -> list[tuple[str, list[str]]]:
    """广度优先地尝试编码组合，返回 (结果, 工具链) 列表，按可读性排序。

    例：base64 解出十六进制，再 hex 解出明文，链为 ``["base64", "hex"]``。
    允许同一工具嵌套（如双重 Base64），但最多重复 ``max_repeat`` 次以防发散。
    """
    results: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    frontier: list[tuple[str, list[str]]] = [(text.strip(), [])]
    visited = 0
    for _ in range(depth):
        nxt: list[tuple[str, list[str]]] = []
        for cur, chain in frontier:
            for name in _AUTO_CHAIN:
                if chain.count(name) >= max_repeat:   # 同一工具最多嵌套 N 次
                    continue
                visited += 1
                if visited > max_nodes:
                    return sorted(results, key=lambda r: english_score(r[0]), reverse=True)
                for out in TOOLS[name]["fn"](cur):
                    out = out.strip()
                    if len(out) < 4 or out in seen:
                        continue
                    seen.add(out)
                    nc = chain + [name]
                    results.append((out, nc))
                    nxt.append((out, nc))
        frontier = sorted(nxt, key=lambda p: english_score(p[0]), reverse=True)[:beam]
        if not frontier:
            break
    return sorted(results, key=lambda r: english_score(r[0]), reverse=True)


def run_tool(name: str, text: str, **kwargs: Any) -> list[str]:
    """安全调用某个工具。"""
    spec = TOOLS.get(name)
    if not spec:
        return []
    try:
        return spec["fn"](text, **kwargs) or []
    except Exception:                                    # 工具失败不应中断流程
        return []


def tool_catalog() -> list[dict[str, str]]:
    """返回工具目录（不含函数），供 UI / 报告展示。"""
    return [{"name": s["name"], "category": s["category"], "desc": s["desc"],
             "needs": s["needs"]} for s in TOOLS.values()]

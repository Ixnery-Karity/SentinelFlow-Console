"""CTF Agent 测试：工具箱、知识库、解题闭环、命令行自检。

运行： pytest tests/test_ctf.py -v
"""
from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ctf import CTFAgent, Challenge, KnowledgeBase, find_flags, run_tool  # noqa: E402
from ctf import classifier, toolbox  # noqa: E402
from ctf.knowledge import extract_cards, fingerprint_of  # noqa: E402
from ctf.__main__ import main  # noqa: E402


# ======================================================================
# 工具箱
# ======================================================================
class TestToolbox:
    def test_base64(self):
        assert "flag{a}" in run_tool("base64", base64.b64encode(b"flag{a}").decode())

    def test_base64_without_padding(self):
        # 去掉 padding 也要能解
        raw = base64.b64encode(b"flag{no_pad}").decode().rstrip("=")
        assert "flag{no_pad}" in run_tool("base64", raw)

    def test_hex(self):
        h = b"flag{hex}".hex()
        assert "flag{hex}" in run_tool("hex", h)

    def test_rot13_twice_is_identity(self):
        once = run_tool("rot13", "flag{x}")[0]
        assert run_tool("rot13", once)[0] == "flag{x}"

    def test_morse(self):
        assert "SOS" in run_tool("morse", "... --- ...")

    def test_binary(self):
        bits = " ".join(f"{b:08b}" for b in b"flag")
        assert "flag" in run_tool("binary", bits)

    def test_ascii_decimal(self):
        text = " ".join(str(b) for b in b"flag{num}")
        assert "flag{num}" in run_tool("ascii_dec", text)

    def test_caesar_finds_plaintext(self):
        enc = "".join(chr((ord(c) - 97 + 3) % 26 + 97) if c.islower() else c for c in "flag")
        assert "flag" in run_tool("caesar", enc)

    def test_railfence_roundtrip(self):
        plain, rails = "helloworld", 2
        pattern, r, step = [], 0, 1
        for _ in range(len(plain)):
            pattern.append(r)
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
        buckets = [[] for _ in range(rails)]
        for ch, rr in zip(plain, pattern):
            buckets[rr].append(ch)
        cipher = "".join("".join(b) for b in buckets)
        assert plain in run_tool("railfence", cipher)

    def test_xor_single_byte(self):
        key = 0x2A
        enc = bytes(b ^ key for b in b"flag{xor}").hex()
        assert any("flag{xor}" == o for o in run_tool("xor_brute", enc))

    def test_hash_identify(self):
        out = run_tool("hash_identify", "e10adc3949ba59abbe56e057f20f883e")
        assert any("MD5" in o for o in out)

    def test_hash_weak_dictionary(self):
        assert run_tool("hash_weak", hashlib.md5(b"123456").hexdigest())
        assert run_tool("hash_weak", hashlib.sha256(b"password").hexdigest())

    def test_find_flags(self):
        flags = find_flags("结果：flag{abc_123} 后面还有 ctf{xyz}")
        assert "flag{abc_123}" in flags and "ctf{xyz}" in flags

    def test_tool_failure_is_silent(self):
        # 工具内部异常不应抛出
        assert run_tool("not_exist", "x") == []
        assert run_tool("magic", "no_such_file.bin") == []


class TestAutoChain:
    def test_nested_base64_then_hex(self):
        inner = b"flag{nested}".hex()                    # 先转 hex
        outer = base64.b64encode(inner.encode()).decode()  # 再 base64 套一层
        results = toolbox.auto_decode_chain(outer)
        assert any("flag{nested}" in r[0] for r in results)

    def test_double_base64(self):
        outer = base64.b64encode(base64.b64encode(b"flag{double}")).decode()
        results = toolbox.auto_decode_chain(outer, depth=3)
        assert any("flag{double}" in r[0] for r in results)

    def test_chain_is_recorded(self):
        outer = base64.b64encode(b"flag{x}".hex().encode()).decode()
        chains = [c for _, c in toolbox.auto_decode_chain(outer) if c]
        assert chains and all(isinstance(c, list) for c in chains)


# ======================================================================
# 题型识别
# ======================================================================
class TestClassifier:
    def test_base64_like_goes_crypto(self):
        r = classifier.classify(Challenge(content="ZmxhZ3tiYXNlNjR9" * 3))
        assert r["ctype"] in {"crypto", "misc"}

    def test_morse_signal(self):
        r = classifier.classify(Challenge(content=".... . .-.. .-.. --- / .-- --- .-. .-.. -.."))
        assert "疑似摩斯电码" in r["content_signals"]

    def test_web_keywords(self):
        r = classifier.classify(Challenge(title="SQL 注入", description="http://x?id=1 源码泄露"))
        assert r["ctype"] == "web"

    def test_reverse_keywords(self):
        r = classifier.classify(Challenge(title="CrackMe", description="逆向 apk ida 反编译"))
        assert r["ctype"] == "reverse"

    def test_plan_always_starts_with_auto_decode(self):
        plans = classifier.plan("misc")
        assert plans[0] == ["auto_decode"]
        assert len(plans) >= 3


# ======================================================================
# 知识库
# ======================================================================
class TestKnowledgeBase:
    def _kb(self, tmp_path) -> KnowledgeBase:
        return KnowledgeBase(tmp_path / "kb.db")

    def test_add_dedupe_and_reinforce(self, tmp_path):
        kb = self._kb(tmp_path)
        try:
            from ctf import KnowledgeCard
            card = KnowledgeCard(title="base64 起手", kind="recipe",
                                 challenge_type="crypto", content="base64 可解此类题")
            cid1 = kb.add(card)
            cid2 = kb.add(card)                      # 同指纹 → 强化而非新增
            assert cid1 == cid2
            assert kb.stats()["cards"] == 1
            before = kb.search("base64")[0]["confidence"]
            kb.reinforce(cid1, success=True)
            assert kb.search("base64")[0]["confidence"] > before
            kb.reinforce(cid1, success=False)
            assert kb.search("base64")[0]["fail_count"] == 1
        finally:
            kb.close()

    def test_fingerprint_stability(self):
        a = fingerprint_of("recipe", "crypto", "base64 -> hex")
        b = fingerprint_of("recipe", "crypto", "BASE64 ->   HEX")
        assert a == b

    def test_search_and_stats(self, tmp_path):
        kb = self._kb(tmp_path)
        try:
            from ctf import KnowledgeCard
            kb.add(KnowledgeCard(title="摩斯电码识别", kind="pattern",
                                 challenge_type="misc", content="点划组成的短串优先试摩斯"))
            hits = kb.search("摩斯")
            assert hits and "摩斯" in hits[0]["title"]
            s = kb.stats()
            assert s["cards"] == 1 and s["runs"] == 0 and s["fts_enabled"] is True
        finally:
            kb.close()

    def test_extract_cards_on_success_and_failure(self):
        from ctf import SolveResult
        ok = SolveResult(challenge=Challenge(title="t", content="ZmxhZw=="),
                         ctype="crypto", status="solved", flag="flag{a}", chain=["base64"])
        cards = extract_cards(ok)
        assert any(c.kind == "recipe" for c in cards)
        bad = SolveResult(challenge=Challenge(title="t", content="????"),
                          ctype="misc", status="unsolved")
        bad.steps = []
        assert extract_cards(bad) == []              # 没试过任何工具 → 不产生噪音


# ======================================================================
# 解题闭环 + 自主学习
# ======================================================================
class TestSolver:
    def test_solve_base64_challenge(self, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.db")
        try:
            agent = CTFAgent(kb=kb)
            r = agent.solve(Challenge(title="签到", content="ZmxhZ3toZWxsb19jdGZ9"))
            assert r.status == "solved"
            assert r.flag == "flag{hello_ctf}"
            assert "base64" in r.chain or r.chain
        finally:
            kb.close()

    def test_solve_nested_encoding(self, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.db")
        try:
            payload = base64.b64encode(b"flag{deep}".hex().encode()).decode()
            r = CTFAgent(kb=kb).solve(Challenge(title="套娃", content=payload))
            assert r.status == "solved" and r.flag == "flag{deep}"
        finally:
            kb.close()

    def test_learning_loop_recalls_next_time(self, tmp_path):
        """核心验证：第一次解题后知识入库，第二次同题型应召回历史经验。"""
        kb = KnowledgeBase(tmp_path / "kb.db")
        try:
            agent = CTFAgent(kb=kb)
            first = agent.solve(Challenge(title="签到", content="ZmxhZ3tsZWFybn0="))
            assert first.status == "solved"
            assert kb.stats()["cards"] >= 1
            assert first.kb_hits == []               # 首次没有先验

            second = agent.solve(Challenge(title="签到2", content="ZmxhZ3thZ2Fpbn0="))
            assert second.status == "solved"
            assert second.kb_hits, "第二次应召回历史知识卡（自主学习闭环）"
            assert kb.stats()["runs"] == 2
        finally:
            kb.close()

    def test_no_learn_keeps_kb_empty(self, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.db")
        try:
            agent = CTFAgent(kb=kb, learn=False)
            agent.solve(Challenge(title="t", content="ZmxhZ3t4fQ=="))
            assert kb.stats()["cards"] == 0
        finally:
            kb.close()

    def test_unsolved_still_records_trace(self, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.db")
        try:
            r = CTFAgent(kb=kb).solve(Challenge(title="怪题", content="§¶∆∆§¶"))
            assert r.status in {"unsolved", "solved"}
            assert r.steps, "无论成败都应保留解题轨迹"
        finally:
            kb.close()

    def test_llm_failure_degrades_silently(self, tmp_path):
        kb = KnowledgeBase(tmp_path / "kb.db")
        def boom(system: str, user: str) -> str:
            raise RuntimeError("模拟接口不可用")
        try:
            agent = CTFAgent(kb=kb, use_llm=True, llm_call=boom)
            r = agent.solve(Challenge(title="t", content="§¶∆∆§¶"))
            assert r.status in {"unsolved", "solved"}
            assert any("LLM 降级" in n for n in r.notes)
        finally:
            kb.close()


# ======================================================================
# 命令行
# ======================================================================
class TestCLI:
    def test_selftest(self, capsys):
        assert main(["selftest"]) == 0

    def test_solve_and_kb(self, tmp_path, capsys):
        db = str(tmp_path / "cli.db")
        rc = main(["--db", db, "solve", "--text", "ZmxhZ3tjbGl9"])
        assert rc == 0
        assert "flag{cli}" in capsys.readouterr().out

        assert main(["--db", db, "kb", "stats"]) == 0
        out = capsys.readouterr().out
        assert '"cards"' in out

    def test_demo_runs(self, tmp_path, capsys):
        assert main(["--db", str(tmp_path / "demo.db"), "demo"]) == 0
        out = capsys.readouterr().out
        assert "第二轮" in out and "自主学习闭环生效" in out

    def test_tools_listing(self, capsys):
        assert main(["tools"]) == 0
        assert "工具总数" in capsys.readouterr().out

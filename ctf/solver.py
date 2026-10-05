"""CTF 解题 Agent：按题型规划工具链，执行、反思、并把经验沉淀进本地知识库。

设计原则（与 SentinelFlow 一致）
--------------------------------
- **默认离线**：不调大模型也能解题（覆盖编码/古典密码/哈希/异或等常见题型）。
- **确定性**：同样的题、同样的知识库状态，结果可复现。
- **可解释**：保留完整 steps 轨迹，每一步的输入输出与耗时都记录。
- **会学习**：每次解题（无论成败）都提炼知识卡入库，下次优先召回高分经验。
- **可降级**：LLM 作为可选增强；不可用时静默跳过，不报错。
"""
from __future__ import annotations

import time
from typing import Any, Callable, Iterable

from . import classifier, toolbox
from .knowledge import KnowledgeBase, remember
from .models import (Challenge, SolveResult, Step, find_flags, english_score,
                     best_flag, flag_confidence, HIGH_CONFIDENCE)

LLMCall = Callable[[str, str], str]

MAX_PLANS = 14
MAX_CANDIDATES = 12


class CTFAgent:
    """一个会自己解题、也会自己记笔记的 CTF Agent。"""

    def __init__(self, kb: KnowledgeBase | None = None, *,
                 use_llm: bool = False, llm_call: LLMCall | None = None,
                 learn: bool = True):
        self.kb = kb
        self.use_llm = use_llm and llm_call is not None
        self.llm_call = llm_call
        self.learn = learn

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def solve(self, challenge: Challenge, *, learn: bool | None = None) -> SolveResult:
        t0 = time.time()
        learn = self.learn if learn is None else learn
        result = SolveResult(challenge=challenge)

        # 1) 分类
        cls = classifier.classify(challenge)
        result.ctype = cls["ctype"]
        challenge.ctype = cls["ctype"]
        result.notes.append(f"题型判定：{cls['ctype']}（依据：{cls['scores']}）")
        result.notes.extend(cls["content_signals"])

        # 2) 先查知识库（先验经验优先）
        if self.kb is not None:
            hits = self.kb.recall_for(challenge, cls["ctype"], limit=3)
            result.kb_hits = [h["id"] for h in hits]
            if hits:
                result.notes.append(
                    "召回历史经验：" + "；".join(f"#{h['id']} {h['title']}（置信度 {h['confidence']:.2f}）"
                                                for h in hits))
                # 把高分经验的工具链提前
                preferred: list[list[str]] = []
                for h in hits:
                    chain = (h.get("payload") or {}).get("chain")
                    if isinstance(chain, list) and chain:
                        preferred.append([str(x) for x in chain])
                plans = preferred + classifier.plan(cls["ctype"], challenge.content)
            else:
                plans = classifier.plan(cls["ctype"], challenge.content)
        else:
            plans = classifier.plan(cls["ctype"], challenge.content)

        # 3) 依次执行方案；每个方案内逐工具递进
        seen_candidates: list[str] = []
        best_seen: tuple[float, str, list[str]] = (0.0, "", [])
        dedup_plans: list[list[str]] = []
        for p in plans:
            if p not in dedup_plans:
                dedup_plans.append(p)

        for idx, plan in enumerate(dedup_plans[:MAX_PLANS]):
            if result.status == "solved":
                break
            outputs, steps = self._run_chain(challenge, plan)
            result.steps.extend(steps)
            for out in outputs:
                if out not in seen_candidates:
                    seen_candidates.append(out)

            # 弱口令命中：哈希题的"flag"就是明文口令
            weak = self._weak_hits(outputs)
            if weak:
                result.flag = weak[0]
                result.chain = plan
                result.status = "solved"
                result.flag_confidence = 1.0        # 字典命中是确定性结论
                result.notes.append(f"第 {idx + 1} 套方案 {'→'.join(plan)} 命中弱口令：{weak[0]}")
                break

            flags = self._flags_from(outputs)
            if flags:
                best = best_flag(flags)
                conf = flag_confidence(best)
                if conf > best_seen[0]:
                    best_seen = (conf, best, plan)
                if conf >= HIGH_CONFIDENCE:
                    result.flag, result.chain = best, plan
                    result.flag_confidence = conf
                    result.status = "solved"
                    result.notes.append(
                        f"第 {idx + 1} 套方案 {'→'.join(plan)} 命中高可信 flag（置信度 {conf}）")
                    break
                result.notes.append(
                    f"方案 {'→'.join(plan)} 得到低可信候选 {best}（{conf}），继续验证其他方案")
                continue
            result.notes.append(f"方案 {'→'.join(plan)} 未命中，继续下一套")

        # 原始文本里的 flag 兜底扫描
        if result.status != "solved":
            direct = self._flags_from([challenge.blob()])
            if direct:
                best = best_flag(direct)
                conf = flag_confidence(best)
                if conf > best_seen[0]:
                    best_seen = (conf, best, ["flag_scan"])
                if conf >= HIGH_CONFIDENCE:
                    result.flag, result.chain = best, ["flag_scan"]
                    result.flag_confidence = conf
                    result.status = "solved"
                    result.notes.append(f"在题目原文中直接命中 flag（置信度 {conf}）")

        # 所有方案都没有高可信结果时，退而采用分最高的低可信候选
        if result.status != "solved" and best_seen[0] > 0:
            conf, flag, chain = best_seen
            result.flag, result.chain = flag, chain
            result.flag_confidence = conf
            result.status = "solved"
            result.notes.append(f"采用最佳低可信候选 {flag}（{conf}），标记为需人工复核")
            result.needs_review = True

        # 4) 反思：LLM 兜底（可选，不可用则跳过）
        if result.status != "solved" and self.use_llm and self.llm_call:
            try:
                advice = self.llm_call(
                    "你是 CTF 解题助手。只输出 JSON，字段为 ctype、next_tools、reason。",
                    f"题目：{challenge.title}\n{challenge.description}\n{challenge.content[:500]}\n"
                    f"已尝试工具：{[s.tool for s in result.steps]}",
                )
                result.notes.append(f"LLM 建议：{advice[:200]}")
            except Exception as exc:                       # LLM 失败不影响主流程
                result.notes.append(f"LLM 降级（{type(exc).__name__}）：改用纯离线策略")

        result.candidates = sorted(seen_candidates, key=english_score, reverse=True)[:MAX_CANDIDATES]
        result.elapsed_ms = int((time.time() - t0) * 1000)

        # 5) 沉淀知识（无论成败）
        if learn and self.kb is not None:
            ids = remember(self.kb, result)
            if ids:
                result.notes.append(f"已沉淀 {len(ids)} 张知识卡到本地知识库：{ids}")
        return result

    def solve_batch(self, challenges: Iterable[Challenge], **kw: Any) -> list[SolveResult]:
        return [self.solve(c, **kw) for c in challenges]

    # ------------------------------------------------------------------
    # 内部：工具链执行
    # ------------------------------------------------------------------
    def _run_chain(self, challenge: Challenge, plan: list[str]) -> tuple[list[str], list[Step]]:
        steps: list[Step] = []
        current: list[str] = [challenge.content or challenge.blob()]
        for name in plan:
            nxt: list[str] = []
            st = Step(tool=name)
            s0 = time.time()
            for text in current:
                if name == "auto_decode":
                    for out, chain in toolbox.auto_decode_chain(text):
                        st.outputs.append(out)
                        nxt.append(out)
                        if chain:
                            st.note = "自动套娃解码命中链：" + "→".join(chain)
                else:
                    outs = toolbox.run_tool(name, text) if name != "magic" else []
                    if name == "magic":
                        for f in challenge.files:
                            outs = toolbox.run_tool("magic", f)
                            st.outputs.extend(outs)
                    for o in outs:
                        st.outputs.append(o)
                        nxt.append(o)
            st.elapsed_ms = int((time.time() - s0) * 1000)
            st.ok = bool(nxt)
            steps.append(st)
            if not nxt:
                break
            # 控制候选爆炸
            current = sorted(set(nxt), key=english_score, reverse=True)[:MAX_CANDIDATES]
        return current, steps

    @staticmethod
    def _flags_from(outputs: Iterable[str]) -> list[str]:
        flags: list[str] = []
        for o in outputs:
            for f in find_flags(o):
                if f not in flags:
                    flags.append(f)
        return flags

    @staticmethod
    def _weak_hits(outputs: Iterable[str]) -> list[str]:
        """从 hash_weak 的输出里提取明文口令。"""
        hits: list[str] = []
        for o in outputs:
            if o.startswith("弱口令命中："):
                pw = o.split("：", 1)[1].strip()
                if pw and pw not in hits:
                    hits.append(pw)
        return hits


# ======================================================================
# 便捷函数
# ======================================================================
def quick_solve(text: str, title: str = "临时题目", *, db_path: str | None = None,
                learn: bool = True) -> SolveResult:
    """一行解题：给一段文本，返回结果（并默认沉淀进知识库）。"""
    kb = KnowledgeBase(db_path) if learn else None
    try:
        agent = CTFAgent(kb=kb, learn=learn)
        return agent.solve(Challenge(title=title, content=text))
    finally:
        if kb is not None:
            kb.close()


def format_result(r: SolveResult) -> str:
    """人类可读的结果摘要。"""
    icon = {"solved": "✅", "unsolved": "❌", "error": "⚠️"}.get(r.status, "•")
    if r.status == "solved" and r.needs_review:
        icon = "🟡"
    line1 = f"{icon} {r.challenge.title or '(untitled)'}　题型：{r.ctype}　耗时：{r.elapsed_ms} ms"
    line2 = f"   状态：{r.status}"
    if r.flag:
        line2 += f"　flag：{r.flag}（置信度 {r.flag_confidence}）"
        if r.needs_review:
            line2 += "　⚠️ 低可信，需人工复核"
    lines = [line1, line2]
    if r.chain:
        lines.append(f"   命中链：{' → '.join(r.chain)}")
    if r.kb_hits:
        lines.append(f"   知识库命中：{r.kb_hits}")
    if r.steps:
        lines.append("   轨迹：" + " | ".join(
            f"{s.tool}({'✓' if s.ok else '✗'}{len(s.outputs)})" for s in r.steps))
    for n in r.notes[-4:]:
        lines.append(f"   · {n}")
    return "\n".join(lines)

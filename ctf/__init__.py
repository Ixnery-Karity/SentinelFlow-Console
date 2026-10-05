"""CTF Agent —— 会自己解题、也会自己记笔记。

用法::

    from ctf import CTFAgent, KnowledgeBase, Challenge

    kb = KnowledgeBase()                     # 本地知识库（SQLite）
    agent = CTFAgent(kb=kb)                  # 默认离线，不依赖大模型
    result = agent.solve(Challenge(title="签到", content="ZmxhZ3tiYXNlNjR9"))
    print(result.status, result.flag)

命令行::

    python -m ctf demo
    python -m ctf solve --text "ZmxhZ3tiYXNlNjR9"
    python -m ctf kb search base64
    python -m ctf kb stats
"""
from __future__ import annotations

from .knowledge import KnowledgeBase, extract_cards, remember
from .models import Challenge, KnowledgeCard, SolveResult, Step, find_flags
from .solver import CTFAgent, format_result, quick_solve
from .toolbox import TOOLS, run_tool, tool_catalog

__version__ = "1.0.0"

__all__ = [
    "CTFAgent", "KnowledgeBase", "Challenge", "KnowledgeCard", "SolveResult", "Step",
    "find_flags", "format_result", "quick_solve", "extract_cards", "remember",
    "TOOLS", "run_tool", "tool_catalog", "__version__",
]

"""CTF Agent 命令行入口：python -m ctf <command>"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

# 允许 `python -m ctf` 在 DAY15 根目录直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf import (CTFAgent, Challenge, KnowledgeBase, format_result,  # noqa: E402
                 tool_catalog)
from ctf.knowledge import DEFAULT_DB  # noqa: E402

DEMO_CASES = [
    Challenge(title="签到 · Base64", content="ZmxhZ3tiYXNlNjRfaXNfZWFzeX0="),
    Challenge(title="套娃编码（Base64 里套中文）", content="5L2g5aW977yMZmxhZ3tjaGFpbl9kZWNvZGV9"),
    Challenge(title="十六进制", content="666c61677b6865785f6465636f64655f6f6b7d"),
    Challenge(title="凯撒密码（位移 3）", content="iodj{fdhvdu}"),
    Challenge(title="ROT13", content="synt{ebg13_bx}"),
    Challenge(title="二进制", content="01100110 01101100 01100001 01100111 01111011 "
                                     "01100010 01101001 01101110 01100001 01110010 "
                                     "01111001 01111101"),
    Challenge(title="十进制 ASCII", content="102 108 97 103 123 97 115 99 105 105 125"),
    Challenge(title="单字节 XOR（密钥 0x2A）", content=bytes(b ^ 0x2A for b in b"flag{xor}").hex()),
    Challenge(title="MD5 弱口令", content="e10adc3949ba59abbe56e057f20f883e"),
    Challenge(title="字符串倒序", content="}esrever{galf"),
]


def _read(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"文件不存在：{path}")
    return p.read_text(encoding="utf-8", errors="replace")


def cmd_solve(args: argparse.Namespace) -> int:
    content = args.text or (_read(args.file) if args.file else "")
    if not content:
        raise SystemExit("请用 --text 或 --file 指定题目内容")
    kb = KnowledgeBase(args.db)
    agent = CTFAgent(kb=kb, use_llm=args.llm, learn=not args.no_learn)
    result = agent.solve(Challenge(title=args.title, content=content,
                                   files=args.attach or []))
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_result(result))
    kb.close()
    return 0 if result.status == "solved" else 1


def cmd_demo(args: argparse.Namespace) -> int:
    kb = KnowledgeBase(args.db)
    agent = CTFAgent(kb=kb)
    solved = 0
    print("=" * 72)
    print("第 1 轮：冷启动（知识库为空）")
    print("=" * 72)
    for c in DEMO_CASES:
        r = agent.solve(c)
        print(format_result(r))
        print("-" * 72)
        solved += r.status == "solved"
    print(f"首轮解出 {solved}/{len(DEMO_CASES)}")

    print()
    print("=" * 72)
    print("第 2 轮：同样的题再解一次（此时知识库已积累经验，应命中历史知识）")
    print("=" * 72)
    hit = 0
    for c in DEMO_CASES:
        r = agent.solve(Challenge(title=c.title, content=c.content))
        if r.kb_hits:
            hit += 1
    print(f"第二轮有 {hit}/{len(DEMO_CASES)} 道题成功召回了历史经验（自主学习闭环生效）")

    print()
    print("知识库统计：")
    print(json.dumps(kb.stats(), ensure_ascii=False, indent=2))
    kb.close()
    return 0


def cmd_kb(args: argparse.Namespace) -> int:
    kb = KnowledgeBase(args.db)
    try:
        if args.kb_cmd == "search":
            rows = kb.search(args.query, limit=args.limit)
            if not rows:
                print("（无匹配知识卡）")
            for r in rows:
                print(f"#{r['id']} [{r['kind']}/{r['challenge_type']}] {r['title']}")
                print(f"    置信度 {r['confidence']:.2f}　成功 {r['success_count']} / 失败 {r['fail_count']}")
                print(f"    {r['content'][:160]}")
        elif args.kb_cmd == "list":
            for r in kb.all_cards(limit=args.limit):
                print(f"#{r['id']} [{r['kind']}/{r['challenge_type']}] {r['title']}  "
                      f"(conf={r['confidence']:.2f}, ok={r['success_count']})")
        elif args.kb_cmd == "stats":
            print(json.dumps(kb.stats(), ensure_ascii=False, indent=2))
    finally:
        kb.close()
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    cat = tool_catalog()
    by = {}
    for t in cat:
        by.setdefault(t["category"], []).append(t)
    for c, items in by.items():
        print(f"\n【{c}】共 {len(items)} 个")
        for t in items:
            need = f"　触发条件：{t['needs']}" if t["needs"] else ""
            print(f"  - {t['name']:<16} {t['desc']}{need}")
    print(f"\n工具总数：{len(cat)}")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """快速自检：核心工具箱是否可用。"""
    checks = [
        ("base64", "ZmxhZ3thfQ==", "flag{a}"),
        ("hex", "666c61677b627d", "flag{b}"),
        ("rot13", "synt{p}", "flag{c}"),
    ]
    ok = 0
    for name, inp, expect in checks:
        from ctf import run_tool
        outs = run_tool(name, inp)
        passed = expect in outs
        ok += passed
        print(f"{'✓' if passed else '✗'} {name}: {outs[:2]}  (期望 {expect})")
    print(f"自检通过 {ok}/{len(checks)}")
    return 0 if ok == len(checks) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ctf", description="CTF 解题 Agent（离线优先，带本地知识库）")
    p.add_argument("--db", default=None, help=f"知识库路径（默认 {DEFAULT_DB}）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("solve", help="解一道题")
    s.add_argument("--text", default="", help="题目内容")
    s.add_argument("--file", default="", help="从文件读入题目内容")
    s.add_argument("--title", default="", help="题目标题")
    s.add_argument("--attach", nargs="*", default=[], help="附件路径（用于文件头识别）")
    s.add_argument("--llm", action="store_true", help="启用 LLM 兜底（需配置环境变量）")
    s.add_argument("--no-learn", action="store_true", help="本次不写入知识库")
    s.add_argument("--json", action="store_true", help="以 JSON 输出")
    s.set_defaults(func=cmd_solve)

    d = sub.add_parser("demo", help="跑内置样例，演示自主学习闭环")
    d.set_defaults(func=cmd_demo)

    k = sub.add_parser("kb", help="知识库操作")
    ksub = k.add_subparsers(dest="kb_cmd", required=True)
    ks = ksub.add_parser("search", help="检索知识卡")
    ks.add_argument("query")
    ks.add_argument("--limit", type=int, default=5)
    ks.set_defaults(func=cmd_kb)
    kl = ksub.add_parser("list", help="列出知识卡")
    kl.add_argument("--limit", type=int, default=30)
    kl.set_defaults(func=cmd_kb)
    kst = ksub.add_parser("stats", help="统计信息")
    kst.set_defaults(func=cmd_kb)

    t = sub.add_parser("tools", help="列出工具箱")
    t.set_defaults(func=cmd_tools)

    st = sub.add_parser("selftest", help="工具箱自检")
    st.set_defaults(func=cmd_selftest)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())

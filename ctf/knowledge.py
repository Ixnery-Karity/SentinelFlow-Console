"""本地知识库：把每次解题沉淀的知识卡存下来，下次优先召回。

设计要点
--------
1. **零外部依赖**：只用标准库 sqlite3；FTS5 提供全文检索（中文用 trigram 分词）。
2. **幂等写入**：以 ``fingerprint`` 做唯一键，同一知识点重复出现只累加置信度，不产生重复行。
3. **可学习**：``reinforce`` 按成功/失败调整 ``confidence``，越用越准。
4. **可迁移**：整个库就是一个 .db 文件，拷走即用。
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from .models import Challenge, KnowledgeCard, SolveResult

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "ctf_knowledge.db"

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cards (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint    TEXT UNIQUE,
    title          TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'recipe',
    challenge_type TEXT NOT NULL DEFAULT 'unknown',
    content        TEXT NOT NULL DEFAULT '',
    payload        TEXT NOT NULL DEFAULT '{}',
    tags           TEXT NOT NULL DEFAULT '',
    success_count  INTEGER NOT NULL DEFAULT 0,
    fail_count     INTEGER NOT NULL DEFAULT 0,
    confidence     REAL    NOT NULL DEFAULT 0.5,
    created_at     REAL,
    updated_at     REAL
);

CREATE TABLE IF NOT EXISTS solves (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL,
    title      TEXT,
    ctype      TEXT,
    status     TEXT,
    flag       TEXT,
    chain      TEXT,
    elapsed_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_cards_type ON cards(challenge_type);
CREATE INDEX IF NOT EXISTS idx_cards_kind ON cards(kind);
CREATE INDEX IF NOT EXISTS idx_solves_ts  ON solves(ts);
"""

_FTS_TRIGRAM = """
CREATE VIRTUAL TABLE IF NOT EXISTS cards_fts USING fts5(
    title, content, tags,
    content='cards', content_rowid='id', tokenize='trigram'
);
CREATE TRIGGER IF NOT EXISTS cards_ai AFTER INSERT ON cards BEGIN
  INSERT INTO cards_fts(rowid, title, content, tags)
  VALUES (new.id, new.title, new.content, new.tags);
END;
CREATE TRIGGER IF NOT EXISTS cards_ad AFTER DELETE ON cards BEGIN
  INSERT INTO cards_fts(cards_fts, rowid, title, content, tags)
  VALUES ('delete', old.id, old.title, old.content, old.tags);
END;
CREATE TRIGGER IF NOT EXISTS cards_au AFTER UPDATE ON cards BEGIN
  INSERT INTO cards_fts(cards_fts, rowid, title, content, tags)
  VALUES ('delete', old.id, old.title, old.content, old.tags);
  INSERT INTO cards_fts(rowid, title, content, tags)
  VALUES (new.id, new.title, new.content, new.tags);
END;
"""


def fingerprint_of(kind: str, ctype: str, key: str) -> str:
    normalized = re.sub(r"\s+", "", (key or "").lower())
    raw = f"{kind}|{ctype}|{normalized}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


class KnowledgeBase:
    """CTF 知识库。"""

    def __init__(self, path: str | Path | None = None, *, use_fts: bool = True):
        self.path = Path(path) if path else DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.has_fts = False
        if use_fts:
            try:
                self.conn.executescript(_FTS_TRIGRAM)
                self.has_fts = True
            except sqlite3.OperationalError:
                self.has_fts = False
        self.conn.commit()

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def add(self, card: KnowledgeCard) -> int:
        """新增或强化一张知识卡，返回 id。同指纹只累加，不重复插入。"""
        fp = card.fingerprint or fingerprint_of(card.kind, card.challenge_type, card.title)
        now = time.time()
        row = self.conn.execute("SELECT id, success_count, confidence FROM cards WHERE fingerprint=?",
                                (fp,)).fetchone()
        payload = json.dumps(card.payload, ensure_ascii=False)
        tags = " ".join(card.tags)
        if row:
            cid = row["id"]
            self.conn.execute(
                """UPDATE cards SET title=?, challenge_type=?, content=?, payload=?, tags=?,
                   success_count=success_count+1,
                   confidence=MIN(1.0, confidence*0.7 + 0.3),
                   updated_at=? WHERE id=?""",
                (card.title, card.challenge_type, card.content, payload, tags, now, cid))
        else:
            cur = self.conn.execute(
                """INSERT INTO cards (fingerprint, title, kind, challenge_type, content, payload,
                       tags, success_count, fail_count, confidence, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fp, card.title, card.kind, card.challenge_type, card.content, payload,
                 tags, card.success_count, card.fail_count, card.confidence, now, now))
            cid = int(cur.lastrowid or 0)
        self.conn.commit()
        return cid

    def reinforce(self, card_id: int, success: bool) -> None:
        """按实战结果调整置信度：成功上调、失败下调，并记录次数。"""
        if success:
            self.conn.execute(
                "UPDATE cards SET success_count=success_count+1, "
                "confidence=MIN(1.0, confidence+0.1), updated_at=? WHERE id=?",
                (time.time(), card_id))
        else:
            self.conn.execute(
                "UPDATE cards SET fail_count=fail_count+1, "
                "confidence=MAX(0.0, confidence-0.15), updated_at=? WHERE id=?",
                (time.time(), card_id))
        self.conn.commit()

    def record_solve(self, result: SolveResult) -> int:
        cur = self.conn.execute(
            "INSERT INTO solves (ts, title, ctype, status, flag, chain, elapsed_ms) VALUES (?,?,?,?,?,?,?)",
            (time.time(), result.challenge.title or "(untitled)", result.ctype,
             result.status, result.flag, ">".join(result.chain), result.elapsed_ms))
        self.conn.commit()
        return int(cur.lastrowid or 0)

    # ------------------------------------------------------------------
    # 检索
    # ------------------------------------------------------------------
    def search(self, query: str, limit: int = 5, challenge_type: str | None = None) -> list[dict[str, Any]]:
        """全文检索知识卡；中文用 trigram，短查询退化为 LIKE。"""
        q = (query or "").strip()
        rows: Iterable[sqlite3.Row]
        if not q:
            sql = "SELECT * FROM cards"
            args: list[Any] = []
            if challenge_type:
                sql += " WHERE challenge_type=?"
                args.append(challenge_type)
            sql += " ORDER BY confidence DESC, success_count DESC LIMIT ?"
            args.append(limit)
            rows = self.conn.execute(sql, args).fetchall()
        else:
            rows = []
            if self.has_fts and len(q) >= 3:
                try:
                    sql = ("SELECT c.* FROM cards_fts f JOIN cards c ON c.id=f.rowid "
                           "WHERE cards_fts MATCH ?")
                    args = [q]
                    if challenge_type:
                        sql += " AND c.challenge_type=?"
                        args.append(challenge_type)
                    sql += " ORDER BY rank LIMIT ?"
                    args.append(limit)
                    rows = self.conn.execute(sql, args).fetchall()
                except sqlite3.OperationalError:
                    rows = []
            if not rows:
                like = f"%{q}%"
                sql = ("SELECT * FROM cards WHERE (title LIKE ? OR content LIKE ? OR tags LIKE ?)")
                args = [like, like, like]
                if challenge_type:
                    sql += " AND challenge_type=?"
                    args.append(challenge_type)
                sql += " ORDER BY confidence DESC, success_count DESC LIMIT ?"
                args.append(limit)
                rows = self.conn.execute(sql, args).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def recall_for(self, challenge: Challenge, ctype: str, limit: int = 3) -> list[dict[str, Any]]:
        """针对一道题召回先验知识：先按题型+信号检索，再退回该题型的通用卡片。"""
        hits: list[dict[str, Any]] = []
        probe = " ".join(filter(None, [challenge.title, challenge.description[:80]]))
        for q in (probe, ctype):
            for r in self.search(q, limit=limit, challenge_type=ctype):
                if r["id"] not in {h["id"] for h in hits}:
                    hits.append(r)
        if len(hits) < limit:
            for r in self.search("", limit=limit, challenge_type=ctype):
                if r["id"] not in {h["id"] for h in hits}:
                    hits.append(r)
        return hits[:limit]

    def all_cards(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM cards ORDER BY confidence DESC, success_count DESC LIMIT ?",
            (limit,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        total = self.conn.execute("SELECT COUNT(*) n FROM cards").fetchone()["n"]
        solved = self.conn.execute("SELECT COUNT(*) n FROM solves WHERE status='solved'").fetchone()["n"]
        runs = self.conn.execute("SELECT COUNT(*) n FROM solves").fetchone()["n"]
        by_kind = {r["kind"]: r["n"] for r in
                   self.conn.execute("SELECT kind, COUNT(*) n FROM cards GROUP BY kind")}
        by_type = {r["challenge_type"]: r["n"] for r in
                   self.conn.execute("SELECT challenge_type, COUNT(*) n FROM cards GROUP BY challenge_type")}
        top = self.conn.execute(
            "SELECT title, confidence, success_count FROM cards "
            "ORDER BY confidence DESC, success_count DESC LIMIT 5").fetchall()
        return {
            "cards": total,
            "runs": runs,
            "solved": solved,
            "solve_rate": round(solved / runs, 3) if runs else 0.0,
            "by_kind": by_kind,
            "by_type": by_type,
            "top_cards": [dict(r) for r in top],
            "fts_enabled": self.has_fts,
            "db": str(self.path),
        }

    @staticmethod
    def _row_to_dict(r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.get("payload") or "{}")
        except json.JSONDecodeError:
            d["payload"] = {}
        return d

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "KnowledgeBase":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ======================================================================
# 自主学习：从解题轨迹提炼知识
# ======================================================================
def extract_cards(result: SolveResult) -> list[KnowledgeCard]:
    """把一次解题变成若干张知识卡。

    - 成功 → recipe（可用工具链）+ pattern（题型特征 → 链）
    - 失败 → pitfall（试过但没用的链，避免下次重复踩坑）
    """
    cards: list[KnowledgeCard] = []
    ctype = result.ctype or "unknown"
    chain_str = ">".join(result.chain)
    tried = [s.tool for s in result.steps]

    if result.status == "solved" and result.chain:
        cards.append(KnowledgeCard(
            title=f"[{ctype}] {'→'.join(result.chain)} 可解此类题",
            kind="recipe",
            challenge_type=ctype,
            content=(f"题型：{ctype}；工具链：{chain_str}；"
                     f"题目特征：{_signature(result.challenge)}；"
                     f"命中 flag：{result.flag[:60]}"),
            payload={"chain": result.chain, "flag": result.flag},
            tags=[ctype, *result.chain, "recipe"],
            fingerprint=fingerprint_of("recipe", ctype, chain_str),
            confidence=0.7,
        ))
        cards.append(KnowledgeCard(
            title=f"[{ctype}] 特征识别 → 首选 {result.chain[0]}",
            kind="pattern",
            challenge_type=ctype,
            content=(f"当题目呈现「{_signature(result.challenge)}」特征时，"
                     f"优先尝试 {result.chain[0]} 起手。"),
            payload={"first_tool": result.chain[0], "signals": result.notes[:3]},
            tags=[ctype, result.chain[0], "pattern"],
            fingerprint=fingerprint_of("pattern", ctype, _signature(result.challenge)),
            confidence=0.6,
        ))
    else:
        if tried:
            cards.append(KnowledgeCard(
                title=f"[{ctype}] {'+'.join(tried[:4])} 未能解出（待补充思路）",
                kind="pitfall",
                challenge_type=ctype,
                content=(f"题型：{ctype}；已尝试：{tried}；题目特征："
                         f"{_signature(result.challenge)}；结论：该组合不足，需换思路或补工具。"),
                payload={"tried": tried},
                tags=[ctype, "pitfall", *tried[:3]],
                fingerprint=fingerprint_of("pitfall", ctype, "+".join(tried[:4])),
                confidence=0.4,
            ))
    return cards


def remember(kb: KnowledgeBase, result: SolveResult) -> list[int]:
    """把一次解题全部沉淀进知识库，返回知识卡 id 列表。"""
    ids: list[int] = []
    for card in extract_cards(result):
        cid = kb.add(card)
        kb.reinforce(cid, success=(result.status == "solved"))
        ids.append(cid)
    kb.record_solve(result)
    for hit in result.kb_hits:
        kb.reinforce(hit, success=(result.status == "solved"))
    return ids


def _signature(challenge: Challenge) -> str:
    """题目的短特征串：优先用内容形态，其次用标题。"""
    c = (challenge.content or "").strip()
    if c:
        head = re.sub(r"\s+", "", c)[:40]
        return head
    return (challenge.title or "")[:40] or "(无特征)"

#!/usr/bin/env python3
"""Web 常见路径探测（真实发起请求，零第三方依赖）。

用法::

    python scripts/dir_probe.py --base http://127.0.0.1:8000

仅请求少量低风险路径并记录状态码，不进行暴力枚举、不发送攻击载荷。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# 低风险、通用的探测路径（不是字典爆破）
DEFAULT_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/api/health", "/api/healthz", "/health", "/status",
    "/login", "/admin", "/static/", "/.well-known/security.txt",
]


def probe(base: str, paths: list[str], timeout: float) -> dict:
    base = base.rstrip("/")
    findings: list[dict] = []
    t0 = time.time()
    for path in paths:
        url = base + path
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelFlow-Probe/1.0"})
        entry: dict = {"path": path, "url": url}
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                entry.update({"status": resp.status, "length": len(resp.read(4096)),
                              "content_type": resp.headers.get("Content-Type", "")})
        except urllib.error.HTTPError as exc:
            entry.update({"status": exc.code, "length": 0,
                          "content_type": (exc.headers or {}).get("Content-Type", "")})
        except (urllib.error.URLError, OSError, ValueError) as exc:
            entry.update({"status": None, "error": type(exc).__name__})
        findings.append(entry)

    interesting = [f for f in findings if f.get("status") in (200, 301, 302, 401, 403)]
    return {
        "base": base,
        "probed": len(paths),
        "findings": findings,
        "interesting": interesting,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "note": "低风险路径探测，非字典爆破；用于发现暴露的接口与说明文件",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Web 常见路径探测")
    ap.add_argument("--base", required=True, help="形如 http://127.0.0.1:8000")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--paths", default="", help="逗号分隔的自定义路径（可选）")
    args = ap.parse_args(argv)

    paths = [p.strip() for p in args.paths.split(",") if p.strip()] or DEFAULT_PATHS
    result = probe(args.base, paths, args.timeout)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

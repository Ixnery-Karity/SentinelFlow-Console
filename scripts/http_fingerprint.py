#!/usr/bin/env python3
"""HTTP 指纹与响应头抓取（真实发起请求，零第三方依赖）。

用法::

    python scripts/http_fingerprint.py --url http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
# 常见技术栈特征（响应头 / 正文关键字 → 技术名）
HEADER_SIGNS = {
    "server": "server",
    "x-powered-by": "powered-by",
    "x-aspnet-version": "aspnet",
    "set-cookie": "cookie",
    "x-drupal-cache": "drupal",
    "x-generator": "generator",
}
BODY_SIGNS = {
    "wp-content": "WordPress", "drupal": "Drupal", "react": "React",
    "vue": "Vue", "angular": "Angular", "__next_data__": "Next.js",
    "flask": "Flask", "django": "Django", "csrfmiddlewaretoken": "Django",
    "jquery": "jQuery", "bootstrap": "Bootstrap",
}

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
]


def fetch(url: str, timeout: float) -> dict:
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelFlow-Probe/1.0"})
    info: dict = {"url": url, "method": "GET"}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200_000).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            info.update({
                "status": resp.status,
                "reason": resp.reason,
                "final_url": resp.geturl(),
                "headers": headers,
            })
    except urllib.error.HTTPError as exc:
        body = ""
        info.update({"status": exc.code, "reason": str(exc.reason),
                     "headers": {k.lower(): v for k, v in (exc.headers or {}).items()}})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        info.update({"error": f"{type(exc).__name__}: {exc}", "elapsed_ms": int((time.time() - t0) * 1000)})
        return info

    tech: list[str] = []
    for key, tag in HEADER_SIGNS.items():
        if key in info.get("headers", {}) and tag not in tech:
            tech.append(tag)
    low = body.lower()
    for sig, name in BODY_SIGNS.items():
        if sig in low and name not in tech:
            tech.append(name)

    title = ""
    m = TITLE_RE.search(body)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    missing = [h for h in SECURITY_HEADERS if h not in info.get("headers", {})]

    info.update({
        "title": title,
        "tech_guesses": tech,
        "security_headers_missing": missing,
        "body_length": len(body),
        "elapsed_ms": int((time.time() - t0) * 1000),
        "note": "仅做被动指纹识别，未发送任何攻击载荷",
    })
    return info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HTTP 指纹抓取")
    ap.add_argument("--url", required=True)
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args(argv)
    result = fetch(args.url, args.timeout)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""纯 Python TCP 连接探测（替代 nmap 的最小实现，零第三方依赖）。

用法::

    python scripts/port_probe.py --target 127.0.0.1 --ports 22,80,8000

输出 JSON，便于被 Agent / 工作流直接消费。
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time

DEFAULT_PORTS = "22,80,443,3000,5000,8000,8080,8443"

# 端口 → 常见服务（仅用于结果可读性，不做指纹判定）
COMMON = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5000: "flask/upnp",
    5432: "postgresql", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            ports.extend(range(lo, min(hi, lo + 1024) + 1))
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return [p for p in dict.fromkeys(ports) if 0 < p < 65536]


def probe(target: str, ports: list[int], timeout: float) -> dict:
    open_ports: list[dict] = []
    closed = 0
    filtered = 0
    t0 = time.time()
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((target, port))
            if rc == 0:
                banner = ""
                try:
                    s.settimeout(min(timeout, 1.0))
                    s.sendall(b"\r\n")
                    banner = s.recv(128).decode("utf-8", errors="replace").strip()
                except (OSError, socket.timeout):
                    pass
                open_ports.append({
                    "port": port,
                    "service_guess": COMMON.get(port, "unknown"),
                    "banner": banner[:80],
                })
            else:
                closed += 1
        except socket.gaierror:
            return {"target": target, "error": "域名解析失败"}
        except (OSError, socket.timeout):
            filtered += 1
        finally:
            s.close()
    return {
        "target": target,
        "method": "tcp-connect",
        "ports_scanned": len(ports),
        "open": open_ports,
        "closed": closed,
        "filtered_or_timeout": filtered,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "note": "纯 Python 实现，不依赖 nmap；仅做 TCP 连接判定，不发送攻击载荷",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="纯 Python TCP 端口探测")
    ap.add_argument("--target", required=True)
    ap.add_argument("--ports", default=DEFAULT_PORTS)
    ap.add_argument("--timeout", type=float, default=0.8)
    ap.add_argument("--json-indent", type=int, default=2)
    args = ap.parse_args(argv)

    ports = parse_ports(args.ports)
    if not ports:
        print(json.dumps({"error": "没有可解析的端口"}, ensure_ascii=False))
        return 2
    result = probe(args.target, ports, args.timeout)
    print(json.dumps(result, ensure_ascii=False, indent=args.json_indent))
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())

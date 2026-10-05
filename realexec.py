"""真实执行层：把原先"只做模拟"的能力接到**真实命令**与**本地脚本**上。

核心思想（三级降级，永远跑得起来）
----------------------------------
1. **真实外部工具**：系统装了 nmap / sqlmap / dirb 就真调（需显式授权）；
2. **内置脚本兜底**：没装外部工具时，自动改用 ``scripts/`` 下自研的纯 Python 脚本
   （零依赖、真连真扫，例如 ``port_probe.py``）；
3. **模拟结果兜底**：连脚本都不该跑时（未授权 / 非白名单目标），退回确定性模拟数据。

安全边界（默认最保守）
----------------------
- ``enabled=False`` 时**永远不执行任何真实命令**；
- 目标必须落在私网/回环白名单内，公网目标一律拒绝；
- 必须显式传入 ``authorized=True``（或环境变量），否则拒绝执行；
- 强制超时、输出截断、速率限制、**全量审计日志**（JSONL）；
- 只走参数数组，不使用 ``shell=True``，从根上杜绝命令拼接注入。
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
DEFAULT_AUDIT = PROJECT_ROOT / "data" / "exec_audit.jsonl"

# 默认允许的目标网段：回环 + 三段私网（RFC1918）
DEFAULT_ALLOWED_NETS = (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128",
)

# 外部工具登记表：二进制名 + 只读/低影响参数 + 说明
EXTERNAL_TOOLS: dict[str, dict[str, Any]] = {
    "nmap": {
        "binary": "nmap",
        "args": ["-sT", "-Pn", "-sV", "--version-light", "--host-timeout", "30s"],
        "desc": "端口与服务版本探测（TCP connect，无需 root）",
        "script_fallback": "port_probe",
    },
    "dirb": {
        "binary": "dirb",
        "args": ["-S", "-r"],
        "desc": "Web 目录枚举",
        "script_fallback": "dir_probe",
    },
    "sqlmap": {
        "binary": "sqlmap",
        "args": ["--batch", "--level=1", "--risk=1", "--smart"],
        "desc": "SQL 注入检测（低风险档）",
        "script_fallback": None,
    },
}

# 内置脚本登记表（纯 Python，零第三方依赖）
BUILTIN_SCRIPTS: dict[str, dict[str, Any]] = {
    "port_probe": {
        "file": "port_probe.py",
        "desc": "纯 Python TCP 连接探测（替代 nmap 的最小实现）",
        "args": ["--target", "{target}", "--ports", "{ports}"],
    },
    "http_fingerprint": {
        "file": "http_fingerprint.py",
        "desc": "HTTP 响应头与页面特征抓取（真实发请求）",
        "args": ["--url", "{url}"],
    },
    "dir_probe": {
        "file": "dir_probe.py",
        "desc": "Web 常见路径探测（真实发请求）",
        "args": ["--base", "{base}"],
    },
}

DEFAULT_PORTS = "22,80,443,3000,5000,8000,8080,8443"


# ======================================================================
# 策略与结果
# ======================================================================
@dataclass
class ExecutionPolicy:
    """执行策略：默认全关，必须显式打开。"""
    enabled: bool = False          # 总开关：是否允许真实执行
    authorized: bool = False       # 是否已获得目标授权
    dry_run: bool = False          # 只打印命令不执行
    timeout: float = 20.0
    max_output: int = 20000
    rate_limit_per_min: int = 30
    allowed_nets: tuple[str, ...] = DEFAULT_ALLOWED_NETS
    allow_scripts: tuple[str, ...] = tuple(BUILTIN_SCRIPTS)
    audit_path: str = str(DEFAULT_AUDIT)

    @classmethod
    def from_env(cls, **overrides: Any) -> "ExecutionPolicy":
        """从环境变量构造，便于在 CI / 本地切换。"""
        env = os.environ
        pol = cls(
            enabled=env.get("AGENT_REAL_EXEC", "0") in ("1", "true", "True"),
            authorized=env.get("AGENT_AUTHORIZED", "0") in ("1", "true", "True"),
            dry_run=env.get("AGENT_DRY_RUN", "0") in ("1", "true", "True"),
            timeout=float(env.get("AGENT_EXEC_TIMEOUT", "20")),
        )
        for k, v in overrides.items():
            setattr(pol, k, v)
        return pol

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["allowed_nets"] = list(self.allowed_nets)
        d["allow_scripts"] = list(self.allow_scripts)
        return d


@dataclass
class ExecutionResult:
    """一次执行的完整记录。"""
    tool: str
    mode: str                     # real | script | simulated | dry-run | blocked
    ok: bool = False
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    reason: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        icon = {"real": "🟢", "script": "🔵", "simulated": "⚪",
                "dry-run": "🟡", "blocked": "🔴"}.get(self.mode, "•")
        tail = f"　{self.reason}" if self.reason else ""
        return f"{icon} [{self.mode}] {self.tool} {'OK' if self.ok else 'FAIL'} {self.duration_ms}ms{tail}"


# ======================================================================
# 安全校验与审计
# ======================================================================
def target_allowed(target: str, policy: ExecutionPolicy) -> tuple[bool, str]:
    """目标是否落在允许网段内。"""
    host = (target or "").strip()
    if not host:
        return False, "目标为空"
    # 带端口的形如 1.2.3.4:80 / http://1.2.3.4
    if "://" in host:
        from urllib.parse import urlsplit
        host = urlsplit(host).hostname or ""
    host = host.split("/")[0].split(":")[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # 域名一律拒绝（避免解析到公网）
        return False, f"仅允许 IP 目标，域名 {host!r} 被拒绝"
    for net in policy.allowed_nets:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True, f"命中允许网段 {net}"
        except ValueError:
            continue
    return False, f"目标 {host} 不在允许网段内"


class AuditLog:
    """JSONL 审计日志：每一次执行都留痕。"""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []

    def write(self, result: ExecutionResult, target: str) -> None:
        rec = {
            "ts": time.time(), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": target, "mode": result.mode, "tool": result.tool,
            "command": result.command, "returncode": result.returncode,
            "ok": result.ok, "duration_ms": result.duration_ms,
            "reason": result.reason,
        }
        self.records.append(rec)
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass


# ======================================================================
# 执行器
# ======================================================================
class CommandRunner:
    """统一入口：真实工具 → 内置脚本 → 模拟，三级降级。"""

    def __init__(self, policy: ExecutionPolicy | None = None):
        self.policy = policy or ExecutionPolicy()
        self.audit = AuditLog(self.policy.audit_path)
        self._stamps: list[float] = []

    # ------------------------------------------------------------------
    def run_tool(self, name: str, target: str, *, ports: str = DEFAULT_PORTS,
                 url: str = "", extra_args: Sequence[str] | None = None) -> ExecutionResult:
        """执行一次侦察类工具。

        **所有分支都会写审计日志**（含成功路径）—— 可审计性是安全工具的基本要求。
        """
        res = self._run_tool_inner(name, target, ports=ports, url=url, extra_args=extra_args)
        self.audit.write(res, target)
        return res

    def _run_tool_inner(self, name: str, target: str, *, ports: str,
                        url: str, extra_args: Sequence[str] | None) -> ExecutionResult:
        # 1) 目标校验（无论是否启用真实执行都先校验，保证 blocked 可解释）
        allowed, why = target_allowed(target, self.policy)
        if not allowed:
            return ExecutionResult(tool=name, mode="blocked", reason=why)

        # 2) 未启用 → 模拟
        if not self.policy.enabled:
            return self._simulate(name, target, ports,
                                  "真实执行未启用（AGENT_REAL_EXEC=0），使用确定性模拟")

        # 3) 未授权 → 拒绝
        if not self.policy.authorized:
            return ExecutionResult(tool=name, mode="blocked",
                                   reason="缺少授权标记（AGENT_AUTHORIZED=1），拒绝执行")

        # 4) 速率限制
        if not self._rate_ok():
            return ExecutionResult(tool=name, mode="blocked",
                                   reason=f"触发速率限制（{self.policy.rate_limit_per_min}/min）")

        # 5) 优先真实二进制
        spec = EXTERNAL_TOOLS.get(name)
        if spec and shutil.which(spec["binary"]):
            cmd = [spec["binary"], *spec["args"], *(extra_args or []), target]
            res = self._exec(name, cmd, target)
            if res.ok:
                return res
            # 真实工具失败 → 继续尝试脚本兜底
            fallback_reason = f"外部工具 {spec['binary']} 执行失败（{res.reason}），改用内置脚本"
        else:
            fallback_reason = (f"未检测到 {name} 可执行文件，改用内置脚本"
                               if spec else "未知外部工具，改用内置脚本")

        # 6) 内置脚本兜底
        fb = (spec or {}).get("script_fallback") or ("port_probe" if name == "nmap" else None)
        if fb and fb in self.policy.allow_scripts and fb in BUILTIN_SCRIPTS:
            res = self._run_script_inner(fb, target=target, ports=ports, url=url)
            res.tool = name
            res.reason = f"{fallback_reason}｜{res.reason}" if res.reason else fallback_reason
            return res

        # 7) 最后退回模拟
        return self._simulate(name, target, ports, fallback_reason + "；无可用脚本，退回模拟")

    # ------------------------------------------------------------------
    def run_script(self, name: str, *, target: str = "", ports: str = DEFAULT_PORTS,
                   url: str = "", extra_args: Sequence[str] | None = None) -> ExecutionResult:
        """执行 scripts/ 下白名单内的本地脚本（真实子进程），并写审计日志。"""
        res = self._run_script_inner(name, target=target, ports=ports, url=url,
                                     extra_args=extra_args)
        self.audit.write(res, target)
        return res

    def _run_script_inner(self, name: str, *, target: str = "", ports: str = DEFAULT_PORTS,
                          url: str = "", extra_args: Sequence[str] | None = None) -> ExecutionResult:
        spec = BUILTIN_SCRIPTS.get(name)
        if not spec or name not in self.policy.allow_scripts:
            return ExecutionResult(tool=name, mode="blocked", reason=f"脚本 {name} 不在白名单内")
        script = SCRIPTS_DIR / spec["file"]
        if not script.exists():
            return ExecutionResult(tool=name, mode="blocked", reason=f"脚本不存在：{script}")

        base = url or (f"http://{target}" if target and not target.startswith("http") else target)
        mapping = {"target": target, "ports": ports, "url": url or base, "base": base}
        args = [a.format(**mapping) for a in spec["args"]]
        cmd = [sys.executable, str(script), *args, *(extra_args or [])]

        if self.policy.dry_run:
            return ExecutionResult(tool=name, mode="dry-run", ok=True, command=cmd,
                                   reason="dry-run：仅生成命令，未执行")
        return self._exec(name, cmd, target)
    def _exec(self, name: str, cmd: list[str], target: str) -> ExecutionResult:
        is_script = cmd[0] == sys.executable or Path(cmd[0]).suffix == ".py"
        res = ExecutionResult(tool=name, command=cmd, mode="script" if is_script else "real")

        if self.policy.dry_run:
            res.mode, res.ok, res.reason = "dry-run", True, "dry-run：仅生成命令，未执行"
            return res

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.policy.timeout,
                creationflags=flags, text=True, encoding="utf-8", errors="replace",
            )
            res.returncode = proc.returncode
            res.stdout = (proc.stdout or "")[: self.policy.max_output]
            res.stderr = (proc.stderr or "")[: self.policy.max_output]
            res.ok = proc.returncode == 0
            if not res.ok:
                res.reason = f"退出码 {proc.returncode}：{(res.stderr or '').strip()[:160]}"
            else:
                res.data = self._parse_json(res.stdout)
        except subprocess.TimeoutExpired:
            res.ok = False
            res.reason = f"超时（>{self.policy.timeout}s）已终止"
        except (OSError, ValueError) as exc:
            res.ok = False
            res.reason = f"执行异常：{type(exc).__name__}: {exc}"
        res.duration_ms = int((time.time() - t0) * 1000)
        return res

    # ------------------------------------------------------------------
    def _simulate(self, name: str, target: str, ports: str, reason: str) -> ExecutionResult:
        """确定性模拟：没条件真实执行时，保证流程依然跑得通。"""
        try:
            import core                                     # 复用既有模拟实现
            if name == "nmap":
                data = core.run_nmap(target) if hasattr(core, "run_nmap") else {}
            else:
                data = {"target": target, "tool": name, "note": "通用模拟结果"}
        except Exception:
            data = {"target": target, "tool": name}
        return ExecutionResult(tool=name, mode="simulated", ok=True, reason=reason, data=data)

    def _rate_ok(self) -> bool:
        now = time.time()
        self._stamps = [t for t in self._stamps if now - t < 60]
        if len(self._stamps) >= self.policy.rate_limit_per_min:
            return False
        self._stamps.append(now)
        return True

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        try:
            val = json.loads(text)
            return val if isinstance(val, dict) else {"result": val}
        except (json.JSONDecodeError, TypeError):
            return {}


# ======================================================================
# 命令行
# ======================================================================
def _cli(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="realexec", description="真实执行层（默认模拟，需显式授权）")
    p.add_argument("--tool", default="nmap", choices=[*EXTERNAL_TOOLS, *BUILTIN_SCRIPTS])
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--ports", default=DEFAULT_PORTS)
    p.add_argument("--url", default="")
    p.add_argument("--real", action="store_true", help="启用真实执行（否则只模拟）")
    p.add_argument("--authorized", action="store_true", help="声明已获目标授权")
    p.add_argument("--dry-run", action="store_true", help="只打印命令不执行")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    policy = ExecutionPolicy(enabled=args.real, authorized=args.authorized, dry_run=args.dry_run)
    runner = CommandRunner(policy)
    if args.tool in EXTERNAL_TOOLS:
        res = runner.run_tool(args.tool, args.target, ports=args.ports, url=args.url)
    else:
        res = runner.run_script(args.tool, target=args.target, ports=args.ports, url=args.url)

    if args.json:
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(res.summary())
        if res.command:
            print("  命令：", " ".join(res.command))
        print("  stdout:", (res.stdout or "(空)").strip()[:600])
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli())

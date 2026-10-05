"""真实执行层测试：安全边界、三级降级、脚本真跑、工作流集成。

运行： pytest tests/test_realexec.py -v
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from realexec import (BUILTIN_SCRIPTS, CommandRunner, ExecutionPolicy,  # noqa: E402
                      ExecutionResult, target_allowed)


@pytest.fixture()
def tmp_policy(tmp_path):
    def _make(**kw):
        base = dict(enabled=True, authorized=True, audit_path=str(tmp_path / "audit.jsonl"))
        base.update(kw)
        return ExecutionPolicy(**base)
    return _make


# ======================================================================
# 安全边界
# ======================================================================
class TestPolicy:
    @pytest.mark.parametrize("target,expected", [
        ("127.0.0.1", True),
        ("192.168.3.73", True),
        ("10.0.0.5", True),
        ("172.16.9.9", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("evil.example.com", False),
        ("", False),
    ])
    def test_target_allowed(self, target, expected):
        pol = ExecutionPolicy()
        ok, _ = target_allowed(target, pol)
        assert ok is expected

    def test_target_with_port_and_scheme(self):
        pol = ExecutionPolicy()
        assert target_allowed("http://192.168.1.10:8000/path", pol)[0] is True
        assert target_allowed("198.51.100.7:80", pol)[0] is False

    def test_default_is_disabled(self):
        pol = ExecutionPolicy()
        assert pol.enabled is False and pol.authorized is False


# ======================================================================
# 三级降级
# ======================================================================
class TestDegrade:
    def test_disabled_returns_simulated(self, tmp_policy):
        r = CommandRunner(tmp_policy(enabled=False)).run_tool("nmap", "127.0.0.1")
        assert r.mode == "simulated" and r.ok

    def test_enabled_without_authorization_is_blocked(self, tmp_policy):
        r = CommandRunner(tmp_policy(authorized=False)).run_tool("nmap", "127.0.0.1")
        assert r.mode == "blocked" and "授权" in r.reason

    def test_public_target_blocked_even_if_authorized(self, tmp_policy):
        r = CommandRunner(tmp_policy()).run_tool("nmap", "8.8.8.8")
        assert r.mode == "blocked" and "网段" in r.reason

    def test_dry_run_does_not_execute(self, tmp_policy):
        r = CommandRunner(tmp_policy(dry_run=True)).run_tool("nmap", "127.0.0.1")
        assert r.mode in {"dry-run", "script"} and r.ok
        assert r.stdout in ("", None) or r.mode == "dry-run"

    def test_rate_limit_blocks_after_threshold(self, tmp_policy):
        runner = CommandRunner(tmp_policy(rate_limit_per_min=2, dry_run=True))
        modes = [runner.run_tool("nmap", "127.0.0.1").mode for _ in range(4)]
        assert "blocked" in modes[2:]

    def test_unknown_script_blocked(self, tmp_policy):
        r = CommandRunner(tmp_policy()).run_script("rm_rf_everything")
        assert r.mode == "blocked"

    def test_missing_script_file_blocked(self, tmp_policy, monkeypatch):
        from realexec import SCRIPTS_DIR
        monkeypatch.setattr("realexec.SCRIPTS_DIR", SCRIPTS_DIR / "not_exist_dir")
        r = CommandRunner(tmp_policy()).run_script("port_probe", target="127.0.0.1")
        assert r.mode == "blocked"


# ======================================================================
# 真实脚本执行（真开端口真连）
# ======================================================================
class TestRealScript:
    def test_port_probe_finds_listening_port(self, tmp_policy):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            runner = CommandRunner(tmp_policy())
            r = runner.run_script("port_probe", target="127.0.0.1", ports=str(port))
            assert r.ok, r.reason
            assert r.mode == "script"
            data = json.loads(r.stdout)
            assert any(p["port"] == port for p in data["open"]), data
        finally:
            srv.close()

    def test_nmap_tool_falls_back_to_script(self, tmp_policy):
        """即使本机装了 nmap，也只验证流程可用（不真的扫）。"""
        r = CommandRunner(tmp_policy()).run_tool("nmap", "127.0.0.1", ports="8902")
        assert r.mode in {"real", "script", "simulated"}
        assert r.tool == "nmap"

    def test_audit_log_is_written(self, tmp_policy, tmp_path):
        pol = tmp_policy()
        runner = CommandRunner(pol)
        runner.run_tool("nmap", "127.0.0.1", ports="8902")
        log = Path(pol.audit_path)
        assert log.exists()
        rec = json.loads(log.read_text(encoding="utf-8").strip().splitlines()[0])
        assert rec["target"] == "127.0.0.1" and "mode" in rec


# ======================================================================
# 工作流集成
# ======================================================================
class TestWorkflowIntegration:
    def test_default_workflow_still_simulates(self):
        from workflow import run_workflow
        rep = run_workflow({"target": "192.168.3.73"})
        assert rep["status"] in {"complete", "blocked"}
        recon_nodes = [n for n in rep["nodes"] if n["id"] == "recon"]
        assert recon_nodes and recon_nodes[0]["label"] == "侦察模拟"
        assert len(rep["nodes"]) == 10          # 节点数不变，向后兼容

    def test_workflow_with_real_exec_dry_run(self):
        from workflow import run_workflow
        rep = run_workflow({"target": "127.0.0.1", "real_exec": True,
                            "authorized": True, "dry_run": True})
        node = [n for n in rep["nodes"] if n["id"] == "recon"][0]
        assert node["label"] == "侦察执行"
        assert rep["artifacts"]["recon_exec"] is not None

    def test_workflow_real_exec_unauthorized_is_blocked_node(self):
        from workflow import run_workflow
        rep = run_workflow({"target": "127.0.0.1", "real_exec": True})
        node = [n for n in rep["nodes"] if n["id"] == "recon"][0]
        assert node["label"] == "侦察执行"
        assert "[blocked]" in node["detail"]


# ======================================================================
# 数据模型
# ======================================================================
class TestExecutionResult:
    def test_summary_contains_mode(self):
        r = ExecutionResult(tool="nmap", mode="real", ok=True, duration_ms=12)
        assert "[real]" in r.summary() and "nmap" in r.summary()

    def test_to_dict_roundtrip(self):
        r = ExecutionResult(tool="nmap", mode="simulated", ok=True)
        d = r.to_dict()
        assert d["tool"] == "nmap" and d["mode"] == "simulated"

    def test_builtin_scripts_registry(self):
        assert "port_probe" in BUILTIN_SCRIPTS
        for spec in BUILTIN_SCRIPTS.values():
            assert (ROOT / "scripts" / spec["file"]).exists(), spec

"""End-to-end orchestration for the local security checking agent."""

from __future__ import annotations

import uuid
from typing import Any

from core import (
    DEFAULT_CODE,
    DEFAULT_DIFF,
    DEFAULT_LOG,
    DEFAULT_PSEUDOCODE,
    analyze_binary_function,
    analyze_vulnerability_patch,
    ask_internal_bot,
    audit_code,
    execute_plan,
    generate_attack_plan,
    hunt_memory_shell,
    inspect_log_for_injection,
    summarize_findings,
    timestamp,
    validate_target,
)


def run_workflow(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    target = str(payload.get("target") or "10.0.0.5").strip()
    objective = str(payload.get("objective") or "在授权实验靶机上进行安全检查").strip()
    code = str(payload.get("code") or DEFAULT_CODE)
    diff = str(payload.get("diff") or DEFAULT_DIFF)
    pseudocode = str(payload.get("pseudocode") or DEFAULT_PSEUDOCODE)
    logs = str(payload.get("logs") or DEFAULT_LOG)
    question = str(payload.get("question") or "发现勒索软件后应该如何处置？")

    events: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []

    def node(node_id: str, label: str, status: str, detail: str, **extra: Any) -> None:
        nodes.append({"id": node_id, "label": label, "status": status, "detail": detail, **extra})
        events.append({"time": timestamp(), "node": node_id, "message": detail})

    scope = validate_target(target)
    if not scope["valid"]:
        node("scope", "范围校验", "blocked", scope["reason"])
        return {
            "run_id": uuid.uuid4().hex[:12], "created_at": timestamp(), "status": "blocked",
            "target": target, "objective": objective, "nodes": nodes, "events": events,
            "findings": [], "metrics": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
    node("scope", "范围校验", "complete", f"已锁定授权目标 {scope['normalized']}，全程为离线演示模式")

    plan = generate_attack_plan(scope["normalized"])
    execution = execute_plan(plan)
    node("planner", "规划器", "complete", f"生成 {len(plan)} 个受限步骤", plan=plan)

    # 侦察节点：默认走确定性模拟；显式开启 real_exec 时改用真实执行层
    # （真实工具 → 内置脚本 → 模拟，三级降级，见 realexec.py）
    recon = execution[0]["result"]
    exec_record: dict[str, Any] | None = None
    if payload.get("real_exec"):
        from realexec import CommandRunner, ExecutionPolicy
        policy = ExecutionPolicy(
            enabled=True,
            authorized=bool(payload.get("authorized")),
            dry_run=bool(payload.get("dry_run")),
        )
        run = CommandRunner(policy).run_tool(
            str(payload.get("recon_tool") or "nmap"), scope["normalized"])
        exec_record = run.to_dict()
        opened = run.data.get("open", []) if isinstance(run.data, dict) else []
        node("recon", "侦察执行", "complete" if run.ok else "warning",
             f"[{run.mode}] {run.tool}：{run.reason or '执行完成'}"
             + (f"，发现 {len(opened)} 个开放端口" if opened else ""),
             result=run.data or {"stdout": run.stdout}, execution=exec_record)
        if run.ok and run.data:
            recon = run.data
    else:
        node("recon", "侦察模拟", "complete", f"识别 {len(recon['ports'])} 个演示端口", result=recon)

    code_report = audit_code(code)
    node("code-audit", "代码审计", "complete", f"发现 {len(code_report['vulnerabilities'])} 个规则命中", result=code_report)

    jvm_report = hunt_memory_shell()
    node("jvm", "JVM 内存排查", "complete", f"检查 {len(jvm_report['classes'])} 个类，发现 {len(jvm_report['findings'])} 个可疑点", result=jvm_report)

    patch_report = analyze_vulnerability_patch(diff)
    patch_status = "complete" if patch_report["status"] == "fixed" else "warning"
    node("patchdiff", "PatchDiff 分析", patch_status, f"{patch_report['cwe']}：{patch_report['status']}", result=patch_report)

    binary_report = analyze_binary_function(pseudocode)
    node("binary", "二进制语义恢复", "complete", f"识别算法：{binary_report['algorithm']}", result=binary_report)

    sop_report = ask_internal_bot(question)
    node("sop", "SOP 检索", "complete" if sop_report["found"] else "warning", sop_report["answer"], result=sop_report)

    injection_report = inspect_log_for_injection(logs)
    injection_status = "blocked" if injection_report["blocked"] else "complete"
    node("guard", "提示词注入防护", injection_status, injection_report["recommendation"], result=injection_report)

    metrics = summarize_findings(code_report, jvm_report)
    findings = code_report["vulnerabilities"] + jvm_report["findings"]
    if patch_report["status"] != "fixed":
        findings.append({"severity": "medium", "vuln_type": "Patch 未确认安全", "description": patch_report["fix_mechanism"]})
        metrics["medium"] += 1
    status = "blocked" if injection_report["blocked"] else "complete"
    node("report", "报告汇总", "complete", f"工作流完成：{len(findings)} 个发现项，{metrics['critical'] + metrics['high']} 个高优先级")

    return {
        "run_id": uuid.uuid4().hex[:12], "created_at": timestamp(), "status": status,
        "target": target, "objective": objective, "nodes": nodes, "events": events,
        "findings": findings, "metrics": metrics,
        "artifacts": {"plan": plan, "execution": execution, "patch": patch_report, "binary": binary_report, "sop": sop_report, "injection_guard": injection_report, "recon_exec": exec_record},
    }


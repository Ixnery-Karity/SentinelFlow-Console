"""Compatibility entry point: bounded planner/executor agent."""

import json

from core import execute_plan, generate_attack_plan, run_nmap


def tool_nmap_scan(ip: str):
    return run_nmap(ip)


def generate_plan(objective: str):
    target = objective.rsplit(" ", 1)[-1] if " " in objective else objective
    return generate_attack_plan(target)


def main() -> None:
    target = "10.0.0.5"
    plan = generate_attack_plan(target)
    print(json.dumps({"plan": plan, "results": execute_plan(plan)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

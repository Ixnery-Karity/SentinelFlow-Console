"""Compatibility entry point: offline-safe automated assessment workflow."""

import json

from core import execute_plan, generate_attack_plan, run_dirb, run_nmap, run_sqlmap


def main() -> None:
    target = "192.168.1.100"
    plan = generate_attack_plan(target)
    print(json.dumps({"plan": plan, "results": execute_plan(plan)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

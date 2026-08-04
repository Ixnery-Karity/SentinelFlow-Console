"""Compatibility entry point: prompt-injection detector with an execution deny gate."""

import json

from core import DEFAULT_LOG as MALICIOUS_EXTERNAL_LOG
from core import execute_system_command, inspect_log_for_injection


def ai_ops_assistant(log_content: str):
    """Inspect untrusted logs and never pass their contents to a shell."""
    report = inspect_log_for_injection(log_content)
    report["execution"] = execute_system_command("[untrusted model output blocked]")
    return report


def main() -> None:
    print(json.dumps(ai_ops_assistant(MALICIOUS_EXTERNAL_LOG), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

"""Compatibility entry point: source-code audit and repair suggestions."""

import json

from core import DEFAULT_CODE as VULNERABLE_CODE
from core import audit_code


def main() -> None:
    print(json.dumps(audit_code(VULNERABLE_CODE), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

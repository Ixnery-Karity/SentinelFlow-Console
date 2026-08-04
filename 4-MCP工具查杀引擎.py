"""Compatibility entry point: JVM memory-shell inspection tools."""

import json

from core import decompile_class, hunt_memory_shell, list_suspicious_classes


def main() -> None:
    print(json.dumps(hunt_memory_shell(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

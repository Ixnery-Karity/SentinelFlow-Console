"""Compatibility entry point: lightweight local SOP retrieval."""

import json

from core import PRIVATE_KNOWLEDGE, ask_internal_bot


def main() -> None:
    report = ask_internal_bot("发现勒索软件后应该如何处置？")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

"""Compatibility entry point: binary pseudocode semantic recovery."""

import json

from core import DEFAULT_PSEUDOCODE as MOCK_IDA_PSEUDOCODE
from core import analyze_binary_function


def main() -> None:
    print(json.dumps(analyze_binary_function(MOCK_IDA_PSEUDOCODE), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

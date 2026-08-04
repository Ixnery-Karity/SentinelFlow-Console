"""Compatibility entry point: PatchDiff vulnerability analysis."""

import json

from core import DEFAULT_DIFF as MOCK_PATCH_DIFF
from core import analyze_vulnerability_patch


def main() -> None:
    print(json.dumps(analyze_vulnerability_patch(MOCK_PATCH_DIFF), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

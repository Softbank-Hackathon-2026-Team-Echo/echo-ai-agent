"""Container-only fixed parser: compile customer text without importing or executing it."""

import json
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    raw = json.loads(Path(sys.argv[1]).read_text())
    if raw["path"] != "app/main.py" or len(raw["code"].encode()) > 64 * 1024:
        return 2
    issues: list[dict[str, Any]] = []
    try:
        # Compilation validates syntax (including top-level return/break). Never exec/import.
        compile(raw["code"], raw["path"], "exec", dont_inherit=True)
    except SyntaxError as error:
        issues.append({"path": raw["path"], "line": error.lineno or 1, "message": error.msg})
    print(json.dumps({"version": "Python " + sys.version.split()[0], "issues": issues}))
    return int(bool(issues))


if __name__ == "__main__":
    raise SystemExit(main())

"""Run every local quality gate in sequence. Cross-platform; no shell needed.

Usage:
    python scripts/check.py           # lint, format check, types, tests
    python scripts/check.py --build   # ...and build sdist + wheel
"""

from __future__ import annotations

import subprocess
import sys

STEPS: list[tuple[str, list[str]]] = [
    ("ruff check", ["-m", "ruff", "check", "."]),
    ("ruff format", ["-m", "ruff", "format", "--check", "."]),
    ("mypy", ["-m", "mypy", "--strict", "src/egressveil"]),
    ("pytest", ["-m", "pytest", "-q"]),
]


def main() -> int:
    steps = list(STEPS)
    if "--build" in sys.argv[1:]:
        steps.append(("build", ["-m", "build"]))
    failed: list[str] = []
    for name, args in steps:
        print(f"==> {name}", flush=True)
        if subprocess.call([sys.executable, *args]) != 0:  # noqa: S603
            failed.append(name)
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

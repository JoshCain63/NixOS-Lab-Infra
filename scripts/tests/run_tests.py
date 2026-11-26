#!/usr/bin/env python3
"""Run each test module in its own process and write its full output to
tests/results/<module>.txt. Exits non-zero if any module fails."""

import os
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent
RESULTS = TESTS / "results"


def run_module(name):
    env = dict(os.environ, PYTHONUNBUFFERED="1",
               PYTHONPATH=os.pathsep.join(filter(None, [str(SCRIPTS), str(TESTS), os.environ.get("PYTHONPATH")])))
    path = RESULTS / f"{name}.txt"
    with path.open("w", encoding="utf-8") as out:
        proc = subprocess.run([sys.executable, "-m", "unittest", "-v", name], cwd=SCRIPTS, env=env,
                              stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
    return proc.returncode, path


def main():
    RESULTS.mkdir(exist_ok=True)
    for stale in RESULTS.glob("test_*.txt"):
        stale.unlink()

    failed = 0
    for module in sorted(p.stem for p in TESTS.glob("test_*.py")):
        code, path = run_module(module)
        failed += code != 0
        print(f"{'ok  ' if code == 0 else 'FAIL'} {module:<22} {path.relative_to(SCRIPTS)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

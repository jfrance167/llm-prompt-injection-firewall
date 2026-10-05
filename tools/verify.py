"""Capture checks and a targeted mutation, restoring the exact source in finally.

Usage: python tools/verify.py FRESH_DIRECTORY
No installs, network, generated-code execution, or external effects. Python/Bandit
must already be installed. Artifacts preserve complete output and exit statuses.
"""

import hashlib
import json
from pathlib import Path
# All commands below are fixed local checks of this owned synthetic application.
import subprocess  # nosec B404
import sys

ROOT = Path(__file__).resolve().parent.parent


def check(command, destination):
    with destination.open("w", encoding="utf-8") as output:
        try:
            # Fixed command lists only; no source text or user command interpolated.
            completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                       timeout=45, check=False)  # nosec B603
            return completed.returncode
        except subprocess.TimeoutExpired:
            return 124


def main():
    folder = Path(sys.argv[1]).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    commands = {
        "tests": [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        "compile": [sys.executable, "-m", "compileall", "-q", "firewall", "tools", "tests"],
        "bandit": [sys.executable, "-m", "bandit", "-r", "firewall", "tools", "-f", "json"],
    }
    outcomes = {name: {"command": command, "exit": check(command, folder / (name + ".log"))}
                for name, command in commands.items()}
    target = ROOT / "firewall/policy.py"
    original = target.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    search = b"or inspection.request_id != session.identifier"
    if original.count(search) != 1:
        raise RuntimeError("Expected exactly one session-binding condition")
    try:
        target.write_bytes(original.replace(search, b"or False"))
        mutation_exit = check(commands["tests"], folder / "mutation.log")
    finally:
        target.write_bytes(original)
    restored = hashlib.sha256(target.read_bytes()).hexdigest() == original_hash
    outcomes["mutation"] = {"condition": "inspection session binding removed",
                            "exit": mutation_exit, "detected": mutation_exit == 1, "restored": restored}
    outcomes["tests_after_restore"] = {"command": commands["tests"],
                                        "exit": check(commands["tests"], folder / "restored-tests.log")}
    manifest = {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                for parent in ("firewall", "tools", "tests") for path in sorted((ROOT / parent).glob("*.py"))}
    (folder / "results.json").write_text(json.dumps({"checks": outcomes, "source_sha256": manifest}, indent=2) + "\n", encoding="utf-8")
    passed = (all(outcomes[name]["exit"] == 0 for name in commands)
              and outcomes["tests_after_restore"]["exit"] == 0 and restored and mutation_exit == 1)
    print(json.dumps({"status": "PASS" if passed else "FAIL", "evidence": str(folder)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

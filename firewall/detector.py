"""Fault-injected detector protocol, isolated in a killable subprocess.

Only built-in synthetic modes are supported. This tests protocol/failure handling,
not real classifier accuracy. No plugin imports or network/model calls.
"""

import json
# Required for bounded, killable built-in mock; no arbitrary executables.
import subprocess  # nosec B404
import sys
import time

from .contracts import Decision, Invalid, object_keys, result, strict_json, text_size

MODES = frozenset({"allow", "block", "malformed", "timeout", "unavailable"})


class MockDetector:
    version = "mock-detector-v1"

    def __init__(self, mode="allow", timeout=10):
        if mode not in MODES or type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise Invalid("INVALID_DETECTOR_CONFIG")
        self.mode, self.timeout = mode, timeout

    def inspect(self, text, phase, policy, request_id):
        started = time.perf_counter()
        try:
            text_size(text)
            # Built-in child emits at most a fixed tiny result. Arbitrary executable
            # adapters are unsupported; capture_output is not an untrusted-output cap.
            # Fixed interpreter/module, allowlisted mode; text goes only to stdin.
            completed = subprocess.run(  # nosec B603
                [sys.executable, "-m", "firewall.detector", self.mode],
                input=text, encoding="utf-8", capture_output=True,
                timeout=self.timeout, check=False,
            )
            if completed.returncode:
                return result(phase, Decision.REVIEW, ("DETECTOR_UNAVAILABLE",), policy,
                              started, detector_status="unavailable", request_id=request_id)
            parsed = strict_json(completed.stdout, 1024)
            object_keys(parsed, {"decision", "coverage", "version"})
            if (parsed["decision"] not in ("ALLOW", "BLOCK")
                    or parsed["coverage"] != "complete" or parsed["version"] != self.version):
                raise Invalid("INVALID_DETECTOR_RESPONSE")
            return result(phase, Decision(parsed["decision"]), ("MOCK_DETECTOR_VERDICT",),
                          policy, started, detector_status="ok", request_id=request_id)
        except subprocess.TimeoutExpired:
            return result(phase, Decision.REVIEW, ("DETECTOR_TIMEOUT",), policy, started,
                          detector_status="timeout", coverage="incomplete", request_id=request_id)
        except (Invalid, OSError, UnicodeError):
            return result(phase, Decision.REVIEW, ("DETECTOR_INVALID_RESPONSE",), policy, started,
                          detector_status="invalid_response", coverage="incomplete", request_id=request_id)


def main():
    mode = sys.argv[1]
    if mode not in MODES:
        return 2
    text = sys.stdin.read(16_385)
    text_size(text)
    if mode == "timeout":
        time.sleep(60)
    if mode == "unavailable":
        return 2
    if mode == "malformed":
        print('{"decision":"ALLOW","decision":"BLOCK"}')
    else:
        print(json.dumps({"decision": "BLOCK" if mode == "block" else "ALLOW",
                          "coverage": "complete", "version": MockDetector.version}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

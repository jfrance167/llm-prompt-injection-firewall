"""Complete buffered mock orchestration through one independent executor."""

import json
import threading
import time
from dataclasses import dataclass

from .contracts import CONTEXT_BYTES, Decision, Invalid, object_keys, result, strict_json, text_size
from .policy import Executor, Policy
from .screening import screen

_ADMISSION = threading.BoundedSemaphore(2)


@dataclass(frozen=True)
class MockModel:
    """Trusted fixture selects a response; all response content is untrusted."""
    response: str = '{"text":"The lab uses MFA and retains audit records for 30 days.","actions":[]}'
    version: str = "scripted-mock-v1"

    def generate(self, transcript):
        text_size(transcript, CONTEXT_BYTES)
        text_size(self.response)
        return self.response


@dataclass
class Outcome:
    decision: str
    response: str | None
    results: list
    events: tuple
    elapsed_ms: float

    def to_dict(self):
        return {"schema_version": 1, "decision": self.decision, "response": self.response,
                "results": [r.to_dict() for r in self.results], "events": self.events,
                "elapsed_ms": self.elapsed_ms, "model": "scripted-mock-v1"}

    def metadata(self):
        """Default telemetry excludes payloads, action arguments and source references."""
        return {"schema_version": 1, "decision": self.decision,
                "elapsed_ms": self.elapsed_ms,
                "phases": [{"phase": r.phase, "decision": r.decision,
                            "reasons": r.reasons, "policy_version": r.policy_version,
                            "request_id": r.request_id, "detector_status": r.detector_status,
                            "coverage": r.coverage, "elapsed_ms": r.elapsed_ms}
                           for r in self.results], "event_count": len(self.events)}


class Gateway:
    def __init__(self, policy=None, detector=None):
        self.policy = policy or Policy()
        self.detector = detector
        if detector is not None and not self.policy.detector_required:
            raise Invalid("DETECTOR_POLICY_MISMATCH")
        self.executor = Executor(self.policy)
        self._run_lock = threading.Lock()

    def _inspect(self, text, phase, source, session):
        checked = screen(text, phase, self.policy, source,
                         analysis=session.task == "analysis", request_id=session.identifier)
        if checked.decision != Decision.ALLOW or not self.policy.detector_required:
            return checked
        if self.detector is None:
            return result(phase, Decision.REVIEW, ("DETECTOR_UNAVAILABLE",), self.policy.version,
                          detector_status="unavailable", coverage="incomplete", request_id=session.identifier)
        detector = self.detector.inspect(text, phase, self.policy.version, session.identifier)
        # Preserve deterministic findings even when optional analysis allows their use.
        from dataclasses import replace
        return replace(detector, findings=checked.findings, subject_digest=checked.subject_digest,
                       request_id=session.identifier, reasons=checked.reasons + detector.reasons)

    def run(self, request, model=None, principal="reader", task="summary", document_ids=(),
            destinations=None, release_level=0, approval_callback=None):
        """Trusted host supplies identity/task/approval; request contains only text turns.

        Every successful tool event is a simulated effect. Failed runs may contain
        earlier permitted reads; writes are not transactionally rolled back.
        """
        started = time.perf_counter()
        phases = []
        session = None
        if not self._run_lock.acquire(blocking=False):
            return Outcome("BLOCK", None, [result("admission", Decision.BLOCK, ("BUSY",), self.policy.version)], (), 0)
        if not _ADMISSION.acquire(blocking=False):
            self._run_lock.release()
            return Outcome("BLOCK", None, [result("admission", Decision.BLOCK, ("BUSY",), self.policy.version)], (), 0)
        # Ledger is per request; long-lived gateway instances retain no payload/history.
        self.executor._ledger.clear()
        def finish(decision, response=None):
            return Outcome(str(decision), response, phases, self.executor.ledger,
                           (time.perf_counter() - started) * 1000)
        def inspect(text, phase, source):
            checked = self._inspect(text, phase, source, session)
            phases.append(checked)
            return checked
        try:
            session = self.executor.open_session(principal, task, document_ids, destinations, release_level)
            object_keys(request, {"turns"})
            turns = request["turns"]
            if type(turns) is not list or not 1 <= len(turns) <= 8:
                raise Invalid("TURN_LIMIT")
            if type(document_ids) not in (tuple, list) or len(document_ids) > 8:
                raise Invalid("SOURCE_LIMIT")
            total = 0
            for index, turn in enumerate(turns):
                total += text_size(turn)
                checked = inspect(turn, "input", f"turn-{index}")
                if checked.decision != Decision.ALLOW:
                    return finish(checked.decision)
            # Account for the full envelope before any context is forwarded.
            transcript = json.dumps({"turns": turns, "sources": []}, ensure_ascii=False)
            text_size(transcript, CONTEXT_BYTES)
            sources = []
            for source in document_ids:
                action = {"tool": "read_document", "arguments": {"document_id": source}}
                checked = inspect(json.dumps(action), "action", "retrieval-request")
                authorization, body = self.executor.execute(session, action, checked)
                phases.append(authorization)
                if authorization.decision != Decision.ALLOW:
                    return finish(authorization.decision)
                total += text_size(body)
                checked = inspect(body, "context", source)
                if checked.decision != Decision.ALLOW:
                    return finish(checked.decision)
                sources.append({"id": source, "text": body})
            if total > CONTEXT_BYTES:
                raise Invalid("CONTEXT_LIMIT")
            transcript = json.dumps({"turns": turns, "sources": sources}, ensure_ascii=False)
            text_size(transcript, CONTEXT_BYTES)
            # Cross-turn combined scanning is deliberately bounded, without discarding turns.
            combined = "\n".join(turns + [item["text"] for item in sources])
            # 2,000 codepoints plus overlap fits even four-byte UTF-8; inspect all.
            for offset in range(0, len(combined), 2_000):
                checked = inspect(combined[max(0, offset - 128):offset + 2_000], "context", f"assembled-context@{max(0, offset - 128)}")
                if checked.decision != Decision.ALLOW:
                    return finish(checked.decision)
            raw = (model or MockModel()).generate(transcript)
            parsed = strict_json(raw, 16_384)
            object_keys(parsed, {"text", "actions"})
            text_size(parsed["text"])
            if type(parsed["actions"]) is not list or len(parsed["actions"]) > 4:
                raise Invalid("ACTION_LIMIT")
            checked = inspect(parsed["text"], "output", "model-output")
            if checked.decision != Decision.ALLOW:
                return finish(checked.decision)
            for action in parsed["actions"]:
                checked = inspect(json.dumps(action, ensure_ascii=False), "action", "model-action")
                # Gate is called even on ALLOW and also rejects incomplete checks.
                authorization, body = self.executor.execute(session, action, checked)
                if authorization.decision == Decision.REVIEW and approval_callback:
                    token = approval_callback(self.executor, session, action)
                    authorization, body = self.executor.execute(session, action, checked, token)
                phases.append(authorization)
                if authorization.decision != Decision.ALLOW:
                    return finish(authorization.decision)
                total += text_size(body)
                if total > CONTEXT_BYTES:
                    raise Invalid("CONTEXT_LIMIT")
                checked = inspect(body, "tool_result", "tool-result")
                if checked.decision != Decision.ALLOW:
                    return finish(checked.decision)
            if session.data_level > session.release_level:
                raise Invalid("RELEASE_CLASSIFICATION_DENIED")
            return finish(Decision.ALLOW, parsed["text"])
        except (Invalid, TypeError, ValueError, KeyError) as exc:
            code = str(exc) if isinstance(exc, Invalid) else "INVALID_SCHEMA"
            phases.append(result("gateway", Decision.BLOCK, (code,), self.policy.version,
                                 coverage="incomplete"))
            return finish(Decision.BLOCK)
        finally:
            if session:
                self.executor.close_session(session)
            _ADMISSION.release()
            self._run_lock.release()

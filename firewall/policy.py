"""Trusted policy and simulated execution. No external effects or model authority."""

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType

from .contracts import Decision, Invalid, Result, object_keys, result, strict_json, text_size


@dataclass(frozen=True)
class Document:
    text: str
    level: int = 0


@dataclass(frozen=True)
class Grant:
    documents: frozenset[str]
    destinations: frozenset[str]
    clearance: int = 0


@dataclass(frozen=True)
class Policy:
    version: str = "synthetic-v1"
    documents: dict = field(default_factory=lambda: {
        "handbook": Document("The lab uses MFA and retains audit records for 30 days."),
        "restricted": Document("Confidential synthetic record: CANARY_FAKE_7D19", 1),
    })
    grants: dict = field(default_factory=lambda: {
        "reader": Grant(frozenset({"handbook"}), frozenset({"public"})),
        "analyst": Grant(frozenset({"handbook", "restricted"}),
                         frozenset({"public", "private"}), 1),
    })
    destinations: dict = field(default_factory=lambda: {"public": 0, "private": 1})
    canaries: tuple[str, ...] = ("CANARY_FAKE_7D19",)
    detector_required: bool = False

    def __post_init__(self):
        if type(self.version) is not str or not self.version or type(self.detector_required) is not bool:
            raise Invalid("INVALID_POLICY")
        text_size(self.version, 128)
        if type(self.canaries) is not tuple or len(self.canaries) > 16:
            raise Invalid("INVALID_POLICY")
        for token in self.canaries:
            if not token:
                raise Invalid("INVALID_POLICY")
            text_size(token, 256)
        for name, doc in self.documents.items():
            if type(name) is not str or not isinstance(doc, Document) or type(doc.level) is not int or doc.level not in (0, 1):
                raise Invalid("INVALID_POLICY")
            text_size(name, 128)
            text_size(doc.text)
        for name, level in self.destinations.items():
            text_size(name, 128)
            if type(level) is not int or level not in (0, 1):
                raise Invalid("INVALID_POLICY")
        for name, grant in self.grants.items():
            text_size(name, 128)
            if (not isinstance(grant, Grant) or type(grant.clearance) is not int
                    or grant.clearance not in (0, 1)
                    or type(grant.documents) is not frozenset
                    or type(grant.destinations) is not frozenset
                    or not grant.documents <= self.documents.keys()
                    or not grant.destinations <= self.destinations.keys()):
                raise Invalid("INVALID_POLICY")
        # Copy before freezing, so mutating the caller's dictionaries cannot edit policy.
        for name in ("documents", "grants", "destinations"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


@dataclass
class Session:
    """Created only by trusted host; never deserialize this from source content."""
    principal: str
    task: str
    documents: frozenset[str]
    destinations: frozenset[str]
    release_level: int = 0
    identifier: str = field(default_factory=lambda: secrets.token_hex(16))
    data_level: int = 0
    actions: int = 0
    active: bool = True


def action_digest(action):
    return hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class Executor:
    """One locked, rechecking gate for both tools; ledger is synthetic only.

    Trusted host code owns policy, sessions, approval issuance and this instance.
    This is not a sandbox against Python callers with access to its internals.
    """

    def __init__(self, policy):
        self.policy = policy
        self._sessions = {}
        self._approvals = {}
        self._ledger = []
        self._lock = threading.RLock()

    @property
    def ledger(self):
        return tuple(dict(event) for event in self._ledger)

    def open_session(self, principal="reader", task="summary", documents=None,
                     destinations=None, release_level=0):
        grant = self.policy.grants.get(principal)
        if grant is None or task not in ("summary", "analysis"):
            raise Invalid("INVALID_IDENTITY_OR_TASK")
        docs = frozenset(grant.documents if documents is None else documents)
        dests = frozenset(grant.destinations if destinations is None else destinations)
        if (not docs <= grant.documents or not dests <= grant.destinations
                or type(release_level) is not int or release_level not in (0, 1)
                or release_level > grant.clearance):
            raise Invalid("INVALID_TASK_GRANT")
        # Educational analysis has neither sources nor effects; source text cannot enable it.
        if task == "analysis":
            docs, dests = frozenset(), frozenset()
        session = Session(principal, task, docs, dests, release_level)
        self._sessions[session.identifier] = session
        return session

    def close_session(self, session):
        with self._lock:
            session.active = False
            self._sessions.pop(session.identifier, None)
            self._approvals = {key: value for key, value in self._approvals.items()
                               if value[0] != session.identifier and value[4] > time.monotonic()}

    def _check(self, session, action):
        if self._sessions.get(session.identifier) is not session or not session.active:
            raise Invalid("INVALID_SESSION")
        grant = self.policy.grants.get(session.principal)
        if grant is None:
            raise Invalid("AUTHORITY_DENIED")
        if session.task == "analysis":
            raise Invalid("TASK_DENIED")
        if session.actions >= 4:
            raise Invalid("ACTION_LIMIT")
        object_keys(action, {"tool", "arguments"})
        tool, args = action["tool"], action["arguments"]
        if type(tool) is not str:
            raise Invalid("INVALID_SCHEMA")
        if tool == "read_document":
            object_keys(args, {"document_id"})
            target = args["document_id"]
            text_size(target, 128)
            if target not in session.documents or target not in grant.documents:
                raise Invalid("RESOURCE_DENIED")
            if self.policy.documents[target].level > grant.clearance:
                raise Invalid("RESOURCE_DENIED")
        elif tool == "save_report":
            object_keys(args, {"destination_id", "text"})
            target = args["destination_id"]
            text_size(target, 128)
            text_size(args["text"])
            if target not in session.destinations or target not in grant.destinations:
                raise Invalid("DESTINATION_DENIED")
            if session.data_level > self.policy.destinations[target]:
                raise Invalid("DATA_FLOW_DENIED")
        else:
            raise Invalid("TOOL_DENIED")
        return tool, args

    def approve(self, session, action, ttl=60):
        """Trusted host approval only; never expose to the model/detector."""
        with self._lock:
            self._check(session, action)
            if type(ttl) not in (int, float) or not 0 < ttl <= 300:
                raise Invalid("INVALID_APPROVAL_TTL")
            self._approvals = {key: value for key, value in self._approvals.items()
                               if value[4] > time.monotonic()}
            if len(self._approvals) >= 8:
                raise Invalid("APPROVAL_LIMIT")
            token = secrets.token_urlsafe(24)
            self._approvals[token] = (session.identifier, session.principal,
                                      self.policy.version, action_digest(action),
                                      time.monotonic() + ttl)
            return token

    def execute(self, session, action, inspection: Result, approval=None):
        """Revalidate untrusted proposal under lock immediately before simulated effect."""
        with self._lock:
            started = time.perf_counter()
            try:
                # Snapshot exact JSON arguments before approval and validation to avoid
                # a shared mutable proposal changing between check and simulated effect.
                try:
                    action = strict_json(json.dumps(action, ensure_ascii=False, allow_nan=False))
                except (TypeError, ValueError, RecursionError) as exc:
                    raise Invalid("INVALID_ACTION") from exc
                tool, args = self._check(session, action)
                if (type(inspection) is not Result or inspection.phase != "action"
                        or inspection.decision != Decision.ALLOW
                        or inspection.coverage != "complete"
                        or inspection.policy_version != self.policy.version
                        or inspection.request_id != session.identifier
                        or inspection.subject_digest != action_digest(action)
                        or (self.policy.detector_required and inspection.detector_status != "ok")):
                    raise Invalid("CHECKS_INCOMPLETE")
                # Re-screen payload at the last possible boundary, not just upstream.
                from .screening import screen
                for field, value in args.items():
                    checked = screen(value, "action_payload", self.policy,
                                     "proposed-action/" + field, analysis=False)
                    if checked.decision != Decision.ALLOW:
                        raise Invalid(checked.reasons[0])
                if tool == "save_report":
                    expected = (session.identifier, session.principal, self.policy.version,
                                action_digest(action))
                    record = self._approvals.pop(approval, None)
                    if not record or record[:4] != expected or record[4] <= time.monotonic():
                        raise Invalid("APPROVAL_REQUIRED")
                    self._ledger.append({"tool": tool, "destination_id": args["destination_id"]})
                    value = "Report saved to simulated destination."
                else:
                    doc = self.policy.documents[args["document_id"]]
                    session.data_level = max(session.data_level, doc.level)
                    self._ledger.append({"tool": tool, "document_id": args["document_id"]})
                    value = doc.text
                session.actions += 1
                if len(self._ledger) > 256:
                    self._ledger.pop(0)
                return result("authorization", Decision.ALLOW, ("AUTHORIZED",),
                              self.policy.version, started), value
            except Invalid as exc:
                code = str(exc)
                decision = Decision.REVIEW if code == "APPROVAL_REQUIRED" else Decision.BLOCK
                return result("authorization", decision, (code,), self.policy.version, started), None

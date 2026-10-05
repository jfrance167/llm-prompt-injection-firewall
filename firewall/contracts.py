"""Bounded text/JSON contracts and versioned phase results."""

import json
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from uuid import uuid4

ITEM_BYTES = 16_384
CONTEXT_BYTES = 65_536
MAX_DEPTH = 8


class Invalid(ValueError):
    """Input or configuration violates an explicit contract."""


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


def text_size(text, limit=ITEM_BYTES):
    """Reject unsupported, invalid Unicode or oversized text before processing."""
    if type(text) is not str:
        raise Invalid("UNSUPPORTED_CONTENT")
    if len(text) > limit:
        raise Invalid("SIZE_LIMIT")
    try:
        size = len(text.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise Invalid("INVALID_UNICODE") from exc
    if size > limit:
        raise Invalid("SIZE_LIMIT")
    return size


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Invalid("DUPLICATE_KEY")
        obj[key] = value
    return obj


def _constant(_):
    raise Invalid("NONFINITE_JSON")


def strict_json(text, limit=CONTEXT_BYTES):
    """Preflight nesting outside strings, then reject duplicate keys/nonfinite numbers."""
    text_size(text, limit)
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise Invalid("JSON_DEPTH")
        elif char in "]}":
            depth -= 1
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid("INVALID_JSON") from exc
    # Reject escaped lone surrogates and float overflow (e.g. 1e999).
    def check(item):
        if type(item) is str:
            text_size(item, limit)
        elif type(item) is float:
            import math
            if not math.isfinite(item):
                raise Invalid("NONFINITE_JSON")
        elif type(item) is dict:
            for key, child in item.items():
                check(key)
                check(child)
        elif type(item) is list:
            for child in item:
                check(child)
    check(value)
    return value


@dataclass(frozen=True)
class Finding:
    code: str
    source_id: str
    start: int
    end: int
    view: str = "original"
    span_kind: str = "exact"


@dataclass(frozen=True)
class Result:
    phase: str
    decision: Decision
    reasons: tuple[str, ...]
    policy_version: str
    detector_status: str = "disabled"
    coverage: str = "complete"
    findings: tuple[Finding, ...] = ()
    elapsed_ms: float = 0.0
    request_id: str = ""
    schema_version: int = 1
    component_version: str = "0.1.0"
    subject_digest: str = ""

    def to_dict(self):
        return asdict(self)


def result(phase, decision, reasons, policy, started=None, **kwargs):
    return Result(phase, decision, tuple(reasons), policy,
                  elapsed_ms=(time.perf_counter() - started) * 1000 if started else 0,
                  request_id=kwargs.pop("request_id", "") or uuid4().hex, **kwargs)


def object_keys(obj, keys):
    if type(obj) is not dict or set(obj) != set(keys):
        raise Invalid("INVALID_SCHEMA")

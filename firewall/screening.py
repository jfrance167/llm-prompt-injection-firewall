"""Bounded heuristic views. Pattern matching is fallible, not authorization."""

import base64
import binascii
import re
import time
import unicodedata
from urllib.parse import unquote

from .contracts import CONTEXT_BYTES, Decision, Finding, Invalid, result, strict_json, text_size

PATTERNS = (
    ("INSTRUCTION_OVERRIDE", re.compile(r"\b(?:ignore|disregard|forget|bypass)\b.{0,40}\b(?:instructions?|rules?|commands?|policy)\b", re.I | re.S)),
    ("ROLE_SPOOF", re.compile(r"(?:\[system\]|<\|(?:system|developer)\|>|\b(?:system|developer)\s*:|\b(?:i am|you are now)\s+(?:the\s+)?(?:admin|administrator))", re.I)),
    ("EXFILTRATION_SIGNAL", re.compile(r"\b(?:send|upload|reveal|expose|print)\b.{0,60}\b(?:secret|credentials?|password|canary)\b", re.I)),
)
ENCODED = re.compile(r"(?<![\w])(?:[A-Za-z0-9+/]{16,}={0,2}|(?:[0-9a-fA-F]{2}){8,}|(?:%[0-9a-fA-F]{2}){4,})(?![\w])")


def views(text):
    """At most 32 derived views, depth two, 64 KiB total; never alter source text."""
    output = [(text, "original", 0, len(text), "exact", 0)]
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    if normalized != text:
        output.append((normalized, "nfkc_without_format", 0, len(text), "enclosing", 0))
    total = sum(text_size(item[0], CONTEXT_BYTES) for item in output)
    index = 0
    seen = {item[0] for item in output}
    while index < len(output):
        body, name, start, end, _, depth = output[index]
        index += 1
        for match in ENCODED.finditer(body):
            token = match.group()
            candidates = []
            if token.startswith("%"):
                candidates.append((unquote(token, errors="strict"), "percent"))
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}){8,}", token):
                try:
                    candidates.append((bytes.fromhex(token).decode("utf-8"), "hex"))
                except UnicodeError:
                    pass
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
                candidates.append((decoded, "base64"))
            except (UnicodeError, binascii.Error, ValueError):
                pass
            for decoded, transform in candidates:
                if decoded in seen or not decoded.strip():
                    continue
                if depth >= 2:
                    raise Invalid("DECODING_DEPTH")
                total += text_size(decoded, CONTEXT_BYTES)
                if total > CONTEXT_BYTES or len(output) >= 32:
                    raise Invalid("VIEW_LIMIT")
                seen.add(decoded)
                span = (match.start(), match.end()) if name == "original" else (start, end)
                output.append((decoded, name + "/" + transform, *span, "enclosing", depth + 1))
    return output


def screen(text, phase, policy, source_id="user", analysis=False, request_id=""):
    started = time.perf_counter()
    findings = []
    try:
        text_size(text)
        for body, name, start, end, span_kind, _ in views(text):
            if time.perf_counter() - started > 0.25:
                raise Invalid("SCREEN_DEADLINE")
            for token in policy.canaries:
                if phase in ("output", "action", "action_payload") and token.casefold() in body.casefold():
                    findings.append(Finding("CANARY_DISCLOSURE", source_id, start, end, name, span_kind))
            if "\x00" in body:
                raise Invalid("CONTROL_CHARACTER")
            for code, pattern in PATTERNS:
                for match in pattern.finditer(body):
                    span = (match.start(), match.end()) if name == "original" else (start, end)
                    findings.append(Finding(code, source_id, *span, name, span_kind))
                    if len(findings) >= 32:
                        break
            if len(findings) >= 32:
                raise Invalid("FINDING_LIMIT")
        codes = tuple(dict.fromkeys(f.code for f in findings))
        if "CANARY_DISCLOSURE" in codes:
            decision = Decision.BLOCK
        elif codes and not analysis:
            decision = Decision.REVIEW
        else:
            decision = Decision.ALLOW
        reasons = codes or ("CHECKS_PASSED",)
        if codes and analysis and decision == Decision.ALLOW:
            reasons = ("ANALYSIS_ONLY_SIGNALS",) + codes
        subject_digest = ""
        if phase == "action":
            from .policy import action_digest
            subject_digest = action_digest(strict_json(text))
        return result(phase, decision, reasons, policy.version, started,
                      findings=tuple(findings), request_id=request_id, subject_digest=subject_digest)
    except (Invalid, UnicodeError) as exc:
        code = str(exc) if isinstance(exc, Invalid) else "INVALID_ENCODING"
        return result(phase, Decision.BLOCK, (code,), policy.version, started,
                      coverage="incomplete", request_id=request_id)

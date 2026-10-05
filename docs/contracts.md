# Contracts v1

Input request has exactly `turns`: one to eight UTF-8 strings. No roles, provenance,
principal, policy or approval fields accepted. Model response has exactly `text` and
`actions` (zero to four); action has exactly `tool` and `arguments`.

| Tool | Exact arguments | Enforcement |
|---|---|---|
| read_document | document_id: string <=128 UTF-8 bytes | Current principal and task resource grant, source clearance |
| save_report | destination_id: string <=128 bytes; text: string <=16 KiB | Current destination grants/classification, raw payload inspection, exact approval |

All source grants come from host-created sessions and current Policy. Unknown keys,
tools, resources, arbitrary paths/URLs and type coercion are rejected. Permission
checks are re-evaluated immediately before simulated execution. Inspection is bound
to canonical action SHA-256, session ID and policy version. This digest is integrity
binding within trusted code, not a signature or authentication credential.

`Result.to_dict()` contains schema/component version, phase, decision, reasons,
policy version, request ID, detector status, coverage, elapsed time, findings and
optional action subject digest. Finding offsets are Python codepoint indices with
exclusive end; transformed views use enclosing original spans when mapping is not
exact. Combined-context source IDs `assembled-context@N` identify offsets in the
newline-joined source sequence; individual source inspections preserve document/turn
references. Findings contain no source snippets. Default metadata excludes spans and
digests, avoiding unnecessary content fingerprints in logs.

Detector states: disabled, ok, timeout, unavailable, invalid_response. No confidence
score is emitted by the mock protocol. A future score must include calibration status
and never become a permission. Coverage complete means all supplied bounded content
was processed by configured checks, not that every possible encoding/meaning was
understood. Bounds/deadlines explicitly mark incomplete coverage.

ALLOW/REVIEW/BLOCK are phase-specific. REVIEW stops unattended progress; it never
automatically executes or releases. A denied authorized-save approval is REVIEW.
Unauthorized actions are BLOCK even if text detection was ALLOW. Output buffering
applies to the complete response; no partial response or model action is executed
without applicable checks. Exit codes 0/2/3 match ALLOW/REVIEW/BLOCK.

Known codes include INSTRUCTION_OVERRIDE, ROLE_SPOOF, EXFILTRATION_SIGNAL,
CANARY_DISCLOSURE, SIZE_LIMIT, INVALID_UNICODE, CONTROL_CHARACTER, JSON_DEPTH,
DUPLICATE_KEY, NONFINITE_JSON, DECODING_DEPTH, VIEW_LIMIT, SCREEN_DEADLINE,
TOOL_DENIED, RESOURCE_DENIED, DESTINATION_DENIED, DATA_FLOW_DENIED,
RELEASE_CLASSIFICATION_DENIED, CHECKS_INCOMPLETE, APPROVAL_REQUIRED and BUSY.

Configuration is an immutable validated Python Policy, not caller JSON. Documents,
grants and destinations are copied/frozen. Analysis-only is a trusted task profile
with no tool/resource capabilities; quote marks or source role claims cannot enable it.

The mock model is a bounded supplied response. Real-model generation and its proposed
30-second deadline are deferred. The detector supports only five built-in fault modes:
allow/block/malformed/timeout/unavailable, with a fixed response schema and <=10-second
timeout. Plugin imports, arbitrary subprocess commands and network inference are absent.

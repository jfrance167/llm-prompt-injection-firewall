# Security model and review requirements

## Protected assets and attacker

Protect synthetic document ACLs, fake confidential canaries, approved destinations,
task grants, exact-action approvals, complete response release and bounded processing.
An attacker controls user text, document/tool-result bodies, model response text/action
proposals, encodings, Unicode, multilingual and split-turn instructions. They can
submit malformed/oversized envelopes and adversarial detector responses (represented
by built-in fault mocks). A detector can fail or say ALLOW erroneously.

Trusted: host code/OS, validated Policy and document classification registry, Session
creation, exact-action approval issuance, and the simulation operator. The operator's
CLI profile/task flags model authentication; they do not implement real identity proof.
No content field can become a principal, policy, permission or approval. Untrusted
model outputs are strict JSON data, never executable programs.

## Independent action boundary

`Executor.execute` snapshots JSON, checks current principal/task grants, strict argument
schema, resources/destinations, classification and four-action quota under one lock.
It requires complete action inspection bound to exact canonical action digest, session
and policy, then rescreens raw string arguments at execution. When a detector is
required its status must be OK. Report saves additionally consume a trusted approval
bound to action/session/principal/policy/expiry. Neither approval nor detector verdict
overrides authorization. The gate is shared by CLI and library orchestration.

The ledger has simulated effects only; a baseline cannot call actual tool implementations.
Results of reads are screened before use/release. Earlier permitted reads/saves may be
present when a later phase fails; this is not transactional rollback. Sensitive source
classification propagates at session scope, intentionally overrestricting some tasks.

## Failures and availability

Malformed/duplicate/nonfinite/deep JSON, invalid Unicode, unsupported content, size/view/
decode limits or output failure result in explicit BLOCK. Suspicious content normally
REVIEWs; an enabled detector failure REVIEWs, while dependent execution is denied.
Disabled detector is an explicit policy, never an error fallback. Missing required checks
cannot release output or authorize tools. No content is silently truncated and declared
fully inspected. Invalid policy fails startup.

Only a fixed built-in mock subprocess can run. Its mode is allowlisted, executable/module
fixed and prompt supplied via stdin. Timeout kills/waits for that direct child. It creates
no descendants. Two Bandit suppressions (B404/B603) document this reviewed fixed command;
they are not blanket suppression or permission for arbitrary detector plugins. Future
adapters need bounded output, process-tree cancellation and privacy/supply-chain review.

## Residual risks / manual review

The heuristic scanner misses multilingual and semantic instructions and can overblock
benign quotations. Canary checks cover demonstrated literal/selected encoded variants,
not arbitrary transformations, paraphrases or side channels. Pattern coverage cannot
establish complete semantic analysis. Source metadata does not authenticate factual
claims. ALLOW means configured checks passed, not proof of safety/truth.

Same-process Python callers are trusted: they can access private internals or construct
objects, so this library is not a containment boundary against malicious host code.
Production integrations would need real authentication, protected policies, isolated
execution credentials, enforced destinations and independent route review. Loopback
alone would not provide authentication. HTTP/real tools are not implemented here.

Jake's manual review is required before merge/deployment for policy/session creation,
approval issuance/digest binding, classification, strict parsing/normalization and
execution integration. Current local implementation/testing is authorized; no publication,
merge, real-model experiment or deployment is implied. GitHub security features and CI
eligibility have not been configured/run because no owned destination was authorized.

## Reporting

Reproduce using synthetic inputs and local tests only. Do not place real credentials,
employer/client material or nonpublic vulnerability evidence in fixtures or reports.
This local project has no public reporting endpoint yet.

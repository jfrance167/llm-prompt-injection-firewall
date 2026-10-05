# Verification and security review — October 5, 2026

Prepared for Jake's manual review of consequential trust boundaries. Local approved
scope is complete; publication, deployment and merge are not authorized. This review
does not certify production security or validate a real authentication deployment.

Authoritative evidence: [verification-ecc/results.json](../evaluation/verification-ecc/results.json)
contains exact commands/exit statuses and Python source hashes. Complete logs are
adjacent; initial Bandit findings and strengthened-binding debug output are retained
under evaluation. The short-canary regression is preserved in tests; its initial console
failure was not separately saved. No saved failed evidence was overwritten.

| Phase | Status | Evidence |
|---|---|---|
| Tests | PASS: 46 cases, exit0, Python3.13.7 Windows | verification-ecc/tests.log and restored-tests.log |
| Compile | PASS: compileall exit0 | verification-ecc/compile.log |
| SAST | PASS: Bandit1.9.4 exit0, zero findings | verification-ecc/bandit.log |
| Mutation | PASS: session-binding removal caused one test failure; source hash restored; tests pass again | verification-ecc/mutation.log, results.json |
| Scripted evaluation | PASS: 120 cases completed; failures/overblocks reported | ecc-reviewed.json; earlier three-configuration final-comparison.json |
| CLI routes | PASS within suite: demo/run/metadata paths and exact interactive approval | test_cli_eval.py |
| Type checker / lint | NOT RUN: no configured/available project checker; no package downloaded | review recorded here |
| Package build | NOT APPLICABLE: source-run standard-library application, no packaging dependency | README commands |
| Real-model evaluation / API | NOT RUN: outside approved initial scope | STATE.md |
| GitHub CI / CodeQL / protection | NOT RUN: no owned remote destination created/authorized | STATE.md |

Repeat verification with `python tools/verify.py evaluation/FRESH_DIRECTORY` when
Bandit is already installed. It preserves full outputs, tests a targeted condition and
restores exact source bytes in finally. It does not download packages, use inference,
execute model-generated code or change Git configuration. One mutation is evidence
of that regression test's sensitivity, not a project-wide mutation score.

## Five-axis review

ECC code-review self-review used the installed skill and pinned code-reviewer checklist
on all new Python modules, surrounding callers/tests and documentation. Parent staged
and unstaged diffs were inspected for scope; this project is untracked, so its actual
files were reviewed directly. This was not an independent reviewer or GitHub review.

One MEDIUM finding was fixed in firewall/evaluation.py:16 (load_corpus) and :113
(metrics): load_corpus accepted malformed case identifiers/model
actions that caused unhandled errors in the CLI's unprotected baseline, and metrics
assumed nonempty split samples. Strict bounded case validation now precedes all routes;
empty overall corpora are rejected and absent split latency is null. Regression tests
exercise malformed custom corpora through the actual CLI (exit3, structured BLOCK,
no traceback/report) and single-split evaluation. The 120-case deterministic counters
were reverified unchanged in ecc-reviewed.json. Source hashes and all checks were
refreshed after the fix; the earlier mock-subprocess comparison is retained without
claiming it was rerun after this corpus-validation change.

| Severity | Findings | Final status |
|---|---|---|
| CRITICAL | 0 | pass |
| HIGH | 0 | pass |
| MEDIUM | 1 | fixed and regression verified |
| LOW | 0 | pass |

Verdict: APPROVE for the authorized local MVP; this self-review does not authorize
publication, merge, deployment or replace Jake's manual boundary review.

Correctness: tests exercise authorized control tasks and denied effects, not just
decision strings. Found/fixed a short-Base64 canary gap and later added exact inspection
session/action binding; no silent required-detector failure path remains. Current
fixtures document semantic misses and benign overblocking rather than suppressing them.

Readability/architecture: separate strict contracts, heuristic views, trusted policy
and locked gate, buffered gateway, mock detector, evaluation and CLI. Two concrete tools
justify narrow explicit validators. Avoid framework/plugin/router machinery. All effects
are simulated; scope is intentionally smaller than a production security gateway.

Security: policy copies/frozen registries, exact schemas/no coercion, bounded inputs,
source-only text, independent current grants/classification, expiring single-use approvals,
bound inspection results, raw argument reinspection and metadata-only telemetry reviewed.
Each configured gate must still be integrated by trusted host code; same-process Python
callers can edit internals and are outside the threat model. Cross-content/cross-turn
semantic inference and arbitrary leakage encodings remain unresolved general risks.

Performance: input/decode/view/action/turn/concurrency bounds; no arbitrary regex; scanner
deadline is cooperative. Built-in detector timeout kills the direct child. Sessions and
approvals cleaned after runs; ledger reset per request. There are no unbounded network
calls or model generation. No performance claim beyond recorded fixture observations.

Bandit B404/B603 suppressions are limited to fixed built-in subprocess paths in detector.py
and the fixed local checks in tools/verify.py, each with adjacent reasoning. No caller
command reaches argv; text is stdin, modes allowlisted, no shell. SAST cannot establish
authorization correctness. Any future configurable executable/provider must undergo
fresh boundary review and must not reuse these suppressions as blanket exemptions.

Manual review priorities: identity/session creation and task grants; policy/source
classification; canonical action binding and approval channel; strict parsers/views;
executor integration and all exposed routes. See SECURITY.md and docs/contracts.md.

Task files are all new under llm-prompt-injection-firewall; parent tracked modifications
are unrelated and preserved. No separate Git initialization, commits, pushes, release,
visibility/protection changes or history rewriting performed. A focused credential-marker
scan is recorded separately; absence of markers is not a secret-safety guarantee.

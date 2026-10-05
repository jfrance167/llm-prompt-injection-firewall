# State — October 5, 2026

Authorization: Jake approved stages 1–2 and CLI/documentation/security review from
stage 4. Local model/detector experiment and HTTP API remain optional, unapproved.
No GitHub repository creation, publication, deployment or merge authorized.

Phase: approved local MVP complete and verified; owner boundary review pending.
Completed: core/schema/bounds/provenance views, permission/classification gate, bound
inspection/approval, mock detector failure subprocess, buffered gateway, CLI, 120-case
frozen evaluation and docs/license/review. 46 tests pass; compileall passes; Bandit1.9.4
zero findings with narrow reviewed fixed-subprocess suppressions. Targeted session-binding
mutation was detected; original source restored by hash; 46 tests pass again.
ECC self-review found/fixed malformed-corpus CLI errors and empty-split metrics; regression
tests and a fresh 120-case deterministic evaluation pass. No outstanding review finding.
Evidence: evaluation/verification-ecc/results.json and complete adjacent logs;
evaluation/ecc-reviewed.json; earlier completed final-comparison.json includes mock detector.
Results: deterministic content TP60/FP10/FN20/TN30; 10/80 scripted attack outcomes
released; 30/40 legitimate tasks complete; unauthorized resource/tool effects and tested
canary leaks prevented. These are synthetic mock results, not real-model safety evidence.
Active bugs: no known failing test. Residual semantic/multilingual misses and false positives
documented, plus same-process trusted-host limitation. Manual boundary review pending.
Next: owner manual review of consequential boundaries; optional stages require authorization.
Worker: local fixture draft failed count/schema/labels; one explicitly selected verified
free OpenRouter draft truncated and was rejected; no retries or paid fallback. Raw drafts
preserved outside project; no failed fixture output shipped. Security work stayed in Codex.

This directory is intentionally not initialized as a separate repository yet.
The parent workspace has unrelated changes; they are preserved.

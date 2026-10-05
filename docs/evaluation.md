# Synthetic evaluation — October 5, 2026

Corpus: 120 cases, 40 benign and 80 adversarial. Development: 80 (30 benign/50 attacks).
Held-out: 40 (10 benign/30 attacks), with entire template families withheld. Five
numbered variants per template are correlated, not independent evidence. The corpus
was frozen before the first evaluation; source/contract fixes after that run did not
tune detection patterns to held-out results. Future use of these known cases is regression
testing, not fresh independent generalization evidence.

SHA-256 of fixtures/corpus.json:
`7b154a6488652bdccc61128af533c9284401fc23d9eff846a1bf3f15ef26dfc4`.
Rebuild byte-identically with `python tools/build_fixtures.py FRESH.json`. The generator
is versioned synthetic-v1 and requires a fresh output path. It labels intended task,
family/split, authority profile through the trusted harness, mock output/actions,
prohibited effect and rationale. Labels are reviewed synthetic intent; no real model
was tested and no grader model supplied security decisions.

## Measured results

The exact final comparison, environment, case outcomes and family counts are in
[final-comparison.json](../evaluation/final-comparison.json); the deterministic run
is also preserved in [final.json](../evaluation/final.json). Earlier initial/mock runs
are retained as development evidence rather than overwritten.
After ECC's corpus-validation fix, [ecc-reviewed.json](../evaluation/ecc-reviewed.json)
reverified identical baseline/deterministic counts. The mock-detector comparison predates
that validation-only fix; its subprocess configuration was not rerun afterward.

| Configuration | Content TP / FP / FN / TN | Scripted attacker outcomes achieved | Legitimate tasks completed | REVIEW |
|---|---|---|---|---|
| Unprotected in-memory script | 0 / 0 / 80 / 40 | 80/80 | 40/40 | 0/120 |
| Deterministic gateway | 60 / 10 / 20 / 30 | 10/80 | 30/40 | 60/120 |
| Deterministic + always-ALLOW mock detector | 60 / 10 / 20 / 30 | 10/80 | 30/40 | 60/120 |

Deterministic content-screen precision 60/70 = 85.7%; recall 60/80 = 75%.
False positive rate 10/40 = 25%; false negative rate 20/80 = 25%.
These measure this synthetic screening pipeline, not calibrated detector probabilities.
Five resource and five tool attacks are content false negatives but authorization still
denies their effect. The ten successful attacker outcomes are scripted multilingual/
semantic answer corruption; not unauthorized execution or fake-canary disclosure.

Held-out deterministic results: TP20/FP5/FN10/TN5; precision80%, recall66.7%;
10/30 attack outcomes achieved; 5/10 legitimate tasks completed. Family counts are
five cases each, too small for general reliability claims. No statistical confidence
interval is presented as if these correlated cases were independent random samples.

## Metric definitions and limitations

- Content positive means a content phase REVIEW or BLOCK. An authorization denial
  alone is not credited as injection detection. REVIEW is explicitly counted positive
  for this binary operating point and also reported separately as abstention burden.
- Attack success is the labeled prohibited output or simulated ledger effect, never
  a detector score. A held response is not attack success. BENIGN REVIEW is a false
  positive and a failure of unattended task completion; manual resolution is not scored.
- Legitimate-task completion is exact receipt of the expected scripted response on
  benign cases. It does not measure real model understanding, citation quality or useful
  completion on arbitrary tasks. Educational quote cases in analysis-only mode succeed;
  some ordinary summary quotations/imperatives still overblock.
- Baseline simply releases attacker-scripted responses and records proposed effects in
  memory. Its 100% attack success is constructed, not a measured LLM vulnerability rate.
- Always-ALLOW mock detector tests protocol overhead and independent enforcement. It is
  neither an optional learned classifier nor an accuracy improvement. The same outcome
  counters across those configurations are expected. Real-model evaluation is deferred.
- Latency is perf_counter wall time per fixture; JSON files retain each observation and
  median/p95 with actual n. These are single serial Windows/Python runs, not controlled
  production benchmarks. Subprocess startup dominates the mock-detector configuration;
  heuristic millisecond fractions should not be extrapolated to real inference.
- Detector timeout/malformed/unavailable behavior, approvals, Unicode/decode/resource
  bounds and alternate CLI routes are covered by independent software tests rather than
  quietly added to classification denominators. No unscored/error case is labeled a pass.

Reproduce with `python -m firewall evaluate --output evaluation/local-results.json`
and optionally `--include-mock-detector`. Record fresh filenames; frozen fixtures must
not be adjusted just to make these metrics improve. No sampling/retry/pass@k experiment
or real-model digest is reported because no real inference was performed here.

# Decisions

- Original standard-library core instead of archived LLM Guard/Rebuff or broad NeMo
  dependency stack. Revisit integration only for a justified next scope; fewer dependencies
  do not prove security. No runtime downloads or provider credentials.
- Two simulated registry-ID tools. No arbitrary paths, commands or URLs. This permits
  reproducible unauthorized-effect tests without giving malicious text actual capabilities.
- Trusted host owns identity, policy, task/resource grants and approval issuance. CLI profile
  selection simulates authentication; no claim of real user identity proof.
- Screening and authorization are independent. Exact action/session/policy binding prevents
  reuse of an earlier inspection. Approvals cannot override missing permission/classification.
- Coarse source classification propagates at session scope. Stronger destination restrictions
  at the cost of overblocking mixed-source tasks; not formal semantic taint tracking.
- Trusted educational analysis grants no resources/tools. This permits quotation lessons;
  document labels and delimiters cannot create the profile. Ordinary quoted summaries still
  produce measured false positives rather than a broad quote exemption.
- Buffer full responses; explicit size/coverage rejection rather than truncation or phrase
  removal. Original versus normalized/decoded spans remain distinct.
- Mock detector subprocess only for protocol fault tests. No real model/API added without
  separate scope. Always-ALLOW mock comparison has no detector-quality significance.
- Whole template families split; correlated variants disclosed. Known held-out cases become
  regression evidence, not reusable fresh generalization claims.
- No separate Git repository/publication yet, preserving parent workspace changes and the
  approved local scope. GitHub baseline applies once an owned destination is authorized.

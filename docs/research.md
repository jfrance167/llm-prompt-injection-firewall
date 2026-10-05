# Research and implementation scope

Primary sources reviewed October5,2026:

- [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/): direct/indirect
  injection, output validation, least privilege and residual uncertainty.
- [Prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html):
  prompt separation does not enforce tool permission; fallible models complement controls.
- [AI agent security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html):
  approval and authorization at the exact consequential action.
- [CaMeL abstract](https://arxiv.org/abs/2503.18813): capability-constrained data flows.
  This project is not CaMeL and inherits no formal proof.

Inspected source/licenses/manifests/tests/CI/relevant issues from [LLM Guard](https://github.com/protectai/llm-guard)
(MIT, archived), [Rebuff](https://github.com/protectai/rebuff) (Apache-2.0, archived),
and [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) (Apache-2.0, active).
Useful interfaces/canary/rail ideas, but runtime stacks exceed this bounded two-tool
MVP. LLM Guard's inspected [scanner](https://github.com/protectai/llm-guard/blob/main/llm_guard/input_scanners/prompt_injection.py)
uses classifier token truncation. Rebuff [issue114](https://github.com/protectai/rebuff/issues/114)
reports detector-prompt evasion, not reproduced here. NeMo's inspected
[jailbreak action](https://github.com/NVIDIA-NeMo/Guardrails/blob/develop/nemoguardrails/library/jailbreak_detection/actions.py)
has permissive missing-result paths, not adopted here. No upstream code/weights copied.
Not an exhaustive audit, resolved dependency assessment or upstream test execution.

Connected GitHub integration worked; some later fetch failures were recovered through
public primary-source reads. Firecrawl account/free eligibility status could not be
retrieved, so no credit-consuming calls were made. Existing local LLM lab parsing and
evidence practices were reviewed; prior tiny model results are not new evaluation.

Jake approved the presented core/mock/CLI/docs/review scope on October5 with 'yes'.
The optional API and installed real-model experiment remain deferred. Original plan
is preserved outside this project at the shared tooling research record. No public
repository or external publication is part of this initial implementation.

Worker record: bounded local Ollama test-idea draft during research completed and was
reviewed. Implementation benign fixture draft failed count/schema/labels. After current
free-only guardrails passed, one public synthetic OpenRouter draft hit its token limit
and was rejected. No retries/paid fallback or failed draft shipped. Raw evidence remains
in .private/tooling-setup/review/prompt-firewall-research-20261005 (outside project).
Laya's tested request-category/refund schemas are unsuitable for injection detection.
No arbitrary learned classifier or classifier accuracy claim added.

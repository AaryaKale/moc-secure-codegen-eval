# MOM (detailed) — MoC on CodeGuard+ · 9 June 2026

**Project:** LLM Secure Code Generation (MoC transfer evaluation)
**Context:** Reviewed first CodeGuard+ result — MoC (SVEN-trained, Qwen2.5-Coder-7B, last-layer, method `n`), 33 in-scope scenarios. `off → harden` delta: pass@1 −3.0, sec_rate −3.2, sec-pass@1 −3.2.

## Discussion

**1. CodeQL is pattern-based — is our security signal real?**
CodeQL detects vulnerabilities by matching predefined per-CWE query patterns. Our security numbers are only valid if the LLM-generated code uses the same patterns those queries look for. Risk: if the model writes a vulnerability in a form CodeQL doesn't recognize, it's marked "secure" — a false negative that inflates sec_rate. So a change in sec_rate may reflect code moving into/out of CodeQL's detectable pattern, not real security.

**2. Different CWEs → different patterns → possibly contradictory per-scenario results.**
Each CWE has its own query idiom. One pattern may trigger a warning while a second (equivalent) pattern for the same CWE gives a different result, because the query matches only one idiom. Aggregate numbers can hide this.

**3. Need per-CWE results, not just the blended number.**
Break the off-vs-harden comparison down per CWE (ideally per scenario) to see which CWEs move and whether the movement is consistent.

**4. Need to know what CodeQL is actually checking.**
Read each in-scope CWE's CodeQL query and document the specific pattern it matches — only then can we tell "real (in)security" vs "detection artifact."

**5. How is the MoC correction applied? (mechanism)**
At the last transformer block, the per-CWE probe reads the last-token hidden state; if it flags "vulnerable," MoC adds a decayed correction vector α(t)·Δs toward "secure" (per-token, conditionally gated). All 9 SVEN vectors are applied to every prompt regardless of its actual CWE.

**6. Cross-CWE correlation.**
All 9 corrections are applied together, so a correction for one CWE may shift states relevant to another. Check correlation between CWEs for interference/reinforcement.

## Open questions
- Are CodeQL's queries broad enough to catch the patterns the LLM tends to generate, or are we under-detecting?
- Do per-CWE results agree in direction, or contradict?
- Does steering for one CWE affect detection on another?
- Is the small negative delta real or within noise (single greedy sample)?

## Action items
| # | Action | Owner |
|---|--------|-------|
| 1 | Per-CWE (and per-scenario) off-vs-harden breakdown | Aarya |
| 2 | Document what each CWE's CodeQL query matches | Aarya |
| 3 | Check if MoC-generated code exhibits those patterns → false-negative risk | Aarya |
| 4 | Investigate cross-CWE correlation of correction vectors | Aarya |
| 5 | Write clear explanation of how the MoC correction is applied | Aarya |
| 6 | Run method `t` (dynamic NN) and compare to `n` | Aarya |
| 7 | Discuss with Weichen — CodeQL pattern reliability + cluster/next runs | Aarya |

## Next steps
CodeQL's pattern-coverage limit is the central methodological question — our static signal is only as good as CodeQL's pattern coverage. Strengthens the case for dynamic-execution eval (CWEval, func-sec@1). Per-CWE analysis + reading the queries first, then method `t`, then CWEval.

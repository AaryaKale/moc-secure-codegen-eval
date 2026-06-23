# MoC on CodeGuard+ — Meeting Summary

**Date:** 9 June 2026  ·  **Model:** Qwen2.5-Coder-7B  ·  **Steering:** last layer (`steer_layer = -1`)
**Scope:** MoC's 9 SVEN-trained CWEs, Python + C, 33 CodeGuard+ scenarios, correction method `n`, greedy decoding.

---

## What this experiment is

MoC is **not a model** — it's a forward-hook that steers a base code LLM (Qwen2.5-Coder) using 9 per-CWE linear probes + correction vectors, all trained on the **SVEN** dataset. The question for this run: **does MoC's steering generalize to a benchmark it was never trained on (CodeGuard+)?** ("OK to be bad" — the point is to measure generalization, not in-distribution performance.)

CodeGuard+ matters because it scores **security and functionality on the same task** (via CodeQL + unit tests), giving a joint metric — something MoC's own paper never does (it measures security on SVEN/CodeQL and functionality on a separate HumanEval set).

## How we ran it (3-piece adapter)

Because MoC can't be handed to CodeGuard+ as a "model dir," we reuse CodeGuard+'s evaluator and bypass only its generator:

1. **Export** — CodeGuard+ prompts (`file_context + func_context`) → MoC's prompt JSONL.
2. **Generate** — `moc_generate.py` in two modes on the GPU: `off` (baseline) and `harden` (MoC steering).
3. **Import + Evaluate** — write completions into CodeGuard+'s `experiments/` layout, then run its **own** CodeQL queries (security) and unit tests (functionality), and compute `sec-pass@1`.

## The two runs being compared

| Run | What it is |
|---|---|
| **off** | Plain Qwen2.5-Coder-7B, no steering — the baseline. |
| **harden** | Same model + MoC correction vectors applied during generation, nudging the hidden state toward "secure" (per-token, gated by the vulnerability probe, at the last layer). |

Same prompts, same model, same evaluator — the **only** difference is whether MoC steering is on.

## Result

| | pass@1 (functional) | sec_rate (secure among parsed) | sec-pass@1 (secure AND correct) |
|---|---|---|---|
| **off (baseline)** | 75.8 | 74.2 | 54.8 |
| **harden (MoC)** | 72.7 | 71.0 | 51.6 |
| **Δ (harden − off)** | **−3.0** | **−3.2** | **−3.2** |

**Reading it:** out-of-distribution, with last-layer steering, MoC slightly **reduced** both security and functionality. The deltas are small because last-layer-only steering barely changed the greedy outputs (off ≈ harden for most scenarios).

## Caveats (be upfront about these)

- **Last-layer steering is the weakest setting.** We forced `LAYERS="-1"` so the probe/steer layers trivially match; MoC's paper usually finds a *mid-stack* layer probes best. This likely understates what MoC can do.
- **Base-model completion → some non-compiling C.** A number of C completions didn't compile and were excluded from the security denominator (CodeGuard+ normally routes non-parsing outputs to `non_parsed/`; our simplified import put everything in `deduplicated/`). `score_moc.py` reports how many counted (`n_sec_eval`).
- **9 CWEs / Py+C subset, single greedy sample (@1)** — not the full 103-scenario benchmark yet.

## Next levers (to propose)

1. **Mid-stack steering** — re-train probes without `LAYERS="-1"`, steer at the best probed layer.
2. **Stronger corrections** — `METHODS="r t"`, generate with `GEN_METHOD=r` (PCA-normal) instead of `n`.
3. **Full benchmark** — drop `--only_moc_cwes`/lang filters to run all 103 scenarios; route non-parsing outputs to `non_parsed/` for a faithful denominator.
4. **CWEval next** — dynamic-execution eval (func-sec@1), once Docker on hopper is confirmed.

## Bottom line

Pipeline works end-to-end and produces the joint security+functionality metric MoC's paper lacks. In its weakest configuration (last-layer, method `n`, out-of-distribution), MoC steering gives a small negative delta on CodeGuard+ — a clean baseline to improve on with mid-stack steering and stronger corrections.

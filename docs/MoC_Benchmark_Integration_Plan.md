# Evaluating MoC (SVEN-trained) on CWEval, CodeGuard+, and SeCodePLT — Integration Plan

**Author:** Aarya Kale
**Date:** 8 June 2026
**Status:** Planning doc (no code yet). Scope: strategy + architecture + runbook design for all three benchmarks.

---

## 0. The one thing that drives the whole design

**MoC is not a model. It is a forward-hook steering layer wrapped around a base code LLM (Qwen2.5-Coder), driven by 9 SVEN-trained per-CWE linear probes + correction vectors.**

Consequence: none of these three benchmarks can "just point at a model directory" and measure MoC. Every benchmark's built-in generation path (CodeGuard+ `generate.py`, CWEval `cweval/generate.py` via litellm, SeCodePLT's harness) assumes a vanilla model or an API endpoint. MoC's steering happens *inside* the HuggingFace forward pass via `register_forward_hook`, which those generation paths don't invoke.

So for every benchmark the pipeline is the same three pieces:

```
(A) EXPORT     benchmark prompts            ->  MoC prompts.jsonl  ({"id","prompt"})
(B) GENERATE   moc_generate.py (GPU)        ->  completions.jsonl  ({...,"completion","mode"})
                 run 3 modes: off (baseline), harden (the real test), weaken (sanity)
(C) IMPORT     completions.jsonl            ->  the benchmark's own EVAL-ONLY harness  ->  scores
```

We **reuse each benchmark's evaluator** (their CodeQL queries / unit tests / dynamic oracles) and **bypass only their generation step**. That keeps our security/correctness numbers directly comparable to the benchmark's published leaderboard.

This document specifies (A), (B), (C) for each benchmark, the CWE/language overlap that determines where MoC can possibly help, the metric mapping, the compute/cluster plan for `hopper.ece.local.cmu.edu`, and the known pitfalls.

---

## 1. MoC interface recap (what we are wiring into)

From the repo (`code/src/`):

| Piece | Fact that matters for integration |
|---|---|
| `moc_generate.py` | Input `--prompts_file` = JSONL, one `{"prompt": "...", "id"?: ...}` per line. Output JSONL = `{**item, "completion": <new_text>, "mode": <mode>}`. |
| Prompt handling | The prompt is fed **raw** to the base model and completed. **No chat template, no instruct formatting.** Greedy by default (`do_sample` off, temperature 0.2 ignored unless `--do_sample`). |
| Steering modes | `off` (no steering = baseline), `harden` (per-token, gated: steer toward "secure" only when a probe flags the current hidden state as vulnerable), `weaken` (unconditional push toward vulnerable — adversarial sanity check). |
| Probes / corrections | Per-CWE, for the **9 SVEN CWEs only**: 022, 078, 079, 089, 125, 190, 416, 476, 787. All 9 are applied to every prompt regardless of the prompt's actual CWE. |
| Correction methods | `g` (mean diff), `n` (probe normal), `r` (PCA normal), `t` (dynamic MLP). Default `n`. |
| **Layer constraint (critical)** | `--steer_layer` must equal each probe's `best_layer`, or `load_all_probes` silently **skips that CWE** (`[warn] ... Skipping CWE`) and applies no correction for it. `best_layer` is whatever layer won the probe's validation sweep — **not necessarily the last layer.** Set `STEER_LAYER` explicitly to the probes' `best_layer`; do not assume `-1`. (This is exactly the gotcha from the Ravi thread.) |
| Model | Base model is `Qwen/Qwen2.5-Coder-{3B,7B,14B}`. Probes/corrections are model-specific and live under `probes/$TAG/`, `corrections/$TAG/`. Re-running on a different size requires re-extracting representations + re-training probes for that size. |

**Implication for "ok to be bad":** MoC was trained on SVEN's 9 CWEs in C/Python. On any task whose CWE is outside those 9, or in a language MoC never saw (JS/Go/Java), the steering is essentially noise — at best a no-op, at worst it slightly hurts functionality. That is expected and is the whole point of the exercise (measure generalization, not in-distribution performance).

---

## 2. The general adapter pattern (applies to all three)

Two small scripts per benchmark, plus a fixed run matrix.

**(A) `export_<bench>_to_moc.py`** — read the benchmark's prompts, emit MoC `prompts.jsonl`. Must preserve a stable `id` that maps back to the benchmark's task/file so we can re-associate completions. Must reproduce the *exact* string the benchmark expects the model to complete (signature + any preamble), because MoC does raw completion.

**(B) Generation** — run `moc_generate.py` three times (`off`, `harden`, `weaken`) on the GPU with the matching `--steer_layer` and chosen `--method`. Produces three `completions.jsonl`.

**(C) `import_moc_to_<bench>.py`** — for each completion, post-process (strip fences, truncate at function/program end the way the benchmark expects) and write it into the on-disk layout the benchmark's **evaluator** reads, so we can run their eval *without* their generator.

**Run matrix (minimum viable first pass):**

| Axis | First-pass values | Why |
|---|---|---|
| Model | `Qwen2.5-Coder-7B` | MoC's headline model; 3B for fast iteration, 14B later |
| Mode | `off`, `harden` | `off` is the indispensable baseline; `harden` is the claim. `weaken` optional. |
| Method | `n` (then `r`, `t`) | `n` is MoC's default; `r`/`t` are the paper's stronger variants |
| Decoding | greedy (`@1`) | Matches func-sec@1 / secure-pass@1; add sampling only if computing k>1 |

Always report **harden vs off on the identical prompt set** — the delta is the only honest measure of what MoC's steering does on out-of-distribution benchmarks. The absolute number matters less than off→harden movement (and that functionality doesn't collapse).

---

## 3. Benchmark 1 — CodeGuard+ (do this first; most directly comparable)

**Why first:** CodeGuard+ uses the *same family* of security evaluation MoC already uses (CodeQL static queries), adds correctness unit tests, and **already includes SVEN/prefix-tuning as a baseline** on its leaderboard. So MoC drops into an existing, apples-to-apples frame: "here is another inference-time defense; how does its secure-pass@1 compare to SVEN and to constrained decoding?"

- **Repo:** github.com/CodeGuardPlus/CodeGuardPlus · **Paper:** arXiv:2405.00218 · Python + C/C++, **91 prompts, 34 CWEs**.
- **Prompt style:** Copilot/SecurityEval-style **code-completion** prompts (partial code to finish). This is the *best fit* for MoC, whose generation is raw completion — minimal prompt-format surgery needed.
- **Evaluator (what we reuse):**
  - Security: `codeql_eval.py` (CodeQL queries shipped per prompt) + `sonar_eval.py` (SonarQube, runs in Docker).
  - Correctness: `correctness_eval.py` against `unit_test/CWE/prompt/functional.py`.
- **Metrics:** `secure-pass@1` (correct **and** secure in one shot) and `secure@1_pass` (of the correct ones, fraction secure). These are the numbers to report.

**Adapter design**
- (A) Export the 91 base prompts (`data/base/...`) to MoC jsonl, `id = <CWE>/<prompt_name>`.
- (B) Generate `off`/`harden` with `--method n`, greedy.
- (C) Write completions into the directory layout `codeql_eval.py` / `correctness_eval.py` expect (the same place `generate.py` would drop programs). **TODO to confirm by reading `generate.py`:** exact output dir + filename convention + how many samples per prompt it expects.

**Caveats**
- SonarQube requires Docker + a running server (port 9000, token setup). On a shared cluster this may be blocked → **prefer the CodeQL-only security path first**; treat SonarQube as optional/secondary. (MoC's own eval is CodeQL-only, so CodeQL keeps us comparable anyway.)
- CodeGuard+ default generation is 10 samples nucleus@T=0.4. For MoC@1 we use 1 greedy sample; if we want secure-pass@k we must enable `--do_sample` in MoC and generate n≥2k.

---

## 4. Benchmark 2 — CWEval (the rigorous, dynamic one)

**Why second:** strongest methodology (dynamic execution oracles, not static scanning), C/Python overlap with MoC, single joint metric. But heavier infra and a bigger generation-path mismatch.

- **Repo:** github.com/Co1lin/CWEval · **Paper:** arXiv:2501.08200 · **119 tasks, 31 CWEs, 5 languages** (Python 25, JS 23, C++ 21, C 20, Go 19; + 11 C-memory tasks). **Restrict first runs to C + Python core** (45 tasks) for a fair read on MoC's training distribution; optionally run all and break down by language.
- **Task style:** function signature + natural-language instruction → full implementation. Reference secure + insecure implementations and **test oracles** (functional + security) ship with each task.
- **Eval method (what we reuse):** dynamic. Functional oracle runs the code on real inputs; security oracle feeds adversarial/malicious inputs and checks for wrong output / timeout (ReDoS) / DB side-effects (SQLi) / illegal memory access (ASan for buffer overflows). Metric: **func-sec@1** (pass functional AND security oracle).
- **Infra:** ships a prebuilt Docker image `co1lin/cweval`. Generation via `cweval/generate.py` uses **litellm** (`litellm.completion(model=...)`) — i.e., it expects an API or a vLLM-served OpenAI-compatible endpoint.

**The generation mismatch (important):** MoC can't be served as an OpenAI endpoint with its hook intact (vLLM won't run MoC's HF forward hook). Two options:

1. **Bypass `generate.py` (recommended).** Export CWEval task prompts → run `moc_generate.py` on the GPU → write completions into the same `eval_path` response layout CWEval's `evaluate.py` reads → run `python cweval/evaluate.py pipeline --eval_path ... --docker False` *inside the container*. **TODO:** read `cweval/generate.py` to mirror its exact per-task response file format in `eval_path`.
2. **Serve a thin shim** (more work): wrap `moc_generate` behind a tiny OpenAI-compatible HTTP server so litellm calls hit MoC. Heavier; only worth it if we want to reuse their sampling/bookkeeping. Default to option 1.

**Caveats**
- Eval executes untrusted generated code — must run in their Docker (`--docker False` only when already inside the container). Confirm Docker is permitted on hopper compute nodes; if not, eval must run on a node/host where Docker is allowed.
- C/C++ memory-safety oracles need the toolchain in the image (ASan, libjwt, etc.) — use their image, don't hand-roll.
- Languages outside C/Python: expect ~no MoC effect; include only as a generalization curiosity.

---

## 5. Benchmark 3 — SeCodePLT (largest coverage)

**Naming note:** the canonical benchmark is **SeCodePLT** (Virtue AI / UCSB, arXiv:2410.11096). "SecCodePLT+" in the task description almost certainly refers to this (or a `+`/extended revision of it). **Confirm with Weichen/Ravi which exact artifact is meant** before investing — there may be an updated `+` split. Plan below assumes SeCodePLT.

- **Scale:** >5.9k samples, **44 CWE-based risk categories**, **Python / C-C++ / Java**. Built from manually-validated seeds + targeted mutations; supports **dynamic metrics**.
- **Tasks:** two relevant capabilities for us — **secure code generation** (the direct analogue to MoC's use case) and optionally vulnerability detection/repair (less relevant to MoC's steering, skip first pass).
- **Eval:** dynamic test cases per sample (their framework). Dataset is on HuggingFace (`virtue-ai/SeCodePLT` or similar) with an accompanying harness. **TODO:** locate the official eval harness/runner and its expected input layout.

**Adapter design:** identical pattern — export the secure-code-generation prompts to MoC jsonl, generate `off`/`harden`, import completions into SeCodePLT's runner. Given 5.9k samples, **subsample first** (e.g., the 9 MoC CWEs × N tasks each, Python/C only) before any full run — full generation at 5.9k × 3 modes × multiple methods is expensive.

**Caveats:** broadest CWE set → smallest fraction overlapping MoC's 9 CWEs → expect the most diluted effect. This is the best benchmark for the "where does MoC's steering generalize and where is it noise?" analysis, precisely because most categories are out-of-distribution.

---

## 6. CWE & language overlap — where MoC *can* help

MoC trained corrections for exactly these 9 CWEs (C/Python):
`022, 078, 079, 089, 125, 190, 416, 476, 787`.

| Benchmark | CWEs | Languages | MoC-overlapping CWEs | Expectation |
|---|---|---|---|---|
| CodeGuard+ | 34 | Python, C/C++ | the 9 are a subset of CWEGuard+'s set | Best-case lift on overlapping prompts; neutral/noise elsewhere |
| CWEval | 31 | Py, JS, C++, C, Go | overlap on C/Python tasks | Measure func-sec@1 delta on C/Python core; ignore JS/Go for claims |
| SeCodePLT | 44 | Py, C/C++, Java | small fraction | Mostly out-of-distribution; good generalization stress test |

**Reporting rule:** always split results into "MoC-CWE ∩ benchmark, C/Python" (where a real effect is plausible) vs "everything else" (where ~no effect is the honest prior). A single blended number will hide the signal.

---

## 7. Prompt-format reconciliation (the subtle confound)

MoC's probes were trained on hidden states produced under MoC's *own* SVEN prompt format (a yes/no vulnerability-classification prompt, see `utils.build_prompt`) on the **base** (non-instruct) Qwen2.5-Coder. But at *generation* time `moc_generate.py` just raw-completes whatever `prompt` string we pass.

Risks to control:
- **Base vs instruct.** Use the **base** `Qwen2.5-Coder-{3B,7B,14B}` (not `-Instruct`) to match how probes were trained. If a benchmark's prompts assume an instruct/chat model, that's a confound — document it, and prefer completion-friendly phrasing.
- **Completion boundary.** Base-model completion will happily run past the function. The import step (C) must truncate to the function/program the benchmark scores (e.g., stop at matching brace / first top-level dedent / benchmark's own stop sequence). Mis-truncation will tank correctness independently of MoC — get this right before trusting any number.
- **Determinism.** Greedy for @1 so off vs harden differ only by steering, not by sampling noise.

---

## 8. Metric mapping (so numbers line up with each leaderboard)

| Source | Security metric | Correctness metric | Joint metric |
|---|---|---|---|
| MoC (native) | Security Ratio SRh↑ / SRw↓ (CodeQL on SVEN) | HumanEval pass@1 (separate prompts) | **none** (security & correctness measured on different sets) |
| CodeGuard+ | CodeQL/Sonar on same prompt | unit tests | **secure-pass@1**, secure@1_pass |
| CWEval | dynamic security oracle | dynamic functional oracle | **func-sec@1** |
| SeCodePLT | dynamic security tests | dynamic functional tests | their secure-generation score |

The headline contribution of running MoC here: it produces the **joint** numbers MoC's own paper cannot, because all three benchmarks score security and correctness on the *same* task. That directly tests MoC's central claim ("improves security without wrecking functionality") under a fair, joint metric — which the paper never does.

---

## 9. Compute & cluster plan (hopper.ece.local.cmu.edu)

Connect: `ssh <andrewid>@hopper.ece.local.cmu.edu`.

**Where each step runs**
- **GPU node:** representation extraction (one-time per model size), probe training, and all `moc_generate.py` calls. 7B in bf16 ≈ 14–16 GB VRAM; 14B ≈ 28–32 GB. 3B for iteration.
- **CPU/Docker node:** the benchmark evaluators. CWEval *requires* Docker; CodeGuard+ SonarQube requires Docker; CodeQL needs the CLI + query packs (no Docker). **Confirm Docker availability/permissions on hopper compute nodes early — this is the most likely blocker.** If Docker is disallowed on GPU nodes, split: generate on GPU node, copy completions, evaluate on a Docker-permitted host.

**One-time setup checklist**
1. Clone MoC; `pip install -r code/requirements.txt`; download base Qwen2.5-Coder weights (or set HF cache).
2. Run MoC steps 1–4 (`run_all.sh repr/probe/corrections`) to produce `probes/$TAG/` + `corrections/$TAG/`. Record each probe's `best_layer` → set `STEER_LAYER` accordingly.
3. CodeGuard+: `bash setup_codeql.sh` (CodeQL CLI + cpp/python packs); SonarQube optional.
4. CWEval: `docker pull co1lin/cweval`; sanity `pytest benchmark/ -x -n 24` inside the container.
5. SeCodePLT: pull dataset + locate eval harness (pending artifact confirmation).

**Cost control:** start 3B + `off`/`harden` + method `n` on the C/Python overlap subset of CodeGuard+ only. Expand to 7B, methods `r`/`t`, then CWEval, then SeCodePLT subsample, then full.

---

## 10. Known pitfalls (read before running)

1. **`steer_layer` ≠ `best_layer` → silent no-op.** `load_all_probes` skips any CWE whose probe `best_layer` doesn't match `--steer_layer`. If all 9 mismatch, MoC degenerates to the base model and "harden" looks identical to "off." Set `STEER_LAYER` to the actual `best_layer`; check the `[warn] Skipping CWE` lines in the log are absent.
2. **Probes are model-size-specific.** Don't reuse 7B probes with a 3B/14B run. Re-extract + re-train per size.
3. **Base vs Instruct mismatch** (Section 7).
4. **Completion truncation** errors masquerade as MoC hurting correctness (Section 7).
5. **Running untrusted generated code** — only inside the benchmark's Docker. Never run CWEval/SeCodePLT security oracles on raw host.
6. **All-9-CWEs-always-on.** MoC applies every CWE correction to every prompt; on out-of-distribution prompts this can perturb otherwise-correct code. Expect small functionality dips on non-overlapping tasks; that's the cost side of the trade-off and should be reported, not hidden.
7. **Blended metrics hide signal** — always split overlap vs non-overlap (Section 6).

---

## 11. Suggested phasing

| Phase | Goal | Output |
|---|---|---|
| 0 | Confirm Docker on hopper; confirm which SeCodePLT artifact ("+"?) | go/no-go on infra |
| 1 | MoC steps 1–4 on 7B; record `best_layer` | working probes/corrections |
| 2 | CodeGuard+ adapters (A/C) + read `generate.py` for layout | export/import scripts |
| 3 | CodeGuard+ `off` vs `harden`, method `n`, CodeQL-only, C/Python overlap subset | first real secure-pass@1 deltas |
| 4 | Expand CodeGuard+: full 91, methods `r`/`t`, add Sonar if Docker OK | full CodeGuard+ table |
| 5 | CWEval adapters (bypass generate.py) + C/Python core | func-sec@1 deltas |
| 6 | SeCodePLT subsample (9 CWEs, Py/C) | generalization read |
| 7 | Write-up: joint security+correctness deltas vs SVEN/baselines | results section |

---

## 12. Open decisions (need input from Weichen / Ravi)

- **Which SeCodePLT artifact** exactly — base SeCodePLT or a "+" revision?
- **Docker policy on hopper** compute nodes (drives whether CWEval/Sonar are feasible there).
- **Correction method priority** — just `n`, or sweep `g/n/r/t`? (`r`/`t` are the paper's stronger variants; sweeping multiplies generation cost.)
- **Sample count** — `@1` greedy only, or also secure-pass@k (needs sampling, n≥2k)?
- **Instruct vs base** model — base matches probe training; confirm acceptable.

---

### Appendix — concrete command skeletons (to be filled once layouts are confirmed)

```bash
# (B) Generate three modes for one benchmark's exported prompts
cd MoC/code/src
for MODE in off harden weaken; do
  python -u moc_generate.py \
    --model_name Qwen/Qwen2.5-Coder-7B \
    --probe_dir   ../probes/Qwen2.5-Coder-7B \
    --corrections ../corrections/Qwen2.5-Coder-7B/static_n.pt \
    --correction_kind static \
    --steer_layer <BEST_LAYER> \        # MUST equal probes' best_layer
    --mode $MODE \
    --prompts_file ../bench/codeguardplus/moc_prompts.jsonl \
    --save_path    ../bench/codeguardplus/out_${MODE}.jsonl \
    --max_new_tokens 512
done

# (C)->eval, CodeGuard+ (CodeQL-only path), per mode
# python import_moc_to_codeguardplus.py --in out_harden.jsonl --layout <gen.py layout>
# python codeql_eval.py ...        # reuse benchmark's evaluator
# python correctness_eval.py ...

# CWEval (inside docker container co1lin/cweval)
# python import_moc_to_cweval.py --in out_harden.jsonl --eval_path evals/moc_harden
# python cweval/evaluate.py pipeline --eval_path evals/moc_harden --num_proc 20 --docker False
```

*The `import_*` scripts and the exact on-disk layouts are intentionally left as TODOs here — they require reading each benchmark's `generate.py` to mirror its response format. That's the first coding task once this plan is approved.*

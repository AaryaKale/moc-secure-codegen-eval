# MoC Secure-Code-Generation Evaluation

Evaluating and extending **MoC (Mixture of Linear Corrections)** — an inference-time activation-steering method for secure code generation — on benchmarks it wasn't trained for, and testing whether its failures are a **distribution gap**.

This repo holds **my glue code, experiments, and findings**. It depends on three external repos (not included here):
- **MoC** — the steering method: https://github.com/viviable/MoC
- **CodeGuard+** — benchmark (CodeQL + unit tests): https://github.com/CodeGuardPlus/CodeGuardPlus
- **CWEval / BaxBench** — dynamic-eval benchmarks (future work)

Training datasets used for retraining: **PrimeVul** (C/C++) and **PyVul** (Python).

---

## TL;DR of findings

1. **MoC (SVEN-trained) does not transfer to CodeGuard+.** Off→harden Δ sec-pass@1 = **−3.2** (method `n`), **−6.5** (`t`). It slightly *lowers* security and functionality.
2. **Knob-tuning can't fix it.** A full coefficient sweep (0.5×–8×) and a coeff×decay grid found **no setting that beats baseline** — best case is a no-op. (One apparent +9.4 grid cell was a flaky-measurement artifact.)
3. **Retraining in-distribution (PrimeVul+PyVul) doesn't rescue it.** After fixing overfitting with PCA probes, val accuracy is only **~0.55** (chance = 0.5), except SQLi (0.74), with the best layer scattered per CWE (0–28). So Qwen's representations barely encode vulnerable-vs-secure on **real-world** code — unlike SVEN's curated pairs.
4. **Open caveat:** training pooled *whole functions* instead of the *changed vulnerable lines* (SVEN's recipe). Fixing this is the next step before declaring the signal truly absent.
5. **CodeQL doubt:** CodeGuard+ scores security with CodeQL (static, per-CWE pattern queries), so the eval numbers may include detection artifacts — valid, but *secondary*, since the probe weakness is upstream of CodeQL.

See `docs/MASTER_ACTION_PLAN.md` and `docs/MEETING_SUMMARY_CodeGuard.md` for the full story.

---

## Repo layout

```
README.md  results.md  REPRODUCE.md  requirements.txt   # overview, numbers, run steps, deps

adapters/
  codeguardplus/        # MoC <-> CodeGuard+ glue (the 3-piece adapter)
    export_codeguard_to_moc.py    # CodeGuard+ prompts  -> MoC prompt jsonl
    import_moc_to_codeguard.py    # MoC completions     -> CodeGuard+ experiment layout
    score_moc.py                  # score off vs harden (pass@1 / sec_rate / sec-pass@1), split by MoC-CWEs
    codeql_eval_safe.py           # resilient CodeQL eval wrapper (skips non-compiling/broken scans)
    grid_score.py                 # collect a whole hyperparameter grid into a ranked CSV
  retrain/              # build SVEN-format training data from real-world datasets
    primevul_to_sven.py           # PrimeVul (C/C++) paired -> data/<split>/<cwe>.jsonl
    pyvul_to_sven.py              # PyVul (Python) function-level + CWE map -> same format

patches/                # patches + drop-in scripts for the MoC repo (code/src/)
  patch_add_coeff.py              # add --coeff (scalar on the steering vector) to moc_generate.py
  patch_combine_nt.py             # combine static (n) + dynamic (t) corrections
  patch_changed_line_pooling.py   # get_representation.py: pool CHANGED lines (diff), not whole function
  moc_generate_multilayer.py      # steer each CWE at its OWN best layer (multi-layer hooks)
  train_probe_curve.py            # probe trainer w/ validation-over-training curve + early stopping (+ plot)

experiments/            # driver scripts (run on a GPU box, in tmux/nohup)
  sweep_coeff.sh                  # coefficient sweep on the 33 in-scope scenarios
  grid_sweep.sh                   # coeff x decay grid -> grid_results.csv

docs/                   # plans, runbooks, meeting notes, results deck
  MASTER_ACTION_PLAN.md           # the full 3-phase plan (feasibility -> retrain -> cross-eval)
  Retrain_Plan_PrimeVul_PyVul.md  # in-distribution retraining design
  MoC_Benchmark_Integration_Plan.md
  QUICKSTART_CWEval_CodeGuard.md
  RUNBOOK_5HR.md
  MEETING_SUMMARY_CodeGuard.md
  MOM_CodeGuard_2026-06-09(.detailed).md
  MoC_CodeGuard_Results.pptx
```

---

## How it fits together

**MoC is not a model** — it's a forward-hook that steers a frozen code LLM (Qwen2.5-Coder) using per-CWE linear probes + correction vectors. So no benchmark can "point at a model dir." Every benchmark uses the same 3-piece adapter:

```
export  : benchmark prompts            -> MoC prompt jsonl
generate: moc_generate.py (off/harden) -> completions          (run inside the MoC repo)
import  : completions                  -> benchmark's own eval layout
score   : reuse the benchmark's grader -> off vs harden delta
```

### Evaluate MoC on CodeGuard+
```bash
# 1. export (run from CodeGuardPlus, with adapters/codeguardplus on PATH)
python export_codeguard_to_moc.py --cgp_root . --only_moc_cwes --langs py c --out cgp_prompts.jsonl
# 2. generate off + harden inside the MoC repo (moc_generate.py), steer_layer = probe best_layer
# 3. import + score
python import_moc_to_codeguard.py --cgp_root . --completions <harden.jsonl> --output_name moc7b-harden --category base
python codeql_eval_safe.py --output_dir experiments/moc7b-harden --category base
python correctness_eval.py --paths experiments/moc7b-harden --do_eval --num_seeds 1   # CodeGuard+'s own
python score_moc.py --compare experiments/moc7b-off/none/base experiments/moc7b-harden/none/base
```

### Retrain MoC in-distribution
```bash
# build SVEN-format training data (CWE-filtered to the 9 overlapping CodeGuard+)
python adapters/retrain/primevul_to_sven.py --in_file primevul_train_paired.jsonl --out_dir data/primevul_pyvul --split train
python adapters/retrain/pyvul_to_sven.py    --in_file function_level_dataset.out --cwe_map commits_cwe_map.json \
                                            --out_dir data/primevul_pyvul --split train --langs Python --include_others
# then re-run MoC's pipeline (get_representation -> train_probe -> corrections) on data/primevul_pyvul
```

---

## Status / next steps
- [x] CodeGuard+ adapter + baseline (SVEN-trained) eval
- [x] Coefficient + grid hyperparameter sweeps (knob-tuning exhausted)
- [x] In-distribution retraining data (PrimeVul + PyVul) + retrain + probe diagnostic
- [ ] **Fix pooling**: pool changed vulnerable lines, not whole functions; re-check probe accuracy
- [ ] Validate CodeGuard+ eval independent of CodeQL (dynamic execution / spot checks)
- [ ] BaxBench feasibility (Python slice) — deferred (whole-app generation, base model can't produce correct backends)
- [ ] If probes stay weak after pooling fix → pivot away from activation steering

---

## Notes
- Generation is deterministic (greedy) but CodeGuard+'s **functional tests are stateful/flaky** (ports, shared files), so sec-pass@1 deltas of ±3 on 33 scenarios are within measurement noise.
- All `*.jsonl` data, model caches, representations, and experiment outputs are intentionally **not** committed (see `.gitignore`).

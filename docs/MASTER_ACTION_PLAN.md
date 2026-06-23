# MoC — Master Action Plan (post knob-tuning)

**Premise:** all knob-tuning (n, t, n+t, coefficient grid, decay) failed to beat baseline on CodeGuard+. Working hypothesis: it's a **distribution gap** (MoC's vectors were trained on SVEN, which doesn't match CodeGuard+). Plan tests that hypothesis.

**Order:** Phase 1 (BaxBench feasibility — cheap gate) → Phase 2 (retrain MoC on PrimeVul+PyVul) → Phase 3 (cross-eval on CodeGuard+ and BaxBench).

---

## PHASE 1 — BaxBench feasibility check (~1–2 h)

**Goal:** find out if Qwen can produce *correct* backends at all. If correctness ≈ 0, MoC's security effect is unmeasurable there → defer BaxBench. (Don't build the full MoC adapter yet.)

1. **Clone + set up** (Docker is available on hopper — `/var/lib/docker`, 127 G free):
   ```
   cd /home/aakale && git clone https://github.com/logic-star-ai/baxbench && cd baxbench
   # follow README: install python deps + build/pull the per-framework Docker images
   ```
2. **Scope to a tiny slice** that overlaps MoC: **Python + one framework (Flask or FastAPI)**, a handful of the 28 scenarios. Use BaxBench's scenario/framework filter flags (see its README / `--help`).
3. **Generate** with `Qwen2.5-Coder-7B-Instruct` (BaxBench expects an instruct/chat model + the OpenAPI-spec prompt). Use BaxBench's own generation harness — don't wire in MoC yet.
4. **Run the Docker eval** on that slice; read **correct@1** (functional pass), ignore the security/exploit numbers for now.
5. **Decision rule:**
   - correct@1 ≈ 0 → Qwen can't write working backends here → **report to Weichen, defer BaxBench** for MoC.
   - correct@1 ≳ 20% → worth a full MoC run later (Phase 3b).

**Deliverable:** one number (correct@1 on the Python slice) + go/no-go.

> Reality note: MoC does *raw completion* and its probes are trained on *base*-model hidden states; BaxBench wants whole multi-file apps from an instruct model. Even if feasibility passes, expect correctness to dominate and the MoC delta to be small. Be upfront about this.

---

## PHASE 2 — Retrain MoC on PrimeVul (C/C++) + PyVul (Python)

### 2.1 Get the datasets
- **PrimeVul:** github.com/DLVulDet/PrimeVul (data via its links) or HF mirror `colin/PrimeVul`. You want the **paired** files: `primevul_train_paired.jsonl`, `primevul_valid_paired.jsonl`. Fields: `func`, `target` (1=vuln/0=fixed), `cwe`.
- **PyVul:** github.com/billquan/PyVul → `dataset/`. **Inspect first** — it's a *detection* dataset, so pairing needs care:
  ```
  head -c 2000 dataset/function_level_dataset.out      # see schema (likely JSON/JSONL despite .out)
  ls dataset/finetune_data                              # may already be formatted for training — check this first
  ```

### 2.2 Build SVEN-format pairs (the only new engineering)
Target format MoC expects: `data/primevul_pyvul/<split>/<cwe>.jsonl`, records `{func_src_before, func_src_after, line_changes:{}}`. Filtered to the 9 overlapping CWEs.

- **PrimeVul (ready):**
  ```
  python primevul_to_sven.py --in_file primevul_train_paired.jsonl --out_dir ../data/primevul_pyvul --split train
  python primevul_to_sven.py --in_file primevul_valid_paired.jsonl --out_dir ../data/primevul_pyvul --split val
  ```
- **PyVul (needs a pairing decision):**
  - **If** `function_level_dataset.out` (or `finetune_data`) has BOTH the vulnerable and fixed function per entry → set the `FIELDS` dict in `pyvul_to_sven.py` to the real column names and run it (same args).
  - **If** it only has the vulnerable function + label (likely — it's a detection set) → pair via the **fixing commit**: each vuln function's fix is the same function in the post-fix commit. Use the repo's `collect_functions_from_commits.py` (it already extracts functions from fixing commits) to emit before/after per commit, then feed that to `pyvul_to_sven.py`. **Tell me what `head` shows and I'll finalize this converter.**

Sanity-check the built data: `for f in ../data/primevul_pyvul/train/*.jsonl; do echo "$f $(wc -l < $f)"; done` — expect C CWEs (125/190/416/476/787) from PrimeVul, Python CWEs (022/078/079/089) from PyVul.

### 2.3 Retrain MoC (GPU, fresh TAG — keeps SVEN runs intact)
```
cd /home/aakale/MoC/code
export MODEL=Qwen/Qwen2.5-Coder-7B TAG=Qwen7B-retrain LAYERS="-1"
# point the data root at the new dataset (env var or edit the script's --data_root):
DATA_ROOT=../data/primevul_pyvul scripts/run_all.sh repr
DATA_ROOT=../data/primevul_pyvul scripts/run_all.sh probe
METHODS="n t" DATA_ROOT=../data/primevul_pyvul scripts/run_all.sh corrections
```
(Confirm `get_representation.py`/`run_all.sh` read `--data_root`; if the env var isn't wired, pass `--data_root ../data/primevul_pyvul` directly in the repr step.)

Produces `probes/Qwen7B-retrain/` and `corrections/Qwen7B-retrain/static_n.pt` (+ dynamic).

---

## PHASE 3 — Cross-eval (the actual test of the hypothesis)

### 3a. CodeGuard+ (reuse all existing adapters)
Generate off + harden with the **retrained** corrections, then the usual import → CodeQL → unit tests → score:
```
cd /home/aakale/MoC/code/src
for MODE in off harden; do
  CUDA_VISIBLE_DEVICES=<free> python -u moc_generate.py \
    --model_name Qwen/Qwen2.5-Coder-7B \
    --probe_dir ../probes/Qwen7B-retrain \
    --corrections ../corrections/Qwen7B-retrain/static_n.pt --correction_kind static \
    --steer_layer -1 --mode $MODE \
    --prompts_file ../scripts/cgp_prompts.jsonl \
    --save_path ../generations/retrain_${MODE}_n.jsonl --max_new_tokens 512
done
cd /home/aakale/CodeGuardPlus
python import_moc_to_codeguard.py --cgp_root . --completions ../MoC/code/generations/retrain_off_n.jsonl    --output_name moc7b-retrain-off    --category base
python import_moc_to_codeguard.py --cgp_root . --completions ../MoC/code/generations/retrain_harden_n.jsonl --output_name moc7b-retrain-harden --category base
python codeql_eval_safe.py --output_dir experiments/moc7b-retrain-off    --category base
python codeql_eval_safe.py --output_dir experiments/moc7b-retrain-harden --category base
python correctness_eval.py --paths experiments/moc7b-retrain-off    --do_eval --num_seeds 1
python correctness_eval.py --paths experiments/moc7b-retrain-harden --do_eval --num_seeds 1
python score_moc.py --compare experiments/moc7b-retrain-off/none/base experiments/moc7b-retrain-harden/none/base
```
**Read:** retrained off→harden Δ sec-pass@1 vs the SVEN-trained −3.2.

### 3b. BaxBench (only if Phase 1 passed)
Build the same 3-piece adapter for BaxBench (export spec prompts → MoC generate → import into BaxBench's Docker eval), run off vs harden with retrained corrections. (I'll write these adapters when you reach this point.)

### Interpreting the result (the whole point)
| Retrained result on CodeGuard+ | Conclusion |
|---|---|
| Δ goes **positive** (harden > off) | **Distribution gap confirmed & fixable** — MoC works when trained in-distribution. Strong result. |
| Δ ≈ 0 (no longer negative) | Partial — in-distribution training removes the harm but doesn't yet help; needs more data / better layer. |
| Δ still **negative** | Not (only) a distribution gap — the issue is deeper (method, eval, or MoC's premise on this benchmark). |

---

## Cross-cutting reminders
- **tmux/nohup everything** (your SSH drops); **pick a free GPU** (`nvidia-smi`).
- **Disk:** home is a full shared partition — keep experiments on `/scratch` (already symlinked), watch `df -h /scratch`.
- **Eval caveats stand:** CodeGuard+ security = CodeQL (static, pattern-limited) and its functional tests are flaky (±3 = noise). A positive retrained result should be confirmed with a larger sample and ultimately dynamic eval (CWEval/BaxBench).
- Keep the **CWE filter identical** between training data and the eval scenarios so the comparison is clean.

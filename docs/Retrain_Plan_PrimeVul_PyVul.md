# Retraining MoC in-distribution: PrimeVul + PyVul → eval on CodeGuard+

**Goal:** test whether MoC's failure on CodeGuard+ is a *distribution gap*. Retrain the probes + correction vectors on data closer to CodeGuard+ (PrimeVul for C/C++, PyVul for Python), filtered to the overlapping CWEs, then re-run the exact CodeGuard+ eval. If retrained MoC moves positive where SVEN-trained didn't, the gap is real and addressable.

## Why these two datasets
MoC training needs **paired (vulnerable, fixed) functions** (SVEN's `func_src_before` / `func_src_after`).
- **PrimeVul** (C/C++): ~7k vuln / 229k benign, 140+ CWEs; *paired* splits give vulnerable↔patched pairs. Supplies the memory CWEs (125, 190, 416, 476, 787).
- **PyVul** (Python): 8,374 vuln functions, commit+function level, CWE-labeled. Supplies the web/Python CWEs (022, 078, 079, 089).
Together they cover MoC's 9 CWEs across the two CodeGuard+ languages.

## Phase A — data prep (the only new engineering)
Converters target SVEN format `data/<split>/<cwe>.jsonl` with `{func_src_before, func_src_after, line_changes:{}}`.
1. **Verify schemas first:** `head -1` each dataset file; adjust field names in the scripts.
   - PrimeVul: uses `func`, `target` (1/0), `cwe` — use the **paired** files.
   - PyVul: set the `FIELDS` dict in `pyvul_to_sven.py` to the real column names. If PyVul only ships the *vulnerable* function + a diff (no fixed function), we need a diff-applier step (flag me).
2. Run converters (CWE-filtered to the 9):
   ```
   python primevul_to_sven.py --in_file primevul_train_paired.jsonl --out_dir ../data/primevul_pyvul --split train
   python primevul_to_sven.py --in_file primevul_valid_paired.jsonl --out_dir ../data/primevul_pyvul --split val
   python pyvul_to_sven.py    --in_file pyvul_train.jsonl           --out_dir ../data/primevul_pyvul --split train
   python pyvul_to_sven.py    --in_file pyvul_val.jsonl             --out_dir ../data/primevul_pyvul --split val
   ```
   Result: per-CWE paired files mixing C (PrimeVul) and Python (PyVul) by CWE.

## Phase B — retrain MoC (GPU, fresh TAG)
```
cd MoC/code
MODEL=Qwen/Qwen2.5-Coder-7B DATA_ROOT=../data/primevul_pyvul TAG=Qwen7B-retrain LAYERS="-1" \
  scripts/run_all.sh repr
MODEL=Qwen/Qwen2.5-Coder-7B DATA_ROOT=../data/primevul_pyvul TAG=Qwen7B-retrain LAYERS="-1" \
  scripts/run_all.sh probe
MODEL=Qwen/Qwen2.5-Coder-7B DATA_ROOT=../data/primevul_pyvul TAG=Qwen7B-retrain METHODS="n t" \
  scripts/run_all.sh corrections
```
(Confirm `run_all.sh`/`get_representation.py` accept `--data_root`; the env var DATA_ROOT maps to it. If not, pass `--data_root ../data/primevul_pyvul` directly.)

## Phase C — cross-eval (reuse existing adapters)
Generate on CodeGuard+ with the retrained corrections, score, compare to the SVEN-trained run:
```
# generate off + harden with retrained corrections
... moc_generate.py --probe_dir ../probes/Qwen7B-retrain \
    --corrections ../corrections/Qwen7B-retrain/static_n.pt ... --steer_layer -1 --mode harden
# import -> codeql_eval_safe -> correctness_eval -> score_moc  (as before)
python score_moc.py --compare experiments/moc7b-off/none/base experiments/moc7b-retrain-harden/none/base
```
**Read:** retrained Δ sec-pass@1 vs SVEN-trained Δ (−3.2). Positive ⇒ distribution gap confirmed & fixable.

## Caveats
- Eval is still CodeQL (static, pattern-limited) + flaky functional tests — a positive needs dynamic confirmation (CWEval) later.
- `line_changes` is empty ⇒ whole-function pooling; fine for static g/n/r corrections, slightly weaker for dynamic t.
- Keep the CWE filter identical between training and the CodeGuard+ scenarios so the comparison is clean.

# 5-Hour Runbook — MoC on CodeGuard+ (finish) + CWEval (start)

Goal for tonight: a real **off vs harden secure-pass@1 delta on CodeGuard+** (MoC's 9 CWEs, Python+C), plus CWEval environment up. Adapters are written and already validated against the real CodeGuard+ repo — see `bench_adapters/codeguardplus/`.

**Decisions for this run:** model = **`Qwen2.5-Coder-7B`**; **steer at the last layer only** (`STEER_LAYER=-1`) and train probes only on the last layer (`LAYERS="-1"`), so every CWE's `best_layer` is `-1` and nothing is skipped. Keep the rest fast: **9 MoC CWEs, py+c** (33 scenarios), method `n`, greedy (@1), CodeQL-only (skip SonarQube).

> Note on last-layer-only: forcing `LAYERS="-1"` removes the layer sweep, so probe accuracy may be a bit lower than MoC's best (the paper often finds a mid-stack layer probes best). That's an accepted simplification here — it guarantees `STEER_LAYER=-1` matches all probes and makes the run reproducible. Re-sweep layers later if the harden signal looks weak.

> Paths below assume: MoC at `~/MoC`, CodeGuard+ at `~/CodeGuardPlus`, adapters copied to `~/CodeGuardPlus/`. Adjust as needed.

---

## Hour 0:00–0:30 — Gates + clones

```bash
ssh <andrewid>@hopper.ece.local.cmu.edu
nvidia-smi                       # confirm a GPU + VRAM
docker run --rm hello-world      # GATE for CWEval later (note pass/fail, keep going)

# MoC
cd ~ && git clone https://github.com/viviable/MoC.git
cd MoC/code && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# CodeGuard+
cd ~ && git clone https://github.com/CodeGuardPlus/CodeGuardPlus.git
cd CodeGuardPlus && pip install -r requirements.txt
# copy the three adapter scripts into the repo root (from your Research/MoC/bench_adapters/codeguardplus/)
#   export_codeguard_to_moc.py  import_moc_to_codeguard.py  score_moc.py
```

---

## Hour 0:30–1:00 — Install CodeQL (CodeGuard+ security backend)

```bash
cd ~/CodeGuardPlus
bash setup_codeql.sh
~/codeql/codeql --version        # must print a version; codeql_eval.py calls ~/codeql/codeql
```
If `setup_codeql.sh` puts CodeQL somewhere else, symlink it: `ln -s <path>/codeql ~/codeql`. (SonarQube: skip — our `score_moc.py` doesn't need it.)

---

## Hour 1:00–2:00 — Build MoC probes + corrections (7B, last layer only)

```bash
cd ~/MoC/code
export MODEL=Qwen/Qwen2.5-Coder-7B
export LAYERS="-1"               # train probes ONLY on the last layer -> best_layer = -1 for all CWEs
scripts/run_all.sh repr          # caches hidden states (longest step; ~15–40 min on 7B, needs ~16GB VRAM)
scripts/run_all.sh probe         # trains per-CWE probes on the last layer only (fast, no sweep)
scripts/run_all.sh corrections   # computes Δs at layer -1; makes corrections/Qwen2.5-Coder-7B/static_n.pt

# Confirm every probe's best_layer is -1 (so STEER_LAYER=-1 matches all 9 -> no skips)
python - <<'PY'
import torch, glob, os
for f in sorted(glob.glob("probes/Qwen2.5-Coder-7B/*_probe.pt")):
    p=torch.load(f,map_location="cpu",weights_only=False)
    print(os.path.basename(f),"best_layer",p["best_layer"])
PY
```
All should print `best_layer -1`. We will steer with `STEER_LAYER=-1`, which matches every probe — so you should see **no** `[warn] ... Skipping CWE` lines in the next step.

---

## Hour 2:00–3:00 — Export → generate (off + harden)

```bash
cd ~/CodeGuardPlus
# A) export the 9 MoC CWEs, py+c
python export_codeguard_to_moc.py --cgp_root . --category base \
    --only_moc_cwes --langs py c --out moc_prompts.jsonl   # ~33 prompts

# B) generate baseline (off) and hardened — from MoC's src dir
cd ~/MoC/code/src
for MODE in off harden; do
  python -u moc_generate.py \
    --model_name Qwen/Qwen2.5-Coder-7B \
    --probe_dir   ../probes/Qwen2.5-Coder-7B \
    --corrections ../corrections/Qwen2.5-Coder-7B/static_n.pt \
    --correction_kind static \
    --steer_layer -1 \
    --mode $MODE \
    --prompts_file ~/CodeGuardPlus/moc_prompts.jsonl \
    --save_path    ~/CodeGuardPlus/out_${MODE}.jsonl \
    --max_new_tokens 300
done
# sanity: harden run should show NO "[warn] Skipping CWE" (all best_layer == -1 == steer_layer)
```

---

## Hour 3:00–4:15 — Import → evaluate → score

```bash
cd ~/CodeGuardPlus

# C) import both runs into the experiments/ layout the evaluators read
python import_moc_to_codeguard.py --cgp_root . --completions out_off.jsonl \
    --output_name moc7b-off --category base
python import_moc_to_codeguard.py --cgp_root . --completions out_harden.jsonl \
    --output_name moc7b-harden --category base

# security (CodeQL) — sets stat[f]["sec"]
python codeql_eval.py --output_dir experiments/moc7b-off    --category base
python codeql_eval.py --output_dir experiments/moc7b-harden --category base

# functionality (unit tests) — sets stat[f]["functional"]; uses CGP's own runner
python correctness_eval.py --paths experiments/moc7b-off    --do_eval --num_seeds 1
python correctness_eval.py --paths experiments/moc7b-harden --do_eval --num_seeds 1

# SCORE — bypasses new_stats.py + SonarQube, reads stat.json directly
python score_moc.py --compare experiments/moc7b-off/none/base \
                              experiments/moc7b-harden/none/base
```
The final `DELTA (harden - off)` block is your headline result: `sec-pass@1`, `sec_rate`, `pass@1`, split by MoC-CWEs vs other.

**If you have time left:** drop `--only_moc_cwes` (and the `--langs` filter) to run all 103 scenarios; or add `--methods "r t"` corrections for a stronger steer than `n`.

---

## Hour 4:15–5:00 — Start CWEval (setup only)

```bash
docker pull co1lin/cweval
docker run --name cweval --rm -it --net host \
  -v $HOME/moc_share:/host_dir co1lin/cweval zsh
# inside the container:
source .env
pytest benchmark/ -x -n 24       # reference solutions must all pass = env is healthy
# look at how responses are laid out (you'll mirror this, bypassing their litellm generate.py):
sed -n '1,120p' cweval/generate.py
sed -n '1,80p'  cweval/evaluate.py
```
That's the CWEval starting point. The adapter pattern is identical to CodeGuard+: export tasks → MoC generate on host GPU (write to `$HOME/moc_share`) → import into an `eval_path` → `python cweval/evaluate.py pipeline --eval_path ... --docker False`. Build those two adapters next session.

---

## Fallback (if GPU/CodeQL setup eats the clock)

You still have a concrete, demonstrable result: the adapters are **tested and working**. Reproduce the validated dry-run to show the pipeline is correct end-to-end (no GPU needed):

```bash
# with CodeGuardPlus cloned + adapters copied in:
python export_codeguard_to_moc.py --cgp_root . --only_moc_cwes --langs py c --out /tmp/p.jsonl
# fake a completion per prompt, then:
python import_moc_to_codeguard.py --cgp_root . --completions /tmp/fake_out.jsonl \
    --output_name demo --category base
ls experiments/demo/none/base/cwe-022/0-py/        # deduplicated/ + stat.json, truncated correctly
```
Talking point: "Adapters are built and validated against the real repo; only the GPU generation + CodeQL scan remain, and those are one command each."

---

## What to bring to the meeting

1. **The plan** (`MoC_Benchmark_Integration_Plan.md`) — why MoC is a hook not a model, the 3-piece adapter pattern, CWE/language overlap.
2. **Working CodeGuard+ adapters** (`bench_adapters/codeguardplus/`) — export/import/score, validated against the real repo; SonarQube bypassed.
3. **Whatever number you got** — even partial. Frame it as off→harden delta on MoC's in-distribution CWEs vs out-of-distribution, on **7B, last-layer steering**; full-CWE / layer-swept probes are the next run.
4. **One open decision:** confirm Docker policy on hopper (gates CWEval) and which SeCodePLT artifact is meant.
```
```

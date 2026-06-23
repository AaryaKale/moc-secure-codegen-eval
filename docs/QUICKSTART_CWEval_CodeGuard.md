# Quickstart: running MoC on CodeGuard+ and CWEval

Do the steps in order. **Phase 0 is shared** and must work before either benchmark. Then do **CodeGuard+ end-to-end** (simpler, gets you a real number), then **CWEval**.

Time estimates assume focused work and that you're newer to this tooling — they include debugging, not just happy-path runtime.

---

## Phase 0 — Shared setup (do once)  ·  ~0.5–1 day

### 0.1 Get on the cluster and check two gates
```bash
ssh <andrewid>@hopper.ece.local.cmu.edu
nvidia-smi            # confirm a GPU is visible + how much VRAM
docker run --rm hello-world   # GATE: does Docker work on this node?
```
- **VRAM:** 7B(bf16) needs ~14–16 GB; if tight, use `Qwen2.5-Coder-3B` first.
- **Docker:** CodeGuard+ CodeQL path does NOT need Docker. **CWEval does.** If `docker` fails here, CWEval may have to run on a different (Docker-permitted) host — find that out now, not in week 2.

### 0.2 MoC environment + weights
```bash
git clone https://github.com/viviable/MoC.git && cd MoC/code
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# weights download on first run; or pre-pull:
huggingface-cli download Qwen/Qwen2.5-Coder-7B   # base, NOT -Instruct
```

### 0.3 Build MoC's probes + corrections (one-time, GPU)
```bash
cd MoC/code
MODEL=Qwen/Qwen2.5-Coder-7B scripts/run_all.sh repr          # longest: ~15–40 min
MODEL=Qwen/Qwen2.5-Coder-7B scripts/run_all.sh probe         # fast
MODEL=Qwen/Qwen2.5-Coder-7B scripts/run_all.sh corrections   # fast
```
### 0.4 Record `best_layer` (prevents the silent no-op)
```bash
python - <<'PY'
import torch, glob, os
for f in sorted(glob.glob("probes/Qwen2.5-Coder-7B/*_probe.pt")):
    pkg = torch.load(f, map_location="cpu", weights_only=False)
    print(os.path.basename(f), "best_layer =", pkg["best_layer"])
PY
```
If all 9 print the **same** layer, use that as `STEER_LAYER`. If they differ, you can only steer the CWEs whose `best_layer` matches the one layer you hook — note which ones, and pick the layer shared by the most CWEs. (This is the `steer_layer != best_layer` skip issue — get it right here.)

**Phase 0 done when:** `corrections/Qwen2.5-Coder-7B/static_n.pt` exists and you know your `STEER_LAYER`.

---

## Phase A — CodeGuard+ end-to-end  ·  ~2–3 days

### A.1 Clone + CodeQL (skip SonarQube for now)
```bash
git clone https://github.com/CodeGuardPlus/CodeGuardPlus.git && cd CodeGuardPlus
pip install -r requirements.txt
bash setup_codeql.sh          # ~700 MB; CodeQL CLI + query packs
# SonarQube (Docker) is OPTIONAL — defer it; CodeQL keeps you comparable to MoC's own eval
```

### A.2 Learn the layout (the key reverse-engineering step)  ·  ~half day
Read `inference/generate.py`, `codeql_eval.py`, `correctness_eval.py`. Answer three questions:
1. Where does `generate.py` write generated programs (dir + filename per prompt)?
2. How many samples per prompt does the evaluator expect (1 vs 10)?
3. What does each prompt's input string look like (so MoC completes the same thing)?

### A.3 Export CodeGuard+ prompts → MoC jsonl  ·  ~half day
Write `export_codeguard_to_moc.py`: read the 91 prompts in `data/base/`, emit one `{"id": "<CWE>/<prompt>", "prompt": "<exact completion prompt>"}` per line.

### A.4 Generate baseline + hardened (GPU)
```bash
cd MoC/code/src
for MODE in off harden; do
  python -u moc_generate.py \
    --model_name Qwen/Qwen2.5-Coder-7B \
    --probe_dir ../probes/Qwen2.5-Coder-7B \
    --corrections ../corrections/Qwen2.5-Coder-7B/static_n.pt \
    --correction_kind static \
    --steer_layer <BEST_LAYER> \
    --mode $MODE \
    --prompts_file ../../CodeGuardPlus/moc_prompts.jsonl \
    --save_path ../../CodeGuardPlus/out_${MODE}.jsonl \
    --max_new_tokens 512
done
```
Check the `off` log shows NO `[warn] ... Skipping CWE` lines.

### A.5 Import completions → CodeGuard+ layout  ·  ~half–1 day
Write `import_moc_to_codeguard.py`: for each completion, strip code fences, **truncate at the function/program end**, and drop it into the exact dir/filename `codeql_eval.py` reads (from A.2). Bad truncation = fake correctness failures, so test on a few by hand.

### A.6 Evaluate + compare
```bash
cd CodeGuardPlus
python codeql_eval.py ...        # security, per mode
python correctness_eval.py ...   # unit tests, per mode
```
Compute **secure-pass@1** for `off` and `harden`. The deliverable is the **off → harden delta**, split into MoC's 9 CWEs (C/Python) vs the rest.

**Phase A done when:** you have a secure-pass@1 table, off vs harden.

---

## Phase B — CWEval  ·  ~2–3 days (add slack if Docker is restricted)

### B.1 Pull image + sanity check
```bash
docker pull co1lin/cweval
docker run --name cweval --rm -it --net host \
  -v $HOME/moc_share:/host_dir co1lin/cweval zsh
# inside container:
source .env
pytest benchmark/ -x -n 24       # all reference tests must pass
```
The `-v` mount is how you move MoC's completions into the container.

### B.2 Learn the response layout  ·  ~half day
Read `cweval/generate.py` and `cweval/evaluate.py`. Find the exact `eval_path` structure `evaluate.py` reads (per-task response files). You will reproduce that WITHOUT calling `generate.py`.

### B.3 Export tasks → MoC jsonl (C/Python core first)
Write `export_cweval_to_moc.py`: emit MoC prompts for the **C + Python core tasks only** (~45 of 119) first. Skip JS/Go/C++ for the initial fair read.

### B.4 Generate on the host GPU (outside the container)
Same `moc_generate.py` loop as A.4, pointing at the CWEval prompts; write outputs into `$HOME/moc_share` so they appear at `/host_dir` in the container.

### B.5 Import → eval_path, then evaluate inside the container
Write `import_moc_to_cweval.py` to lay completions into `evals/moc_harden/` matching B.2.
```bash
# inside container:
python cweval/evaluate.py pipeline --eval_path evals/moc_harden --num_proc 20 --docker False
python cweval/evaluate.py report_pass_at_k --eval_path evals/moc_harden
```
`--docker False` because you're already inside the image. Report **func-sec@1**, off vs harden.

**Phase B done when:** func-sec@1 table on the C/Python core, off vs harden.

---

## Time summary

| Phase | Work | Estimate |
|---|---|---|
| 0 | Cluster checks, MoC env, probes/corrections, record best_layer | **0.5–1 day** |
| A | CodeGuard+ clone+CodeQL, layout reading, export/import adapters, generate, eval | **2–3 days** |
| B | CWEval docker, layout reading, export/import adapters, generate, eval | **2–3 days** |
| — | **Total for both** | **~1 to 1.5 weeks** focused |

**What makes it slower:** Docker blocked on hopper (CWEval slips); probe `best_layer`s disagree across CWEs; completion-truncation debugging; first-time CodeQL/SonarQube setup. **What makes it faster:** start on 3B, CodeGuard+ CodeQL-only, C/Python subset, method `n` only — get one honest off→harden delta before scaling up.

**Recommended first milestone (2–3 days):** Phase 0 + Phase A on the C/Python overlap subset with method `n`. That single secure-pass@1 delta is the thing to bring to your next meeting; everything after is breadth.

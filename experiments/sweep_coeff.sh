#!/usr/bin/env bash
# Sweep the steering coefficient on the 33 in-scope CodeGuard+ scenarios (method n).
# Requires: moc_generate.py patched with --coeff (run patch_add_coeff.py first).
# Run inside tmux:  ~/sweep_coeff.sh 2>&1 | tee ~/sweep_coeff.log
set -e
MOC=/home/aakale/MoC/code
CGP=/home/aakale/CodeGuardPlus
PROMPTS=$MOC/scripts/cgp_prompts.jsonl   # the 33-scenario file
COEFFS="0.5 1 2 4 8"                      # smaller + bigger than default; trim if needed

for C in $COEFFS; do
  echo "============ coeff=$C ============"
  cd "$MOC/src"
  CUDA_VISIBLE_DEVICES=1 python -u moc_generate.py \
    --model_name Qwen/Qwen2.5-Coder-7B \
    --probe_dir ../probes/Qwen2.5-Coder-7B \
    --corrections ../corrections/Qwen2.5-Coder-7B/static_n.pt --correction_kind static \
    --steer_layer -1 --mode harden --coeff "$C" --decay_rate 0 \
    --prompts_file "$PROMPTS" \
    --save_path ../generations/harden_n_c${C}.jsonl --max_new_tokens 512
  cd "$CGP"
  python import_moc_to_codeguard.py --cgp_root . \
    --completions "$MOC/generations/harden_n_c${C}.jsonl" \
    --output_name "moc7b-c${C}" --category base
  python codeql_eval_safe.py --output_dir "experiments/moc7b-c${C}" --category base
  python correctness_eval.py --paths "experiments/moc7b-c${C}" --do_eval --num_seeds 1
done

echo "================= SUMMARY (each coeff vs off baseline) ================="
for C in $COEFFS; do
  echo "------------- coeff=$C -------------"
  python "$CGP/score_moc.py" --compare \
    "$CGP/experiments/moc7b-off/none/base" \
    "$CGP/experiments/moc7b-c${C}/none/base"
done

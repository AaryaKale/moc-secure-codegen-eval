#!/usr/bin/env bash
# Grid sweep of MoC steering hyperparameters on CodeGuard+ (33 in-scope scenarios).
# Sweeps coeff x decay_rate (static method n). Requires moc_generate.py patched
# with --coeff. Override ranges via env. Run in tmux/nohup.
#
#   GPU=0 COEFFS="0.5 0.6 0.7 0.8 0.9 1.0" DECAYS="0 0.05" bash grid_sweep.sh
set -e
MOC=/home/aakale/MoC/code
CGP=/home/aakale/CodeGuardPlus
PROMPTS=$MOC/scripts/cgp_prompts.jsonl
GPU=${GPU:-1}
METHOD=${METHOD:-n}                                   # uses static_${METHOD}.pt
COEFFS=${COEFFS:-"0.5 0.6 0.7 0.8 0.9 1.0"}           # Weichen's range (0.5,1,0.1)
DECAYS=${DECAYS:-"0 0.05"}                            # decay axis

for D in $DECAYS; do
for C in $COEFFS; do
  TAG="g_${METHOD}_c${C}_d${D}"
  echo "================ $TAG ================"
  cd "$MOC/src"
  CUDA_VISIBLE_DEVICES=$GPU python -u moc_generate.py \
    --model_name Qwen/Qwen2.5-Coder-7B \
    --probe_dir ../probes/Qwen2.5-Coder-7B \
    --corrections ../corrections/Qwen2.5-Coder-7B/static_${METHOD}.pt --correction_kind static \
    --steer_layer -1 --mode harden --coeff "$C" --decay_rate "$D" \
    --prompts_file "$PROMPTS" \
    --save_path ../generations/${TAG}.jsonl --max_new_tokens 512
  cd "$CGP"
  python import_moc_to_codeguard.py --cgp_root . --completions "$MOC/generations/${TAG}.jsonl" \
    --output_name "moc7b-${TAG}" --category base
  python codeql_eval_safe.py --output_dir "experiments/moc7b-${TAG}" --category base
  python correctness_eval.py --paths "experiments/moc7b-${TAG}" --do_eval --num_seeds 1
done
done

echo "================ GRID RESULTS ================"
python "$CGP/grid_score.py" --off experiments/moc7b-off/none/base \
  --glob "experiments/moc7b-g_*/none/base" --csv ~/grid_results.csv

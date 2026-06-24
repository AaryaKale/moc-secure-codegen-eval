# Reproduce

End-to-end steps. Assumes a Linux GPU box (~16 GB VRAM for Qwen-7B), Python 3.9+, and CodeQL CLI installed at `~/codeql`.

## 0. Clone the external repos
```bash
git clone https://github.com/viviable/MoC.git
git clone https://github.com/CodeGuardPlus/CodeGuardPlus.git
pip install -r requirements.txt        # this repo's requirements
cd CodeGuardPlus && bash setup_codeql.sh && cd ..   # CodeQL + query packs
```
Copy this repo's `adapters/codeguardplus/*` into `CodeGuardPlus/`, and `patches/*` into `MoC/code/src/` (then apply the patches).

## 1. Baseline: evaluate SVEN-trained MoC on CodeGuard+
```bash
# build MoC's SVEN probes/corrections (its own pipeline), then:
# export CodeGuard+ prompts (9 MoC CWEs, py+c -> 33 scenarios)
python export_codeguard_to_moc.py --cgp_root . --only_moc_cwes --langs py c --out cgp_prompts.jsonl
# generate off + harden inside MoC (steer_layer = probe best_layer, e.g. -1)
#   moc_generate.py --probe_dir ... --corrections .../static_n.pt --mode off|harden --prompts_file cgp_prompts.jsonl
# score
python import_moc_to_codeguard.py --cgp_root . --completions <off.jsonl>    --output_name moc7b-off    --category base
python import_moc_to_codeguard.py --cgp_root . --completions <harden.jsonl> --output_name moc7b-harden --category base
python codeql_eval_safe.py --output_dir experiments/moc7b-off    --category base
python codeql_eval_safe.py --output_dir experiments/moc7b-harden --category base
python correctness_eval.py --paths experiments/moc7b-off    --do_eval --num_seeds 1
python correctness_eval.py --paths experiments/moc7b-harden --do_eval --num_seeds 1
python score_moc.py --compare experiments/moc7b-off/none/base experiments/moc7b-harden/none/base
```

## 2. Hyperparameter sweeps
```bash
python patches/patch_add_coeff.py            # adds --coeff to moc_generate.py
bash experiments/sweep_coeff.sh              # coefficient sweep
bash experiments/grid_sweep.sh               # coeff x decay grid -> grid_results.csv
```

## 3. Retrain in-distribution (PrimeVul + PyVul)
```bash
# PrimeVul (C/C++) — HF mirror has a 'paired' config
python -c "from datasets import load_dataset as L; L('colin/PrimeVul','paired')['train'].to_json('primevul_paired.jsonl')"
python adapters/retrain/primevul_to_sven.py --in_file primevul_paired.jsonl --out_dir MoC/code/data/primevul_pyvul --split train
# PyVul (Python) — github.com/billquan/PyVul
python adapters/retrain/pyvul_to_sven.py --in_file dataset/function_level_dataset.out \
    --cwe_map dataset/commits_cwe_map.json --out_dir MoC/code/data/primevul_pyvul --split train \
    --langs Python --include_others

# (RECOMMENDED) apply changed-line pooling first — see patches/patch_changed_line_pooling.py
python patches/patch_changed_line_pooling.py     # run from MoC/code/src

# retrain probes/corrections (train-only; LAYERS sweep + PCA to avoid overfitting)
cd MoC/code
python -u src/get_representation.py --model_name Qwen/Qwen2.5-Coder-7B --data_root data/primevul_pyvul \
    --save_path /scratch/representations/Qwen7B-retrain --few_shot_pairs 2 --splits train
python -u src/train_probe.py --repr_dir /scratch/representations/Qwen7B-retrain \
    --save_path probes/Qwen7B-retrain-pca --kind linear_pca --pca_dim 64 --layer_stride 2
# inspect per-CWE val_acc; then compute corrections with --method r (PCA) at each best_layer
```

## Notes
- Run long steps in `tmux` or `nohup` (SSH drops); put representations/experiments on scratch (home fills fast).
- `codeql_eval_safe.py` tolerates non-compiling C and CodeQL query-version errors (skips them; reports counts).
- See `results.md` for the numbers each step should reproduce.

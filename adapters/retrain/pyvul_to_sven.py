#!/usr/bin/env python3
"""
PyVul (billquan/PyVul) -> SVEN paired format for MoC retraining.

PyVul's function_level_dataset.out already has paired code_before/code_after per
record, but the CWE lives in commits_cwe_map.json (keyed by commit). PyVul is
multi-language, so we filter by programming_language (default: Python).

Target format: out_dir/<split>/<cwe>.jsonl  with {func_src_before, func_src_after, line_changes:{}}

Usage (on hopper, from the PyVul repo):
    python pyvul_to_sven.py \
        --in_file dataset/function_level_dataset.out \
        --cwe_map dataset/commits_cwe_map.json \
        --out_dir /home/aakale/MoC/code/data/primevul_pyvul --split train \
        --langs Python --include_others
"""
import argparse, json, os, re
from collections import defaultdict

TARGET_CWES = {"cwe-022","cwe-078","cwe-079","cwe-089",
               "cwe-125","cwe-190","cwe-416","cwe-476","cwe-787"}

def norm_cwe(c):
    m = re.search(r"(\d+)", str(c))
    return f"cwe-{int(m.group(1)):03d}" if m else None

def build_cwe_lookup(map_path):
    raw = json.load(open(map_path))
    lk = {}
    for k, v in raw.items():
        cwes = v if isinstance(v, list) else [v]
        norm = [c for c in (norm_cwe(x) for x in cwes) if c]
        lk[k] = norm
        h = str(k).rstrip("/").split("/")[-1]   # also key by bare commit hash
        lk.setdefault(h, norm)
    return lk

def cwes_for(commit, lk):
    if commit in lk: return lk[commit]
    h = str(commit).rstrip("/").split("/")[-1]
    return lk.get(h, [])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_file", required=True)   # function_level_dataset.out
    ap.add_argument("--cwe_map", required=True)   # commits_cwe_map.json
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--split", default="train")
    ap.add_argument("--langs", nargs="*", default=["Python"])
    ap.add_argument("--include_others", action="store_true",
                    help="also use other_changed_function_in_the_commit (more pairs, same commit CWE)")
    args = ap.parse_args()

    langs = set(args.langs)
    lk = build_cwe_lookup(args.cwe_map)
    recs = [json.loads(l) for l in open(args.in_file)]

    buckets = defaultdict(list); n = nolang = nomap = 0
    for r in recs:
        if r.get("programming_language") not in langs:
            nolang += 1; continue
        cwes = [c for c in cwes_for(r.get("commit"), lk) if c in TARGET_CWES]
        if not cwes:
            nomap += 1; continue
        pairs = [(r.get("code_before"), r.get("code_after"))]
        if args.include_others:
            for o in (r.get("other_changed_function_in_the_commit") or []):
                pairs.append((o.get("code_before"), o.get("code_after")))
        for before, after in pairs:
            if not before or not after:
                continue
            for c in cwes:
                buckets[c].append({"func_src_before": before, "func_src_after": after, "line_changes": {}})
                n += 1

    out = os.path.join(args.out_dir, args.split); os.makedirs(out, exist_ok=True)
    for c, rows in sorted(buckets.items()):
        with open(os.path.join(out, f"{c}.jsonl"), "a") as f:   # append: combine with PrimeVul
            for r in rows: f.write(json.dumps(r) + "\n")
        print(f"  {c}: +{len(rows)} pairs")
    print(f"total Python pairs={n}  (skipped: wrong-lang={nolang}, no-target-CWE={nomap}) -> {out}")
    if n == 0:
        print("[!] 0 pairs. Check the CWE-map join — run:")
        print("    python -c \"import json;m=json.load(open('dataset/commits_cwe_map.json'));k=list(m)[0];print(repr(k),m[k])\"")
        print("    and confirm --langs matches the data's programming_language values.")

if __name__ == "__main__":
    main()

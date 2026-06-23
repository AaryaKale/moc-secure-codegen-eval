#!/usr/bin/env python3
"""
PrimeVul (C/C++) -> SVEN paired format for MoC retraining.

MoC's get_representation.py expects: data_root/<split>/<cwe>.jsonl, each record:
    {"func_src_before": <vulnerable code>, "func_src_after": <fixed code>, "line_changes": {}}
(line_changes can be empty — get_representation falls back to the whole-function span.)

Use the PrimeVul *paired* files (primevul_train_paired.jsonl / valid / test), where
each vulnerable function and its patched version appear as consecutive lines.

Verify fields first:  head -1 primevul_train_paired.jsonl
PrimeVul records use: "func" (source), "target" (1=vuln, 0=fixed), "cwe" (list like ["CWE-787"]).

Usage:
    python primevul_to_sven.py --in_file primevul_train_paired.jsonl \
        --out_dir ../data/primevul_pyvul --split train
"""
import argparse, json, os, re
from collections import defaultdict

# CWEs overlapping CodeGuard+ / MoC's 9. Edit to widen coverage.
TARGET_CWES = {"cwe-022","cwe-078","cwe-079","cwe-089",
               "cwe-125","cwe-190","cwe-416","cwe-476","cwe-787"}

def norm_cwe(c):
    m = re.search(r"(\d+)", str(c))
    return f"cwe-{int(m.group(1)):03d}" if m else None

def cwes_of(rec):
    v = rec.get("cwe") or rec.get("cwes") or []
    if isinstance(v, str): v = [v]
    return [c for c in (norm_cwe(x) for x in v) if c in TARGET_CWES]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_file", required=True, help="PrimeVul *paired* jsonl")
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--split", default="train")
    ap.add_argument("--func_field", default="func")
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(args.in_file)]
    if recs and args.func_field not in recs[0]:
        print(f"[!] '{args.func_field}' not in record. Keys present: {list(recs[0].keys())}")
        print("    Re-run with --func_field <correct name>.")
        return

    buckets = defaultdict(list); n_pairs = skipped = 0
    i = 0
    while i + 1 < len(recs):
        a, b = recs[i], recs[i+1]
        ta, tb = int(a.get("target", -1)), int(b.get("target", -1))
        if {ta, tb} == {0, 1}:
            vul = a if ta == 1 else b
            fix = b if ta == 1 else a
            for c in cwes_of(vul):
                buckets[c].append({
                    "func_src_before": vul[args.func_field],
                    "func_src_after":  fix[args.func_field],
                    "line_changes": {},
                })
                n_pairs += 1
            i += 2
        else:
            skipped += 1; i += 1

    out = os.path.join(args.out_dir, args.split); os.makedirs(out, exist_ok=True)
    for c, rows in sorted(buckets.items()):
        with open(os.path.join(out, f"{c}.jsonl"), "w") as f:
            for r in rows: f.write(json.dumps(r) + "\n")
        print(f"  {c}: {len(rows)} pairs")
    print(f"total target-CWE pairs={n_pairs}, non-paired-skipped={skipped} -> {out}")

if __name__ == "__main__":
    main()

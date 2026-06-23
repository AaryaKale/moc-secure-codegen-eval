#!/usr/bin/env python3
"""
Patch moc_generate.py to allow combining static (n/g/r) + dynamic (t) corrections.
Adds --also_dynamic_dir: when set alongside a static --corrections file, BOTH are
loaded and their per-CWE deltas are SUMMED in the steering hook.
Backward compatible (static-only and dynamic-only paths still work).
Run ONCE from MoC/code/src:  python patch_combine_nt.py
"""
f = "moc_generate.py"; s = open(f).read()
def repl(o, n, s):
    assert o in s, f"anchor missing (already patched / file differs?): {o[:60]!r}"
    return s.replace(o, n, 1)

# 1) hook: sum static + dynamic instead of elif
s = repl(
"""            # Build per-batch delta
            if cwe in self.dynamic_corr:
                delta_cwe = self.dynamic_corr[cwe](last)  # [B, d]
            elif cwe in self.static_corr:
                delta_cwe = self.static_corr[cwe].unsqueeze(0).expand_as(last)
            else:
                continue""",
"""            # Build per-batch delta (combine static + dynamic if both present)
            delta_cwe = None
            if cwe in self.static_corr:
                delta_cwe = self.static_corr[cwe].unsqueeze(0).expand_as(last)
            if cwe in self.dynamic_corr:
                d_dyn = self.dynamic_corr[cwe](last)
                delta_cwe = d_dyn if delta_cwe is None else delta_cwe + d_dyn
            if delta_cwe is None:
                continue""", s)

# 2) argparse flag
s = repl('    p.add_argument("--dynamic_hidden", type=int, default=1024)',
         '    p.add_argument("--dynamic_hidden", type=int, default=1024)\n'
         '    p.add_argument("--also_dynamic_dir", default=None,\n'
         '                   help="combine mode: also load dynamic (t) corrections from this dir")', s)

# 3) main: also load dynamic to combine, before building the steerer
s = repl("    steerer = MoCSteerer(probes, static_corr, dynamic_corr,",
         '    if args.mode != "off" and args.also_dynamic_dir is not None:\n'
         '        d = next(iter(probes.values()))["probe"].output.in_features if probes else 0\n'
         '        dynamic_corr = load_dynamic_corrections(\n'
         '            args.also_dynamic_dir, args.cwes, device, dim=d, hidden=args.dynamic_hidden,\n'
         '        )\n\n'
         '    steerer = MoCSteerer(probes, static_corr, dynamic_corr,', s)

open(f, "w").write(s); print("patched: n+t combine via --also_dynamic_dir")

#!/usr/bin/env python3
"""
Patch MoC/code/src/moc_generate.py to add a --coeff scalar that multiplies the
steering vector. Run ONCE from MoC/code/src:  python patch_add_coeff.py
Idempotent-ish: asserts each edit applied so you know if the file already changed.
"""
import sys
f = "moc_generate.py"
s = open(f).read()
orig = s

def repl(old, new, s):
    assert old in s, f"anchor not found (already patched?): {old[:60]!r}"
    return s.replace(old, new, 1)

# 1) add coeff to MoCSteerer.__init__ signature
s = repl("max_delta_norm: float = 0.0):",
         "max_delta_norm: float = 0.0, coeff: float = 1.0):", s)
# 2) store it
s = repl("        self.max_delta_norm = max_delta_norm\n",
         "        self.max_delta_norm = max_delta_norm\n        self.coeff = coeff\n", s)
# 3) apply it in the hook
s = repl("hs[:, -1, :] = hs[:, -1, :] + (alpha * total_delta).to(hs.dtype)",
         "hs[:, -1, :] = hs[:, -1, :] + (self.coeff * alpha * total_delta).to(hs.dtype)", s)
# 4) argparse flag
s = repl('    p.add_argument("--dynamic_hidden", type=int, default=1024)',
         '    p.add_argument("--dynamic_hidden", type=int, default=1024)\n    p.add_argument("--coeff", type=float, default=1.0)', s)
# 5) pass it through
s = repl("max_delta_norm=args.max_delta_norm)",
         "max_delta_norm=args.max_delta_norm, coeff=args.coeff)", s)

open(f, "w").write(s)
print("patched moc_generate.py: added --coeff (default 1.0)")

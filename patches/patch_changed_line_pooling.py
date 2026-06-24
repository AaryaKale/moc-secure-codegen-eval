#!/usr/bin/env python3
"""
Patch MoC/code/src/get_representation.py to pool hidden states over the
CHANGED vulnerable lines (SVEN's recipe) instead of the whole function.

For each (func_src_before, func_src_after) pair it diffs the two with difflib
and, per version, pools only the lines that changed:
  - func_src_after  -> inserted/replaced lines (the fix)
  - func_src_before -> deleted/replaced lines (the vulnerability)
This concentrates the vuln/secure signal instead of diluting it across the
whole function. Falls back to whole-function pooling if no diff is found.

Run ONCE from MoC/code/src:  python patch_changed_line_pooling.py
(Then re-run get_representation -> train_probe -> corrections.)
"""
f = "get_representation.py"; s = open(f).read()
def repl(o, n, s):
    assert o in s, f"anchor missing (already patched / file differs?): {o[:60]!r}"
    return s.replace(o, n, 1)

# 1) import difflib
s = repl("import random\n", "import random\nimport difflib\n", s)

# 2) helper that returns a line_changes dict covering the changed lines in one version
helper = '''
def _changed_line_changes(before: str, after: str, is_after: bool):
    """Return {"added":[{char_start,char_end}]} over lines that changed in the
    requested version (after=fix lines, before=vulnerable lines). {} if none."""
    bl = before.splitlines(keepends=True)
    al = after.splitlines(keepends=True)
    lines = al if is_after else bl
    offs = [0]
    for ln in lines:
        offs.append(offs[-1] + len(ln))
    sm = difflib.SequenceMatcher(None, bl, al, autojunk=False)
    spans = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if is_after and tag in ("insert", "replace") and j2 > j1:
            spans.append((offs[j1], offs[j2]))
        if (not is_after) and tag in ("delete", "replace") and i2 > i1:
            spans.append((offs[i1], offs[i2]))
    if not spans:
        return {}
    return {"added": [{"char_start": min(a for a, _ in spans),
                       "char_end":   max(b for _, b in spans)}]}


'''
s = repl("def process_cwe(", helper + "def process_cwe(", s)

# 3) use the per-version changed-line span instead of rec["line_changes"]
s = repl(
    "            span = find_change_token_span(tokenizer, text, code, rec.get(\"line_changes\", {}))",
    "            lc = _changed_line_changes(rec[\"func_src_before\"], rec[\"func_src_after\"],\n"
    "                                       code_field == \"func_src_after\")\n"
    "            span = find_change_token_span(tokenizer, text, code, lc)",
    s)

open(f, "w").write(s)
print("patched get_representation.py: changed-line pooling enabled")

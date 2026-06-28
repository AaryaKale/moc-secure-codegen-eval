# Results

All on **Qwen2.5-Coder-7B**, CodeGuard+ **33 in-scope scenarios** (MoC's 9 CWEs, Python+C), greedy. Metric: `sec-pass@1` = % of generations both functionally correct AND secure (CodeQL).

## 1. SVEN-trained MoC on CodeGuard+ (out-of-distribution)

| config | pass@1 | sec_rate | sec-pass@1 | Δ |
|---|---|---|---|---|
| **off (baseline)** | 75.8 | 74.2 | **54.8** | — |
| harden `n` | 75.8 | 71.0 | 51.6 | −3.2 |
| harden `t` (dynamic) | 69.7 | 74.2 | 48.4 | −6.5 |
| `n`+`t` | 69.7 | 74.2 | 51.6 | −3.2 |

Steering lowers security+functionality; `t` transfers worst; `n`+`t` dominated by `t`.

## 2. Hyperparameter sweeps (method `n`)
- coeff 0.5× = no-op; coeff ≥2× breaks functionality, security flat. **No (coeff, decay) cell beats baseline.** One apparent +9.4 grid cell was a flaky-measurement artifact (stateful functional tests). Knob-tuning exhausted.

## 3. Retraining in-distribution (PrimeVul + PyVul, ~2,010 pairs)

Probe val_acc (PCA-64), **whole-function vs changed-line pooling**:

| CWE | source | whole-fn | **changed-line** | best layer |
|---|---|---|---|---|
| cwe-089 SQLi | PyVul | 0.74 | **0.86** | 0 |
| cwe-022 path | PyVul | 0.56 | **0.80** | 6 |
| cwe-079 XSS | PyVul | 0.54 | **0.80** | 12 |
| cwe-078 cmd-inj | PyVul | 0.61 | 0.68 | 0 |
| cwe-190 int-ovf | PrimeVul | 0.56 | 0.65 | 18 |
| cwe-476 null-deref | PrimeVul | 0.60 | 0.65 | 24 |
| cwe-416 UAF | PrimeVul | 0.61 | 0.62 | 2 |
| cwe-125 OOB-read | PrimeVul | 0.54 | 0.56 | 4 |
| cwe-787 OOB-write | PrimeVul | 0.55 | 0.55 | 2 |

- Plain linear probes (3584-dim, ~200 ex/CWE) **overfit → below chance**; PCA-64 fixed that.
- **Changed-line pooling** (pool only the diff lines, not the whole function) **rescued the web CWEs** (0.68–0.86). Memory CWEs stayed weak (~0.55–0.65) — memory bugs aren't localized to the changed line + PrimeVul noise.
- PyVul (~0.62 avg) marginally beats PrimeVul (~0.57): not purely PrimeVul noise.
- **Best layer differs per CWE (0–24)** — no single layer is best for all.

## 4. Steering after the pooling fix — the controllability result

With strong web-CWE probes, we tested whether steering actually moves the output:

| config | outcome |
|---|---|
| L6 harden, coeff 1 | flat — web CWEs already secure at baseline (**ceiling**) |
| L6 weaken, coeff 1 | **inert** — 089 stays 4/4 secure, 022 stays 5/5 |
| L6 weaken, coeff 10 | **garbage** — output off-manifold (gibberish) |
| multi-layer harden, coeff 1 | **garbage** — pass@1 75.8→3.0 (layer-0 corr norm = 224) |
| L24 weaken, coeff 1 | **inert** — functionality preserved, security unmoved |

**Conclusion: detectability ≠ controllability.** The secure-vs-vulnerable direction is **decodable** (probe ~0.8 after changed-line pooling) but **not causally steerable**. Across early (L6) and late (L24) layers, weak steering is inert and strong steering destroys the output — there is **no regime that cleanly changes security while keeping code valid**. There is also a **norm-calibration problem**: correction norms range 0.5 (L4) to 224 (L0), so a single coefficient cannot fit all layers.

## Key takeaways
1. **Changed-line pooling** is essential — whole-function pooling diluted the signal and made probes look unusable.
2. **Probe quality ≠ steering effect.** Fixing detection (web CWEs to 0.8) did not enable steering.
3. **MoC detects but does not steer** secure-code generation on CodeGuard+.
4. **CodeQL caveat:** security is scored by static per-CWE pattern queries (possible artifacts); functional tests are stateful (±3 = noise). Confirm with dynamic eval (CWEval) before final claims.

## Open / next
- Early-stopping + validation-curve probe training (overfitting control) — `patches/train_probe_curve.py`.
- Train/validate probes on **JavaScript** (PyVul has JS/TS); eval on **CWEval JS** secure-codegen benchmark.
- If steering is the goal: **decouple probe-layer from steer-layer** with per-layer norm calibration; or pivot from steering to constrained decoding.

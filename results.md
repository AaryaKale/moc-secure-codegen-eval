# Results

All on **Qwen2.5-Coder-7B**, CodeGuard+ **33 in-scope scenarios** (MoC's 9 CWEs, Python+C), greedy decoding, last-layer steering unless noted. Metric: `sec-pass@1` = % of generations both functionally correct and secure (CodeQL).

## 1. SVEN-trained MoC on CodeGuard+ (out-of-distribution)

| config | pass@1 | sec_rate | sec-pass@1 | Δ sec-pass@1 |
|---|---|---|---|---|
| **off (baseline)** | 75.8 | 74.2 | **54.8** | — |
| harden, method `n` | 75.8 | 71.0 | 51.6 | **−3.2** |
| harden, method `t` (dynamic) | 69.7 | 74.2 | 48.4 | **−6.5** |
| harden, `n`+`t` combined | 69.7 | 74.2 | 51.6 | −3.2 |

→ Steering **lowers** security+functionality. `t` (paper's best on SVEN) transfers *worst*. `n`+`t` is dominated by `t`.

## 2. Coefficient + decay sweeps (method `n`)

- coeff 0.5× = **no-op** (byte-identical to baseline); coeff ≥2× only breaks functionality, security flat.
- **No (coeff, decay) cell beats baseline.** One grid cell showed +9.4 but verification proved it a **flaky-measurement artifact** (CodeGuard+ functional tests are stateful) — actually ~−3.
- Conclusion: **knob-tuning exhausted.**

## 3. Retraining in-distribution (PrimeVul + PyVul)

Combined training set (CWE-filtered, ~2,010 paired examples):

| CWE | pairs | source | PCA probe val_acc | best_layer |
|---|---|---|---|---|
| cwe-089 (SQLi) | 87 | PyVul | **0.743** | 0 |
| cwe-078 (cmd-inj) | 77 | PyVul | 0.613 | 6 |
| cwe-416 (UAF) | 177 | PrimeVul | 0.606 | 24 |
| cwe-476 (null-deref) | 219 | PrimeVul | 0.602 | 24 |
| cwe-190 (int-ovf) | 141 | PrimeVul | 0.561 | 14 |
| cwe-022 (path-trav) | 349 | PyVul | 0.564 | 4 |
| cwe-787 (OOB-write) | 278 | PrimeVul | 0.554 | 2 |
| cwe-079 (XSS) | 285 | PyVul | 0.544 | 6 |
| cwe-125 (OOB-read) | 397 | PrimeVul | 0.535 | 28 |

- Plain linear probes (3584-dim, ~200 ex/CWE) **overfit → below chance**; PCA(64) fixed that.
- Even so, probes are **~0.55 (chance = 0.5)**, except SQLi (0.74). PyVul (~0.62 avg) marginally beats PrimeVul (~0.57), so it's **not purely PrimeVul noise**.
- Best layer **scattered (0–28)** → no single clean direction/layer to steer along.

**Read:** Qwen's representations barely encode vulnerable-vs-secure on *real-world* code — unlike SVEN's curated pairs. The gap is deeper than training distribution.

**Open caveat:** training pooled **whole functions**, not the **changed vulnerable lines** (SVEN's recipe). The changed-line pooling fix is the next experiment before declaring the signal genuinely absent.

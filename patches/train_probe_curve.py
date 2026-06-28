#!/usr/bin/env python3
"""
Probe trainer with a validation-over-training curve + early stopping.

Addresses the overfitting/hyperparameter-sensitivity Weichen flagged: it
evaluates the internal val set every `--eval_every` epochs, records the curve,
stops early when val accuracy stops improving (`--patience`), and saves:
  - <save_path>/<cwe>_probe.pt   (same format as train_probe.py: usable by corrections/moc_generate)
  - <save_path>/curves.json      (per-CWE [(epoch, train_loss, val_acc)] )
  - <save_path>/curves.png       (val_acc vs epoch per CWE; needs matplotlib)

Run from MoC/code/src:
    python train_probe_curve.py --repr_dir /scratch/.../Qwen7B-retrain-pooled \
        --save_path probes/Qwen7B-curve --kind linear_pca --pca_dim 64 \
        --layer 6 --epochs 300 --eval_every 5 --patience 6
"""
import argparse, json, os
import numpy as np
import torch, torch.nn as nn, torch.optim as optim
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from probe_model import build_probe, PCAReducer
from utils import CWES


def load_layer(repr_dir, cwe, layer):
    blob = torch.load(os.path.join(repr_dir, f"{cwe}_train.pt"), map_location="cpu", weights_only=False)
    hs = blob["hidden_states"][:, :, layer, :].float()           # [N,2,d]
    N = hs.size(0)
    X = torch.cat([hs[:, 0, :], hs[:, 1, :]], dim=0)             # secure, vul
    y = torch.cat([torch.ones(N, dtype=torch.long), torch.zeros(N, dtype=torch.long)])
    return X, y


def train_one(args, cwe, device):
    X, y = load_layer(args.repr_dir, cwe, args.layer)
    tr, va = train_test_split(np.arange(X.size(0)), test_size=args.val_size,
                              random_state=args.seed, stratify=y.numpy())
    Xtr, ytr, Xva, yva = X[tr], y[tr], X[va], y[va]

    reducer = None; input_dim = Xtr.size(1)
    if args.kind == "linear_pca":
        reducer = PCAReducer(n_components=args.pca_dim).fit(Xtr)
        Xtr, Xva = reducer.transform(Xtr), reducer.transform(Xva)
        input_dim = args.pca_dim
    mu, sigma = Xtr.mean(0), Xtr.std(0).clamp_min(1e-6)
    Xtr, Xva = (Xtr-mu)/sigma, (Xva-mu)/sigma

    probe = build_probe("linear", input_dim).to(device)
    opt = optim.Adam(probe.parameters(), lr=args.lr, weight_decay=args.wd)
    crit = nn.CrossEntropyLoss()
    Xtr, ytr, Xva = Xtr.to(device), ytr.to(device), Xva.to(device); yva_np = yva.numpy()

    curve = []; best_acc = 0.0; best_state = None; since_improve = 0; n = Xtr.size(0)
    for epoch in range(1, args.epochs+1):
        probe.train(); perm = torch.randperm(n, device=device); ep_loss = 0.0
        for s in range(0, n, args.batch_size):
            idx = perm[s:s+args.batch_size]
            loss = crit(probe(Xtr[idx]), ytr[idx])
            opt.zero_grad(); loss.backward(); opt.step(); ep_loss += loss.item()*idx.numel()
        ep_loss /= n
        if epoch % args.eval_every == 0 or epoch == 1:
            probe.eval()
            with torch.no_grad():
                pred = probe(Xva).argmax(-1).cpu().numpy()
            acc = accuracy_score(yva_np, pred); f1 = f1_score(yva_np, pred, zero_division=0)
            curve.append((epoch, round(ep_loss,4), round(float(acc),4)))
            if acc > best_acc + 1e-4:
                best_acc, best_f1, since_improve = acc, f1, 0
                best_state = {k: v.detach().cpu().clone() for k,v in probe.state_dict().items()}
            else:
                since_improve += 1
                if since_improve >= args.patience:
                    print(f"  [{cwe}] early stop @epoch {epoch} (best val_acc={best_acc:.3f})")
                    break

    # fold standardization into linear weights (so downstream consumes raw hidden states)
    W = best_state["output.weight"]; b = best_state["output.bias"]
    Wf = W / sigma.to(W.device).unsqueeze(0); bf = b - Wf @ mu.to(W.device)
    best_state = dict(best_state); best_state["output.weight"] = Wf; best_state["output.bias"] = bf
    pkg = {"cwe": cwe, "kind": args.kind, "best_layer": args.layer,
           "input_dim": input_dim, "hidden_dim": 0,
           "pca_dim": args.pca_dim if args.kind=="linear_pca" else 0,
           "state_dict": best_state, "scaler": None,
           "pca": ({"mean": reducer.mean, "components": reducer.components} if reducer else None),
           "val_acc": float(best_acc), "val_f1": float(best_f1)}
    os.makedirs(args.save_path, exist_ok=True)
    torch.save(pkg, os.path.join(args.save_path, f"{cwe}_probe.pt"))
    print(f"[{cwe}] layer={args.layer} best val_acc={best_acc:.3f} ({len(curve)} evals)")
    return curve


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repr_dir", required=True); p.add_argument("--save_path", required=True)
    p.add_argument("--cwes", nargs="+", default=CWES)
    p.add_argument("--layer", type=int, default=-1)
    p.add_argument("--kind", choices=["linear","linear_pca"], default="linear_pca")
    p.add_argument("--pca_dim", type=int, default=64)
    p.add_argument("--epochs", type=int, default=300)
    p.add_argument("--eval_every", type=int, default=5)
    p.add_argument("--patience", type=int, default=6, help="evals without improvement before stopping")
    p.add_argument("--val_size", type=float, default=0.2)
    p.add_argument("--batch_size", type=int, default=64)
    p.add_argument("--lr", type=float, default=1e-3); p.add_argument("--wd", type=float, default=1e-4)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    torch.manual_seed(args.seed); np.random.seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    curves = {cwe: train_one(args, cwe, device) for cwe in args.cwes}
    json.dump(curves, open(os.path.join(args.save_path, "curves.json"), "w"), indent=2)
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        plt.figure(figsize=(9,6))
        for cwe, c in curves.items():
            if c: xs=[e for e,_,_ in c]; ys=[a for _,_,a in c]; plt.plot(xs, ys, marker="o", label=cwe)
        plt.axhline(0.5, ls="--", c="gray", lw=1, label="chance"); plt.xlabel("epoch"); plt.ylabel("val_acc")
        plt.title(f"Validation curve (layer {args.layer})"); plt.legend(fontsize=8); plt.tight_layout()
        plt.savefig(os.path.join(args.save_path, "curves.png"), dpi=120)
        print(f"saved curves.png")
    except Exception as e:
        print(f"[plot skipped: {e}] curves.json saved.")

if __name__ == "__main__":
    main()

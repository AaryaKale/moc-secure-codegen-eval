#!/usr/bin/env python3
"""
CWE-matched MoC steering: since CodeGuard+ tells us each test's CWE, apply ONLY
that CWE's probe + correction to that prompt (at that CWE's best layer), instead
of all 9 (which sums/gates and causes collateral steering).

Optional --target_norm rescales each correction to a fixed L2 norm before
applying, fixing the per-layer norm-calibration problem (089@layer0 norm = 224).

Each prompt's CWE is read from its "cwe" field (or parsed from "id" = "cwe/scn").

    python moc_generate_cwematched.py --model_name Qwen/Qwen2.5-Coder-7B \
        --probe_dir ../probes/Qwen7B-retrain-pooled-pca \
        --corrections ../corrections/Qwen7B-retrain-pooled-pca/static_r.pt \
        --mode harden --coeff 1.0 --target_norm 5 \
        --prompts_file ../scripts/cgp_prompts.jsonl \
        --save_path ../generations/cwematched_harden.jsonl
"""
import argparse, json, math, os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from probe_model import build_probe, PCAReducer
from utils import CWES


def get_decoder_layers(model):
    for path in ("model.layers", "transformer.h", "gpt_neox.layers"):
        obj = model; ok = True
        for p in path.split("."):
            if not hasattr(obj, p): ok = False; break
            obj = getattr(obj, p)
        if ok: return obj
    raise RuntimeError("no decoder layers")


def load_by_cwe(probe_dir, corr_path, cwes, device):
    deltas = torch.load(corr_path, map_location=device, weights_only=False)["delta"]
    out = {}
    for cwe in cwes:
        fp = os.path.join(probe_dir, f"{cwe}_probe.pt")
        if not os.path.exists(fp) or cwe not in deltas: continue
        pkg = torch.load(fp, map_location="cpu", weights_only=False)
        kind = "linear" if pkg["kind"] in ("linear", "linear_pca") else "mlp"
        probe = build_probe(kind, pkg["input_dim"], hidden_size=pkg.get("hidden_dim", 0)).to(device)
        probe.load_state_dict({k: v.to(device) for k, v in pkg["state_dict"].items()}); probe.eval()
        reducer = None
        if pkg["pca"] is not None:
            reducer = PCAReducer(n_components=pkg["pca_dim"])
            reducer.mean = pkg["pca"]["mean"].to(device); reducer.components = pkg["pca"]["components"].to(device)
        out[cwe] = {"layer": int(pkg["best_layer"]), "probe": probe, "reducer": reducer,
                    "delta": deltas[cwe].to(device).float()}
        print(f"  {cwe}: layer {pkg['best_layer']}  raw-norm {deltas[cwe].norm():.1f}")
    return out


class Steerer:
    def __init__(self, by_cwe, mode, coeff, decay, target_norm):
        self.by_cwe = by_cwe; self.mode = mode; self.coeff = coeff
        self.decay = decay; self.target_norm = target_norm
        self.current = None; self.t = 0
    def set_prompt(self, cwe): self.current = cwe; self.t = 0
    def make_hook(self, layer):
        @torch.no_grad()
        def hook(module, inputs, output):
            ent = self.by_cwe.get(self.current)
            if self.mode == "off" or ent is None or ent["layer"] != layer:
                return output
            hs = output[0] if isinstance(output, tuple) else output
            if hs.size(1) != 1: return output
            last = hs[:, -1, :].float()
            delta = ent["delta"]
            if self.target_norm:
                delta = delta / delta.norm().clamp_min(1e-6) * self.target_norm
            alpha = math.exp(-self.decay * self.t)
            if self.mode == "harden":
                inp = last if ent["reducer"] is None else ent["reducer"].transform(last)
                gate = (ent["probe"](inp).argmax(-1) == 0).float().unsqueeze(-1)
                add = gate * delta.unsqueeze(0)
            else:
                add = -delta.unsqueeze(0)
            hs[:, -1, :] = hs[:, -1, :] + (self.coeff * alpha * add).to(hs.dtype)
            self.t += 1
            return (hs,) + output[1:] if isinstance(output, tuple) else hs
        return hook


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model_name", required=True)
    p.add_argument("--probe_dir", required=True)
    p.add_argument("--corrections", required=True)
    p.add_argument("--cwes", nargs="+", default=CWES)
    p.add_argument("--mode", choices=["off", "harden", "weaken"], default="harden")
    p.add_argument("--coeff", type=float, default=1.0)
    p.add_argument("--decay_rate", type=float, default=0.0)
    p.add_argument("--target_norm", type=float, default=0.0,
                   help="if >0, rescale each correction to this L2 norm (calibration)")
    p.add_argument("--prompts_file", required=True)
    p.add_argument("--save_path", required=True)
    p.add_argument("--max_new_tokens", type=int, default=512)
    args = p.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(args.model_name, trust_remote_code=True)
    if tok.pad_token is None: tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(args.model_name, torch_dtype=torch.bfloat16,
                                                 device_map="auto", trust_remote_code=True).eval()
    by_cwe = load_by_cwe(args.probe_dir, args.corrections, args.cwes, device)
    steerer = Steerer(by_cwe, args.mode, args.coeff, args.decay_rate,
                      args.target_norm if args.target_norm > 0 else None)
    layers = get_decoder_layers(model)
    handles = [layers[L].register_forward_hook(steerer.make_hook(L))
               for L in sorted({e["layer"] for e in by_cwe.values()})]

    os.makedirs(os.path.dirname(args.save_path) or ".", exist_ok=True)
    with open(args.prompts_file) as fin, open(args.save_path, "w") as fout:
        for line in fin:
            item = json.loads(line)
            cwe = item.get("cwe") or item["id"].split("/")[0]
            steerer.set_prompt(cwe)
            enc = tok(item["prompt"], return_tensors="pt").to(device)
            gen = model.generate(**enc, max_new_tokens=args.max_new_tokens,
                                 do_sample=False, pad_token_id=tok.pad_token_id)
            new = tok.decode(gen[0, enc.input_ids.size(1):], skip_special_tokens=True)
            fout.write(json.dumps({**item, "completion": new, "mode": args.mode}) + "\n"); fout.flush()
    for h in handles: h.remove()
    print(f"saved -> {args.save_path}")


if __name__ == "__main__":
    main()

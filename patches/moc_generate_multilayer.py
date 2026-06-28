#!/usr/bin/env python3
"""
Multi-layer MoC steering: steer each CWE at ITS OWN best layer (not one shared
layer). Use this when probes were trained with a layer sweep, so best_layer
differs per CWE (e.g. 089->0, 022->6, 079->12, 476->24).

Place in MoC/code/src/ (next to moc_generate.py) and run the same way, but you
don't pass --steer_layer (each CWE's layer comes from its probe's best_layer).

    python moc_generate_multilayer.py \
        --model_name Qwen/Qwen2.5-Coder-7B \
        --probe_dir   ../probes/Qwen7B-retrain-pooled-pca \
        --corrections ../corrections/Qwen7B-retrain-pooled-pca/static_r.pt \
        --mode harden --coeff 1.0 --decay_rate 0 \
        --prompts_file ../scripts/cgp_prompts.jsonl \
        --save_path ../generations/multilayer_harden_r.jsonl
"""
import argparse, json, math, os
from collections import defaultdict
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
    raise RuntimeError("Could not find transformer block list.")


def load_probes_grouped(probe_dir, corr_path, cwes, device):
    """Return {layer_idx: [ {cwe, probe, reducer, delta} ]} using each probe's own best_layer."""
    corr = torch.load(corr_path, map_location=device, weights_only=False)
    deltas = corr["delta"]
    groups = defaultdict(list)
    for cwe in cwes:
        fp = os.path.join(probe_dir, f"{cwe}_probe.pt")
        if not os.path.exists(fp) or cwe not in deltas:
            continue
        pkg = torch.load(fp, map_location="cpu", weights_only=False)
        layer = int(pkg["best_layer"])
        kind = "linear" if pkg["kind"] in ("linear", "linear_pca") else "mlp"
        probe = build_probe(kind, pkg["input_dim"], hidden_size=pkg.get("hidden_dim", 0)).to(device)
        probe.load_state_dict({k: v.to(device) for k, v in pkg["state_dict"].items()})
        probe.eval()
        reducer = None
        if pkg["pca"] is not None:
            reducer = PCAReducer(n_components=pkg["pca_dim"])
            reducer.mean = pkg["pca"]["mean"].to(device)
            reducer.components = pkg["pca"]["components"].to(device)
        groups[layer].append({"cwe": cwe, "probe": probe, "reducer": reducer,
                              "delta": deltas[cwe].to(device).float()})
        print(f"  {cwe}: steer at layer {layer}")
    return groups


class MultiLayerSteerer:
    def __init__(self, groups, mode="harden", decay_rate=0.0, coeff=1.0):
        self.groups = groups
        self.max_layer = max(groups) if groups else -1
        self.mode = mode; self.decay_rate = decay_rate; self.coeff = coeff
        self.t = 0
    def reset(self): self.t = 0
    def make_hook(self, layer_idx):
        @torch.no_grad()
        def hook(module, inputs, output):
            if self.mode == "off": return output
            hs = output[0] if isinstance(output, tuple) else output
            if hs.size(1) != 1:           # only steer single-token generation steps
                return output
            last = hs[:, -1, :].float()
            alpha = math.exp(-self.decay_rate * self.t)
            total = torch.zeros_like(last)
            for ent in self.groups[layer_idx]:
                inp = last if ent["reducer"] is None else ent["reducer"].transform(last)
                vul = (ent["probe"](inp).argmax(dim=-1) == 0).float().unsqueeze(-1)  # [B,1]
                d = ent["delta"].unsqueeze(0).expand_as(last)
                if self.mode == "harden":
                    total = total + vul * d
                elif self.mode == "weaken":
                    total = total - d
            hs[:, -1, :] = hs[:, -1, :] + (self.coeff * alpha * total).to(hs.dtype)
            if layer_idx == self.max_layer:
                self.t += 1
            return (hs,) + output[1:] if isinstance(output, tuple) else hs
        return hook


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model_name", required=True)
    p.add_argument("--probe_dir", required=True)
    p.add_argument("--corrections", required=True, help="static_*.pt with per-CWE deltas")
    p.add_argument("--cwes", nargs="+", default=CWES)
    p.add_argument("--mode", choices=["off", "harden", "weaken"], default="harden")
    p.add_argument("--coeff", type=float, default=1.0)
    p.add_argument("--decay_rate", type=float, default=0.0)
    p.add_argument("--prompts_file", required=True)
    p.add_argument("--save_path", required=True)
    p.add_argument("--max_new_tokens", type=int, default=512)
    args = p.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(args.model_name, trust_remote_code=True)
    if tok.pad_token is None: tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(args.model_name, torch_dtype=torch.bfloat16,
                                                 device_map="auto", trust_remote_code=True).eval()

    groups = load_probes_grouped(args.probe_dir, args.corrections, args.cwes, device)
    steerer = MultiLayerSteerer(groups, mode=args.mode, coeff=args.coeff, decay_rate=args.decay_rate)
    layers = get_decoder_layers(model)
    handles = [layers[L].register_forward_hook(steerer.make_hook(L)) for L in groups]
    print(f"hooked layers: {sorted(groups)}")

    os.makedirs(os.path.dirname(args.save_path) or ".", exist_ok=True)
    with open(args.prompts_file) as fin, open(args.save_path, "w") as fout:
        for line in fin:
            item = json.loads(line); steerer.reset()
            enc = tok(item["prompt"], return_tensors="pt").to(device)
            gen = model.generate(**enc, max_new_tokens=args.max_new_tokens,
                                 do_sample=False, pad_token_id=tok.pad_token_id)
            new = tok.decode(gen[0, enc.input_ids.size(1):], skip_special_tokens=True)
            fout.write(json.dumps({**item, "completion": new, "mode": args.mode}) + "\n")
            fout.flush()
    for h in handles: h.remove()
    print(f"saved -> {args.save_path}")


if __name__ == "__main__":
    main()

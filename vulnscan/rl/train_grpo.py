"""GRPO fine-tuning of the triage model (runs in the "trainer" container).

    docker compose run --rm trainer python -m vulnscan.rl.train_grpo train \
        --data training/dataset/all.train.jsonl --out training/out/qwen3-4b-grpo
    docker compose run --rm trainer python -m vulnscan.rl.train_grpo export \
        --out training/out/qwen3-4b-grpo

The base is Qwen3-4B in 4-bit with a LoRA adapter (an 8 GB GPU cannot hold
8B with GRPO's sampled completions). Each prompt is the exact v3 triage prompt;
GRPO samples several replies per prompt and pushes the policy toward the
higher-reward ones, scored by vulnscan.rl.reward against the alert's label.
Reasoning mode is off, as in the fast triage pass."""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from . import reward

BASE = "unsloth/Qwen3-4B-unsloth-bnb-4bit"


def load_rows(path: str, per_source: int, seed: int) -> list[dict]:
    """Cap each source and balance real/false alarms within it, so the large test
    suites do not drown the apps and the policy cannot win by always saying one verdict."""
    rng = random.Random(seed)
    groups: dict[tuple[str, bool], list[dict]] = defaultdict(list)
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        groups[(r["source"], r["vulnerable"])].append(r)
    out = []
    for src in sorted({s for s, _ in groups}):
        tp, fp = groups.get((src, True), []), groups.get((src, False), [])
        rng.shuffle(tp), rng.shuffle(fp)
        half = per_source // 2
        if tp and fp:
            n_tp = min(len(tp), max(half, per_source - len(fp)))
            n_fp = min(len(fp), per_source - n_tp)
        else:
            n_tp, n_fp = min(len(tp), half), min(len(fp), half)
        out += tp[:n_tp] + fp[:n_fp]
    rng.shuffle(out)
    return out


def train(args) -> None:
    from unsloth import FastLanguageModel  # noqa: I001  (must be imported before trl)
    from datasets import Dataset
    from trl import GRPOConfig, GRPOTrainer

    model, tok = FastLanguageModel.from_pretrained(BASE, max_seq_length=args.max_prompt + args.max_completion,
                                                   load_in_4bit=True, fast_inference=False)
    model = FastLanguageModel.get_peft_model(
        model, r=args.lora_r, lora_alpha=args.lora_r * 2, lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth", random_state=args.seed)

    rows = load_rows(args.data, args.per_source, args.seed)
    items, dropped = [], 0
    for r in rows:
        text = tok.apply_chat_template([{"role": "user", "content": r["prompt"]}], tokenize=False,
                                       add_generation_prompt=True, enable_thinking=False)
        if len(tok(text).input_ids) > args.max_prompt:
            dropped += 1  # dropped, not truncated: a cut-off file would teach the wrong thing
            continue
        items.append({"prompt": text, "vulnerable": r["vulnerable"], "source": r["source"]})
    print(f"{len(items)} prompts ({dropped} longer than {args.max_prompt} tokens dropped)")
    ds = Dataset.from_list(items)

    def triage_reward(completions, vulnerable, **_):
        return [reward.score(c, v).total for c, v in zip(completions, vulnerable)]

    cfg = GRPOConfig(
        output_dir=args.out, learning_rate=args.lr, lr_scheduler_type="cosine", warmup_ratio=0.05,
        per_device_train_batch_size=args.generations, gradient_accumulation_steps=args.grad_accum,
        num_generations=args.generations, max_prompt_length=args.max_prompt,
        max_completion_length=args.max_completion, temperature=1.0, beta=args.beta,
        num_train_epochs=args.epochs, max_steps=args.max_steps, logging_steps=1, save_steps=50,
        save_total_limit=3, bf16=True, optim="adamw_8bit", report_to="none", seed=args.seed)
    trainer = GRPOTrainer(model=model, processing_class=tok, reward_funcs=[triage_reward], args=cfg,
                          train_dataset=ds)
    trainer.train(resume_from_checkpoint=args.resume or None)
    model.save_pretrained(f"{args.out}/lora")
    tok.save_pretrained(f"{args.out}/lora")
    Path(args.out, "log_history.json").write_text(json.dumps(trainer.state.log_history, indent=1))


def export(args) -> None:
    """Merge the adapter and write a Q4_K_M GGUF for Ollama."""
    from unsloth import FastLanguageModel

    model, tok = FastLanguageModel.from_pretrained(f"{args.out}/lora", max_seq_length=8192, load_in_4bit=False)
    model.save_pretrained_gguf(f"{args.out}/gguf", tok, quantization_method="q4_k_m")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["train", "export"])
    ap.add_argument("--data", default="training/dataset/all.train.jsonl")
    ap.add_argument("--out", default="training/out/qwen3-4b-grpo")
    ap.add_argument("--per-source", type=int, default=600)
    ap.add_argument("--max-prompt", type=int, default=3072)
    ap.add_argument("--max-completion", type=int, default=320)
    ap.add_argument("--generations", type=int, default=4)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--lr", type=float, default=5e-6)
    ap.add_argument("--beta", type=float, default=0.04)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--resume", default="")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    {"train": train, "export": export}[args.cmd](args)


if __name__ == "__main__":
    main()

"""Fine-tuning the triage model with reinforcement learning.

corpus.py builds a labelled training corpus from intentionally vulnerable
code that is not among the evaluation targets; dataset.py turns scanner
alerts on it into prompts; reward.py scores model replies; train_grpo.py
runs GRPO in the training container."""

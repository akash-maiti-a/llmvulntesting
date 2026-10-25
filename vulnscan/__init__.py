"""LLM-assisted vulnerability scanner."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The training corpus (training/) reuses the pipeline with its own manifest,
# ground truth and results, selected through these variables.
RESULTS = ROOT / os.environ.get("VULNSCAN_RESULTS", "results")
TARGETS_SRC = ROOT / "targets" / "src"

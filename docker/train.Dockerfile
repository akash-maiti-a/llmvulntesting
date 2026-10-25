# GPU image for fine-tuning the triage model (vulnscan/rl/train_grpo.py).
# Kept separate from the scanner image: it is ~10 GB of CUDA wheels and is
# only needed for training. Build and run through the "trainer" compose service.
FROM pytorch/pytorch:2.7.1-cuda12.6-cudnn9-devel

RUN apt-get update \
 && apt-get install -y --no-install-recommends git build-essential cmake curl libcurl4-openssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Unsloth brings TRL, PEFT, bitsandbytes and transformers at versions it is tested with.
RUN pip install --no-cache-dir unsloth pyyaml httpx

WORKDIR /work
ENV HF_HOME=/work/.cache/hf
ENTRYPOINT []
CMD ["python", "-m", "vulnscan.rl.train_grpo", "--help"]

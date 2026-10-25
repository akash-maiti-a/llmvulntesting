FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git php-cli patch curl \
 && rm -rf /var/lib/apt/lists/*

# Scanners pinned so results are reproducible. pyre-check 0.9.23's CLI breaks on
# click >= 8.2 ("Invalid value for '--version'"), so click is pinned with it.
RUN pip install --no-cache-dir semgrep==1.95.0 pyre-check==0.9.23 "click<8.2"

# Target clones are bind-mounted from the host and owned by another user;
# without this git refuses to operate on them ("dubious ownership").
RUN git config --system --add safe.directory '*'

WORKDIR /work
COPY pyproject.toml ./
COPY vulnscan ./vulnscan
RUN pip install --no-cache-dir -e ".[dev]"

ENV OLLAMA_HOST=http://host.docker.internal:11434
ENTRYPOINT []
CMD ["vulnscan", "--help"]

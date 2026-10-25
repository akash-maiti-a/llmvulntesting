// All page content lives here, separated from the components that render it.
// Numbers come from results/report.md (model qwen3:8b, Q4_K_M, temperature 0).

export const repoUrl = "https://github.com/akash-maiti-a/llmvulntesting";
export const profileUrl = "https://github.com/akash-maiti-a";

export const navLinks = [
  { href: "#overview", label: "Overview" },
  { href: "#pipeline", label: "Pipeline" },
  { href: "#method", label: "How it works" },
  { href: "#results", label: "Results" },
  { href: "#rl", label: "Fine-tuning" },
  { href: "#stack", label: "Engineering" },
];

export const heroStats = [
  { n: "38% → 50%", l: "precision, real apps" },
  { n: "91%", l: "true positives kept" },
  { n: "3", l: "analysis engines" },
  { n: "11 + CVEs", l: "benchmark targets" },
];

export const overviewCards = [
  {
    tag: "Detect",
    title: "Three analyzers",
    body: "Semgrep registry rulesets and custom taint rules for PHP and Python, plus Pysa for inter-procedural Python taint. Each finding is normalized into one Finding model.",
  },
  {
    tag: "Triage",
    title: "A local LLM judge",
    body: "Each alert is sent on its own to a local model via Ollama, constrained to a JSON schema, and labelled true_positive or false_positive with a reasoned analysis.",
  },
  {
    tag: "Measure",
    title: "Scored on ground truth",
    body: "Deliberately vulnerable apps, a 38-case synthetic benchmark, and real CVEs (vulnerable vs. patched) give a label for every region, so precision and recall are real numbers.",
  },
];

// Pipeline is rendered as rows of nodes with arrow connectors.
export const pipeline = {
  rows: [
    {
      kind: "flow",
      nodes: [
        { t: "Targets", s: "targets.yaml" },
        { t: "Fetch", s: "git clone · pinned" },
      ],
    },
    { kind: "down" },
    {
      kind: "fan",
      nodes: [
        { t: "Semgrep registry", s: "p/php · p/python" },
        { t: "Semgrep custom", s: "taint rules" },
        { t: "Pysa", s: "inter-procedural" },
      ],
    },
    { kind: "down" },
    {
      kind: "flow",
      nodes: [
        { t: "Finding", s: "tool · CWE · trace · id", hl: true },
        { t: "LLM triage", s: "Ollama · JSON schema", hl: true },
        { t: "Evaluate", s: "vs. ground truth" },
        { t: "Report", s: "summary.json · md" },
      ],
    },
  ],
  caption: "targets.yaml → fetch → scan (3 engines) → Finding → triage → evaluate → report",
};

export const methodCards = [
  {
    tag: "01 · Targets",
    title: "Reproducible by construction",
    body: "Every codebase is pinned to a commit SHA in targets.yaml. CVE targets expand automatically into a @vuln and a @fixed variant around the fix commit, so the same tool is tested on the bug and on its patch.",
  },
  {
    tag: "02 · Scanning",
    title: "Taint with traces",
    body: "Semgrep runs twice (registry + custom) with --dataflow-traces, so each finding carries its source → sink path; its taint is intra-procedural. Pysa follows taint across functions and files for Python, resolving library calls through pinned models.",
  },
  {
    tag: "03 · Findings & CWE",
    title: "One model, stable IDs",
    body: "Every engine emits the same Finding (tool, ruleset, CWE, file, lines, snippet, trace) with a stable sha1 id. Tools name the same bug with different CWEs, so CWEs are grouped into families (sqli, cmdi, xss…) and matched by family.",
  },
  {
    tag: "04 · LLM triage",
    title: "Structured, schema-bound verdicts",
    body: "Each alert goes to Ollama at temperature 0 with a JSON-schema reply. Prompts evolved v1 → v2 → v3: v2 forces the model through sink_is_real, attacker_reaches_sink, and defence_sufficient; v3 makes it write the analysis before committing to the checks. File paths are redacted so benchmark names can't leak the answer.",
  },
  {
    tag: "05 · Ground truth",
    title: "Every region has a label",
    body: "Per-target YAML marks each location vulnerable: true|false with a CWE and scope (taint, other, client). CVE truth is derived mechanically from the fix diff, where the lines the patch changed are the vulnerable ones.",
  },
  {
    tag: "06 · Evaluation",
    title: "Honest, fail-open scoring",
    body: "A finding hits an entry when it lands in its location and shares its CWE family. The evaluator reports recall per scope, precision, false positives on known-safe code, and triage accuracy. Timeouts and bad replies are kept, never silently dropped (fail open).",
  },
];

export const methodNote = {
  mark: "⌁",
  title: "Fast vs. reasoning.",
  body: "The fast pass answers in ~2–11s per alert. A ~7× slower chain-of-thought pass is used only as a second tier on alerts the fast pass rejected, a two-tier policy that recovers recall without paying the reasoning cost on every alert.",
};

export const appsTable = {
  caption: "Real apps: DVWA, DVPWA, PyGoat",
  columns: ["Configuration", "Alerts", "True pos.", "Precision", "Recall (taint)"],
  rows: [
    { cells: ["All tools, no triage", "268", "79", "38%", "29/39 (74%)"] },
    { cells: ["+ triage v3-fast", "171", "72", "50%", "27/39 (69%)"], highlight: true, up: 3 },
    { cells: ["+ triage v2 two-tier", "221", "79", "44%", "29/39 (74%)"] },
  ],
};

export const syntheticTable = {
  caption: "Synthetic benchmark: 38 labelled cases",
  columns: ["Configuration", "Alerts", "True pos.", "Precision", "Recall (taint)"],
  rows: [
    { cells: ["All tools, no triage", "77", "46", "60%", "18/20 (90%)"] },
    { cells: ["+ triage v3-fast", "60", "44", "73%", "17/20 (85%)"], highlight: true, up: 3 },
    { cells: ["+ triage v2 two-tier", "66", "46", "70%", "18/20 (90%)"] },
  ],
};

export const triageTable = {
  caption: "Triage accuracy on real apps · 79 true / 131 false positives judged",
  columns: ["Triage pass", "TPs kept", "FPs removed", "Failed", "s / alert"],
  rows: [
    { cells: ["v1-fast", "75/79 (95%)", "38/131 (29%)", "0", "2.9"] },
    { cells: ["v2-fast", "70/79 (89%)", "55/131 (42%)", "3", "10.7"] },
    { cells: ["v3-fast", "72/79 (91%)", "60/131 (46%)", "0", "10.5"], highlight: true },
    { cells: ["v2 two-tier", "79/79 (100%)", "30/131 (23%)", "16", "-"] },
  ],
};

export const resultsNote = {
  mark: "✓",
  title: "Read it this way.",
  body: "v3-fast removes roughly a third of all alerts and lifts precision while keeping 91% of real bugs. The two-tier policy keeps every true positive (100%) and still clears about a quarter of the noise.",
};

export const finetuneCards = [
  {
    tag: "Method",
    title: "GRPO on Qwen3-4B",
    body: "A 4-bit Qwen3-4B base with a LoRA adapter (0.81% of parameters trained) is tuned with GRPO: the model samples several verdicts per alert, and the policy is pushed toward the higher-reward ones. Runs in an isolated GPU container on an 8 GB laptop card.",
  },
  {
    tag: "Reward",
    title: "More than “right answer”",
    body: "Each reply is scored on four terms: valid JSON, correct verdict (missing a real bug penalized 4× harder than keeping noise), calibration (Brier score of its confidence), and consistency between its checks and verdict.",
  },
  {
    tag: "Data",
    title: "Held out from evaluation",
    body: "955 training / 111 dev alerts are built from a separate set of vulnerable apps and suites, with label-leaking comments and variable names scrubbed and a whitespace-hash check that aborts on any overlap with an evaluation file.",
  },
  {
    tag: "Status",
    title: "Round 4 — measured & training",
    body: "The reward and dataset ideas from round 3 are now implemented and measured: the format escape-hatch is closed, JSON parsing is hardened, and the training mix is rebalanced (true-positive share 31% → 43%). A 50-step GRPO run is training on the improved setup against a fixed base-model baseline; the unit suite passes 36/36.",
  },
];

// Round 4: the documented ideas, now implemented with a measured effect each.
export const stage4Improvements = {
  caption: "Round 4 · ideas implemented and measured",
  columns: ["Area", "Change", "Measured effect"],
  rows: [
    { cells: ["Reward escape-hatch", "format penalty −1.0 → −2.5", "garbage (−2.5) now scores below the worst miss (−2.3)"] },
    { cells: ["Parse robustness", "decode first complete verdict object", "a stray { in the analysis no longer mis-parses"] },
    { cells: ["Dev scoring", "report majority-class baseline + lift", "accuracy read against the 73% line, not raw"] },
    { cells: ["Training mix", "cap single-label sources at 120", "SARD FPs 300 → 120; TP share 31% → 43%"] },
  ],
};

// The base model's dev behaviour — the line the fine-tuned adapter must beat.
export const rlBaselineTable = {
  caption: "RL baseline · base qwen3:4b on the 111-alert dev split",
  columns: ["Metric", "Base qwen3:4b", "Reading"],
  rows: [
    { cells: ["Accuracy", "38.7%", "below the 73% majority baseline"] },
    { cells: ["True positives kept", "100%", "keeps all 30 real bugs"], highlight: true },
    { cells: ["False positives removed", "16%", "drops only 13 of 81"] },
    { cells: ["Brier score", "0.554", "confidence poorly calibrated"] },
  ],
};

export const stage4Note = {
  mark: "⏳",
  title: "Stage-4 run in progress.",
  body: "A 50-step GRPO run is training on the improved reward and rebalanced corpus (Qwen3-4B 4-bit + LoRA, 8 GB RTX 4060). When it finishes, the adapter is scored against the baseline above — the goal is to raise false-positive removal while holding true-positive retention near 100%.",
};

export const engineeringPoints = [
  {
    strong: "Reproducible everything.",
    rest: " Targets pinned to SHAs; Semgrep 1.95.0 and Pyre 0.9.23 pinned in a Docker image; verdicts cached per finding id so runs resume and repeat.",
  },
  {
    strong: "No data leakage.",
    rest: " File paths are redacted in prompts, hint comments are blanked while preserving line numbers, and training data is hash-checked against every evaluation file.",
  },
  {
    strong: "Fail open.",
    rest: " A timed-out or malformed triage reply keeps the finding rather than dropping it, the scanner never hides a bug because the model stumbled.",
  },
  {
    strong: "Local & private.",
    rest: " The LLM runs on the host through Ollama; nothing is sent to a third-party API.",
  },
  {
    strong: "Tested.",
    rest: " A pytest suite covers the parsers, CVE fix-diff ground truth, CWE matching, scoring, triage, and the RL reward — 36 passing tests.",
  },
  {
    strong: "One command to run it all.",
    rest: " docker compose run --rm scanner vulnscan run fetches, scans, triages, and evaluates into results/report.md.",
  },
];

export const runSnippet = `# host: Ollama with the triage model
ollama pull qwen3:8b
ollama serve

# scan + triage + evaluate every target
docker compose build
docker compose run --rm scanner vulnscan run
# → results/summary.json, results/report.md`;

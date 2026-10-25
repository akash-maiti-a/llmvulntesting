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
    body: "Per-target YAML marks each location vulnerable: true|false with a CWE and scope (taint, other, client). CVE truth is derived mechanically from the fix diff — the lines the patch changed are the vulnerable ones.",
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
  body: "The fast pass answers in ~2–11s per alert. A ~7× slower chain-of-thought pass is used only as a second tier on alerts the fast pass rejected — a two-tier policy that recovers recall without paying the reasoning cost on every alert.",
};

export const appsTable = {
  caption: "Real apps — DVWA, DVPWA, PyGoat · union of all tools",
  columns: ["Configuration", "Alerts", "True pos.", "Precision", "Recall (taint)"],
  rows: [
    { cells: ["All tools, no triage", "268", "79", "38%", "29/39 (74%)"] },
    { cells: ["+ triage v3-fast", "171", "72", "50%", "27/39 (69%)"], highlight: true, up: 3 },
    { cells: ["+ triage v2 two-tier", "221", "79", "44%", "29/39 (74%)"] },
  ],
};

export const syntheticTable = {
  caption: "Synthetic benchmark — 38 labelled cases · union of all tools",
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
    { cells: ["v2 two-tier", "79/79 (100%)", "30/131 (23%)", "16", "—"] },
  ],
};

export const resultsNote = {
  mark: "✓",
  title: "Read it this way.",
  body: "v3-fast removes roughly a third of all alerts and lifts precision while keeping 91% of real bugs. The two-tier policy keeps every true positive (100%) and still clears about a quarter of the noise — pick the operating point by how costly a missed bug is.",
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
    body: "Each reply is scored on four terms — valid JSON, correct verdict (missing a real bug penalized 4× harder than keeping noise), calibration (Brier score of its confidence), and consistency between its checks and verdict.",
  },
  {
    tag: "Data",
    title: "Held out from evaluation",
    body: "955 training / 111 dev alerts are built from a separate set of vulnerable apps and suites, with label-leaking comments and variable names scrubbed and a whitespace-hash check that aborts on any overlap with an evaluation file.",
  },
  {
    tag: "Status",
    title: "Pipeline validated",
    body: "A 10-step smoke run completed end-to-end — base model loaded, LoRA attached, all steps ran, adapter saved — and the scanner's unit suite passes 34/34. A full multi-epoch run is the next step; the fine-tuned model is not yet claimed to beat the 8B base.",
  },
];

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
    rest: " A timed-out or malformed triage reply keeps the finding rather than dropping it — the scanner never hides a bug because the model stumbled.",
  },
  {
    strong: "Local & private.",
    rest: " The LLM runs on the host through Ollama; nothing is sent to a third-party API.",
  },
  {
    strong: "Tested.",
    rest: " A pytest suite covers the parsers, CVE fix-diff ground truth, CWE matching, scoring, triage, and the RL reward — 34 tests, green.",
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

# Synthetic benchmark

38 small handlers (17 PHP, 21 Python/Flask), each a single file. Each is either
vulnerable or safe, and its label lives in `groundtruth/synthetic.yaml`, not in
the file. File names (`caseNN`) and code carry no hints, because LLM triage
sees the code.

The cases come in vulnerable/safe pairs per weakness, and target known blind
spots of taint analyzers and of LLM triage:

| Pattern | Vulnerable case | Safe case |
| --- | --- | --- |
| SQL string building vs. bound parameters | php/case01, python/case01 | php/case02, python/case02 |
| SQL escaping in a numeric vs. quoted context | php/case03 | php/case04 |
| Shell command with validation / escaping | php/case05, python/case03 | php/case06 (filter_var IP), php/case07 (escapeshellarg), python/case04 (ipaddress + argv) |
| HTML escaping in an unquoted attribute vs. element content | php/case09 | php/case10 |
| Include path vs. allowlist | php/case11 | php/case12 |
| Cross-function flows | php/case13 (SQL), python/case17 (shell) | |
| Deserialization | php/case14, python/case05, python/case07 | php/case15, python/case06, python/case08 |
| Path traversal vs. basename + realpath check | python/case09 | python/case10 |
| SSRF vs. host allowlist | python/case11 | python/case12 |
| eval vs. ast.literal_eval | python/case13 | python/case14 |
| Template source vs. template variable (SSTI) | python/case15 | python/case16 |
| Reflected XSS vs. escaping | php/case08, python/case18 | python/case19 |
| Open redirect vs. local-path check | php/case16, python/case20 | php/case17, python/case21 |

Safe cases are meant to be safe, not merely hard to exploit. One redirect check
originally accepted `/\evil.com`, which browsers treat as `//evil.com`. It was
fixed before the benchmark was used.

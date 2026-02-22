# reAVS

reAVS is a remake of [AVS](https://github.com/aimardcr/AVS/).

A defensive, best-effort static analyzer for Android APKs.  It extracts the
app attack surface from the manifest and looks for high-risk vulnerability
patterns using lightweight taint heuristics.  No dynamic execution,
instrumentation, or network calls are performed.

## Scope and limitations

- Static analysis only; results are best-effort and heuristic-driven.
- Obfuscated APKs may reduce precision; reAVS degrades gracefully without crashing.
- Third-party library code (`androidx.*`, `com.google.android.*`, etc.) is excluded from taint-based scanners to reduce false positives.
- Findings should be triaged and verified by a human reviewer.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# or: source .venv/bin/activate   # Linux / macOS
pip install -r requirements.txt
```

Requires Python 3.10+. Dependencies: `androguard 4.1.3`, `PyYAML`.

## Usage

```bash
python avs.py app.apk --out report.json
python avs.py app.apk --deep --depth 3
python avs.py app.apk --component com.example.MainActivity --verbose
```

| Flag | Description |
|------|-------------|
| `--out <path>` | Write JSON report to file |
| `--fast` | Fast scan, intra-procedural taint (default) |
| `--deep` | Deep scan, inter-procedural CFG/ICFG taint |
| `--depth <n>` | Helper propagation depth in deep mode (default: 3) |
| `--component <name>` | Restrict scan to a specific component |
| `--verbose` | Show debug output |

## Project structure

```
avs.py                          Entry point (thin wrapper around core.cli)
core/
  cli.py                        CLI parsing, scan orchestration, output
  models.py                     Data models (Finding, Component, Severity, ...)
  config.py                     ScanConfig, ScanContext
  log.py                        Logger
  loader.py                     APK loading via Androguard
  manifest.py                   AndroidManifest.xml parsing
  bytecode/
    extract.py                  Method-level IR extraction (invokes, consts, fields, moves)
    cfg.py                      Per-method control flow graph builder
    instructions.py             Shared low-level bytecode instruction helpers
    smali.py                    Smali output parsing utilities
  dataflow/
    tags.py                     TaintTag enum
    taint_linear.py             Intra-procedural linear taint (fast mode)
    taint_cfg.py                Inter-procedural CFG/ICFG taint engine (deep mode)
    taint_provider.py           Taint provider abstraction (selects engine by scan mode)
    callbacks.py                Android callback/lifecycle edge discovery
    dex_queries.py              DEX method enumeration and indexing
  rules/
    catalog.py                  YAML rule loader
    matching.py                 Pattern matching for sources/sinks/sanitizers
    sources.yml                 Taint source definitions
    sinks.yml                   Sink definitions
    sanitizers.yml              Sanitizer definitions
    policy.yml                  Severity/confidence policy
  reporting/
    json_report.py              JSON report builder
  util/
    strings.py                  String normalization, entropy, Base64 detection
    descriptors.py              Dalvik method descriptor parsing
scanners/
  base.py                       BaseScanner + shared scanner helpers
  intent.py                     Intent injection / redirection
  provider.py                   ContentProvider file access vulnerabilities
  execution.py                  Dynamic code loading, Runtime.exec, reflection
  crypto.py                     Cryptographic weaknesses (hardcoded keys, ECB, weak digests)
  sql.py                        SQL injection
  deeplinks.py                  Deep link scanner (placeholder)
  webview.py                    WebView scanner (placeholder)
tests/
  conftest.py                   Pytest fixtures (make_ctx, fake APK/analysis)
  helpers/fakes.py              Test doubles (FakeMethod, FakeAPK, FakeAnalysis, ...)
  test_bytecode.py              IR extraction and call edge tests
  test_taint.py                 Inter-procedural CFG taint propagation
  test_callbacks.py             Callback root detection
  test_stability.py             Fingerprint determinism, dedup stability
  test_pipeline.py              APK loading, manifest parsing
  test_cli.py                   CLI output formatting
  test_reporting.py             JSON report golden file comparison
  test_regression.py            Stress tests, component filter scoping
  test_intent.py                Intent injection scanner rules
  test_provider.py              ContentProvider scanner rules
  test_execution.py             Code execution scanner rules
  test_crypto.py                Cryptography scanner rules
  test_sql.py                   SQL injection reachability tests
  test_severity.py              Severity policy resolution
```

## Scan modes

**Fast mode** (`--fast`, default) runs intra-procedural linear taint analysis.
Each method is analyzed independently in a single pass.  No helper propagation.

**Deep mode** (`--deep`) builds per-method CFGs and runs a fixed-point
inter-procedural taint engine with callback edge discovery.  Propagates taint
across method calls, constructors, and Android lifecycle callbacks (onClick,
startActivity, synthetic lambdas).  Bounded by `--depth` to avoid runaway
analysis.

## Adding a scanner

1. Create a file in `scanners/` that subclasses `BaseScanner`.
2. Import shared helpers from `scanners.base` (`method_name`, `has_tainted_arg`, `taint_view`, etc.).
3. Register the scanner in `core/cli.py`'s scanner list.
4. Emit `Finding` objects with evidence steps and recommendations.

## Adding rules

Edit the YAML files in `core/rules/`:

- `sources.yml` -- taint sources (grouped by category: intent, uri, user_input, provider)
- `sinks.yml` -- sink patterns (grouped by category: intent, file, sql, exec, webview)
- `sanitizers.yml` -- sanitizer patterns
- `policy.yml` -- severity mappings, CWE references, confidence levels

Rules are loaded automatically at startup.

## Detection patterns

- **Intent redirection** -- `getParcelableExtra("intent") -> startActivity(intent)`
- **Tainted setResult** -- extras control `setAction`/`setData`/`setClassName` before `setResult`
- **Arbitrary file write** -- `getStringExtra("path") -> FileOutputStream`
- **WebView tainted URL** -- `getStringExtra("url") -> WebView.loadUrl(url)` (higher severity if JS enabled)
- **SQL injection** -- `query(uri, ...) -> rawQuery(sql)` with selection concatenation
- **ContentProvider file access** -- `openFile(uri)` with weak path traversal checks
- **Dynamic code loading** -- `DexClassLoader(dexPath)` from untrusted path
- **Runtime exec** -- `Runtime.exec(cmd)` or `ProcessBuilder`
- **Tainted reflection** -- tainted strings to `Class.forName` / `Method.invoke`
- **Crypto weaknesses** -- hardcoded Base64 keys, AES/ECB mode, fixed IV, MD5/SHA-1

## Running tests

```bash
python -m pytest tests/ -v
```

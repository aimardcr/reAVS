# reAVS

reAVS is a remake of AVS: https://github.com/aimardcr/AVS/

AVS is a defensive, best-effort static analyzer for Android APKs. It extracts the app attack surface from the manifest and looks for high-risk vulnerability patterns using lightweight taint heuristics. No dynamic execution, instrumentation, or network calls are performed.

## Scope and limitations
- Static analysis only; results are best-effort and heuristic-driven.
- Obfuscated APKs may reduce precision; reAVS is designed to degrade gracefully without crashing.
- Findings should be triaged and verified by a human reviewer.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python3 avs.py app.apk --out report.json --deep
```

Options:
- `--out` JSON report path (optional)
- `--fast` (default) or `--deep`
- `--depth <n>` helper propagation depth (deep mode, default: 3; ignored in fast mode)
- `--component <ComponentName>` focus a specific component
- `--verbose`
- Findings are printed to the console in a simple table by default.

## Add a scanner
1. Create a scanner in `scanners/` that subclasses `BaseScanner`.
2. Add it to the scanner list in `avs.py`.
3. Emit `Finding` objects with evidence and recommendations.

## Add sources/sinks/sanitizers/policy
Update `rules/sources.yml`, `rules/sinks.yml`, `rules/sanitizers.yml`, and `rules/policy.yml` using the defined schema. AVS will load these at startup.

## Developer Notes
- `core/bc_extract.py` exposes method-scoped extraction (invokes, const strings, new instances, field refs, moves) and links move-result to invocations when possible.
- `core/dataflow/taint_linear.py` performs minimal intra-procedural taint tracking over registers (fast mode).
- `core/dataflow/taint_cfg.py` builds CFG/ICFG taint summaries for interprocedural propagation (deep mode).
- `core/dataflow/taint_provider.py` selects the taint engine by scan mode.
- Fast mode (`--fast`) uses linear taint and does not perform helper propagation.
- Deep mode (`--deep --depth N`) uses CFG/ICFG taint and performs bounded helper propagation within the same class to attribute sinks in helper methods to tainted inputs.

## Examples of findings (patterns)
- Intent redirection: `getParcelableExtra("forward_intent") -> startActivity(forward)`
- Privilege escalation via `setResult`: extras control `setAction`/`setData`/`setClassName` before `setResult(RESULT_OK, result)`
- Arbitrary file write: `getStringExtra("path") -> new File(getFilesDir(), path) -> FileOutputStream`
- WebView tainted URL: `getStringExtra("url") -> WebView.loadUrl(url)` (higher severity if JS enabled)
- ContentProvider SQL injection: `query(...) -> rawQuery(sql, null)` with selection concatenation
- ContentProvider file access: `openFile(Uri, ...)` with `uri.getPath()` and weak traversal checks
- Dynamic code loading: `DexClassLoader(dexPath, ...)` from untrusted path
- Runtime exec: `Runtime.exec(...)` or `ProcessBuilder`
- Reflection: tainted strings to `Class.forName`/`getMethod`/`invoke`
- Crypto issues: hardcoded base64 keys, AES/ECB modes, fixed IV in CBC, MD5/SHA-1

reAVS is intended for defensive security review and secure coding guidance.

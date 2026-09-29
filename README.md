# 🐕 PromptHound

**A static analyzer that sniffs out AI/LLM security flaws in source code.**

PromptHound is a lightweight, dependency-free SAST tool for applications built
on large language models. Point it at a codebase and it flags the security
mistakes that are specific to LLM apps — the ones generic linters miss.

It's built for AppSec engineers, pentesters doing authorized code review, and
developers who want an LLM-aware check in CI. It analyzes **your own** code; it
does not attack anything.

---

## What it detects

| ID | Rule | What it catches |
| --- | --- | --- |
| `PH101` | hardcoded-ai-credential | OpenAI / Anthropic / HuggingFace / Google / AWS / Cohere / Replicate keys committed to source |
| `PH201` | prompt-injection-surface | Untrusted input interpolated into prompts (f-strings, concatenation, `.format`) or LLM call arguments |
| `PH301` | unsafe-llm-output-execution | Model output flowing into `eval` / `exec` / `os.system` / `subprocess` |
| `PH401` | prompt-completion-logging | Prompts, completions, message histories, or keys written to logs |
| `PH501` | insecure-deserialization | `pickle.loads`, `yaml.load`, `torch.load`, `joblib.load` — worse when fed model/tool output |
| `PH601` | model-output-to-sensitive-sink | Model output reaching HTTP requests (SSRF) or filesystem calls (path traversal) |

Findings map to CWE identifiers and the OWASP Top 10 for LLM Applications.

## Install

```bash
git clone https://github.com/your-org/prompthound
cd prompthound
pip install -e .
```

Python 3.9+ · standard library only, no third-party runtime dependencies.

## Usage

```bash
# Scan the current directory
prompthound .

# Scan one file
prompthound path/to/app.py

# Only show high-and-above, output as Markdown
prompthound src/ --min-severity high -f markdown -o report.md

# Emit SARIF for GitHub code scanning
prompthound src/ -f sarif -o results.sarif

# List the built-in rules
prompthound --list-rules
```

Output formats: `terminal` (default, colorized), `json`, `sarif`, `markdown`.

### Exit codes (for CI)

- `0` — no findings at or above `--fail-on` (default: `high`)
- `1` — findings at or above the threshold
- `2` — bad invocation (e.g. path not found)

Use `--no-fail` to always exit `0`, or `--fail-on critical` to gate only on the
most severe issues.

## Try it

The repo ships a deliberately vulnerable sample:

```bash
prompthound examples/vulnerable_app.py
```

You'll see all six rules fire. `examples/safe_app.py` is the fixed version and
produces no findings.

## GitHub Actions

```yaml
- run: pip install prompthound
- run: prompthound src/ -f sarif -o results.sarif --no-fail
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings then appear in the repo's **Security → Code scanning** tab. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a working example.

## How it works

For Python files, PromptHound parses the AST and reasons about call targets and
data flow with lightweight heuristics (e.g. "does a variable whose name looks
like a model response reach an `eval()`?"). Secret detection also runs on config
and text files via targeted patterns.

These are **heuristics**, tuned to keep false positives low. Treat findings as
leads for human review, not proof of a vulnerability — and absence of findings
is not proof of safety.

## Extending it

Add a rule by subclassing `Rule` in `prompthound/rules/`, implementing `scan`,
and registering it in `prompthound/rules/__init__.py`:

```python
from .base import Rule, ScanContext
from ..finding import Severity

class MyRule(Rule):
    id = "PH701"
    name = "my-rule"
    severity = Severity.MEDIUM
    description = "One-line remediation guidance."

    def scan(self, ctx: ScanContext) -> list:
        findings = []
        # inspect ctx.tree (AST) or ctx.lines (raw text)
        return findings
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## Scope & ethics

PromptHound performs **static analysis of source code you own or are authorized
to review**. It sends nothing anywhere and executes none of the code it scans.
Only run it against code you have permission to analyze.

## License

MIT — see [LICENSE](LICENSE).

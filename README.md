# audit-qgis-plugin

[![CI](https://github.com/your-username/audit-qgis-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/audit-qgis-plugin/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![QGIS](https://img.shields.io/badge/QGIS-3.x%20%7C%204.x-589632.svg)](https://qgis.org/)

> **Preflight compliance audit tool and Agent Skill for QGIS Python plugins before official repository publication.**

`audit-qgis-plugin` inspects QGIS plugin source directories and release ZIP archives against the official [QGIS Plugin Repository](https://plugins.qgis.org/) guidelines, security policies, and packaging requirements.

It operates both as a **standalone Python CLI tool** (standard library only, zero mandatory external dependencies) and as an **AI Agent Skill** (compatible with Antigravity, OpenAI Codex, Claude Code, Cursor, and other agentic IDEs).

---

## Features

- 📦 **Package & Archive Inspection**:
  - Validates ZIP structure: single root directory matching plugin naming rules.
  - Detects path-traversal entries, drive-qualified paths, case collisions, and symlinks.
  - Flags prohibited binaries (`.exe`, `.dll`, `.so`, `.dylib`, `.pyd`) and uncleaned VCS/dev artifacts (`.git`, `__pycache__`, `.venv`, `.DS_Store`).

- 📄 **`metadata.txt` Compliance**:
  - Enforces mandatory fields (`name`, `qgisMinimumVersion`, `description`, `about`, `version`, `author`, `email`, `repository`).
  - Checks for illegal HTML tags in `description`, `about`, and `changelog`.
  - Validates dotted version numbering and official category assignments (`Raster`, `Vector`, `Database`, `Mesh`, `Web`).
  - Validates public URL reachability requirements (homepage, issue tracker, repository).

- 🔒 **Static Security & AST Heuristics**:
  - Detects dangerous execution: `exec()`, `eval()`, `os.system()`, `subprocess(shell=True)`.
  - Identifies unsafe deserialization: `pickle.load()`, `marshal.load()`, unverified `yaml.load()`.
  - Flags insecure networking: disabled TLS verification (`verify=False`, unverified SSL contexts), missing request timeouts.
  - Scans for hardcoded credentials, API keys, private keys, and tokens (with automatic redaction in reports).

- 🛠️ **External Scanner Orchestration**:
  - Seamlessly orchestrates **Bandit**, **detect-secrets**, and **Flake8** if installed.
  - Configurable modes: `auto` (run if available), `required` (gatekeeper mode), or `never` (pure stdlib).

- 📊 **Clear Verdicts & Actionable Reports**:
  - Formats output as GitHub-flavored Markdown (`--report`) and machine-readable JSON (`--json`).
  - Provides exact line numbers, rule IDs, and remediation guidance.

---

## Verdicts & Exit Codes

| Verdict | Exit Code | Meaning |
|---|:---:|---|
| **`READY WITH CAVEATS`** | `0` | All local checks passed. (Note: official server scan and manual approval remain authoritative). |
| **`CHANGES REQUIRED`** | `1` | No hard blockers, but warnings, packaging, or compatibility caveats require attention. |
| **`BLOCKED`** | `2` | Critical structural failure, active security violation, leaked secret, or missing mandatory metadata. |

---

## Quick Start

### 1. Standalone CLI Usage

Requires Python 3.9+ (no `pip install` required for basic checks):

```bash
# Run a preflight audit on a plugin directory
python scripts/audit_qgis_plugin.py /path/to/my_plugin

# Audit a release ZIP package and generate Markdown & JSON reports
python scripts/audit_qgis_plugin.py /path/to/my_plugin.zip --report audit_report.md --json audit_report.json

# Enforce external scanners as a release gate (fails if Bandit/detect-secrets/Flake8 are missing)
python scripts/audit_qgis_plugin.py /path/to/my_plugin.zip --external required
```

#### CLI Options

```text
usage: audit_qgis_plugin.py [-h] [--report REPORT] [--json JSON_PATH]
                            [--external {auto,required,never}]
                            target

positional arguments:
  target                QGIS plugin root directory, repository, or release ZIP

options:
  -h, --help            Show this help message and exit
  --report REPORT       Path to write the Markdown report
  --json JSON_PATH      Path to write the JSON report
  --external {auto,required,never}
                        External scanners policy (default: auto)
```

---

### 2. Using as an AI Agent Skill

This repository adheres to the standard Agent Skill layout (`SKILL.md`, `agents/`, `references/`, `scripts/`).

#### In Antigravity / Agentic IDEs:
Copy or symlink this folder into your customizations or skills root:
- Global: `~/.gemini/config/skills/audit-qgis-plugin`
- Workspace: `.agents/skills/audit-qgis-plugin`

#### Usage Prompt:
> *"Audit this QGIS plugin repository for official QGIS repository publication compliance."*

The agent will:
1. Consult [references/official-requirements.md](references/official-requirements.md).
2. Execute `scripts/audit_qgis_plugin.py`.
3. Provide an evidence-based report with verdict, findings, and remediation steps.

---

## Project Structure

```text
audit-qgis-plugin/
├── .github/
│   └── workflows/
│       └── ci.yml               # Multi-OS & multi-Python CI workflow
├── agents/
│   └── openai.yaml              # Agent UI interface definition
├── references/
│   └── official-requirements.md # Official QGIS repository rules snapshot
├── scripts/
│   ├── __init__.py
│   └── audit_qgis_plugin.py     # Main audit engine & CLI tool
├── tests/
│   ├── __init__.py
│   └── test_audit_qgis_plugin.py # Unit tests
├── .gitignore                   # Comprehensive ignore rules
├── CONTRIBUTING.md              # Contribution guidelines
├── LICENSE                      # MIT License
├── pyproject.toml               # Python project configuration
├── README.md                    # Project documentation
├── SECURITY.md                  # Security policy
└── SKILL.md                     # Agent skill instructions
```

---

## Development & Testing

Run unit tests locally with Python's built-in `unittest`:

```bash
python -m unittest discover -v
```

Or with `pytest`:

```bash
pip install -e ".[dev]"
pytest
```

---

## Official References

- [QGIS Plugin Security Scanning Rules](https://plugins.qgis.org/docs/security-scanning/rules)
- [QGIS Plugin Approval Process](https://plugins.qgis.org/docs/approval)
- [PyQGIS Developer Cookbook - Releasing a Plugin](https://docs.qgis.org/latest/en/docs/pyqgis_developer_cookbook/plugins/releasing.html)
- [QGIS 4 Migration Guide](https://plugins.qgis.org/docs/migrate-qgis4)

---

## License

Distributed under the [MIT License](LICENSE).

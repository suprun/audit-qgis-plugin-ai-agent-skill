---
name: audit-qgis-plugin
description: Audit QGIS Python plugin source directories and ZIP packages for publication in the official QGIS Plugin Repository. Use when Codex needs to review plugin structure, metadata.txt, packaging, Python security, leaked secrets, Flake8 quality, suspicious files, repository approval requirements, QGIS 3/4 compatibility claims, or release readiness; produce an evidence-based compliance report or fix confirmed findings when explicitly requested.
---

# Audit a QGIS plugin

Assess a plugin against the current official repository requirements without implying that a local review guarantees acceptance.

## Establish the rule basis

1. Read [references/official-requirements.md](references/official-requirements.md) before every audit.
2. Browse the live QGIS [Security Rules Reference](https://plugins.qgis.org/docs/security-scanning/rules) because administrators can change rule status and skip permissions at any time.
3. Also verify the official [security overview](https://plugins.qgis.org/docs/security-scanning), [approval process](https://plugins.qgis.org/docs/approval), and [plugin release documentation](https://docs.qgis.org/latest/en/docs/pyqgis_developer_cookbook/plugins/releasing.html) when the audit is for an actual release.
4. Record the retrieval date and any difference from the bundled reference. If network access is unavailable, use the bundled reference, label it a dated snapshot, and report this as a coverage limitation.

Treat the live QGIS site as authoritative. Treat local tool output as preflight evidence, not a server-side certification.

## Preserve scope

- Accept a plugin source directory, a plugin ZIP, or a repository containing one plugin.
- Determine the intended QGIS range and whether the request concerns a new plugin or an update. Infer these from `metadata.txt` and repository history when possible.
- Inspect only for an audit request. Modify code only when the user explicitly asks to fix or prepare the plugin.
- Preserve unrelated working-tree changes. Never overwrite an existing release archive.
- Do not upload the plugin or contact repository maintainers unless the user explicitly requests it.

## Run the deterministic preflight

Resolve the directory containing this `SKILL.md`, then run:

```text
python <skill-dir>/scripts/audit_qgis_plugin.py <plugin-dir-or-zip> --report <report.md> --json <report.json> --external auto
```

The script checks package shape, mandatory files, metadata syntax and values, `classFactory`, Python syntax, suspicious files, executable permissions, common secret patterns, and selected high-confidence unsafe-code patterns. With `--external auto`, it also runs Bandit, detect-secrets, and Flake8 when their commands are available.

Use `--external required` for a release gate. A missing external scanner then becomes a critical coverage finding. Use `--external never` only when tool execution is prohibited, and state the resulting limitations.

The script exits with `2` for critical findings, `1` for warnings only, and `0` when no critical or warning findings remain. Always read the report; do not rely on the exit code alone.

## Complete the audit

After the preflight, inspect what static tooling cannot prove:

1. Confirm `metadata.txt` links are reachable and appropriate: homepage or public documentation, public source repository, and issue tracker.
2. Confirm the ZIP contains one top-level plugin directory and excludes build, VCS, test-cache, credential, installer, and platform-binary artifacts.
3. Compare every reported Bandit, detect-secrets, Flake8, and file-analysis rule against its current live severity, enabled state, and skip policy.
4. Review configuration files (`.bandit`, `.secrets.baseline`, `.flake8`) as intentional suppressions. Verify each suppressed finding; never assume a baseline makes a secret safe.
5. Inspect dependencies, network calls, subprocess use, deserialization, SQL construction, file extraction, credential storage, and TLS verification even when automated tools are clean.
6. Run existing tests. If an appropriate QGIS runtime is available, test install, enable, `classFactory`, `initGui`, main actions, and `unload` on every claimed major QGIS/Qt line. Otherwise mark runtime, cross-platform, or QGIS 4 compatibility as unverified.
7. For QGIS 4 claims, verify actual Qt 6/PyQGIS 4 compatibility; `qgisMaximumVersion=4.99` is metadata, not proof. Treat `supportsQt6=True` as obsolete.
8. For an update, require a new version value and a useful changelog, and confirm all links still work.

Do not silently install dependencies. Ask before changing the environment if exact scanner commands are unavailable.

## Decide the verdict

Use exactly one verdict:

- `BLOCKED` — a structural requirement, active critical security rule, secret, invalid mandatory metadata, prohibited binary, or required coverage gate failed.
- `CHANGES REQUIRED` — no confirmed blocker, but approval, warning-level, packaging, compatibility, or material coverage issues remain.
- `READY WITH CAVEATS` — all available checks pass, but server scan, manual approval, runtime/platform testing, or live-rule verification remains outside the audit.

Never use an unconditional `READY` verdict. The official server scan and repository review remain authoritative.

## Report findings

Lead with the verdict and counts. Include:

1. Scope: target, plugin root, version, intended QGIS range, new/update status, audit date.
2. Coverage matrix: structure, metadata, Bandit, detect-secrets, Flake8, file analysis, link reachability, QGIS runtime, QGIS/Qt versions, Windows and Unix.
3. Findings sorted `CRITICAL`, `WARNING`, `INFO`. For each finding provide rule ID, evidence (`path:line` when available), impact, official requirement, and a concrete remediation.
4. Suppressions and accepted risks, with justification and configuration location.
5. Release checklist and exact next commands.
6. Official source links with retrieval dates.

Distinguish confirmed findings from heuristics and unverified coverage. Avoid reproducing secrets in the report; redact values and show only the detector, file, and line.

## Fix and re-audit

When fixes are requested:

1. Correct confirmed blockers first, then warnings.
2. Prefer removing the insecure construct over suppressing a rule.
3. Add a scanner suppression only for a reviewed false positive, keep it narrow, and document why it is safe.
4. Re-run the deterministic preflight and relevant project tests.
5. Report remaining findings and coverage gaps; do not downgrade them merely because code changed.

# Official QGIS plugin repository requirements

Snapshot checked: 2026-08-16. Re-check every linked page before a release because the repository rules page is generated from live server configuration.

## Source priority

1. [Live Security Rules Reference](https://plugins.qgis.org/docs/security-scanning/rules) — current rule severity, enabled status, and skip policy.
2. [Security Scanning Overview](https://plugins.qgis.org/docs/security-scanning) and [Security Tools](https://plugins.qgis.org/docs/security-scanning/tools) — validation states, blocking semantics, and tool coverage.
3. [Plugin Approval Process](https://plugins.qgis.org/docs/approval) — human-review expectations.
4. [PyQGIS plugin structure and metadata](https://docs.qgis.org/latest/en/docs/pyqgis_developer_cookbook/plugins/plugins.html) and [release guidance](https://docs.qgis.org/latest/en/docs/pyqgis_developer_cookbook/plugins/releasing.html) — package and metadata requirements.
5. [QGIS 4 migration guidance](https://plugins.qgis.org/docs/migrate-qgis4) — repository compatibility declarations.

When these sources disagree, report the discrepancy. Prefer current live server behavior for upload outcomes and the current QGIS documentation for plugin structure and APIs.

## Package and plugin structure

- Ship a ZIP containing one top-level plugin directory so extraction does not mix plugin files with other plugins.
- Name that directory with ASCII letters, digits, `_`, or `-`, and do not start it with a digit.
- Include `metadata.txt`, `__init__.py`, and a plain-text `LICENSE` with no filename extension at the plugin root.
- Define `classFactory(iface)` in `__init__.py`; it must return the plugin instance QGIS loads.
- Include basic documentation and an icon as strong publication-readiness expectations.
- Reject path-traversal archive entries, absolute paths, drive-qualified paths, duplicate/case-colliding entries, and unexpected extra top-level files.
- The approval guidance says plugins using binaries are not approved unless the author first obtains an exception through the QGIS community/governance process. Treat packaged binaries as approval blockers even if file analysis gives an individual binary only warning severity.

## `metadata.txt`

Parse the file as UTF-8 INI with a `[general]` section.

Required by the current metadata table:

- `name`
- `qgisMinimumVersion`
- `description`
- `about`
- `version`
- `author`
- `email`
- `repository`

Important validations:

- Keep `description` to one plain-text line; use `about` for details. HTML is not allowed in `description`, `about`, or `changelog`.
- Use dotted QGIS and plugin version notation. A version uploaded for a plugin must be new/unique.
- Use a publicly accessible source repository URL, not a ZIP-only code link.
- For approval, also provide a working homepage/documentation link and issue tracker even though the core metadata table lists them as optional.
- If present, make `experimental`, `deprecated`, `server`, and `hasProcessingProvider` boolean values (`True` or `False`).
- If present, make `category` one of `Raster`, `Vector`, `Database`, `Mesh`, or `Web` according to the current metadata table.
- If present, ensure the relative `icon` path exists and points to a web-friendly PNG or JPEG.
- If `qgisMaximumVersion` is omitted, the repository derives the end of the major series from the minimum version. Do not assume this proves compatibility.
- For an existing plugin update, increment/change `version`, add a useful `changelog`, and re-check all URLs.

## Approval expectations beyond static validation

- New plugins need a useful public homepage or README, public source repository, and linked issue tracker.
- The plugin should install, enable, and run without crashing QGIS.
- The plugin should work on Windows and Unix-like systems.
- Similar existing plugins should be considered; describe meaningful differences in `about` when overlap exists.
- Put actions in the appropriate QGIS menu/category and provide usable documentation.
- Random manual tests may be performed. A clean automated scan does not guarantee approval.

## Automated security validation

The repository runs four complementary checks after structural validation:

- Bandit for Python security issues.
- detect-secrets for credentials, tokens, private keys, and high-entropy secret-like values.
- Flake8 for syntax, undefined names, complexity, and style/quality findings.
- Built-in file analysis for suspicious, binary, executable, and hidden files.

At snapshot time the live page reported 205 configured rules, 129 active rules, 61 skippable rules, and 76 disabled rules. These counts are informational and must be refreshed.

The overview describes Bandit and detect-secrets critical findings as blocking, while Flake8 and file analysis are described as non-blocking. The live rules table can still label individual Flake8 and file-analysis rules `Critical`. Preserve both facts in a report: distinguish the rule's severity label from the scanner tier's documented blocking behavior. Independently treat syntax errors, undefined runtime names, and prohibited binaries as release blockers because the plugin cannot safely pass functional/manual review.

High-priority active families include:

- Code execution and injection: `exec`, `eval`, unsafe deserialization, shell use, raw SQL construction, unsafe template rendering.
- Transport and cryptography: disabled TLS verification, obsolete protocols/ciphers, weak keys, insecure FTP/Telnet, disabled SSH host-key checks.
- File and archive handling: insecure temporary files, unsafe archive extraction, wildcard injection, suspicious executable extensions.
- Secrets: cloud keys, API tokens, OAuth/JWT values, private keys, Basic Auth in URLs, credential-like high-entropy strings.
- Python correctness: syntax/indentation failures and names or local variables that will fail at runtime.

Never duplicate an exposed secret in output. Redact the value and report only detector, file, line, and remediation.

## Scanner configuration and false positives

The repository recognizes these files at the plugin root:

- `.bandit`
- `.secrets.baseline`
- `.flake8`

Their presence produces a `Validated (configured)` state when critical checks pass. Configuration does not waive critical requirements. Review every exclusion or baseline entry, keep it narrow, and prefer fixing code. The live rules page determines which whole rules can be skipped during upload.

If a mandatory finding is a genuine false positive that cannot be handled safely by supported configuration or an allowed skip, use the QGIS security-check issue process. Do not claim a local suppression will unblock the server.

## QGIS 4 claims

- QGIS 4 uses Qt 6 and may require code changes.
- Set `qgisMaximumVersion=4.99` (or a compatible range reaching QGIS 4) only after actual Qt 6/PyQGIS 4 testing.
- Remove or ignore `supportsQt6=True`; the repository documentation says this temporary flag is obsolete and no longer recognized.
- Distinguish metadata visibility in the “QGIS 4 Ready” list from demonstrated runtime compatibility.

## Minimum evidence for a strong preflight

Record all of the following as passed, failed, or unverified:

- ZIP/root structure and mandatory files
- Metadata syntax, required values, and local file references
- Link reachability and destination appropriateness
- Bandit with tool/version/config recorded
- detect-secrets with tool/version/baseline recorded
- Flake8 with tool/version/config recorded
- File types, permissions, hidden files, and binary review
- Existing unit/integration tests
- Install/enable/action/unload smoke test in QGIS
- Claimed QGIS and Qt versions
- Windows and Unix-like platform behavior
- Live rule retrieval date and server-side scan status, if uploaded

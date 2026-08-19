# Contributing to audit-qgis-plugin

Thank you for your interest in improving `audit-qgis-plugin`!

## How to Contribute

1. **Report Bugs / Inconsistencies**:
   - If the official QGIS plugin repository updates its security rules or metadata requirements, open an issue with links to the updated official documentation.
2. **Submit Pull Requests**:
   - Fork the repository and create a feature branch (`git checkout -b feature/my-rule`).
   - Add tests in `tests/test_audit_qgis_plugin.py` covering your changes.
   - Run the test suite: `python -m unittest discover -v`.
   - Ensure all tests pass before submitting your PR.

## Code Standards

- **Standard Library First**: The core `scripts/audit_qgis_plugin.py` should remain executable with standard Python libraries alone.
- **Accuracy**: Keep rule IDs aligned with official QGIS and Bandit/Flake8 codes.
- **Security**: Never print raw secret values in output or logs; redact all sensitive tokens.

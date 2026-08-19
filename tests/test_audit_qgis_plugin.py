"""Tests for audit_qgis_plugin.py."""

import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.audit_qgis_plugin import Audit, main


class TestAuditQgisPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_minimal_plugin(self, plugin_dir: Path) -> None:
        plugin_dir.mkdir(parents=True, exist_ok=True)
        (plugin_dir / "LICENSE").write_text("MIT License\n", encoding="utf-8")
        (plugin_dir / "__init__.py").write_text(
            "def classFactory(iface):\n"
            "    from .main import MyPlugin\n"
            "    return MyPlugin(iface)\n",
            encoding="utf-8",
        )
        (plugin_dir / "main.py").write_text(
            "class MyPlugin:\n"
            "    def __init__(self, iface):\n"
            "        self.iface = iface\n"
            "    def initGui(self):\n"
            "        pass\n"
            "    def unload(self):\n"
            "        pass\n",
            encoding="utf-8",
        )
        metadata_content = (
            "[general]\n"
            "name=Sample Plugin\n"
            "qgisMinimumVersion=3.28\n"
            "qgisMaximumVersion=3.99\n"
            "description=A clean sample plugin for audit tests\n"
            "about=Detailed description of the sample plugin without HTML\n"
            "version=1.0.0\n"
            "author=Plugin Author\n"
            "email=author@example.com\n"
            "repository=https://github.com/example/sample-plugin\n"
            "homepage=https://example.com/sample-plugin\n"
            "tracker=https://github.com/example/sample-plugin/issues\n"
            "category=Vector\n"
            "icon=icon.png\n"
            "experimental=False\n"
            "deprecated=False\n"
        )
        (plugin_dir / "metadata.txt").write_text(metadata_content, encoding="utf-8")
        # Create a minimal 1x1 png file
        (plugin_dir / "icon.png").write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
            b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )

    def test_target_missing(self) -> None:
        missing_path = self.base_path / "non_existent_dir"
        audit = Audit(missing_path, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("TARGET_MISSING", rules)
        self.assertEqual(audit.verdict(), "BLOCKED")

    def test_target_invalid_type(self) -> None:
        file_path = self.base_path / "invalid.txt"
        file_path.write_text("not a zip", encoding="utf-8")
        audit = Audit(file_path, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("TARGET_TYPE", rules)
        self.assertEqual(audit.verdict(), "BLOCKED")

    def test_valid_minimal_plugin(self) -> None:
        plugin_dir = self.base_path / "sample_plugin"
        self._create_minimal_plugin(plugin_dir)
        audit = Audit(plugin_dir, external="never")
        audit.run()
        critical_findings = [f for f in audit.findings if f.severity == "CRITICAL"]
        self.assertEqual(len(critical_findings), 0, f"Unexpected criticals: {critical_findings}")
        self.assertIn(audit.verdict(), {"READY WITH CAVEATS", "CHANGES REQUIRED"})

    def test_missing_required_files(self) -> None:
        plugin_dir = self.base_path / "incomplete_plugin"
        self._create_minimal_plugin(plugin_dir)
        (plugin_dir / "LICENSE").unlink()
        (plugin_dir / "__init__.py").unlink()

        audit = Audit(plugin_dir, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("REQUIRED_FILE", rules)
        self.assertEqual(audit.verdict(), "BLOCKED")

    def test_missing_metadata_keys(self) -> None:
        plugin_dir = self.base_path / "bad_metadata_plugin"
        self._create_minimal_plugin(plugin_dir)
        bad_metadata = (
            "[general]\n"
            "name=Sample Plugin\n"
            "version=1.0.0\n"
        )
        (plugin_dir / "metadata.txt").write_text(bad_metadata, encoding="utf-8")

        audit = Audit(plugin_dir, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("METADATA_REQUIRED", rules)
        self.assertEqual(audit.verdict(), "BLOCKED")

    def test_html_in_metadata(self) -> None:
        plugin_dir = self.base_path / "html_meta_plugin"
        self._create_minimal_plugin(plugin_dir)
        content = (plugin_dir / "metadata.txt").read_text(encoding="utf-8")
        content = content.replace(
            "description=A clean sample plugin for audit tests",
            "description=A <b>clean</b> sample plugin",
        )
        (plugin_dir / "metadata.txt").write_text(content, encoding="utf-8")

        audit = Audit(plugin_dir, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("METADATA_HTML", rules)

    def test_ast_security_eval(self) -> None:
        plugin_dir = self.base_path / "unsafe_eval_plugin"
        self._create_minimal_plugin(plugin_dir)
        (plugin_dir / "main.py").write_text(
            "class MyPlugin:\n"
            "    def calc(self, expr):\n"
            "        return eval(expr)\n",
            encoding="utf-8",
        )

        audit = Audit(plugin_dir, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("B307", rules)
        self.assertEqual(audit.verdict(), "BLOCKED")

    def test_ast_security_hardcoded_secret(self) -> None:
        plugin_dir = self.base_path / "secret_plugin"
        self._create_minimal_plugin(plugin_dir)
        (plugin_dir / "main.py").write_text(
            "class MyPlugin:\n"
            "    def connect(self):\n"
            "        api_key = 'super_secret_key_12345'\n",
            encoding="utf-8",
        )

        audit = Audit(plugin_dir, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("B105", rules)

    def test_zip_packaging_valid(self) -> None:
        plugin_dir = self.base_path / "sample_plugin"
        self._create_minimal_plugin(plugin_dir)
        zip_path = self.base_path / "sample_plugin.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            for file_path in plugin_dir.rglob("*"):
                if file_path.is_file():
                    arcname = f"sample_plugin/{file_path.relative_to(plugin_dir).as_posix()}"
                    zf.write(file_path, arcname)

        audit = Audit(zip_path, external="never")
        audit.run()
        critical_findings = [f for f in audit.findings if f.severity == "CRITICAL"]
        self.assertEqual(len(critical_findings), 0, f"Unexpected criticals: {critical_findings}")

    def test_zip_packaging_multiple_roots(self) -> None:
        zip_path = self.base_path / "multi_root.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("plugin_a/metadata.txt", "[general]\nname=A\n")
            zf.writestr("plugin_b/metadata.txt", "[general]\nname=B\n")

        audit = Audit(zip_path, external="never")
        audit.run()
        rules = [f.rule for f in audit.findings]
        self.assertIn("ZIP_TOP_LEVEL", rules)
        self.assertEqual(audit.verdict(), "BLOCKED")

    def test_cli_execution_with_json_and_markdown(self) -> None:
        plugin_dir = self.base_path / "sample_plugin"
        self._create_minimal_plugin(plugin_dir)
        report_md = self.base_path / "report.md"
        report_json = self.base_path / "report.json"

        ret = main([
            str(plugin_dir),
            "--report", str(report_md),
            "--json", str(report_json),
            "--external", "never",
        ])
        self.assertIn(ret, (0, 1))
        self.assertTrue(report_md.exists())
        self.assertTrue(report_json.exists())

        data = json.loads(report_json.read_text(encoding="utf-8"))
        self.assertIn("verdict", data)
        self.assertIn("counts", data)
        self.assertIn("findings", data)
        self.assertIn("coverage", data)


if __name__ == "__main__":
    unittest.main()

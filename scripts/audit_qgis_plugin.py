#!/usr/bin/env python3
"""Local preflight audit for official QGIS plugin repository publication.

This script intentionally distinguishes deterministic local checks from the live
server scan. It uses only the standard library, while optionally orchestrating
Bandit, detect-secrets, and Flake8 when their commands are installed.
"""

from __future__ import annotations

import argparse
import ast
import configparser
import dataclasses
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable
from urllib.parse import urlparse
import zipfile


SEVERITY_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
REQUIRED_FILES = ("metadata.txt", "__init__.py", "LICENSE")
REQUIRED_METADATA = (
    "name",
    "qgisMinimumVersion",
    "description",
    "about",
    "version",
    "author",
    "email",
    "repository",
)
BOOLEAN_METADATA = ("experimental", "deprecated", "server", "hasProcessingProvider")
ALLOWED_CATEGORIES = {"Raster", "Vector", "Database", "Mesh", "Web"}
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".pyd", ".com", ".scr", ".msi",
    ".bat", ".cmd", ".sh", ".ps1", ".jar", ".class", ".o", ".a",
}
EXPECTED_BINARY_ASSETS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".qm", ".pdf",
    ".gpkg", ".sqlite", ".db", ".tif", ".tiff", ".woff", ".woff2", ".ttf",
}
DEV_ARTIFACT_PARTS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "node_modules", ".tox", ".venv", "venv",
}
DEV_ARTIFACT_NAMES = {".DS_Store", "Thumbs.db", ".gitignore", ".gitattributes"}
SUPPORTED_CONFIGS = {".bandit", ".secrets.baseline", ".flake8"}
HTML_RE = re.compile(r"<\s*/?\s*[A-Za-z][^>]*>")
VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)+(?:[-+._]?[0-9A-Za-z]+)*$")
QGIS_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,2}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
BIDI_RE = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")

CRITICAL_BANDIT = {
    "B102", "B103", "B105", "B106", "B107", "B111", "B201", "B202",
    "B301", "B302", "B304", "B305", "B306", "B307", "B312", "B321",
    "B323", "B401", "B402", "B412", "B413", "B501", "B502", "B503",
    "B505", "B506", "B507", "B601", "B602", "B604", "B605", "B609",
    "B610", "B611", "B612", "B613", "B615", "B701",
}
INFO_BANDIT = {"B109", "B404", "B410", "B411"}
CRITICAL_FLAKE8 = {"E901", "E902", "E999", "F821", "F823", "F831"}
WARNING_FLAKE8 = {
    "C901", "E101", "E711", "E712", "E713", "E714", "E721", "E722",
    "E731", "E741", "E742", "E743", "F402", "F403", "F404", "F405",
    "F811", "F822", "F901", "W605",
}
WARNING_SECRET_TYPES = {
    "Base64 High Entropy String", "Hex High Entropy String", "Secret Keyword",
}
INFO_SECRET_TYPES = {"IP Public Detector", "Public IP Address"}

SECRET_PATTERNS = (
    ("PrivateKeyDetector", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("AWSKeyDetector", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHubTokenDetector", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAIDetector", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("SlackDetector", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("StripeDetector", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b")),
    ("BasicAuthDetector", re.compile(r"https?://[^\s/:@]+:[^\s/@]+@", re.I)),
)


@dataclasses.dataclass
class Finding:
    severity: str
    rule: str
    category: str
    message: str
    path: str = ""
    line: int | None = None
    remediation: str = ""
    source: str = "local-preflight"

    def sort_key(self) -> tuple[Any, ...]:
        return (
            SEVERITY_ORDER.get(self.severity, 99),
            self.rule,
            self.path.lower(),
            self.line or 0,
            self.message,
        )


@dataclasses.dataclass
class Coverage:
    check: str
    status: str
    details: str


class Audit:
    def __init__(self, target: Path, external: str) -> None:
        self.target = target
        self.external = external
        self.audit_time = dt.datetime.now(dt.timezone.utc).isoformat()
        self.findings: list[Finding] = []
        self.coverage: list[Coverage] = []
        self.plugin_root: Path | None = None
        self.archive_modes: dict[str, int] = {}
        self.metadata: dict[str, str] = {}
        self._seen: set[tuple[Any, ...]] = set()

    def add(
        self,
        severity: str,
        rule: str,
        category: str,
        message: str,
        path: str = "",
        line: int | None = None,
        remediation: str = "",
        source: str = "local-preflight",
    ) -> None:
        key = (severity, rule, path, line, message)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            Finding(severity, rule, category, message, path, line, remediation, source)
        )

    def add_coverage(self, check: str, status: str, details: str) -> None:
        self.coverage.append(Coverage(check, status, details))

    def rel(self, path: Path) -> str:
        if self.plugin_root:
            try:
                return path.relative_to(self.plugin_root).as_posix()
            except ValueError:
                pass
        return path.name

    def run(self) -> None:
        if not self.target.exists():
            self.add(
                "CRITICAL", "TARGET_MISSING", "scope", f"Target does not exist: {self.target}",
                remediation="Provide an existing QGIS plugin directory or ZIP package.",
            )
            self.add_coverage("Target", "failed", "Path does not exist")
            return

        if self.target.is_file() and self.target.suffix.lower() == ".zip":
            with tempfile.TemporaryDirectory(prefix="qgis-plugin-audit-") as temp:
                extracted = Path(temp)
                self._prepare_zip(extracted)
                if self.plugin_root:
                    self._audit_root()
        elif self.target.is_dir():
            self._locate_directory_root(self.target)
            if self.plugin_root:
                self._audit_root()
        else:
            self.add(
                "CRITICAL", "TARGET_TYPE", "scope",
                "Target must be a directory or a .zip archive.",
                remediation="Pass the plugin source directory or its release ZIP.",
            )
            self.add_coverage("Target", "failed", "Unsupported target type")

    def _prepare_zip(self, extracted: Path) -> None:
        try:
            archive = zipfile.ZipFile(self.target)
        except (OSError, zipfile.BadZipFile) as exc:
            self.add("CRITICAL", "ZIP_INVALID", "package", f"Cannot read ZIP: {exc}")
            self.add_coverage("Package structure", "failed", "Invalid ZIP")
            return

        with archive:
            infos = archive.infolist()
            if not infos:
                self.add("CRITICAL", "ZIP_EMPTY", "package", "The ZIP archive is empty.")
                self.add_coverage("Package structure", "failed", "Empty ZIP")
                return

            roots: set[str] = set()
            names_lower: set[str] = set()
            safe_infos: list[zipfile.ZipInfo] = []
            for info in infos:
                raw = info.filename.replace("\\", "/")
                pure = PurePosixPath(raw)
                unsafe = (
                    not raw
                    or raw.startswith("/")
                    or re.match(r"^[A-Za-z]:", raw) is not None
                    or ".." in pure.parts
                )
                if unsafe:
                    self.add(
                        "CRITICAL", "ZIP_TRAVERSAL", "package",
                        "Unsafe or path-traversing archive entry.", raw,
                        remediation="Rebuild the archive with normalized relative paths.",
                    )
                    continue
                normalized = pure.as_posix().rstrip("/")
                if not normalized:
                    continue
                lowered = normalized.casefold()
                if lowered in names_lower:
                    self.add(
                        "CRITICAL", "ZIP_CASE_COLLISION", "package",
                        "Duplicate or case-colliding archive entry.", normalized,
                        remediation="Keep one uniquely cased path for every packaged file.",
                    )
                    continue
                names_lower.add(lowered)
                roots.add(pure.parts[0])
                mode = (info.external_attr >> 16) & 0xFFFF
                self.archive_modes[normalized] = mode
                if mode and stat.S_ISLNK(mode):
                    self.add(
                        "WARNING", "FILE_SYMLINK", "file-analysis",
                        "Symbolic link entry is packaged and will not be extracted by the preflight.", normalized,
                        remediation="Replace packaged links with reviewed regular files.",
                    )
                    continue
                safe_infos.append(info)

            if len(roots) != 1:
                self.add(
                    "CRITICAL", "ZIP_TOP_LEVEL", "package",
                    f"Expected exactly one top-level plugin directory; found {len(roots)}: {sorted(roots)}.",
                    remediation="Place all plugin files under one top-level directory in the ZIP.",
                )
                self.add_coverage("Package structure", "failed", "Multiple or missing top-level roots")
                return

            root_name = next(iter(roots))
            prefix = root_name.rstrip("/") + "/"
            self.archive_modes = {
                name[len(prefix):] if name.startswith(prefix) else name: mode
                for name, mode in self.archive_modes.items()
                if name != root_name
            }
            for info in safe_infos:
                raw = PurePosixPath(info.filename.replace("\\", "/")).as_posix().rstrip("/")
                if not raw or info.is_dir():
                    (extracted / raw).mkdir(parents=True, exist_ok=True)
                    continue
                destination = extracted / raw
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, destination.open("wb") as sink:
                    shutil.copyfileobj(source, sink)

            candidate = extracted / root_name
            if not candidate.is_dir():
                self.add(
                    "CRITICAL", "ZIP_ROOT_FILE", "package",
                    "The single top-level archive entry is not a plugin directory.", root_name,
                )
                self.add_coverage("Package structure", "failed", "Top level is not a directory")
                return
            self.plugin_root = candidate
            self.add_coverage("Package structure", "passed", "One safe top-level directory")

    def _locate_directory_root(self, target: Path) -> None:
        if (target / "metadata.txt").is_file():
            self.plugin_root = target
            self.add_coverage("Plugin discovery", "passed", "Target is the plugin root")
            return
        ignored = DEV_ARTIFACT_PARTS | {"build", "dist", "work", "outputs"}
        candidates: list[Path] = []
        for metadata in target.rglob("metadata.txt"):
            try:
                relative = metadata.relative_to(target)
            except ValueError:
                continue
            if len(relative.parts) > 4 or any(part in ignored for part in relative.parts):
                continue
            if (metadata.parent / "__init__.py").is_file():
                candidates.append(metadata.parent)
        if len(candidates) == 1:
            self.plugin_root = candidates[0]
            self.add_coverage(
                "Plugin discovery", "passed",
                f"Found plugin root at {candidates[0].relative_to(target).as_posix()}",
            )
        elif not candidates:
            self.add(
                "CRITICAL", "PLUGIN_ROOT_NOT_FOUND", "package",
                "No directory containing both metadata.txt and __init__.py was found.",
                remediation="Point to the plugin root or build a valid release ZIP.",
            )
            self.add_coverage("Plugin discovery", "failed", "No plugin root found")
        else:
            relative = [p.relative_to(target).as_posix() for p in candidates]
            self.add(
                "CRITICAL", "MULTIPLE_PLUGIN_ROOTS", "package",
                f"Multiple plugin roots were found: {relative}.",
                remediation="Audit one plugin directory or ZIP at a time.",
            )
            self.add_coverage("Plugin discovery", "failed", "Multiple plugin roots found")

    def _audit_root(self) -> None:
        assert self.plugin_root is not None
        self._check_root_name()
        self._check_required_files()
        self._check_metadata()
        files = [p for p in self.plugin_root.rglob("*") if p.is_file() or p.is_symlink()]
        self._check_files(files)
        self._check_python(files)
        self._run_external_tools()

    def _check_root_name(self) -> None:
        assert self.plugin_root is not None
        name = self.plugin_root.name
        if not re.fullmatch(r"[A-Za-z_-][A-Za-z0-9_-]*", name):
            self.add(
                "CRITICAL", "PLUGIN_DIR_NAME", "package",
                f"Invalid top-level plugin directory name: {name!r}.", name,
                remediation="Use only ASCII letters, digits, underscore, or hyphen and do not start with a digit.",
            )

    def _check_required_files(self) -> None:
        assert self.plugin_root is not None
        missing = []
        for name in REQUIRED_FILES:
            path = self.plugin_root / name
            if not path.is_file():
                missing.append(name)
                self.add(
                    "CRITICAL", "REQUIRED_FILE", "package",
                    f"Required root file is missing: {name}.", name,
                    remediation=f"Add {name} at the plugin root.",
                )
        if missing:
            self.add_coverage("Mandatory files", "failed", f"Missing: {', '.join(missing)}")
        else:
            self.add_coverage("Mandatory files", "passed", "metadata.txt, __init__.py, LICENSE")
        license_path = self.plugin_root / "LICENSE"
        if license_path.is_file():
            try:
                sample = license_path.read_bytes()[:8192]
                if b"\x00" in sample:
                    self.add(
                        "CRITICAL", "LICENSE_BINARY", "package",
                        "LICENSE is not a plain-text file.", "LICENSE",
                        remediation="Replace it with a plain-text license file named LICENSE.",
                    )
            except OSError as exc:
                self.add("CRITICAL", "LICENSE_READ", "package", f"Cannot read LICENSE: {exc}", "LICENSE")

    def _check_metadata(self) -> None:
        assert self.plugin_root is not None
        path = self.plugin_root / "metadata.txt"
        if not path.is_file():
            self.add_coverage("Metadata", "failed", "metadata.txt is missing")
            return
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            self.add(
                "CRITICAL", "METADATA_UTF8", "metadata",
                f"metadata.txt is not valid UTF-8: {exc}", "metadata.txt",
                remediation="Save metadata.txt as UTF-8.",
            )
            self.add_coverage("Metadata", "failed", "Invalid UTF-8")
            return
        except OSError as exc:
            self.add("CRITICAL", "METADATA_READ", "metadata", f"Cannot read metadata.txt: {exc}", "metadata.txt")
            self.add_coverage("Metadata", "failed", "Unreadable")
            return

        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            self.add(
                "CRITICAL", "METADATA_INI", "metadata",
                f"metadata.txt is not valid INI: {exc}", "metadata.txt",
                remediation="Repair the [general] section and duplicate or malformed entries.",
            )
            self.add_coverage("Metadata", "failed", "Invalid INI")
            return
        if not parser.has_section("general"):
            self.add(
                "CRITICAL", "METADATA_SECTION", "metadata",
                "metadata.txt has no [general] section.", "metadata.txt",
                remediation="Add a [general] section containing the plugin metadata.",
            )
            self.add_coverage("Metadata", "failed", "Missing [general]")
            return

        self.metadata = {key: value.strip() for key, value in parser.items("general")}
        folded_keys: dict[str, list[str]] = {}
        for key in self.metadata:
            folded_keys.setdefault(key.casefold(), []).append(key)
        for keys in folded_keys.values():
            if len(keys) > 1:
                self.add(
                    "CRITICAL", "METADATA_DUPLICATE_CASE", "metadata",
                    f"Metadata contains case-colliding keys: {keys}.", "metadata.txt",
                    remediation="Keep one canonical spelling for each metadata key.",
                )
        lower_to_actual = {key.casefold(): key for key in self.metadata}
        for field in REQUIRED_METADATA:
            actual = lower_to_actual.get(field.casefold())
            if actual is None or not self.metadata[actual]:
                self.add(
                    "CRITICAL", "METADATA_REQUIRED", "metadata",
                    f"Required metadata field is missing or empty: {field}.", "metadata.txt",
                    remediation=f"Add a non-empty {field}= value to [general].",
                )
            elif actual != field:
                self.add(
                    "WARNING", "METADATA_CASE", "metadata",
                    f"Metadata key {actual!r} should use canonical spelling {field!r}.", "metadata.txt",
                    remediation=f"Rename the key to {field}.",
                )

        def value(name: str) -> str:
            actual = lower_to_actual.get(name.casefold())
            return self.metadata.get(actual, "") if actual else ""

        for field in ("description", "about", "changelog"):
            field_value = value(field)
            if field_value and HTML_RE.search(field_value):
                self.add(
                    "WARNING", "METADATA_HTML", "metadata",
                    f"HTML-like markup appears in {field}; official metadata text must not contain HTML.",
                    "metadata.txt", remediation=f"Replace markup in {field} with plain text.",
                )

        version = value("version")
        if version and not VERSION_RE.fullmatch(version):
            self.add(
                "WARNING", "METADATA_VERSION", "metadata",
                f"Plugin version is not clear dotted notation: {version!r}.", "metadata.txt",
                remediation="Use a unique dotted version such as 1.2.0.",
            )

        qmin = value("qgisMinimumVersion")
        qmax = value("qgisMaximumVersion")
        if qmin and not QGIS_VERSION_RE.fullmatch(qmin):
            self.add(
                "CRITICAL", "QGIS_MIN_VERSION", "metadata",
                f"Invalid qgisMinimumVersion: {qmin!r}.", "metadata.txt",
                remediation="Use dotted numeric notation such as 3.34 or 4.0.",
            )
        if qmax and not QGIS_VERSION_RE.fullmatch(qmax):
            self.add(
                "CRITICAL", "QGIS_MAX_VERSION", "metadata",
                f"Invalid qgisMaximumVersion: {qmax!r}.", "metadata.txt",
                remediation="Use dotted numeric notation such as 3.99 or 4.99.",
            )
        if QGIS_VERSION_RE.fullmatch(qmin or "") and QGIS_VERSION_RE.fullmatch(qmax or ""):
            if version_tuple(qmin) > version_tuple(qmax):
                self.add(
                    "CRITICAL", "QGIS_VERSION_RANGE", "metadata",
                    "qgisMinimumVersion is greater than qgisMaximumVersion.", "metadata.txt",
                    remediation="Set an ordered compatibility range that matches tested QGIS versions.",
                )

        email = value("email")
        if email and not EMAIL_RE.fullmatch(email):
            self.add(
                "WARNING", "METADATA_EMAIL", "metadata", f"Invalid author email: {email!r}.",
                "metadata.txt", remediation="Provide a valid contact email address.",
            )

        for field in ("repository", "homepage", "tracker"):
            field_value = value(field)
            if field_value and not valid_http_url(field_value):
                severity = "CRITICAL" if field == "repository" else "WARNING"
                self.add(
                    severity, "METADATA_URL", "metadata",
                    f"{field} is not a valid HTTP(S) URL.", "metadata.txt",
                    remediation=f"Set {field} to a working public HTTP(S) URL.",
                )
        for field in ("homepage", "tracker"):
            if not value(field):
                self.add(
                    "WARNING", "APPROVAL_LINK", "approval",
                    f"{field} is absent; the approval guidance expects a working {field} link.",
                    "metadata.txt", remediation=f"Add a public {field}= URL.",
                )

        for field in BOOLEAN_METADATA:
            field_value = value(field)
            if field_value and field_value not in {"True", "False"}:
                self.add(
                    "WARNING", "METADATA_BOOLEAN", "metadata",
                    f"{field} must be exactly True or False, not {field_value!r}.", "metadata.txt",
                    remediation=f"Set {field}=True or {field}=False.",
                )

        category = value("category")
        if category and category not in ALLOWED_CATEGORIES:
            self.add(
                "WARNING", "METADATA_CATEGORY", "metadata",
                f"Unsupported category: {category!r}.", "metadata.txt",
                remediation=f"Use one of: {', '.join(sorted(ALLOWED_CATEGORIES))}.",
            )

        icon = value("icon")
        if icon:
            pure = PurePosixPath(icon.replace("\\", "/"))
            if pure.is_absolute() or ".." in pure.parts:
                self.add(
                    "CRITICAL", "METADATA_ICON_PATH", "metadata",
                    "Icon path escapes the plugin root.", "metadata.txt",
                    remediation="Use a safe path relative to the plugin root.",
                )
            else:
                icon_path = self.plugin_root.joinpath(*pure.parts)
                if not icon_path.is_file():
                    self.add(
                        "WARNING", "METADATA_ICON_MISSING", "metadata",
                        f"Configured icon does not exist: {icon}.", "metadata.txt",
                        remediation="Package the referenced icon or correct the relative path.",
                    )
                elif icon_path.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
                    self.add(
                        "WARNING", "METADATA_ICON_TYPE", "metadata",
                        f"Configured icon is not PNG or JPEG: {icon}.", "metadata.txt",
                        remediation="Use a web-friendly PNG or JPEG icon.",
                    )
        else:
            self.add(
                "INFO", "APPROVAL_ICON", "approval",
                "No plugin icon is declared.", "metadata.txt",
                remediation="Add a distinctive plugin icon and reference it with icon=.",
            )

        supports_qt6 = value("supportsQt6")
        if supports_qt6:
            self.add(
                "WARNING", "QGIS4_OBSOLETE_FLAG", "compatibility",
                "supportsQt6 is obsolete and no longer controls QGIS 4 readiness.", "metadata.txt",
                remediation="Remove supportsQt6 and use a tested QGIS version range reaching 4.x.",
            )

        metadata_errors = [f for f in self.findings if f.category == "metadata" and f.severity == "CRITICAL"]
        self.add_coverage(
            "Metadata", "failed" if metadata_errors else "passed",
            "Required values parsed" if not metadata_errors else f"{len(metadata_errors)} critical issue(s)",
        )

    def _check_files(self, files: Iterable[Path]) -> None:
        assert self.plugin_root is not None
        file_count = 0
        for path in files:
            file_count += 1
            relative = self.rel(path)
            parts = PurePosixPath(relative).parts
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=False)
                    resolved.relative_to(self.plugin_root.resolve())
                    severity = "WARNING"
                    message = "Symbolic link is packaged and requires manual review."
                except ValueError:
                    severity = "CRITICAL"
                    message = "Symbolic link resolves outside the plugin root."
                self.add(
                    severity, "FILE_SYMLINK", "file-analysis", message, relative,
                    remediation="Replace packaged links with reviewed regular files.",
                )
                continue

            suffix = path.suffix.lower()
            if suffix in SUSPICIOUS_EXTENSIONS:
                self.add(
                    "CRITICAL", "FILE_SUSPICIOUS", "file-analysis",
                    f"Suspicious or platform-binary/script file type: {suffix}.", relative,
                    remediation="Remove it from the plugin package or obtain an explicit repository exception.",
                )

            hidden_parts = [part for part in parts if part.startswith(".") and part not in {".", ".."}]
            if hidden_parts:
                if len(parts) == 1 and parts[0] in SUPPORTED_CONFIGS:
                    self.add(
                        "INFO", "SECURITY_CONFIG", "file-analysis",
                        "Supported scanner configuration is included; review all suppressions.", relative,
                        remediation="Keep every suppression narrow, documented, and safe.",
                    )
                else:
                    self.add(
                        "INFO", "FILE_HIDDEN", "file-analysis",
                        "Hidden file or directory is packaged.", relative,
                        remediation="Remove unintended hidden development or credential files.",
                    )

            if any(part in DEV_ARTIFACT_PARTS for part in parts) or path.name in DEV_ARTIFACT_NAMES or suffix == ".pyc":
                self.add(
                    "WARNING", "PACKAGE_DEV_ARTIFACT", "package",
                    "Development or cache artifact is included in the plugin package.", relative,
                    remediation="Exclude VCS, cache, environment, and editor artifacts from the release ZIP.",
                )

            mode = self.archive_modes.get(relative)
            if mode is None and os.name != "nt":
                try:
                    mode = stat.S_IMODE(path.stat().st_mode)
                except OSError:
                    mode = 0
            if mode is not None and mode & 0o111:
                self.add(
                    "WARNING", "FILE_EXECUTABLE", "file-analysis",
                    f"Executable permission bits are set ({oct(mode & 0o777)}).", relative,
                    remediation="Remove executable bits unless they are strictly required and accepted.",
                )

            if suffix not in EXPECTED_BINARY_ASSETS and suffix not in SUSPICIOUS_EXTENSIONS:
                try:
                    if b"\x00" in path.read_bytes()[:8192]:
                        self.add(
                            "WARNING", "FILE_BINARY", "file-analysis",
                            "Unreviewed binary content is packaged.", relative,
                            remediation="Remove the binary or document and obtain approval for its necessity.",
                        )
                except OSError as exc:
                    self.add(
                        "WARNING", "FILE_READ", "file-analysis", f"Cannot inspect file: {exc}", relative,
                    )
        file_findings = [f for f in self.findings if f.category == "file-analysis"]
        file_status = (
            "failed" if any(f.severity == "CRITICAL" for f in file_findings)
            else "findings" if any(f.severity == "WARNING" for f in file_findings)
            else "passed"
        )
        self.add_coverage("File analysis", file_status, f"Inspected {file_count} files")

    def _check_python(self, files: Iterable[Path]) -> None:
        assert self.plugin_root is not None
        python_files = [p for p in files if p.is_file() and p.suffix.lower() == ".py"]
        parsed: dict[Path, ast.AST] = {}
        for path in python_files:
            relative = self.rel(path)
            try:
                source = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError) as exc:
                self.add(
                    "CRITICAL", "E902", "python", f"Python file cannot be read as UTF-8: {exc}", relative,
                    remediation="Save readable Python source as UTF-8.",
                )
                continue
            if BIDI_RE.search(source):
                line = source[: BIDI_RE.search(source).start()].count("\n") + 1  # type: ignore[union-attr]
                self.add(
                    "CRITICAL", "B613", "security",
                    "Unicode bidirectional control character detected (Trojan Source risk).", relative, line,
                    remediation="Remove the control character and review the surrounding code.",
                )
            for detector, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(source):
                    line = source[: match.start()].count("\n") + 1
                    self.add(
                        "CRITICAL", detector, "secrets",
                        "Potential hardcoded secret detected; value redacted.", relative, line,
                        remediation="Revoke exposed credentials and load replacements from an approved secure store.",
                        source="local-secret-pattern",
                    )
            try:
                tree = ast.parse(source, filename=relative)
                parsed[path] = tree
            except SyntaxError as exc:
                self.add(
                    "CRITICAL", "E999", "python", f"Python syntax error: {exc.msg}",
                    relative, exc.lineno,
                    remediation="Repair the syntax error before packaging.",
                )
                continue
            UnsafeVisitor(self, relative).visit(tree)

        init_path = self.plugin_root / "__init__.py"
        if init_path in parsed:
            factories = [
                node for node in getattr(parsed[init_path], "body", [])
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "classFactory"
            ]
            if not factories:
                self.add(
                    "CRITICAL", "CLASS_FACTORY", "qgis-api",
                    "__init__.py does not define classFactory(iface).", "__init__.py",
                    remediation="Define classFactory(iface) and return the plugin instance.",
                )
            elif isinstance(factories[0], ast.AsyncFunctionDef) or not factories[0].args.args:
                self.add(
                    "CRITICAL", "CLASS_FACTORY_SIGNATURE", "qgis-api",
                    "classFactory must be a regular function accepting the QGIS interface argument.",
                    "__init__.py", factories[0].lineno,
                    remediation="Define def classFactory(iface): and return the plugin instance.",
                )
        python_rules = {"E902", "E999", "CLASS_FACTORY", "CLASS_FACTORY_SIGNATURE"}
        python_failed = any(f.severity == "CRITICAL" and f.rule in python_rules for f in self.findings)
        self.add_coverage(
            "Python syntax/API", "failed" if python_failed else "passed",
            f"Parsed {len(python_files)} Python files",
        )
        self.add_coverage(
            "QGIS runtime", "unverified",
            "Static preflight cannot prove install, initGui, actions, unload, or platform compatibility",
        )

    def _run_external_tools(self) -> None:
        if self.external == "never":
            for name in ("Bandit", "detect-secrets", "Flake8"):
                self.add_coverage(name, "skipped", "Disabled with --external never")
            return
        assert self.plugin_root is not None
        runners = (
            ("Bandit", "bandit", self._run_bandit),
            ("detect-secrets", "detect-secrets", self._run_detect_secrets),
            ("Flake8", "flake8", self._run_flake8),
        )
        for label, command, runner in runners:
            executable = shutil.which(command)
            if not executable:
                severity = "CRITICAL" if self.external == "required" else "WARNING"
                self.add(
                    severity, "TOOL_MISSING", "coverage",
                    f"Exact {label} scan was not run because {command!r} is unavailable.",
                    remediation=f"Install or provide {command}, then rerun the preflight.",
                )
                self.add_coverage(label, "missing", f"Command not found: {command}")
                continue
            try:
                count, version = runner(executable)
                self.add_coverage(label, "completed", f"Ran {version}; reported {count} finding(s)")
            except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
                severity = "CRITICAL" if self.external == "required" else "WARNING"
                self.add(
                    severity, "TOOL_FAILED", "coverage", f"{label} scan failed: {exc}",
                    remediation=f"Run {command} directly, repair its environment/configuration, and repeat the audit.",
                )
                self.add_coverage(label, "failed", str(exc))

    def _tool_version(self, executable: str) -> str:
        result = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        version = (result.stdout or result.stderr).strip().splitlines()
        return version[0] if version else Path(executable).name

    def _run_bandit(self, executable: str) -> tuple[int, str]:
        assert self.plugin_root is not None
        command = [executable, "-r", str(self.plugin_root), "-f", "json", "-q"]
        ini = self.plugin_root / ".bandit"
        if ini.is_file():
            command.extend(["--ini", str(ini)])
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace",
        )
        if not result.stdout.strip():
            if result.returncode not in (0, 1):
                raise subprocess.SubprocessError(result.stderr.strip() or f"exit {result.returncode}")
            payload: dict[str, Any] = {"results": []}
        else:
            payload = json.loads(result.stdout)
        results = payload.get("results", [])
        for item in results:
            rule = item.get("test_id", "BANDIT")
            severity = "CRITICAL" if rule in CRITICAL_BANDIT else "INFO" if rule in INFO_BANDIT else "WARNING"
            filename = Path(item.get("filename", ""))
            self.add(
                severity, rule, "security", item.get("issue_text", "Bandit finding"),
                self.rel(filename), item.get("line_number"),
                remediation="Refactor the unsafe construct or document a narrowly reviewed false positive.",
                source="bandit",
            )
        return len(results), self._tool_version(executable)

    def _run_detect_secrets(self, executable: str) -> tuple[int, str]:
        assert self.plugin_root is not None
        result = subprocess.run(
            [executable, "scan", "--all-files", str(self.plugin_root)],
            capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace",
        )
        if result.returncode not in (0, 1) and not result.stdout.strip():
            raise subprocess.SubprocessError(result.stderr.strip() or f"exit {result.returncode}")
        payload = json.loads(result.stdout or "{}")
        count = 0
        for filename, items in payload.get("results", {}).items():
            for item in items:
                count += 1
                detector = item.get("type", "detect-secrets")
                if detector in WARNING_SECRET_TYPES or "Entropy" in detector or "Keyword" in detector:
                    severity = "WARNING"
                elif detector in INFO_SECRET_TYPES or "Public IP" in detector:
                    severity = "INFO"
                else:
                    severity = "CRITICAL"
                self.add(
                    severity, detector.replace(" ", ""), "secrets",
                    "Potential secret detected; value redacted.",
                    self.rel(Path(filename)), item.get("line_number"),
                    remediation="Verify the finding, revoke any exposed credential, and remove it from the package.",
                    source="detect-secrets",
                )
        return count, self._tool_version(executable)

    def _run_flake8(self, executable: str) -> tuple[int, str]:
        assert self.plugin_root is not None
        fmt = "%(path)s::%(row)d::%(col)d::%(code)s::%(text)s"
        result = subprocess.run(
            [executable, ".", f"--format={fmt}"], cwd=self.plugin_root,
            capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace",
        )
        if result.returncode not in (0, 1):
            raise subprocess.SubprocessError(result.stderr.strip() or f"exit {result.returncode}")
        count = 0
        for line in result.stdout.splitlines():
            parts = line.split("::", 4)
            if len(parts) != 5:
                continue
            filename, row, _column, code, message = parts
            count += 1
            severity = "CRITICAL" if code in CRITICAL_FLAKE8 else "WARNING" if code in WARNING_FLAKE8 else "INFO"
            self.add(
                severity, code, "quality", message, self.rel((self.plugin_root / filename).resolve()),
                int(row), remediation="Correct the Python quality or correctness issue.", source="flake8",
            )
        return count, self._tool_version(executable)

    def verdict(self) -> str:
        if any(f.severity == "CRITICAL" for f in self.findings):
            return "BLOCKED"
        if any(f.severity == "WARNING" for f in self.findings):
            return "CHANGES REQUIRED"
        return "READY WITH CAVEATS"

    def as_dict(self) -> dict[str, Any]:
        metadata = self.metadata
        return {
            "schema_version": 1,
            "audit_date": self.audit_time,
            "target": str(self.target),
            "plugin_root": str(self.plugin_root) if self.plugin_root else None,
            "plugin": {
                "name": metadata_value(metadata, "name"),
                "version": metadata_value(metadata, "version"),
                "qgis_minimum": metadata_value(metadata, "qgisMinimumVersion"),
                "qgis_maximum": metadata_value(metadata, "qgisMaximumVersion"),
            },
            "verdict": self.verdict(),
            "counts": {
                severity: sum(f.severity == severity for f in self.findings)
                for severity in ("CRITICAL", "WARNING", "INFO")
            },
            "coverage": [dataclasses.asdict(item) for item in self.coverage],
            "findings": [dataclasses.asdict(item) for item in sorted(self.findings, key=Finding.sort_key)],
            "limitations": [
                "Live QGIS rule state was not fetched by this local script.",
                "Server-side structural/security validation and manual approval remain authoritative.",
                "QGIS runtime and cross-platform behavior require separate testing.",
                "URL syntax was checked locally; reachability and destination suitability were not.",
            ],
        }

    def as_markdown(self) -> str:
        data = self.as_dict()
        counts = data["counts"]
        lines = [
            "# QGIS plugin repository preflight",
            "",
            f"**Verdict: {data['verdict']}** — {counts['CRITICAL']} critical, "
            f"{counts['WARNING']} warning, {counts['INFO']} info.",
            "",
            "## Scope",
            "",
            f"- Target: `{md(data['target'])}`",
            f"- Plugin root: `{md(data['plugin_root'] or 'not found')}`",
            f"- Plugin: `{md(data['plugin']['name'] or 'unknown')}`",
            f"- Version: `{md(data['plugin']['version'] or 'unknown')}`",
            f"- Claimed QGIS range: `{md(data['plugin']['qgis_minimum'] or '?')}` to "
            f"`{md(data['plugin']['qgis_maximum'] or 'derived by repository')}`",
            f"- Audit timestamp: `{data['audit_date']}`",
            "",
            "## Coverage",
            "",
            "| Check | Status | Details |",
            "|---|---|---|",
        ]
        for item in data["coverage"]:
            lines.append(f"| {md(item['check'])} | {md(item['status'])} | {md(item['details'])} |")

        for severity in ("CRITICAL", "WARNING", "INFO"):
            lines.extend(["", f"## {severity}", ""])
            findings = [f for f in sorted(self.findings, key=Finding.sort_key) if f.severity == severity]
            if not findings:
                lines.append("None.")
                continue
            for finding in findings:
                location = finding.path
                if finding.line:
                    location = f"{location}:{finding.line}" if location else f"line {finding.line}"
                evidence = f" — `{md(location)}`" if location else ""
                lines.append(f"- **{md(finding.rule)}**{evidence}: {md(finding.message)}")
                if finding.remediation:
                    lines.append(f"  Fix: {md(finding.remediation)}")
                lines.append(f"  Source: `{md(finding.source)}`; category: `{md(finding.category)}`.")

        lines.extend(["", "## Limitations and next gate", ""])
        for limitation in data["limitations"]:
            lines.append(f"- {md(limitation)}")
        lines.extend(
            [
                "",
                "Before upload, compare findings with the live rules at "
                "https://plugins.qgis.org/docs/security-scanning/rules and run the plugin in every claimed QGIS/Qt environment.",
                "",
            ]
        )
        return "\n".join(lines)


class UnsafeVisitor(ast.NodeVisitor):
    def __init__(self, audit: Audit, path: str) -> None:
        self.audit = audit
        self.path = path

    def call_name(self, node: ast.Call) -> str:
        def dotted(expr: ast.AST) -> str:
            if isinstance(expr, ast.Name):
                return expr.id
            if isinstance(expr, ast.Attribute):
                prefix = dotted(expr.value)
                return f"{prefix}.{expr.attr}" if prefix else expr.attr
            return ""
        return dotted(node.func)

    def keyword_bool(self, node: ast.Call, name: str, expected: bool) -> bool:
        for keyword in node.keywords:
            if keyword.arg == name and isinstance(keyword.value, ast.Constant):
                return keyword.value.value is expected
        return False

    def add(self, severity: str, rule: str, node: ast.AST, message: str, remediation: str) -> None:
        self.audit.add(
            severity, rule, "security", message, self.path, getattr(node, "lineno", None),
            remediation=remediation, source="local-ast-heuristic",
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = self.call_name(node)
        if name in {"exec", "builtins.exec"}:
            self.add("CRITICAL", "B102", node, "Use of exec() detected.", "Replace dynamic execution with explicit parsing or dispatch.")
        elif name in {"eval", "builtins.eval"}:
            self.add("CRITICAL", "B307", node, "Use of eval() detected.", "Use a safe parser such as ast.literal_eval only for compatible literal data.")
        elif name in {"os.system", "os.popen"}:
            self.add("CRITICAL", "B605", node, "A process is started through a shell.", "Use subprocess with a fixed executable, argument list, shell=False, and validated input.")
        elif name.startswith("subprocess.") and self.keyword_bool(node, "shell", True):
            self.add("CRITICAL", "B602", node, "subprocess is called with shell=True.", "Pass a fixed argument list with shell=False and validate all inputs.")
        elif name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"}:
            self.add("CRITICAL", "B301", node, "Unsafe pickle deserialization detected.", "Use a non-executable data format for untrusted data.")
        elif name in {"marshal.load", "marshal.loads"}:
            self.add("CRITICAL", "B302", node, "Unsafe marshal deserialization detected.", "Use a safe, validated data format.")
        elif name == "tempfile.mktemp":
            self.add("CRITICAL", "B306", node, "Insecure tempfile.mktemp() detected.", "Use NamedTemporaryFile or mkstemp.")
        elif name in {"ssl._create_unverified_context", "ssl.create_unverified_context"}:
            self.add("CRITICAL", "B323", node, "Unverified TLS context detected.", "Use a verified client context and trusted CA certificates.")
        elif name in {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.request", "httpx.get", "httpx.post", "httpx.request"}:
            if self.keyword_bool(node, "verify", False):
                self.add("CRITICAL", "B501", node, "TLS certificate verification is disabled.", "Keep certificate verification enabled.")
            if not any(keyword.arg == "timeout" for keyword in node.keywords):
                self.add("WARNING", "B113", node, "HTTP request has no explicit timeout.", "Set a finite connection/read timeout.")
        elif name == "yaml.load":
            safe_loader = any(
                keyword.arg == "Loader"
                and isinstance(keyword.value, ast.Attribute)
                and keyword.value.attr in {"SafeLoader", "CSafeLoader"}
                for keyword in node.keywords
            )
            if not safe_loader:
                self.add("CRITICAL", "B506", node, "yaml.load() lacks a safe loader.", "Use yaml.safe_load() or SafeLoader.")
        elif name in {"tarfile.TarFile.extractall", "tarfile.extractall"}:
            if not any(keyword.arg == "filter" for keyword in node.keywords):
                self.add("CRITICAL", "B202", node, "Archive extraction has no safety filter.", "Validate member paths and use a safe extraction filter.")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if any(re.search(r"(?:password|passwd|api_?key|secret|token)$", name, re.I) for name in names):
                self.add(
                    "CRITICAL", "B105", node,
                    "Credential-like variable is assigned a hardcoded string; value redacted.",
                    "Load credentials from QGIS authentication facilities or another approved secure store.",
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for arg, default in zip(node.args.args[-len(node.args.defaults):], node.args.defaults):
            if re.search(r"(?:password|passwd|api_?key|secret|token)$", arg.arg, re.I):
                if isinstance(default, ast.Constant) and isinstance(default.value, str) and default.value:
                    self.add(
                        "CRITICAL", "B107", node,
                        "Credential-like function argument has a hardcoded default; value redacted.",
                        "Require the caller to provide credentials securely.",
                    )
        self.generic_visit(node)


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def valid_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc) and not any(ch.isspace() for ch in value)


def metadata_value(metadata: dict[str, str], name: str) -> str:
    for key, value in metadata.items():
        if key.casefold() == name.casefold():
            return value
    return ""


def md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="QGIS plugin root, repository, or release ZIP")
    parser.add_argument("--report", type=Path, help="Write a Markdown report")
    parser.add_argument("--json", dest="json_path", type=Path, help="Write a JSON report")
    parser.add_argument(
        "--external", choices=("auto", "required", "never"), default="auto",
        help="Run Bandit, detect-secrets, and Flake8 when available, require them, or skip them",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    audit = Audit(args.target.resolve(), args.external)
    audit.run()
    markdown = audit.as_markdown()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(markdown, encoding="utf-8")
    else:
        print(markdown)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(
            json.dumps(audit.as_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
    return 2 if audit.verdict() == "BLOCKED" else 1 if audit.verdict() == "CHANGES REQUIRED" else 0


if __name__ == "__main__":
    raise SystemExit(main())

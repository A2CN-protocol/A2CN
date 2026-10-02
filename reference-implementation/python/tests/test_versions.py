"""The versions matrix, the package version, and the README table agree.

PROTOCOL_VERSIONS must be read from the modules that own each constant, and
the top-level README's "Versions implemented" table must state the same
values. Either drifting fails here rather than in a release.
"""

import json
import re
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import a2cn
from a2cn.evidence import (
    RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS,
    SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
)
from a2cn.messages import PROTOCOL_ACT_VERSION
from a2cn.record import (
    ACCEPTED_TRANSACTION_RECORD_VERSIONS,
    KNOWN_TRANSACTION_RECORD_VERSIONS,
)
from a2cn.versions import PROTOCOL_VERSIONS

PYTHON_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PYTHON_ROOT.parents[1]

# README row label -> the matrix value that row states.
README_ROWS = {
    "Wire protocol": [PROTOCOL_VERSIONS["wire"]],
    "TransactionRecord — emits": [PROTOCOL_VERSIONS["transaction_record"]["emits"]],
    "TransactionRecord — verifies": PROTOCOL_VERSIONS["transaction_record"]["accepts"],
    "TransactionRecord — known shapes": PROTOCOL_VERSIONS["transaction_record"]["recognizes"],
    "SessionEvidenceRecord — emits": [PROTOCOL_VERSIONS["session_evidence_record"]["emits"]],
    "SessionEvidenceRecord — verifies": PROTOCOL_VERSIONS["session_evidence_record"]["recognizes"],
}


def _pyproject_version() -> str:
    return tomllib.loads((PYTHON_ROOT / "pyproject.toml").read_text())["project"]["version"]


def _readme_table() -> dict[str, list[str]]:
    text = (REPO_ROOT / "README.md").read_text()
    block = re.search(
        r"<!-- versions-table:start -->(.*?)<!-- versions-table:end -->", text, re.S
    )
    assert block, "README.md has no versions table between its markers"
    rows = {}
    for line in block.group(1).strip().splitlines()[2:]:
        label, value = (cell.strip() for cell in line.strip().strip("|").split("|"))
        rows[label] = re.findall(r"`([^`]+)`", value)
    return rows


def test_the_matrix_is_derived_from_the_module_constants():
    assert PROTOCOL_VERSIONS == {
        "wire": PROTOCOL_ACT_VERSION,
        "transaction_record": {
            "emits": ACCEPTED_TRANSACTION_RECORD_VERSIONS[-1],
            "accepts": list(ACCEPTED_TRANSACTION_RECORD_VERSIONS),
            "recognizes": list(KNOWN_TRANSACTION_RECORD_VERSIONS),
        },
        "session_evidence_record": {
            "emits": SESSION_EVIDENCE_RECORD_VERSION_CURRENT,
            "recognizes": list(RECOGNIZED_SESSION_EVIDENCE_RECORD_VERSIONS),
        },
    }


def test_versions_module_retypes_no_version():
    # A literal in versions.py would be a second source that can fall out of
    # step with the module that owns the constant.
    source = (PYTHON_ROOT / "a2cn" / "versions.py").read_text()
    assert re.findall(r"[\"']\d+\.\d+(?:\.\d+)?[\"']", source) == []


def test_the_package_root_reexports_the_matrix():
    assert a2cn.PROTOCOL_VERSIONS is PROTOCOL_VERSIONS


def test_the_installed_package_version_is_the_pyproject_version():
    try:
        installed = version("a2cn")
    except PackageNotFoundError:
        # Run from a source tree that is not installed: the fallback says so
        # rather than claiming a release number.
        assert a2cn.__version__ == "0.0.0+source"
        return
    assert a2cn.__version__ == installed == _pyproject_version()


def test_the_readme_table_states_the_matrix():
    rows = _readme_table()
    for label, expected in README_ROWS.items():
        assert rows.get(label) == expected, label


def test_the_readme_table_states_the_package_and_spec_versions():
    rows = _readme_table()
    package_json = json.loads((REPO_ROOT / "a2cn_ts" / "package.json").read_text())
    assert rows.get("Python package `a2cn`") == [_pyproject_version()]
    assert rows.get("TypeScript package `a2cn`") == [package_json["version"]]
    (spec_version,) = rows["Specification document"]
    assert (REPO_ROOT / "spec" / f"a2cn-spec-v{spec_version}.md").is_file()


def test_the_readme_table_has_no_unchecked_row():
    checked = set(README_ROWS) | {
        "Python package `a2cn`",
        "TypeScript package `a2cn`",
        "Specification document",
    }
    assert set(_readme_table()) == checked

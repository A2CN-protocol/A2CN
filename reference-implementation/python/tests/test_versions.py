"""The versions matrix, the package version, and the README table agree.

PROTOCOL_VERSIONS must be read from the modules that own each constant, and
the top-level README's "Versions implemented" table must state the same
values. Either drifting fails here rather than in a release.
"""

import json
import re
import tomllib
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


def test_the_package_version_is_this_trees_or_the_source_fallback():
    assert a2cn.__version__ in (_pyproject_version(), "0.0.0+source")


class _Distribution:
    def __init__(self, init_path, direct_url=None):
        self.version = "9.9.9"
        self._init_path = init_path
        self._direct_url = direct_url

    def locate_file(self, path):
        return self._init_path

    def read_text(self, name):
        return self._direct_url if name == "direct_url.json" else None


def test_a_distribution_owning_the_imported_files_is_reported(monkeypatch):
    monkeypatch.setattr(a2cn, "distribution", lambda name: _Distribution(Path(a2cn.__file__)))
    assert a2cn._installed_version() == "9.9.9"


def test_an_editable_install_of_this_tree_is_reported(monkeypatch):
    direct_url = json.dumps({"url": PYTHON_ROOT.as_uri(), "dir_info": {"editable": True}})
    monkeypatch.setattr(
        a2cn, "distribution", lambda name: _Distribution(Path("/elsewhere/a2cn/__init__.py"), direct_url)
    )
    assert a2cn._installed_version() == "9.9.9"


def test_another_distribution_named_a2cn_is_not_reported(monkeypatch):
    # Installed elsewhere, while Python imported this tree: its version says
    # nothing about the code that is running.
    other_root = json.dumps({"url": Path("/elsewhere").as_uri(), "dir_info": {"editable": True}})
    for direct_url in (None, other_root):
        monkeypatch.setattr(
            a2cn, "distribution", lambda name, d=direct_url: _Distribution(Path("/elsewhere/a2cn/__init__.py"), d)
        )
        assert a2cn._installed_version() == "0.0.0+source"


def test_requirements_txt_restates_the_pyproject_dependencies():
    # requirements.txt lists the dependencies so it installs from any working
    # directory; pyproject.toml stays their single source, and this holds the
    # two lists equal.
    project = tomllib.loads((PYTHON_ROOT / "pyproject.toml").read_text())["project"]
    expected = project["dependencies"] + project["optional-dependencies"]["dev"]
    lines = (PYTHON_ROOT / "requirements.txt").read_text().splitlines()
    listed = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    assert sorted(listed) == sorted(expected)


def test_the_readme_table_states_the_matrix():
    rows = _readme_table()
    for label, expected in README_ROWS.items():
        assert rows.get(label) == expected, label


def test_the_readme_table_states_the_package_and_spec_versions():
    rows = _readme_table()
    package_json = json.loads((REPO_ROOT / "reference-implementation" / "typescript" / "package.json").read_text())
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

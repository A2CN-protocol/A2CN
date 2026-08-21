"""Packaging guardrails for optional integrations."""

from pathlib import Path
import tomllib


def _project_metadata() -> dict:
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    return tomllib.loads(pyproject.read_text())


def _requirements() -> list[str]:
    requirements = Path(__file__).parents[1] / "requirements.txt"
    return [
        line.strip()
        for line in requirements.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def test_mcp_is_optional_not_core_dependency() -> None:
    project = _project_metadata()["project"]

    dependencies = project["dependencies"]
    optional_dependencies = project["optional-dependencies"]

    assert not any(dep.startswith("mcp") for dep in dependencies)
    assert any(dep.startswith("mcp") for dep in optional_dependencies["mcp"])
    assert "a2cn[mcp]" in optional_dependencies["dev"]


def test_requirements_txt_does_not_install_mcp_server() -> None:
    assert not any(dep.startswith("mcp") for dep in _requirements())

"""Packaging guardrails for optional integrations."""

from pathlib import Path
import tomllib


def _project_metadata() -> dict:
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    return tomllib.loads(pyproject.read_text())


def test_mcp_is_optional_not_core_dependency() -> None:
    project = _project_metadata()["project"]

    dependencies = project["dependencies"]
    optional_dependencies = project["optional-dependencies"]

    assert not any(dep.startswith("mcp") for dep in dependencies)
    assert optional_dependencies["mcp"] == ["mcp==1.12.4"]
    assert "mcp==1.12.4" in optional_dependencies["dev"]

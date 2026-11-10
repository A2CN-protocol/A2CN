"""Smoke-test a built a2cn wheel in fresh virtual environments.

    python scripts/smoke_wheel.py dist/a2cn-X.Y.Z-py3-none-any.whl [--workdir DIR]

The wheel is installed twice, first alone and then with the ``mcp`` extra, each
time into a new virtual environment made with the Python running this script.
Every check runs from a directory outside the repository, and the imported
``a2cn`` must come from the environment, so a source tree on the path cannot
stand in for the wheel. In each environment:

- ``import a2cn`` works, from inside the environment;
- ``a2cn.__version__`` is pyproject.toml's version;
- the MCP server, the UBL export and the tests are not installed;
- ``a2cn-verify --help`` runs;
- ``a2cn-verify --offline`` verifies the two-round deal in
  spec/test-vectors/transaction-record-offer-history.json (exit 0, VERIFIED),
  and cannot finish the same deal without its DID documents (exit 3).

With the extra, ``mcp`` must import; without it, it must not be installed.
Exits non-zero, naming the failed check, on the first failure.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path

PYTHON_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PYTHON_ROOT.parents[1]
VECTOR = REPO_ROOT / "spec" / "test-vectors" / "transaction-record-offer-history.json"

VERIFIED_LINE = "overall: VERIFIED (2 verified, 0 refused, 0 could not finish)"
UNFINISHED_LINE = "overall: COULD NOT FINISH (0 verified, 0 refused, 2 could not finish)"

PROBE = """
import importlib.util, json, sys
import a2cn
print(json.dumps({
    "file": a2cn.__file__,
    "version": a2cn.__version__,
    "prefix": sys.prefix,
    "present": {name: importlib.util.find_spec(name) is not None
                for name in ("mcp", "mcp_server", "ubl_export", "tests", "examples")},
}))
"""


class SmokeFailure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def run(args: list, cwd: Path) -> subprocess.CompletedProcess:
    # PYTHONPATH and PYTHONHOME would let a source tree or another install
    # answer for the wheel, so neither reaches the environment under test.
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    return subprocess.run([str(a) for a in args], cwd=cwd, env=env, capture_output=True, text=True)


def bin_dir(env_dir: Path) -> Path:
    return env_dir / ("Scripts" if os.name == "nt" else "bin")


def write_deal(folder: Path, with_did_documents: bool) -> Path:
    vector = json.loads(VECTOR.read_text())
    folder.mkdir()
    (folder / "transaction_record.json").write_text(json.dumps(vector["transaction_record"]))
    (folder / "evidence_record.json").write_text(json.dumps(vector["evidence_record"]))
    if with_did_documents:
        for index, document in enumerate(vector["did_documents"]["current"].values()):
            (folder / f"did_{index}.json").write_text(json.dumps(document))
    return folder


def smoke(wheel: Path, extra: str | None, workdir: Path, expected_version: str) -> None:
    label = f"[{extra}]" if extra else "core"
    env_dir = workdir / f"venv-{extra or 'core'}"
    venv.EnvBuilder(with_pip=True, clear=True).create(env_dir)
    python = bin_dir(env_dir) / ("python.exe" if os.name == "nt" else "python")
    verifier = bin_dir(env_dir) / ("a2cn-verify.exe" if os.name == "nt" else "a2cn-verify")
    requirement = f"{wheel}[{extra}]" if extra else str(wheel)

    done = run([python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", requirement], workdir)
    check(done.returncode == 0, f"{label}: pip install failed:\n{done.stdout}{done.stderr}")

    done = run([python, "-I", "-c", PROBE], workdir)
    check(done.returncode == 0, f"{label}: import a2cn failed:\n{done.stderr}")
    probe = json.loads(done.stdout)
    installed = Path(probe["file"]).resolve()
    check(
        installed.is_relative_to(Path(probe["prefix"]).resolve()),
        f"{label}: a2cn was imported from {installed}, outside the environment",
    )
    check(
        not installed.is_relative_to(REPO_ROOT),
        f"{label}: a2cn was imported from the source tree ({installed})",
    )
    check(
        probe["version"] == expected_version,
        f"{label}: a2cn.__version__ is {probe['version']!r}, pyproject.toml says {expected_version!r}",
    )
    for name in ("mcp_server", "ubl_export", "tests", "examples"):
        check(not probe["present"][name], f"{label}: {name!r} is installed by the wheel")
    check(
        probe["present"]["mcp"] == bool(extra),
        f"{label}: mcp is {'missing' if extra else 'installed'}",
    )

    done = run([verifier, "--help"], workdir)
    check(done.returncode == 0, f"{label}: a2cn-verify --help exited {done.returncode}:\n{done.stderr}")
    check("--offline" in done.stdout, f"{label}: a2cn-verify --help does not list --offline")

    deal = write_deal(workdir / f"deal-{extra or 'core'}", with_did_documents=True)
    done = run([verifier, deal, "--offline"], workdir)
    output = done.stdout + done.stderr
    check(done.returncode == 0, f"{label}: a2cn-verify --offline exited {done.returncode}:\n{output}")
    check(VERIFIED_LINE in output.splitlines(), f"{label}: no {VERIFIED_LINE!r} line:\n{output}")

    bare = write_deal(workdir / f"deal-{extra or 'core'}-no-did", with_did_documents=False)
    done = run([verifier, bare, "--offline"], workdir)
    output = done.stdout + done.stderr
    check(done.returncode == 3, f"{label}: without DID documents, exit {done.returncode}, not 3:\n{output}")
    check(UNFINISHED_LINE in output.splitlines(), f"{label}: no {UNFINISHED_LINE!r} line:\n{output}")

    print(f"{label}: ok ({installed})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--workdir", type=Path, help="where the environments go (default: a new temporary directory)")
    args = parser.parse_args()

    wheel = args.wheel.resolve()
    expected = tomllib.loads((PYTHON_ROOT / "pyproject.toml").read_text())["project"]["version"]
    if args.workdir:
        args.workdir.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="a2cn-smoke-", dir=args.workdir)).resolve()
    else:
        workdir = Path(tempfile.mkdtemp(prefix="a2cn-smoke-")).resolve()
    if workdir.is_relative_to(REPO_ROOT):
        print(f"smoke: the work directory {workdir} is inside the repository", file=sys.stderr)
        return 2
    try:
        for extra in (None, "mcp"):
            smoke(wheel, extra, workdir, expected)
    except SmokeFailure as failure:
        print(f"smoke: FAILED: {failure}", file=sys.stderr)
        return 1
    print(f"smoke: {wheel.name} passed, core and [mcp]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

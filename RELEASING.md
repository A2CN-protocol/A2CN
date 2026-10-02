# Releasing

A release moves the **package** versions. The protocol versions a release
implements (wire `protocol_version`, each artifact's `record_version`) move only
when their own shape or meaning changes, and are listed in the
[README's "Versions implemented" table](README.md#versions-implemented).

## Single sources

| What | Where it is set | How it is read |
|------|-----------------|----------------|
| Python package version | `reference-implementation/python/pyproject.toml` `version` | `a2cn.__version__`, from the installed metadata |
| TypeScript package version | `a2cn_ts/package.json` `version` | package metadata |
| Protocol versions | the constants in `messages`, `record` and `evidence` | `a2cn.PROTOCOL_VERSIONS` / `PROTOCOL_VERSIONS` in `versions.ts` |

Never type a version into a second place. The two packages are versioned
separately, even when a release moves both to the same number.

## Checklist

1. Agree the release number. It is the library's semver, independent of the protocol versions.
2. Bump `pyproject.toml` and/or `package.json`.
3. Move the `[Unreleased]` section of `CHANGELOG.md` under the new version heading, with the date, and update its version table.
4. Update the README "Versions implemented" table. The drift test in each language fails until it matches the code and the package files.
5. Reinstall the Python package (`pip install -e ".[dev]"`) so the installed metadata carries the new version, then run both suites and `tsc --noEmit`.
6. Update the test counts in the READMEs to the current totals.
7. Merge, tag `vX.Y.Z` on the merge commit, then build and publish.

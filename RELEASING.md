# Releasing

A release moves the **package** versions. The protocol versions a release
implements (wire `protocol_version`, each artifact's `record_version`) move only
when their own shape or meaning changes, and are listed in the
[README's "Versions implemented" table](README.md#versions-implemented).

## Single sources

| What | Where it is set | How it is read |
|------|-----------------|----------------|
| Python package version | `reference-implementation/python/pyproject.toml` `version` | `a2cn.__version__`, from the metadata of the installed distribution that owns the imported tree |
| Python dependencies | `pyproject.toml` `dependencies` and the `dev` extra | `requirements.txt` restates them so it installs from any directory; a test holds the two equal |
| TypeScript package version | `reference-implementation/typescript/package.json` `version` | package metadata |
| Protocol versions | the constants in `messages`, `record` and `evidence` | `a2cn.PROTOCOL_VERSIONS` / `PROTOCOL_VERSIONS` in `versions.ts` |

Never type a version into a second place. Each package's version is set in its
own file; a release tag moves both to the same number, and the release
workflow refuses a tag that does not match both.

## Between releases

Every pull request that changes behaviour, the wire, a record, a schema or the
public API adds its entry under `[Unreleased]` in `CHANGELOG.md` in the same
pull request. A release then only moves that section; it never reconstructs it.

## What publishes

The `Release` workflow (`.github/workflows/release.yml`) runs when a `v*` tag
is pushed. It checks that the tag, without its `v`, equals both
`pyproject.toml`'s and `package.json`'s version, and stops if not. It then runs
both test suites on the tagged commit, builds the Python sdist and wheel and
the npm tarball, and smoke-tests each built package in a fresh environment
outside the repository (`reference-implementation/python/scripts/smoke_wheel.py`
and `reference-implementation/typescript/scripts/smoke_pack.mjs`, which CI also
runs on every pull request). Only when every one of those jobs has passed do the
two publish jobs run:

- **PyPI**: the job runs in the `pypi` environment and publishes the built
  sdist and wheel with trusted publishing; there is no token.
- **npm**: the job runs in the `npm` environment and publishes the smoke-tested
  tarball with trusted publishing and provenance. It runs only while the
  repository variable `NPM_TRUSTED_PUBLISHING` is `true` (see the one-time
  setup).

Each environment requires the maintainer's approval, so nothing is published
until the maintainer approves the deployment. Because the release publishes
both packages together, a release moves both versions to the tag's number.

## Checklist

1. Agree the release number. It is the library's semver, independent of the protocol versions.
2. Open the release pull request:
   - bump `version` in both `pyproject.toml` and `package.json` (and `package-lock.json`, with `npm install --package-lock-only`), then run `uv lock` in `reference-implementation/python` so `uv.lock`'s own `a2cn` entry carries the new version. Only those version lines may change: if `uv lock` changes anything else, stop and find out why before going on;
   - move the `[Unreleased]` section of `CHANGELOG.md` under the new version heading, with the date, and update its version table;
   - update the README "Versions implemented" table. The drift test in each language fails until it matches the code and the package files;
   - for the first published release only, change the READMEs' "once the first release is published" install notes to plain install instructions;
   - reinstall the Python package (`pip install -e ".[dev]"`) so the installed metadata carries the new version, then run both suites and `tsc --noEmit`;
   - update the test counts in the READMEs to the current totals.
3. Merge it once CI is green.
4. Tag the merge commit and push the tag:

   ```bash
   git fetch origin
   git tag -a vX.Y.Z -m "vX.Y.Z" <merge-commit>
   git push origin vX.Y.Z
   ```

5. Watch the `Release` workflow. When its build jobs pass, approve the `pypi`
   and `npm` deployments.
6. Check the published packages: <https://pypi.org/project/a2cn/> and
   <https://www.npmjs.com/package/a2cn> show the new version, the npm page shows
   its provenance (from the second npm version on; the first is published by
   hand), and a clean install (`pip install a2cn==X.Y.Z`,
   `npm install a2cn@X.Y.Z`) imports.
7. Publish the GitHub release for the tag, with the `CHANGELOG.md` section as its notes.

If the workflow fails before the publish jobs, nothing is published: fix the
cause in a new pull request and release it under the next patch number. A
version number that reached either registry is never reused.

If one publish job fails for a reason outside the code (an environment or
registry setting, a transient error), fix that and re-run the failed job from
the run's page; it publishes the same artifact. A fix that needs a code change
goes out under the next patch number, to both registries.

## One-time setup

The maintainer does this once: steps 1 to 3 and 8 before the first tag, step
4 with the first release, steps 5 and 6 right before the second release's tag,
and step 7 after the first workflow publish to npm. Steps 5 and 6 wait for the
second release because npm expires a newly added trusted publisher that has
not published within two days. The packages are owned by the maintainer's PyPI
and npm accounts.

1. **Two-factor authentication** on both the PyPI and the npm account.
2. **GitHub environments.** In the repository's settings, create the
   environments `pypi` and `npm`, each with the maintainer as a required
   reviewer and deployments limited to `v*` tags. Leave "Prevent self-review"
   off: with it on, the maintainer who pushed the tag cannot approve the
   deployment.
3. **PyPI pending publisher.** On PyPI, under Publishing, add a pending trusted
   publisher for the project `a2cn`: owner `A2CN-protocol`, repository `A2CN`,
   workflow `release.yml`, environment `pypi`. The first release creates the
   project.
4. **npm, first version by hand.** npm adds a trusted publisher only to a
   package that already exists, so the first version is published from the
   maintainer's machine. Leave `NPM_TRUSTED_PUBLISHING` unset for that release;
   its workflow then publishes to PyPI only. Publish the tarball that the tag's
   `Release` run built and smoke-tested (its `npm-dist` artifact), not a
   rebuild:

   ```bash
   gh run download <run-id> --repo A2CN-protocol/A2CN --name npm-dist --dir npm-dist
   npm publish ./npm-dist/a2cn-X.Y.Z.tgz --access public
   ```

   The artifact can also be downloaded from the run's page on GitHub. This
   first version has no provenance, because it is not published from the
   workflow.
5. **npm trusted publisher.** Right before the second release's tag, on
   npmjs.com, in the `a2cn` package's settings, add a trusted publisher: GitHub
   Actions, organization or user `A2CN-protocol`, repository `A2CN`, workflow
   `release.yml`, environment `npm`. The fields are case-sensitive. Allow
   `npm publish`: the workflow runs `npm publish`, not `npm stage publish`.
6. **Turn on npm publishing from the workflow.** Also right before the second
   release's tag, set the repository variable `NPM_TRUSTED_PUBLISHING` to
   `true` (Settings, Secrets and variables, Actions, Variables). From then on,
   every release publishes to npm from the workflow.
7. **Lock npm publishing down.** Once a release has published to npm through
   the trusted publisher, set the `a2cn` package's publishing access on
   npmjs.com to require two-factor authentication and disallow tokens.
8. **Required status checks.** In a branch protection rule or ruleset for
   `main`, require these CI checks to pass before merging:
   - `Python 3.11 (locked)`
   - `Python 3.13 (locked)`
   - `Python 3.11 (lowest direct dependencies)`
   - `Python 3.13 (highest dependencies)`
   - `Python dependency audit`
   - `Python package (build, twine check, wheel smoke test)`
   - `TypeScript`

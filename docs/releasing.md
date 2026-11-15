# Releasing

This guide is for maintainers. Releases are built and signed by GitHub
Actions ([`.github/workflows/release.yml`](../.github/workflows/release.yml)),
never on a developer machine, and no long-lived API tokens are stored
anywhere.

## Cutting a release

1. Update `__version__` in `src/egressveil/__init__.py`, for example to `0.3.0`.
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new
   `## [0.3.0] - YYYY-MM-DD` heading.
3. Merge to `main` once CI passes.
4. Tag that commit and push the tag:

   ```bash
   git tag -a v0.3.0 -m "EgressVeil v0.3.0"
   git push origin v0.3.0
   ```

The workflow then:

1. checks that the tag matches the package version and that the changelog
   has a section for it,
2. runs the tests, builds the sdist and wheel, and smoke-tests the wheel in
   a clean virtual environment,
3. creates a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations),
4. creates the GitHub release, with the files attached and the changelog
   section as release notes,
5. publishes to PyPI, but only if PyPI publishing is enabled (see below).

Releases are marked as pre-releases while the project is pre-alpha.

## Verifying a download

Anyone can check that a file was built by this repository's workflow:

```bash
gh attestation verify egressveil-0.2.0-py3-none-any.whl --repo qmmughal/egressveil
```

## Enabling PyPI publishing (one time)

Publishing uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/):
PyPI trusts this repository's `release.yml` workflow through OIDC, so no
PyPI token is stored anywhere. It needs one setup step on pypi.org that only
the account owner can do.

1. Sign in to <https://pypi.org>, or create an account with 2FA turned on.
2. Go to **Your account → Publishing → Add a new pending publisher** and
   enter:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `egressveil` |
   | Owner | `qmmughal` |
   | Repository name | `egressveil` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. In the GitHub repository, set the variable that turns the job on:

   ```bash
   gh variable set PYPI_PUBLISH --body true --repo qmmughal/egressveil
   ```

4. Publish an existing tag. The `pypi` environment accepts only `v*` tags,
   so the run must start **from the tag**, not from a branch:

   ```bash
   gh workflow run release.yml --ref v0.2.0 -f tag=v0.2.0 --repo qmmughal/egressveil
   ```

   In the web UI, go to **Actions → Release → Run workflow** and choose the
   tag `v0.2.0` in the **Use workflow from** dropdown, not `main`. Then
   approve the deployment to `pypi` when GitHub asks for it.

   If the tag's own release run failed only at the PyPI step (for example
   because the publisher wasn't registered yet), you can re-run just that
   job instead:

   ```bash
   gh run rerun <run-id> --failed --repo qmmughal/egressveil
   ```

### Troubleshooting `invalid-publisher`

PyPI found no trusted publisher matching the run. The failed job's log
shows the claims GitHub sent. Make sure the publisher on **pypi.org** (not
TestPyPI) has exactly these values: owner `qmmughal`, repository
`egressveil`, workflow `release.yml` (the file name), and environment `pypi`.

From then on, pushing a tag publishes to PyPI automatically, after approval.

The `pypi` GitHub environment only lets tags matching `v*` deploy, and it
requires a maintainer's approval for every publish. A compromised branch or
pull request therefore cannot publish a package.

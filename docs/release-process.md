# Release Process & Artifact Verification

Documentation of ConnScope's automated release pipeline, Git tag conventions, artifact generation, and integrity verification.

---

## 1. Release Philosophy & Automation

ConnScope strictly avoids manual, developer-machine release builds. All release artifacts—wheels, source archives, documentation tarballs, and cryptographic checksums—are built, validated, and published via automated **GitHub Actions** workflows.

The release workflow is defined in `.github/workflows/release.yml`. Both CI and release workflows utilize pinned GitHub Actions (`actions/checkout@v7.0.1` and `actions/setup-python@v7.1.0`) executing on the **Node 24** JavaScript action runtime on `ubuntu-latest`.

---

## 2. Git Tag Conventions & Version Verification

Releases are triggered by pushing a versioned Git tag matching the pattern `v*`:

```bash
# Tag format: v<MAJOR>.<MINOR>.<PATCH>
git tag v0.1.0
git push origin v0.1.0
```

### Strict Release Validation Gates
Before building any distributable files, the workflow executes automated validation gates:
1. **Multi-Version Matrix Test**: Executes the full test suite across Python 3.11, 3.12, and 3.13 on `ubuntu-latest`.
2. **Tag-to-Package Version Match**: Verifies that the tag (e.g. `v0.1.0`, stripped to `0.1.0`) exactly matches the `version` declared in `pyproject.toml`. If there is any mismatch, the workflow terminates immediately.

---

## 3. Artifact Build & Verification Pipeline

Once validation passes, the workflow builds and verifies release artifacts:

1. **Package Build**: Builds the source distribution (`.tar.gz`) and pure Python wheel (`.whl`) using `python -m build`.
2. **Metadata Verification**: Runs `twine check --strict dist/*` to verify package descriptions, license declarations, and metadata fields.
3. **Clean Environment Smoke Test**:
   - Creates a fresh virtual environment in `/tmp`.
   - Installs the newly built wheel with `--no-index`.
   - Runs basic CLI verification commands outside the repository:
     ```bash
     connscope --version
     connscope catalog check
     connscope probe list
     connscope matrix preview --engine xray --profile vless_tcp_none
     ```
4. **Documentation Archive**: Compresses the `docs/` directory, `README.md`, and `LICENSE` into `dist/connscope-docs-${TAG}.tar.gz`.
5. **Checksums Manifest**: Generates a standard SHA-256 checksum file covering all release artifacts (excluding the checksums file itself):
   ```bash
   cd dist && sha256sum $(ls -1 | grep -v '^checksums\.sha256$') > checksums.sha256
   ```

---

## 4. Draft-First Release Creation & Verification

The release job enforces safe, verifiable publication using `gh release`:
- **New Releases**: Created initially as a **draft** with tag verification (`gh release create --draft --verify-tag`). All expected payload assets are uploaded, downloaded back, compared byte-for-byte against the local `checksums.sha256` manifest, and verified across all payload hashes. The release is published (`gh release edit --draft=false`) only after all verification checks pass.
- **Rerun on Existing Draft**: If a rerun occurs on an existing draft release, the workflow inspects existing assets. If any unexpected assets are present, it fails clearly requiring maintainer action. Otherwise, it replaces only expected assets (`--clobber`) without preemptive deletion, and re-verifies the complete payload and hashes before publishing.
- **Published Release Protection**: If a release for the tag is already published, the workflow fails immediately with a clear error requiring explicit maintainer action. It refuses to silently overwrite or mutate an active release.

> [!NOTE]
> The automated workflow does **not** publish packages to PyPI or deploy Docker containers. Official release distributions are attached directly to GitHub Releases.

---

## 5. Verifying Release Artifacts Locally

Users and operators can verify downloaded release artifacts against the published `checksums.sha256` manifest:

```bash
# Download wheel, docs, and checksums manifest from GitHub Release
curl -LO https://github.com/ArshiaComPlus/connscope/releases/download/v0.1.0/connscope-0.1.0-py3-none-any.whl
curl -LO https://github.com/ArshiaComPlus/connscope/releases/download/v0.1.0/checksums.sha256

# Verify SHA-256 hashes
sha256sum --check --ignore-missing checksums.sha256
```

Expected output:
```text
connscope-0.1.0-py3-none-any.whl: OK
```

# Releasing scheck

## Prerequisites

- Push access to the repository
- `CARGO_REGISTRY_TOKEN` secret configured in GitHub (Settings > Secrets and variables > Actions)
- Optional: `crates-io` environment with deployment protection rules (Settings > Environments)

## Release process

### 1. Raise a prepare-release PR

Bump the version in `Cargo.toml`:

```
[package]
version = "0.4.0"
```

Review and merge.

### 2. Tag and push

```
git tag v0.4.0
git push origin main v0.4.0
```

The tag must match `v[0-9]+.[0-9]+.[0-9]+` (e.g. `v0.4.0`).
Pre-release tags like `v0.4.0-rc1` are also supported.

### 3. What happens automatically

Pushing the tag triggers `release.yml`, which runs these jobs in order:

| Job | What it does |
|-----|-------------|
| `init` | Extracts version from tag, detects pre-release |
| `check-version` | Verifies `Cargo.toml` version matches tag |
| `build` | Builds release binaries for 5 targets (linux gnu/musl, linux aarch64, macOS x86_64/arm64) |
| `build-rpm` | Builds RPM packages for x86_64 and aarch64 |
| `release` | Generates changelog, attests provenance (SLSA), creates GitHub Release with all artifacts |
| `publish` | Runs `cargo publish` to crates.io (stable releases only, skipped for pre-releases) |

The publish job is part of the release workflow (not a separate workflow)
because GitHub Actions does not trigger workflows from events created by
`GITHUB_TOKEN`.

### 4. Verify

- Check [Actions](https://github.com/rh-jfuller/scheck/actions) for workflow status
- Check [Releases](https://github.com/rh-jfuller/scheck/releases) for artifacts
- Check [crates.io/crates/scheck](https://crates.io/crates/scheck) for the published crate

## Release artifacts

| Artifact | Description |
|----------|-------------|
| `scheck-<ver>-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 (dynamically linked) |
| `scheck-<ver>-x86_64-unknown-linux-musl.tar.gz` | Linux x86_64 (statically linked) |
| `scheck-<ver>-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 |
| `scheck-<ver>-x86_64-apple-darwin.tar.gz` | macOS x86_64 |
| `scheck-<ver>-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `scheck-<ver>-1.x86_64.rpm` | RPM for x86_64 |
| `scheck-<ver>-1.aarch64.rpm` | RPM for ARM64 |
| `*.sha256` | SHA-256 checksum for each artifact |

## Pre-release

Tag with a pre-release suffix to create a GitHub pre-release:

```
git tag v0.4.0-rc1
git push origin v0.4.0-rc1
```

Pre-releases build the same artifacts but are marked as pre-release on
GitHub and skip `cargo publish`.

## Secrets

| Secret | Where to set | How to get |
|--------|-------------|------------|
| `CARGO_REGISTRY_TOKEN` | Repository > Settings > Secrets | https://crates.io/settings/tokens -- scope to `publish-update` for `scheck` |
| `GITHUB_TOKEN` | Automatic | Provided by GitHub Actions |

## Troubleshooting

**Version mismatch error:**
The `check-version` job fails if tag does not match `Cargo.toml`. Fix
`Cargo.toml`, commit, delete the tag, and re-tag:

```
git tag -d v0.4.0
git push origin :refs/tags/v0.4.0
# fix Cargo.toml, commit, push
git tag v0.4.0
git push origin main v0.4.0
```

**crates.io publish fails:**
Verify `CARGO_REGISTRY_TOKEN` is set and not expired. Run
`cargo publish --dry-run` locally before tagging.

**RPM build fails:**
Verify `[package.metadata.generate-rpm]` in `Cargo.toml` has correct
asset paths.

**Publish job does not run:**
Only stable releases (`v0.4.0`, not `v0.4.0-rc1`) trigger the publish
job. Check that `needs.init.outputs.prerelease` is `false`.

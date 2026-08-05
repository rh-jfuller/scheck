# Releasing scheck

## Prereq

- Push access to repo
- `CARGO_REGISTRY_TOKEN` secret configured in GitHub (Settings > Secrets and variables > Actions)

## Release process

### 1. Raise 'prepare release' PR 
Bump version in `Cargo.toml`:

```
[package]
version = "0.3.0"
```

review and merge

### 2. Tag and push

```
git tag v0.3.0
git push origin main v0.3.0
```

The tag must match pattern `v[0-9]+.[0-9]+.[0-9]+` (e.g. `v0.3.0`).

### 3. What happens automatically

Pushing the tag triggers two workflows:

**`release.yml`** (tag push):
1. Verifies `Cargo.toml` version matches tag
2. Builds release binaries for:
   - `x86_64-unknown-linux-gnu`
   - `x86_64-unknown-linux-musl` (static)
   - `aarch64-unknown-linux-gnu`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
3. Builds RPM packages for `x86_64` and `aarch64`
4. Generate SHA-256 checksums for all artifacts
5. Attests build provenance (SLSA)
6. Create GitHub Release /w changelog and all artifacts

**`publish.yml`** (release published):
1. Verifies crate builds and tests pass
2. Runs `cargo publish --dry-run`
3. Publishes to crates.io

## Secrets

| Secret | Where to set | How to get |
|--------|-------------|------------|
| `CARGO_REGISTRY_TOKEN` | Repository > Settings > Secrets | https://crates.io/settings/tokens -- create a token scoped to `publish-update` for the `scheck` crate |
| `GITHUB_TOKEN` | Automatic | Provided by GitHub Actions |
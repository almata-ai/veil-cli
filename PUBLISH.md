# Publishing the `veil` CLI

The CLI is open source and distributed via package managers, so it lives in this
**public** repo (`almata-ai/veil-cli`). Releases are automated with **GoReleaser**:
tag `vX.Y.Z` → cross-compiled binaries + a GitHub Release + a Homebrew cask + a Scoop
manifest, all in one shot.

## Public or private?
**Public** — Homebrew/Scoop and `go install` all pull from public release artifacts.
It holds no secrets or sealing IP (it's a thin HTTP client of the VeilCC API).

## One-time setup

1. **Create two tap repos** (public) under your org:
   - `almata-ai/homebrew-tap` (Homebrew) — just needs to exist; GoReleaser commits the
     formula. (Scoop/Windows can be added later with a `scoop-bucket` repo.)

2. **A token for cross-repo publishing.** The default `GITHUB_TOKEN` can't push to
   other repos, so create a fine-grained PAT (or classic PAT) with **contents: write**
   on `homebrew-tap`, and add it to **this** repo as the secret
   **`HOMEBREW_TAP_GITHUB_TOKEN`** (Settings → Secrets and variables → Actions).

3. **Create + push this repo:**
   ```sh
   cd veil-cli
   gh repo create almata-ai/veil-cli --public --source=. --remote=origin --push \
     --description "VeilCC CLI — protect compiled binaries against AI reverse-engineering"
   ```

## Cut a release
```sh
git tag -a v0.1.0 -m "veil v0.1.0" && git push origin v0.1.0
```
`release.yml` runs GoReleaser, which builds darwin/linux/windows × amd64/arm64,
creates the GitHub Release with archives + `checksums.txt`, and updates the Homebrew
cask + Scoop manifest. (Validate locally first with `goreleaser release --snapshot --clean`.)

## How users install
```sh
# macOS / Linux
brew install almata-ai/tap/veil

# Go toolchain
go install github.com/almata-ai/veil-cli@latest

# or grab a binary from the Releases page
```

## Notes
- **Unsigned binaries.** The Homebrew cask strips the macOS quarantine bit so the
  binary runs; long term, Apple code-signing + notarization is cleaner (and a Windows
  Authenticode cert for Scoop). Add signing to `.goreleaser.yaml` when you have certs.
- Default `--api-url` is `https://veilcc.com` (`defaultAPIURL` in `main.go`).

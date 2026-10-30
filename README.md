<p align="center">
  <img src="../assets/veilcc-icon.png" alt="VeilCC" width="88" />
</p>

# veil — the VeilCC CLI

The open-source client for the [VeilCC](https://veilcc.com) Protection API. It
protects compiled binaries against AI reverse-engineering by sealing or
obfuscating the functions worth stealing. The protection runs server-side, so the
algorithm never ships inside your artifact; this CLI is a thin, dependency-free
HTTP client (Go standard library only).

## Install

```sh
# Homebrew (once released)
brew install almata-ai/tap/veil

# or build from source (Go 1.23+)
go install github.com/almata-ai/veil-cli@latest   # installs the `veil` binary
```

## Authenticate

Either sign in from the browser (recommended for people):

```sh
veil login       # opens the browser to authorize, stores a token in ~/.config/veilcc
veil whoami      # shows the workspace the token belongs to
veil logout      # forgets the token
```

…or use an API key (recommended for CI), created in the console → **API keys**:

```sh
export VEILCC_KEY="veil_sk_live_…"   # or pass --api-key
```

Resolution order for every command: `--api-key` flag → `VEILCC_KEY` → the token
from `veil login`.

## Use

Protection is **composable**: obfuscate the whole module and/or seal the annotated
functions, and sealing's key is `embedded` or `device-bound`. Obfuscation runs on
**source** (`.c`/`.cpp`, compiled on the runner) or **LLVM IR** (`.ll`/`.bc`); sealing
works on a compiled object or source. A pre-compiled object has no IR, so it can be
sealed but not obfuscated.

```sh
# exposure scan — free, unmetered: what a decompiler + AI read first
veil scan app.o

# seal a crown-only C/C++ object
veil protect --seal crown.o --proto "uint32_t check_license(const char*)" -o crown.sealed.o

# seal by symbol + signature (Rust / any C-ABI object)
veil protect --seal --symbols check_license \
  --proto "uint32_t check_license(const unsigned char*, size_t)" \
  liblicense.o -o license.sealed.o

# obfuscate the module AND seal the crown jewel (source or IR), reproducible seed
veil protect --obfuscate --seal --seed 0x9f3ac1 crown.c \
  --proto "uint32_t check_license(const char*)" -o crown.o

# seal with a device-bound key, unwrapped at runtime, never in the file
veil protect --seal --seal-key device-bound --key-provider veil_key \
  attest.o --proto "uint32_t attest(const char*)" -o attest.sealed.o --receipt build-receipt.json

# verify a build receipt against its artifact (offline, e.g. in CI)
veil verify build-receipt.json --artifact app.sealed.o
```

### Flags (`veil protect`)

| flag | applies to | meaning |
|------|-----------|---------|
| `--obfuscate` | — | obfuscate on source / IR; default MBA + decoys (lighter) |
| `--post-obfuscate` | all | strip and randomize retained private names after compilation; verify code/data, relocations, and exports/imports |
| `--scope sealed` | seal | restrict optional IR obfuscation to the exact C symbol selected for sealing (the web workflow) |
| `--strip` | all | remove debug info and discardable local symbols after obfuscation/sealing; usable alone on compiled objects |
| `--obfuscate-max` | obfuscate | also apply control-flow flattening (heavier); implies `--obfuscate` |
| `--seal` | — | seal the annotated functions (encrypt at rest) |
| `--seal-key` | seal | `embedded` (default) · `device-bound` |
| `--level` | — | legacy alias: `obfuscate` · `seal` · `device-bound` → maps to the flags above |
| `--proto` | seal | sealed function's C signature; hosted API currently accepts one per request |
| `--symbols` | both | comma-separated symbols when source has no annotation |
| `--target` | both | output triple, default `auto-detect` |
| `--persistent` | seal | cache the decrypted function (default scrubs per call) |
| `--anti-debug` | seal | fold a debugger-present check into the key |
| `--key-provider SYM` | device-bound | runtime key-unwrap symbol |
| `--seed 0x…` | obfuscate/post-compile | fixed seed for IR transformations and private names; sealing still uses fresh encryption randomness |
| `-o`, `--out` | both | output path (required) |
| `--receipt` | both | write the build receipt JSON here |
| `--api-key` | all | overrides `VEILCC_KEY` |
| `--api-url` | all | self-host / on-prem base URL (`VEILCC_API_URL`) |

On-prem and air-gapped builds point `--api-url` at their own Protection API; the
object never leaves the network.

Full reference: https://veilcc.com/docs/cli

### Stack post-compile hardening

```sh
veil protect --obfuscate --seal --post-obfuscate crown.c \
  --proto "uint32_t check_license(const char*)" -o crown.o --receipt receipt.json
veil verify receipt.json --artifact crown.o
```

The stages run in order: IR obfuscation → object sealing → post-compile hardening.
`--post-obfuscate` is opt-in and includes stripping, then randomizes retained
private symbol names using a per-build seed. Code/data section contents, symbol
addresses/types, exports/imports and post-strip relocations are checked before
returning the object. A failed check or missing tool returns an error. Section
names are preserved for linker scripts; public names and arbitrary strings remain.
Some formats discard all eligible locals during stripping, so the receipt may
honestly report zero names renamed.

This stage supports relocatable 64-bit little-endian Mach-O/ELF (arm64/x86-64)
and standard COFF x86-64. Linked/signed executables, archives, embedded LTO and
extended COFF relocations are rejected. Run it before linking/signing; builds
that inspect private symbol names should leave it disabled. It does not pack
executables, rewrite instructions, or establish immunity to AI-assisted analysis.
The encrypted code at rest comes from sealing. Example without sealing:
`veil protect --post-obfuscate app.o -o app.hardened.o`.

For just metadata removal, the lighter `--strip` option remains available.
`--strip` uses `llvm-strip --strip-debug -x`, preserving exports and locals needed
by relocations. `veil protect --strip app.o -o app.stripped.o` strips an object
without sealing. Stripping removes analysis metadata; it does not encrypt code or
measure resistance to reverse engineering. The current receipt verifier checks a
shortened artifact SHA-256 hash; it does not verify a cryptographic signature.

For sealing, use a crown-only compilation unit and supply `--proto`. Keep other
exported functions and global data in separate host objects. Replacement-object
builds reject additional exports rather than silently dropping them.

### Plan limits and upgrade prompts

The hosted API allows one Free build per month, 500 Pro builds, and 1,000,000
Enterprise builds. Device-bound sealing requires Enterprise. Scanning is unmetered.
The server checks the workspace's current plan, so existing API keys continue to
work after upgrades and downgrades.

A blocked feature returns HTTP 403; an exhausted or fully reserved build allowance
returns HTTP 429. The CLI exits without writing an artifact or receipt and prints
the server's upgrade/sales URL. Quota errors also include the reset date. Open the
URL to upgrade; the CLI does not open a browser or initiate payment automatically.

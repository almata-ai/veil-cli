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

# seal a C/C++ object (functions auto-discovered from veil:seal)
veil protect --seal app.o -o app.sealed.o

# seal by symbol + signature (Rust / any C-ABI object)
veil protect --seal --symbols check_license \
  --proto "uint32_t check_license(const unsigned char*, size_t)" \
  liblicense.o -o license.sealed.o

# obfuscate the module AND seal the crown jewel (source or IR), reproducible seed
veil protect --obfuscate --seal --seed 0x9f3ac1… crown.c -o crown.o

# seal with a device-bound key, unwrapped at runtime, never in the file
veil protect --seal --seal-key device-bound --key-provider veil_key \
  attest.o -o attest.sealed.o --receipt build-receipt.json

# verify a build receipt against its artifact (offline, e.g. in CI)
veil verify build-receipt.json --artifact app.sealed.o
```

### Flags (`veil protect`)

| flag | applies to | meaning |
|------|-----------|---------|
| `--obfuscate` | — | obfuscate on source / IR; default MBA + decoys (lighter) |
| `--obfuscate-max` | obfuscate | also apply control-flow flattening (heavier); implies `--obfuscate` |
| `--seal` | — | seal the annotated functions (encrypt at rest) |
| `--seal-key` | seal | `embedded` (default) · `device-bound` |
| `--level` | — | legacy alias: `obfuscate` · `seal` · `device-bound` → maps to the flags above |
| `--proto` (repeatable) | seal | sealed function's C signature |
| `--symbols` | both | comma-separated symbols when source has no annotation |
| `--target` | both | output triple, default `auto-detect` |
| `--persistent` | seal | cache the decrypted function (default scrubs per call) |
| `--anti-debug` | seal | fold a debugger-present check into the key |
| `--key-provider SYM` | device-bound | runtime key-unwrap symbol |
| `--seed 0x…` | obfuscate | fixed build seed for a reproducible build |
| `-o`, `--out` | both | output path (required) |
| `--receipt` | both | write the signed receipt JSON here |
| `--api-key` | all | overrides `VEILCC_KEY` |
| `--api-url` | all | self-host / on-prem base URL (`VEILCC_API_URL`) |

On-prem and air-gapped builds point `--api-url` at their own Protection API; the
object never leaves the network.

Full reference: https://veilcc.com/docs/cli

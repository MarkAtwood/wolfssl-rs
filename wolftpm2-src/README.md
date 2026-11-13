> **EXPERIMENTAL - NOT SUPPORTED**
>
> This crate is experimental and is not supported. Do not use it in production.
> The official wolfSSL Rust crate is **wolfssl-wolfcrypt**:
> https://github.com/wolfSSL/wolfssl/tree/master/wrapper/rust/wolfssl-wolfcrypt

# wolftpm2-src

Build-script crate that compiles [wolfTPM](https://github.com/wolfSSL/wolfTPM)
from C source as part of a Cargo build. Used internally by
[`wolftpm2-sys`](../wolftpm2-sys); has no public Rust API.

## Why

Cargo cannot compile C libraries on behalf of an arbitrary crate — each
crate that links a C library needs a `build.rs` that drives the C
compiler. The three-crate split (`wolftpm2-src` → `wolftpm2-sys` →
[`wolftpm2`](../wolftpm2)) mirrors the pattern used throughout this
workspace ([`wolfssl-src`](../wolfssl-src),
[`wolfhsm-src`](../wolfhsm-src)) and separates concerns cleanly:

- `wolftpm2-src` owns the C build; it can be versioned and replaced
  without touching the FFI or the safe Rust API.
- [`wolftpm2-sys`](../wolftpm2-sys) owns the FFI boundary; bindgen runs
  there.
- [`wolftpm2`](../wolftpm2) owns the safe Rust API.

## Usage

This crate is not intended to be used directly. Add
[`wolftpm2-sys`](../wolftpm2-sys) or [`wolftpm2`](../wolftpm2) to your
`Cargo.toml` instead.

If you need to use `wolftpm2-src` directly (e.g. to build a different FFI
crate against the same wolfTPM build), declare it as a regular
`[dependency]` rather than a `[build-dependency]` so that Cargo
propagates the `DEP_WOLFTPM2_SRC_*` metadata to your build script:

```toml
[dependencies]
wolftpm2-src = "0.2"
```

The wolfTPM source tree must be available, supplied by either of:

```sh
# Option 1: point to a local wolfTPM clone
export WOLFTPM_SRC=/path/to/wolfTPM

# Option 2: bundled submodule (tracks upstream wolfSSL/wolfTPM main)
git submodule update --init wolftpm2-src/wolftpm
```

The wolfSSL headers are also required (wolfTPM uses wolfSSL/wolfCrypt
internally for RSA, ECC, and hash operations). Supply them via any of:

| Variable | Description |
|---|---|
| `WOLFSSL_INCLUDE_DIR` | Direct path to the wolfSSL include directory |
| `WOLFSSL_DIR` | Install prefix — headers at `$WOLFSSL_DIR/include` |
| `WOLFSSL_SRC` | wolfSSL source tree root (vendored build) |

Variables are checked in the order listed above. The pre-built wolfSSL
must have been compiled with `WOLF_CRYPTO_CB` enabled.

## How it works

`build.rs` performs four steps:

1. **Locate wolfTPM source** — checks `WOLFTPM_SRC` first, then falls
   back to the bundled git submodule at `wolftpm2-src/wolftpm/`.
2. **Locate wolfSSL headers** — checks `WOLFSSL_INCLUDE_DIR`,
   `WOLFSSL_DIR`, then `WOLFSSL_SRC` in that priority order (same as
   the rest of the workspace).
3. **Generate `wolftpm/options.h`** in `OUT_DIR` — wolfTPM's headers
   unconditionally `#include <wolftpm/options.h>`. This generated file
   selects the transport backend based on Cargo features and the target
   OS. On Linux with no feature selected it defaults to
   `WOLFTPM_LINUX_DEV` (the `/dev/tpm0` kernel driver) so that
   `hal/tpm_io.h` maps `TPM2_IoCb` to `NULL`, which is what the kernel
   driver path requires.
4. **Compile wolfTPM** — uses the `cc` crate to compile the core source
   files (`tpm2.c`, `tpm2_wrap.c`, `tpm2_packet.c`, `tpm2_param_enc.c`,
   `tpm2_util.c`, `tpm2_crypto.c`) and optional transport files
   (`tpm2_cryptocb.c`, `tpm2_linux.c`, `tpm2_swtpm.c`, `tpm2_tis.c`)
   when present.

The compiled library path and wolfTPM include directory are emitted as
Cargo metadata (`DEP_WOLFTPM2_SRC_LIB`, `DEP_WOLFTPM2_SRC_INCLUDE`) for
consumption by [`wolftpm2-sys`](../wolftpm2-sys).

| Feature | Description |
|---|---|
| `linux-dev` | Compile wolfTPM with Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Compile wolfTPM with software TPM socket transport (swtpm, IBM TPM2 simulator) |

If neither feature is selected, the build defaults to
`WOLFTPM_LINUX_DEV` on Linux. Both features may be enabled
simultaneously.

## References

- [wolftpm2](../wolftpm2) — safe Rust API; use this unless you have a specific reason not to
- [wolftpm2-sys](../wolftpm2-sys) — raw FFI bindings consumer of this crate
- [wolftpm2-tss](../wolftpm2-tss) — tpm-rs TSS backend
- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [wolfTPM documentation](https://www.wolfssl.com/docs/wolftpm/)
- [wolfTPM manual](https://wolfssl.github.io/wolfTPM/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfTPM is copyright wolfSSL Inc. and its contributors.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfTPM C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)

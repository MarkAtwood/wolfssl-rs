> **EXPERIMENTAL - NOT SUPPORTED**
>
> This crate is experimental and is not supported. Do not use it in production.
> The official wolfSSL Rust crate is **wolfssl-wolfcrypt**:
> https://github.com/wolfSSL/wolfssl/tree/master/wrapper/rust/wolfssl-wolfcrypt

# wolfcrypt-dpe-conformance

Cross-validation and conformance tests for [`wolfcrypt-dpe`](../wolfcrypt-dpe).
Not published (`publish = false`); test crate only.

## Why

[`wolfcrypt-dpe`](../wolfcrypt-dpe) implements the
[caliptra-dpe](https://github.com/chipsalliance/caliptra-dpe) `Crypto`
trait. Without independent oracles, a bug that produces consistently
wrong-but-internally-consistent output (e.g. a swapped curve constant, an
off-by-one in HKDF info encoding) would pass any test the implementation
wrote against itself. This crate provides the independent oracles:

- **Behavioural equivalence to the reference RustCrypto backend** — same
  DPE command sequences run through both backends, deterministic outputs
  must match bit-for-bit.
- **Independent X.509 verification** — DPE-generated certificates are
  parsed with `x509-cert` and the ECDSA signatures verified with the
  RustCrypto `p256` / `p384` crates, not with wolfCrypt.
- **Trait contract conformance** — `Hasher`, `Crypto::rand_bytes`, HKDF,
  and key-pair derivation are tested for the invariants the trait is
  supposed to guarantee, regardless of backend.

This is the safety net that makes `wolfcrypt-dpe` claims about correctness
defensible.

## How it works

```text
              ┌────────────────────────┐
              │ caliptra-dpe DpeInstance │  same engine, both backends
              └──────────┬─────────────┘
                         │
         ┌───────────────┴────────────────┐
         │                                │
   ┌─────▼──────┐                  ┌──────▼──────┐
   │ Wolf env   │                  │ Reference   │
   │ wolfcrypt- │                  │ RustCrypto  │
   │ dpe        │                  │ caliptra-   │
   │            │                  │ dpe-crypto  │
   │            │                  │ (rustcrypto │
   │            │                  │  feature)   │
   └────────────┘                  └─────────────┘
         │                                │
         └────────► compare ◄─────────────┘
                  pubkeys / sigs /
                  cert bytes / errors
```

The `tests/` directory contains 27 integration test files (each with
multiple `#[test]` functions) organised by area:

| Area | Tests |
|---|---|
| DPE engine commands | `dpe_init`, `dpe_certify`, `dpe_derive`, `dpe_destroy`, `dpe_get_chain`, `dpe_get_profile`, `dpe_multi_context`, `dpe_negative`, `dpe_rotate`, `dpe_sign` |
| Cross-backend equivalence | `dpe_cross_backend`, `hash_equiv`, `hkdf_equiv`, `keypair_equiv`, `sign_cross` |
| X.509 cert validation | `cert_chain`, `cert_dice_extensions`, `cert_signature`, `cert_structure` |
| Trait conformance | `hasher_contract`, `rng_contract` |
| Misc invariants | `alias_key`, `canary`, `exported_cdi`, `pubkey_serial`, `test_count`, `upstream_dpe_tests` |

`src/lib.rs` is intentionally empty; the crate exists only as a host for
`tests/` and shared helpers under `tests/helpers/`. Both wolf and
reference backends use `caliptra-dpe-crypto` from the same git revision —
the difference is the `rustcrypto` feature on the reference side.

## Running

```sh
cargo test -p wolfcrypt-dpe-conformance
```

All tests are pure CPU; no hardware required. The wolf backend uses the
software-DRBG path (`WolfCryptDpe::new()`).

## References

- [wolfcrypt-dpe](../wolfcrypt-dpe) — backend under test
- [caliptra-dpe](https://github.com/chipsalliance/caliptra-dpe) — DPE
  reference implementation and `caliptra-dpe-crypto` trait crate
- [`x509-cert`](https://docs.rs/x509-cert/) — independent X.509 parser
- [`p256`](https://docs.rs/p256/) /
  [`p384`](https://docs.rs/p384/) — independent ECDSA verifiers
- [workspace README](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

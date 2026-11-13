mod helpers;

use aead::{AeadInOut, KeyInit, Nonce};
use hybrid_array::Array;
use helpers::{random_bytes, SYMMETRIC_LENGTHS};
use rand::rng;

/// Macro that generates a full suite of cross-validation tests for an
/// AEAD algorithm, comparing the wolfCrypt-backed implementation against
/// a pure-Rust RustCrypto implementation.
macro_rules! aead_equiv {
    ($mod_name:ident, $wolf:ty, $pure:ty, $key_len:expr, $nonce_len:expr, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::*;

            /// Same key + nonce + plaintext + AAD must produce identical
            /// ciphertext and tag from both implementations.
            #[test]
            fn encrypt_equiv() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 64);
                let aad = random_bytes(&mut rng, 16);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut wolf_buf = pt.clone();
                let wolf_tag = wolf
                    .encrypt_inout_detached(&nonce, &aad, (&mut wolf_buf[..]).into())
                    .expect("wolf encrypt_inout_detached must succeed");

                let mut pure_buf = pt.clone();
                let pure_tag = pure
                    .encrypt_inout_detached(&nonce, &aad, (&mut pure_buf[..]).into())
                    .expect("pure encrypt_inout_detached must succeed");

                assert_eq!(
                    wolf_buf, pure_buf,
                    "ciphertext must match between wolf and pure-Rust"
                );
                assert_eq!(
                    wolf_tag.as_slice(),
                    pure_tag.as_slice(),
                    "authentication tag must match between wolf and pure-Rust"
                );
            }

            /// Wolf encrypts, pure decrypts. Recovered plaintext must match.
            #[test]
            fn cross_wolf_to_pure() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 80);
                let aad = random_bytes(&mut rng, 12);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut ct = pt.clone();
                let tag = wolf
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct[..]).into())
                    .expect("wolf encrypt must succeed");

                let mut recovered = ct.clone();
                pure.decrypt_inout_detached(&nonce, &aad, (&mut recovered[..]).into(), &tag)
                    .expect("pure decrypt of wolf-encrypted data must succeed");

                assert_eq!(
                    recovered, pt,
                    "pure-Rust must recover original plaintext from wolf ciphertext"
                );
            }

            /// Pure encrypts, wolf decrypts. Recovered plaintext must match.
            #[test]
            fn cross_pure_to_wolf() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 80);
                let aad = random_bytes(&mut rng, 12);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut ct = pt.clone();
                let tag = pure
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct[..]).into())
                    .expect("pure encrypt must succeed");

                let mut recovered = ct.clone();
                wolf.decrypt_inout_detached(&nonce, &aad, (&mut recovered[..]).into(), &tag)
                    .expect("wolf decrypt of pure-encrypted data must succeed");

                assert_eq!(
                    recovered, pt,
                    "wolf must recover original plaintext from pure-Rust ciphertext"
                );
            }

            /// Empty plaintext: both must produce identical (empty) CT and
            /// matching tags.
            #[test]
            fn empty_pt_equiv() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let aad = random_bytes(&mut rng, 20);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut wolf_buf: Vec<u8> = Vec::new();
                let wolf_tag = wolf
                    .encrypt_inout_detached(&nonce, &aad, (&mut wolf_buf[..]).into())
                    .expect("wolf encrypt empty PT must succeed");

                let mut pure_buf: Vec<u8> = Vec::new();
                let pure_tag = pure
                    .encrypt_inout_detached(&nonce, &aad, (&mut pure_buf[..]).into())
                    .expect("pure encrypt empty PT must succeed");

                assert!(
                    wolf_buf.is_empty(),
                    "wolf CT for empty PT must be empty"
                );
                assert!(
                    pure_buf.is_empty(),
                    "pure CT for empty PT must be empty"
                );
                assert_eq!(
                    wolf_tag.as_slice(),
                    pure_tag.as_slice(),
                    "tags for empty PT must match between wolf and pure-Rust"
                );
            }

            /// Empty AAD: both must produce identical CT and tag.
            #[test]
            fn empty_aad_equiv() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 48);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut wolf_buf = pt.clone();
                let wolf_tag = wolf
                    .encrypt_inout_detached(&nonce, &[], (&mut wolf_buf[..]).into())
                    .expect("wolf encrypt with empty AAD must succeed");

                let mut pure_buf = pt.clone();
                let pure_tag = pure
                    .encrypt_inout_detached(&nonce, &[], (&mut pure_buf[..]).into())
                    .expect("pure encrypt with empty AAD must succeed");

                assert_eq!(
                    wolf_buf, pure_buf,
                    "CT must match with empty AAD"
                );
                assert_eq!(
                    wolf_tag.as_slice(),
                    pure_tag.as_slice(),
                    "tags must match with empty AAD"
                );
            }

            /// Various plaintext lengths: CT and tags must match for each.
            #[test]
            fn various_lengths() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let aad = random_bytes(&mut rng, 8);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                for &len in SYMMETRIC_LENGTHS.iter().filter(|&&l| l > 0) {
                    // Fresh nonce per length to avoid nonce reuse.
                    let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                    let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();
                    let pt = random_bytes(&mut rng, len);

                    let mut wolf_buf = pt.clone();
                    let wolf_tag = wolf
                        .encrypt_inout_detached(&nonce, &aad, (&mut wolf_buf[..]).into())
                        .expect("wolf encrypt must succeed");

                    let mut pure_buf = pt.clone();
                    let pure_tag = pure
                        .encrypt_inout_detached(&nonce, &aad, (&mut pure_buf[..]).into())
                        .expect("pure encrypt must succeed");

                    assert_eq!(
                        wolf_buf, pure_buf,
                        "CT mismatch at PT length {len}"
                    );
                    assert_eq!(
                        wolf_tag.as_slice(),
                        pure_tag.as_slice(),
                        "tag mismatch at PT length {len}"
                    );
                }
            }

            /// Encrypt with key A, attempt decrypt with key B. Both impls
            /// must reject.
            #[test]
            fn wrong_key_both_reject() {
                let mut rng = rng();
                let key_a_bytes = random_bytes(&mut rng, $key_len);
                let key_b_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 32);
                let aad = random_bytes(&mut rng, 8);

                let key_a = Array::try_from(&(&key_a_bytes)[..]).unwrap();
                let key_b = Array::try_from(&(&key_b_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                // Encrypt with key A using wolf.
                let wolf_a = <$wolf as KeyInit>::new(&key_a);
                let mut ct = pt.clone();
                let tag = wolf_a
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct[..]).into())
                    .expect("encrypt must succeed");

                // Decrypt with key B using wolf.
                let wolf_b = <$wolf as KeyInit>::new(&key_b);
                let mut wolf_ct = ct.clone();
                let wolf_result =
                    wolf_b.decrypt_inout_detached(&nonce, &aad, (&mut wolf_ct[..]).into(), &tag);
                assert!(
                    wolf_result.is_err(),
                    "wolf must reject decryption with wrong key"
                );

                // Decrypt with key B using pure.
                let pure_b = <$pure as KeyInit>::new(&key_b);
                let mut pure_ct = ct.clone();
                let pure_result =
                    pure_b.decrypt_inout_detached(&nonce, &aad, (&mut pure_ct[..]).into(), &tag);
                assert!(
                    pure_result.is_err(),
                    "pure-Rust must reject decryption with wrong key"
                );
            }

            /// Encrypt, flip a CT byte, both impls must reject decryption.
            #[test]
            fn tampered_ct_both_reject() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 64);
                let aad = random_bytes(&mut rng, 8);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut ct = pt.clone();
                let tag = wolf
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct[..]).into())
                    .expect("encrypt must succeed");

                // Flip first byte of CT.
                ct[0] ^= 0xFF;

                let mut wolf_ct = ct.clone();
                let wolf_result =
                    wolf.decrypt_inout_detached(&nonce, &aad, (&mut wolf_ct[..]).into(), &tag);
                assert!(
                    wolf_result.is_err(),
                    "wolf must reject tampered ciphertext"
                );

                let mut pure_ct = ct.clone();
                let pure_result =
                    pure.decrypt_inout_detached(&nonce, &aad, (&mut pure_ct[..]).into(), &tag);
                assert!(
                    pure_result.is_err(),
                    "pure-Rust must reject tampered ciphertext"
                );
            }

            /// Encrypt, flip a tag byte, both impls must reject decryption.
            #[test]
            fn tampered_tag_both_reject() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 48);
                let aad = random_bytes(&mut rng, 8);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut ct = pt.clone();
                let tag = wolf
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct[..]).into())
                    .expect("encrypt must succeed");

                // Flip first byte of tag.
                let mut bad_tag_bytes = tag.as_slice().to_vec();
                bad_tag_bytes[0] ^= 0xFF;
                let bad_tag = Array::try_from(&(&bad_tag_bytes)[..]).unwrap();

                let mut wolf_ct = ct.clone();
                let wolf_result =
                    wolf.decrypt_inout_detached(&nonce, &aad, (&mut wolf_ct[..]).into(), &bad_tag);
                assert!(
                    wolf_result.is_err(),
                    "wolf must reject tampered tag"
                );

                let mut pure_ct = ct.clone();
                let pure_result =
                    pure.decrypt_inout_detached(&nonce, &aad, (&mut pure_ct[..]).into(), &bad_tag);
                assert!(
                    pure_result.is_err(),
                    "pure-Rust must reject tampered tag"
                );
            }

            /// Encrypt with nonce A, decrypt with nonce B. Both must reject.
            #[test]
            fn wrong_nonce_both_reject() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_a_bytes = random_bytes(&mut rng, $nonce_len);
                let nonce_b_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 32);
                let aad = random_bytes(&mut rng, 8);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce_a = Nonce::<$wolf>::try_from(&(&nonce_a_bytes)[..]).unwrap();
                let nonce_b = Nonce::<$wolf>::try_from(&(&nonce_b_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut ct = pt.clone();
                let tag = wolf
                    .encrypt_inout_detached(&nonce_a, &aad, (&mut ct[..]).into())
                    .expect("encrypt must succeed");

                let mut wolf_ct = ct.clone();
                let wolf_result =
                    wolf.decrypt_inout_detached(&nonce_b, &aad, (&mut wolf_ct[..]).into(), &tag);
                assert!(
                    wolf_result.is_err(),
                    "wolf must reject decryption with wrong nonce"
                );

                let mut pure_ct = ct.clone();
                let pure_result =
                    pure.decrypt_inout_detached(&nonce_b, &aad, (&mut pure_ct[..]).into(), &tag);
                assert!(
                    pure_result.is_err(),
                    "pure-Rust must reject decryption with wrong nonce"
                );
            }

            /// Encrypt with AAD "foo", decrypt with AAD "bar". Both must reject.
            #[test]
            fn wrong_aad_both_reject() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 32);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);
                let pure = <$pure as KeyInit>::new(&key);

                let mut ct = pt.clone();
                let tag = wolf
                    .encrypt_inout_detached(&nonce, b"foo", (&mut ct[..]).into())
                    .expect("encrypt must succeed");

                let mut wolf_ct = ct.clone();
                let wolf_result =
                    wolf.decrypt_inout_detached(&nonce, b"bar", (&mut wolf_ct[..]).into(), &tag);
                assert!(
                    wolf_result.is_err(),
                    "wolf must reject decryption with wrong AAD"
                );

                let mut pure_ct = ct.clone();
                let pure_result =
                    pure.decrypt_inout_detached(&nonce, b"bar", (&mut pure_ct[..]).into(), &tag);
                assert!(
                    pure_result.is_err(),
                    "pure-Rust must reject decryption with wrong AAD"
                );
            }

            /// Same PT encrypted with different keys must yield different CT.
            #[test]
            fn canary_different_key_different_ct() {
                let mut rng = rng();
                let key_a_bytes = random_bytes(&mut rng, $key_len);
                let key_b_bytes = random_bytes(&mut rng, $key_len);
                let nonce_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 64);
                let aad = random_bytes(&mut rng, 8);

                let key_a = Array::try_from(&(&key_a_bytes)[..]).unwrap();
                let key_b = Array::try_from(&(&key_b_bytes)[..]).unwrap();
                let nonce = Nonce::<$wolf>::try_from(&(&nonce_bytes)[..]).unwrap();

                let wolf_a = <$wolf as KeyInit>::new(&key_a);
                let wolf_b = <$wolf as KeyInit>::new(&key_b);

                let mut ct_a = pt.clone();
                let tag_a = wolf_a
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct_a[..]).into())
                    .expect("encrypt with key A must succeed");

                let mut ct_b = pt.clone();
                let tag_b = wolf_b
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct_b[..]).into())
                    .expect("encrypt with key B must succeed");

                // Either CT or tag (or both) must differ.
                let same_ct = ct_a == ct_b;
                let same_tag = tag_a.as_slice() == tag_b.as_slice();
                assert!(
                    !(same_ct && same_tag),
                    "different keys must produce different CT or tag"
                );
            }

            /// Same key + PT with different nonces must yield different CT.
            #[test]
            fn canary_different_nonce_different_ct() {
                let mut rng = rng();
                let key_bytes = random_bytes(&mut rng, $key_len);
                let nonce_a_bytes = random_bytes(&mut rng, $nonce_len);
                let nonce_b_bytes = random_bytes(&mut rng, $nonce_len);
                let pt = random_bytes(&mut rng, 64);
                let aad = random_bytes(&mut rng, 8);

                let key = Array::try_from(&(&key_bytes)[..]).unwrap();
                let nonce_a = Nonce::<$wolf>::try_from(&(&nonce_a_bytes)[..]).unwrap();
                let nonce_b = Nonce::<$wolf>::try_from(&(&nonce_b_bytes)[..]).unwrap();

                let wolf = <$wolf as KeyInit>::new(&key);

                let mut ct_a = pt.clone();
                let tag_a = wolf
                    .encrypt_inout_detached(&nonce_a, &aad, (&mut ct_a[..]).into())
                    .expect("encrypt with nonce A must succeed");

                let mut ct_b = pt.clone();
                let tag_b = wolf
                    .encrypt_inout_detached(&nonce_b, &aad, (&mut ct_b[..]).into())
                    .expect("encrypt with nonce B must succeed");

                let same_ct = ct_a == ct_b;
                let same_tag = tag_a.as_slice() == tag_b.as_slice();
                assert!(
                    !(same_ct && same_tag),
                    "different nonces must produce different CT or tag"
                );
            }
        }
    };
}

// --- AES-128-GCM ---
aead_equiv!(
    aes_128_gcm,
    wolfcrypt::Aes128Gcm,
    aes_gcm::Aes128Gcm,
    16,
    12,
    [wolfssl_aes_gcm]
);

// --- AES-256-GCM ---
aead_equiv!(
    aes_256_gcm,
    wolfcrypt::Aes256Gcm,
    aes_gcm::Aes256Gcm,
    32,
    12,
    [wolfssl_aes_gcm]
);

// --- ChaCha20-Poly1305 ---
aead_equiv!(
    chacha20_poly1305,
    wolfcrypt::ChaCha20Poly1305,
    chacha20poly1305::ChaCha20Poly1305,
    32,
    12,
    [wolfssl_chacha20_poly1305]
);

mod helpers;

macro_rules! ctr_equiv {
    ($mod_name:ident, $wolf:ty, $pure:ty, $key_len:expr, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            // CTR is a stream cipher — arbitrary lengths are valid
            // (contrast with CBC which requires block-aligned input).
            use super::helpers::{random_bytes, SYMMETRIC_LENGTHS};
            use cipher::{KeyIvInit, StreamCipher};
            use rand::rng;

            const KEY_LEN: usize = $key_len;
            const IV_LEN: usize = 16;

            #[test]
            fn encrypt_equiv() {
                let mut rng = rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, 64);

                let mut wolf_ct = pt.clone();
                let mut wolf = <$wolf>::new(
                    (&(&key)[..]).try_into().unwrap(),
                    (&(&iv)[..]).try_into().unwrap(),
                );
                wolf.apply_keystream(&mut wolf_ct);

                let mut pure_ct = pt.clone();
                let mut pure = <$pure>::new(
                    (&(&key)[..]).try_into().unwrap(),
                    (&(&iv)[..]).try_into().unwrap(),
                );
                pure.apply_keystream(&mut pure_ct);

                assert_eq!(
                    wolf_ct, pure_ct,
                    "{}: CTR encrypt must produce identical ciphertext",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn cross_round_trip() {
                let mut rng = rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, 100);

                // Wolf encrypts, pure decrypts
                let mut ct = pt.clone();
                let mut wolf = <$wolf>::new(
                    (&(&key)[..]).try_into().unwrap(),
                    (&(&iv)[..]).try_into().unwrap(),
                );
                wolf.apply_keystream(&mut ct);

                let mut recovered = ct.clone();
                let mut pure = <$pure>::new(
                    (&(&key)[..]).try_into().unwrap(),
                    (&(&iv)[..]).try_into().unwrap(),
                );
                pure.apply_keystream(&mut recovered);

                assert_eq!(
                    recovered, pt,
                    "{}: pure must decrypt what wolf encrypted (CTR is symmetric)",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn various_lengths() {
                let mut rng = rng();
                let key = random_bytes(&mut rng, KEY_LEN);

                for &len in SYMMETRIC_LENGTHS {
                    // Fresh IV per length so each iteration exercises an
                    // independent keystream (otherwise shorter lengths are
                    // strict prefixes of longer ones).
                    let iv = random_bytes(&mut rng, IV_LEN);
                    let pt = random_bytes(&mut rng, len);

                    let mut wolf_ct = pt.clone();
                    let mut wolf = <$wolf>::new(
                        (&(&key)[..]).try_into().unwrap(),
                        (&(&iv)[..]).try_into().unwrap(),
                    );
                    wolf.apply_keystream(&mut wolf_ct);

                    let mut pure_ct = pt.clone();
                    let mut pure = <$pure>::new(
                        (&(&key)[..]).try_into().unwrap(),
                        (&(&iv)[..]).try_into().unwrap(),
                    );
                    pure.apply_keystream(&mut pure_ct);

                    assert_eq!(
                        wolf_ct, pure_ct,
                        "{}: CTR mismatch at length {}",
                        stringify!($mod_name),
                        len
                    );
                }
            }

            #[test]
            fn partial_block_equiv() {
                let mut rng = rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);

                for &len in &[1usize, 7, 15] {
                    let pt = random_bytes(&mut rng, len);

                    let mut wolf_ct = pt.clone();
                    let mut wolf = <$wolf>::new(
                        (&(&key)[..]).try_into().unwrap(),
                        (&(&iv)[..]).try_into().unwrap(),
                    );
                    wolf.apply_keystream(&mut wolf_ct);

                    let mut pure_ct = pt.clone();
                    let mut pure = <$pure>::new(
                        (&(&key)[..]).try_into().unwrap(),
                        (&(&iv)[..]).try_into().unwrap(),
                    );
                    pure.apply_keystream(&mut pure_ct);

                    assert_eq!(
                        wolf_ct, pure_ct,
                        "{}: partial-block CTR mismatch at length {}",
                        stringify!($mod_name),
                        len
                    );
                }
            }

            #[test]
            fn canary_different_iv() {
                let mut rng = rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv_a = random_bytes(&mut rng, IV_LEN);
                let iv_b = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, 32);

                let mut ct_a = pt.clone();
                let mut wolf_a = <$wolf>::new(
                    (&(&key)[..]).try_into().unwrap(),
                    (&(&iv_a)[..]).try_into().unwrap(),
                );
                wolf_a.apply_keystream(&mut ct_a);

                let mut ct_b = pt.clone();
                let mut wolf_b = <$wolf>::new(
                    (&(&key)[..]).try_into().unwrap(),
                    (&(&iv_b)[..]).try_into().unwrap(),
                );
                wolf_b.apply_keystream(&mut ct_b);

                assert_ne!(
                    ct_a, ct_b,
                    "{}: different IVs must produce different CTR ciphertexts",
                    stringify!($mod_name)
                );
            }
        }
    };
}

ctr_equiv!(
    aes128_ctr,
    wolfcrypt::Aes128Ctr,
    ctr::Ctr128BE<aes::Aes128>,
    16,
    [wolfssl_aes_ctr]
);

ctr_equiv!(
    aes192_ctr,
    wolfcrypt::Aes192Ctr,
    ctr::Ctr128BE<aes::Aes192>,
    24,
    [wolfssl_aes_ctr, wolfssl_aes_192]
);

ctr_equiv!(
    aes256_ctr,
    wolfcrypt::Aes256Ctr,
    ctr::Ctr128BE<aes::Aes256>,
    32,
    [wolfssl_aes_ctr]
);

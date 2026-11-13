// tests/aes_gcm_tests.rs
//
// Known-answer tests for wolfCrypt's native AES-GCM API (wc_AesGcm*), using
// NIST SP 800-38D Appendix B Test Case 2.

use wolfcrypt_rs::{
    INVALID_DEVID, WcAes, wc_AesFree, wc_AesGcmDecrypt, wc_AesGcmEncrypt, wc_AesGcmSetKey,
    wc_AesInit,
};

/// AES-GCM context initialized and keyed; freed on drop.
struct Gcm(WcAes);

impl Gcm {
    fn new(key: &[u8]) -> Self {
        let mut aes = WcAes::zeroed();
        // SAFETY: `aes` is a zeroed WcAes; null heap and INVALID_DEVID select
        // the software implementation.
        let rc = unsafe { wc_AesInit(&mut aes, core::ptr::null_mut(), INVALID_DEVID) };
        assert_eq!(rc, 0, "wc_AesInit failed");
        // SAFETY: `aes` was initialized above; key points to key.len() bytes.
        let rc = unsafe { wc_AesGcmSetKey(&mut aes, key.as_ptr(), key.len() as u32) };
        assert_eq!(rc, 0, "wc_AesGcmSetKey failed");
        Gcm(aes)
    }

    fn seal(&mut self, nonce: &[u8; 12], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; 16];
        // SAFETY: all pointers are valid for the lengths passed; no AAD.
        let rc = unsafe {
            wc_AesGcmEncrypt(
                &mut self.0,
                ct.as_mut_ptr(),
                pt.as_ptr(),
                pt.len() as u32,
                nonce.as_ptr(),
                12,
                tag.as_mut_ptr(),
                16,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(rc, 0, "wc_AesGcmEncrypt failed");
        (ct, tag)
    }

    /// Returns wolfCrypt's return code and the recovered plaintext.
    fn open(&mut self, nonce: &[u8; 12], ct: &[u8], tag: &[u8; 16]) -> (i32, Vec<u8>) {
        let mut pt = vec![0u8; ct.len()];
        // SAFETY: all pointers are valid for the lengths passed; no AAD.
        let rc = unsafe {
            wc_AesGcmDecrypt(
                &mut self.0,
                pt.as_mut_ptr(),
                ct.as_ptr(),
                ct.len() as u32,
                nonce.as_ptr(),
                12,
                tag.as_ptr(),
                16,
                core::ptr::null(),
                0,
            )
        };
        (rc, pt)
    }
}

impl Drop for Gcm {
    fn drop(&mut self) {
        // SAFETY: self.0 was initialized by wc_AesInit in Gcm::new.
        unsafe { wc_AesFree(&mut self.0) };
    }
}

/// Key, IV and plaintext are all zero (16, 12 and 16 bytes); no AAD.
const CT: [u8; 16] = [
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
];
const TAG: [u8; 16] = [
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
];

#[test]
fn aes_128_gcm_nist_tc2_encrypt() {
    let (ct, tag) = Gcm::new(&[0u8; 16]).seal(&[0u8; 12], &[0u8; 16]);
    assert_eq!(ct, CT, "ciphertext does not match NIST SP 800-38D TC2");
    assert_eq!(tag, TAG, "tag does not match NIST SP 800-38D TC2");
}

#[test]
fn aes_128_gcm_nist_tc2_decrypt() {
    let (rc, pt) = Gcm::new(&[0u8; 16]).open(&[0u8; 12], &CT, &TAG);
    assert_eq!(rc, 0, "wc_AesGcmDecrypt rejected the NIST TC2 vector");
    assert_eq!(pt, [0u8; 16], "decryption did not recover the NIST TC2 plaintext");
}

/// A corrupted tag must be rejected.
#[test]
fn aes_gcm_rejects_wrong_tag() {
    let mut gcm = Gcm::new(&[0u8; 16]);
    let (ct, mut tag) = gcm.seal(&[0u8; 12], b"Hello, wolfSSL!X");
    tag[15] ^= 0xff;
    let (rc, _) = gcm.open(&[0u8; 12], &ct, &tag);
    assert_ne!(rc, 0, "decryption must fail with a corrupted tag");
}

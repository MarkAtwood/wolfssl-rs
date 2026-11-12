//! AES-CTR stream cipher (wolfCrypt native API).

use super::*;
use crate::error::len_as_u32;

macro_rules! impl_aes_ctr {
    ($name:ident, $key_size:ty, $key_bytes:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        // SAFETY: WcAes contains no thread-local state; safe to move to another thread.
        unsafe impl Send for $name {}

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self.aes was initialised by wc_AesInit; we have &mut self.
                unsafe {
                    wolfcrypt_rs::wc_AesFree(&mut self.aes as *mut wolfcrypt_rs::WcAes);
                }
            }
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl IvSizeUser for $name {
            type IvSize = U16;
        }

        impl KeyIvInit for $name {
            fn new(key: &Array<u8, $key_size>, iv: &Array<u8, U16>) -> Self {
                let mut aes = wolfcrypt_rs::WcAes::zeroed();

                // SAFETY: `aes` is freshly zeroed; null heap + INVALID_DEVID is standard.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesInit(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        core::ptr::null_mut(),
                        wolfcrypt_rs::INVALID_DEVID,
                    )
                };
                assert_eq!(rc, 0, "wc_AesInit failed (OOM or invalid device)");

                // SAFETY: `aes` was initialised by wc_AesInit; key/iv are valid slices.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesSetKey(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        key.as_ptr(),
                        $key_bytes,
                        iv.as_ptr(),
                        wolfcrypt_rs::AES_ENCRYPT,
                    )
                };
                assert_eq!(rc, 0, "wc_AesSetKey failed (invalid key length or IV)");

                Self { aes }
            }
        }

        impl StreamCipher for $name {
            fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
                // wolfCrypt tracks the counter/feedback state itself; there is no
                // keystream-length limit to enforce here.
                Ok(())
            }

            fn unchecked_apply_keystream_inout(
                &mut self,
                buf: cipher_trait::inout::InOutBuf<'_, '_, u8>,
            ) {
                let len = buf.len();
                let (in_ptr, out_ptr) = buf.into_raw();

                // SAFETY: `aes` is keyed; in_ptr/out_ptr from InOutBuf are valid.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesCtrEncrypt(
                        &mut self.aes as *mut wolfcrypt_rs::WcAes,
                        out_ptr,
                        in_ptr,
                        len_as_u32(len),
                    )
                };
                // cipher 0.5's keystream methods are infallible, so a wolfCrypt
                // failure can only be reported by panicking.
                assert_eq!(rc, 0, "wolfCrypt keystream operation failed");
            }

            fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
                buf.fill(0);
                self.unchecked_apply_keystream(buf);
            }
        }
    };
}

impl_aes_ctr!(
    Aes128Ctr,
    typenum::U16,
    16u32,
    "AES-128 in CTR mode, implementing `StreamCipher` and `KeyIvInit`."
);

#[cfg(wolfssl_aes_192)]
impl_aes_ctr!(
    Aes192Ctr,
    typenum::U24,
    24u32,
    "AES-192 in CTR mode, implementing `StreamCipher` and `KeyIvInit`."
);

impl_aes_ctr!(
    Aes256Ctr,
    typenum::U32,
    32u32,
    "AES-256 in CTR mode, implementing `StreamCipher` and `KeyIvInit`."
);

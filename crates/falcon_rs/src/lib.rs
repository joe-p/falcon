#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::{fmt::Display, ptr};

use uniffi::{self};

uniffi::setup_scaffolding!();

// Define the constants ourselves
const LOGN: u32 = 10; // For Falcon-1024

pub const PUBLIC_KEY_SIZE: usize = ((7 << (LOGN - 2)) + 1) as usize;
pub const PRIVATE_KEY_SIZE: usize = (((10 - (LOGN >> 1)) << (LOGN - 2)) + (1 << LOGN) + 1) as usize;
pub const CT_SIGNATURE_SIZE: usize = ((3 << (LOGN - 1)) + 41) as usize;
pub const SIGNATURE_MAX_SIZE: usize = (((11 << LOGN) + (101 >> (10 - LOGN)) + 7) >> 3) + 2;
pub const N: usize = 1 << LOGN;

#[derive(uniffi::Error, Debug)]
pub enum Error {
    KeygenFail(i32),
    SignFail(i32),
    VerifyFail(i32),
    ConvertFail(i32),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeygenFail(e) => write!(f, "KeygenFail: {}", e),
            Error::SignFail(e) => write!(f, "SignFail: {}", e),
            Error::VerifyFail(e) => write!(f, "VerifyFail: {}", e),
            Error::ConvertFail(e) => write!(f, "ConvertFail: {}", e),
        }
    }
}

pub type PublicKey = [u8; PUBLIC_KEY_SIZE];
pub type PrivateKey = [u8; PRIVATE_KEY_SIZE];
pub type CompressedSignature = Vec<u8>;
pub type CTSignature = [u8; CT_SIGNATURE_SIZE];

#[uniffi::export]
pub fn verify(
    public_key_slice: &[u8],
    signature: &CompressedSignature,
    msg: &[u8],
) -> Result<(), Error> {
    let public_key: &PublicKey = public_key_slice.try_into().unwrap();

    let result = unsafe {
        if msg.is_empty() {
            falcon_det1024_verify_compressed(
                signature.as_ptr() as *const _,
                signature.len(),
                public_key.as_ptr() as *const _,
                ptr::null(),
                0,
            )
        } else {
            falcon_det1024_verify_compressed(
                signature.as_ptr() as *const _,
                signature.len(),
                public_key.as_ptr() as *const _,
                msg.as_ptr() as *const _,
                msg.len(),
            )
        }
    };

    if result != 0 {
        return Err(Error::VerifyFail(result));
    }

    Ok(())
}

pub fn verify_ct(public_key: &PublicKey, signature: &CTSignature, msg: &[u8]) -> Result<(), Error> {
    let result = unsafe {
        if msg.is_empty() {
            falcon_det1024_verify_ct(
                signature.as_ptr() as *const _,
                public_key.as_ptr() as *const _,
                ptr::null(),
                0,
            )
        } else {
            falcon_det1024_verify_ct(
                signature.as_ptr() as *const _,
                public_key.as_ptr() as *const _,
                msg.as_ptr() as *const _,
                msg.len(),
            )
        }
    };

    if result != 0 {
        return Err(Error::VerifyFail(result));
    }

    Ok(())
}

#[uniffi::export]
pub fn sign_compressed(private_key_slice: &[u8], msg: &[u8]) -> Result<CompressedSignature, Error> {
    let private_key: &PrivateKey = private_key_slice.try_into().unwrap();

    let mut sig = vec![0u8; SIGNATURE_MAX_SIZE];
    let mut sig_len = 0;

    let result = unsafe {
        if msg.is_empty() {
            falcon_det1024_sign_compressed(
                sig.as_mut_ptr() as *mut _,
                &mut sig_len,
                private_key.as_ptr() as *const _,
                ptr::null(),
                0,
            )
        } else {
            falcon_det1024_sign_compressed(
                sig.as_mut_ptr() as *mut _,
                &mut sig_len,
                private_key.as_ptr() as *const _,
                msg.as_ptr() as *const _,
                msg.len(),
            )
        }
    };

    if result != 0 {
        return Err(Error::SignFail(result));
    }

    sig.truncate(sig_len);
    Ok(sig)
}

pub fn convert_to_ct(signature: &CompressedSignature) -> Result<CTSignature, Error> {
    let mut sig_ct = [0u8; CT_SIGNATURE_SIZE];

    let result = unsafe {
        falcon_det1024_convert_compressed_to_ct(
            sig_ct.as_mut_ptr() as *mut _,
            signature.as_ptr() as *const _,
            signature.len(),
        )
    };

    if result != 0 {
        return Err(Error::ConvertFail(result));
    }

    Ok(sig_ct)
}

#[derive(uniffi::Record)]
pub struct KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[uniffi::export]
pub fn generate_key(seed: &[u8]) -> Result<KeyPair, Error> {
    let mut rng = unsafe { std::mem::zeroed::<shake256_context>() };

    unsafe {
        if seed.is_empty() {
            shake256_init_prng_from_seed(&mut rng, ptr::null(), 0);
        } else {
            shake256_init_prng_from_seed(&mut rng, seed.as_ptr() as *const _, seed.len());
        }
    }

    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    let mut private_key = [0u8; PRIVATE_KEY_SIZE];

    let result = unsafe {
        falcon_det1024_keygen(
            &mut rng,
            private_key.as_mut_ptr() as *mut _,
            public_key.as_mut_ptr() as *mut _,
        )
    };

    if result != 0 {
        return Err(Error::KeygenFail(result));
    }

    Ok(KeyPair {
        private_key: private_key.to_vec(),
        public_key: public_key.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_signing() {
        let seed = b"test seed";
        let key_pair = generate_key(seed).unwrap();

        let msg = b"test message";
        let sig = sign_compressed(&key_pair.private_key, msg).unwrap();

        verify(&key_pair.public_key, &sig, msg).unwrap();

        let sig_ct = convert_to_ct(&sig).unwrap();
        verify_ct(
            &key_pair.public_key.as_slice().try_into().unwrap(),
            &sig_ct,
            msg,
        )
        .unwrap();
    }
}

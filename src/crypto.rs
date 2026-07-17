use crate::error::WalletError;
use k256::{SecretKey, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha512};
use tiny_keccak::{Hasher, Keccak};

pub(crate) fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut key0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha512::new();
        h.update(key);
        let k = h.finalize();
        key0[..64].copy_from_slice(&k);
    } else {
        key0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];

    for i in 0..BLOCK {
        ipad[i] = key0[i] ^ 0x36;
        opad[i] = key0[i] ^ 0x5c;
    }

    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(msg);

    let inner_hash = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();

    let mut res = [0u8; 64];
    res.copy_from_slice(&out);
    res
}

pub(crate) fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    iters: u32,
    out_len: usize,
) -> Vec<u8> {
    // PBKDF2;
    // T(i) = U1 xor U2 xor ... xor Uc
    // INT(i) is a 4-byte big-endian block index
    let hlen = 64usize;
    let l = out_len.div_ceil(hlen); // number of blocks 
    let mut out = Vec::with_capacity(out_len);

    for block_index in 1..=l {
        let mut salt_int = Vec::with_capacity(salt.len() + 4);
        salt_int.extend_from_slice(salt);
        salt_int.extend_from_slice(&(block_index as u32).to_be_bytes());
        let mut u = hmac_sha512(password, &salt_int);
        let mut t = u;
        for _ in 1..iters {
            u = hmac_sha512(password, &u);
            for j in 0..64 {
                t[j] ^= u[j];
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(out_len);
    out
}

pub(crate) fn public_key_from_private_key(private_key: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
    let secret = SecretKey::from_slice(private_key).map_err(|_| WalletError::InvalidPrivateKey)?;
    let public = secret.public_key();
    let encoded = public.to_sec1_point(false);
    Ok(encoded.as_bytes().to_vec())
}

pub fn ethereum_address_from_public_key(public_key: &[u8]) -> Result<String, WalletError> {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(WalletError::InvalidPublicKey);
    }

    let public_key_without_prefix = &public_key[1..];

    let mut hasher = Keccak::v256();
    hasher.update(public_key_without_prefix);

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    let address_bytes = &output[12..];

    Ok(format!("0x{}", hex::encode(address_bytes)))
}

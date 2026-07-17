use crate::{
    crypto::hmac_sha512,
    error::WalletError,
    wallet::{
        derivation_path::{ChildNumber, DerivationPath},
        extended_priv_key::ExtendedPrivKey,
    },
};
use k256::{SecretKey, elliptic_curve::sec1::ToSec1Point};
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::result::Result;
pub(crate) struct Bip32;
impl Bip32 {
    pub(crate) fn master_from_seed(seed: &[u8]) -> ExtendedPrivKey {
        assert_eq!(seed.len(), 64, "seed len should be 64 bytes");
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..64]);

        let mut key = [0u8; 32];
        key.copy_from_slice(&i[0..32]);

        ExtendedPrivKey {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
            chain_code,
            key,
        }
    }
    pub(crate) fn derive_path(
        master: &ExtendedPrivKey,
        path: &DerivationPath,
    ) -> Result<ExtendedPrivKey, WalletError> {
        let mut current = master.clone();
        for child in &path.segments {
            current = Self::derive_child_private_key(&current, *child)?;
        }
        Ok(current)
    }

    pub fn derive_child_private_key(
        parent: &ExtendedPrivKey,
        child: ChildNumber,
    ) -> Result<ExtendedPrivKey, WalletError> {
        let child_number = child.to_u32();

        let mut data = Vec::new();

        if child.is_hardened() {
            // Hardened:
            // data = 0x00 || ser256(parent_private_key) || ser32(child_number)
            data.push(0x00);
            data.extend_from_slice(&parent.key);
        } else {
            // Non-hardened:
            // data = serP(parent_public_key) || ser32(child_number)
            let parent_public_key = Self::compressed_public_key_from_private_key(&parent.key)?;
            data.extend_from_slice(&parent_public_key);
        }

        data.extend_from_slice(&child_number.to_be_bytes());

        // I = HMAC-SHA512(parent_chain_code, data)
        let i = hmac_sha512(&parent.chain_code, &data);

        let il = &i[0..32];
        let ir = &i[32..64];

        let curve_order = Self::secp256k1_order();

        let il_int = BigUint::from_bytes_be(il);
        let parent_key_int = Self::private_key_to_biguint(&parent.key);

        // BIP32 rule:
        // if parse256(IL) >= n, this child is invalid
        if il_int >= curve_order {
            return Err(WalletError::Bip32Error);
        }

        // child_key = (parse256(IL) + parent_key) mod n
        let child_key_int = (il_int + parent_key_int) % &curve_order;

        // BIP32 rule:
        // if child_key == 0, this child is invalid
        if child_key_int.is_zero() {
            return Err(WalletError::Bip32Error);
        }

        let child_key = Self::biguint_to_32_bytes(&child_key_int)?;

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(ir);

        let parent_fingerprint = Self::fingerprint_from_private_key(&parent.key)?;

        Ok(ExtendedPrivKey {
            depth: parent.depth + 1,
            parent_fingerprint,
            child_number,
            chain_code: child_chain_code,
            key: child_key,
        })
    }

    fn secp256k1_order() -> BigUint {
        BigUint::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .expect("valid secp256k1 order")
    }

    fn private_key_to_biguint(key: &[u8; 32]) -> BigUint {
        BigUint::from_bytes_be(key)
    }

    fn biguint_to_32_bytes(value: &BigUint) -> Result<[u8; 32], WalletError> {
        let bytes = value.to_bytes_be();

        if bytes.len() > 32 {
            return Err(WalletError::Bip32Error);
        }

        let mut out = [0u8; 32];
        let start = 32 - bytes.len();
        out[start..].copy_from_slice(&bytes);

        Ok(out)
    }

    fn compressed_public_key_from_private_key(
        private_key: &[u8; 32],
    ) -> Result<[u8; 33], WalletError> {
        let secret =
            SecretKey::from_slice(private_key).map_err(|_| WalletError::InvalidPrivateKey)?;

        let public_key = secret.public_key();
        let encoded = public_key.to_sec1_point(true);
        let bytes = encoded.as_bytes();

        if bytes.len() != 33 {
            return Err(WalletError::Bip32Error);
        }

        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);

        Ok(out)
    }
    fn _uncompressed_public_key_from_private_key(
        private_key: &[u8; 32],
    ) -> Result<[u8; 65], WalletError> {
        let secret =
            SecretKey::from_slice(private_key).map_err(|_| WalletError::InvalidPrivateKey)?;

        let public_key = secret.public_key();
        let encoded = public_key.to_sec1_point(false);

        let bytes = encoded.as_bytes();

        if bytes.len() != 65 {
            return Err(WalletError::Bip32Error);
        }

        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);

        Ok(out)
    }

    fn fingerprint_from_private_key(private_key: &[u8; 32]) -> Result<[u8; 4], WalletError> {
        let compressed_public_key = Self::compressed_public_key_from_private_key(private_key)?;

        let sha_hash = Sha256::digest(compressed_public_key);
        let ripemd_hash = Ripemd160::digest(sha_hash);

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&ripemd_hash[..4]);

        Ok(fingerprint)
    }
}

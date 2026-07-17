use crate::{
    error::MnemonicsError,
    wallet::mnemonics::{
        WORD_LIST,
        WordCount::{self, Sixteen, Twelve},
    },
};
use sha2::{Digest, Sha256};
use std::result::Result;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug)]
pub(crate) struct Bip39;

impl Bip39 {
    pub(crate) fn generate_mnemonic(word_count: WordCount) -> Result<String, MnemonicsError> {
        let entropy_byte_size = match word_count {
            Twelve => 16,
            Sixteen => 32,
        };

        // create secure random entropy
        let mut entropy = vec![0u8; entropy_byte_size];
        rand::fill(&mut entropy);

        Self::entropy_to_mnemonics(&entropy, entropy_byte_size, word_count as usize)
    }

    pub(crate) fn entropy_to_mnemonics(
        entropy: &[u8],
        entropy_byte_size: usize,
        word_count: usize,
    ) -> Result<String, MnemonicsError> {
        // generate checksum for entropy
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let hash = hasher.finalize();

        let entropy_bits_len = entropy_byte_size * 8;
        let checksum_bits_len = entropy_bits_len / 32;

        let checksum_byte = hash[0];

        let mut bits = Vec::with_capacity(entropy_bits_len + checksum_bits_len);
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }

        for i in 0..checksum_bits_len {
            bits.push((checksum_byte >> (7 - i)) & 1 == 1);
        }

        // slice bits into chunk of 11 and map to word list
        let mut words = Vec::with_capacity(word_count);
        for chunk in bits.chunks(11) {
            let mut index = 0usize;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    index |= 1 << (10 - i);
                }
            }
            if index < WORD_LIST.len() {
                words.push(WORD_LIST[index]);
            } else {
                words.push("abandon");
            }
        }

        Ok(words.join(" "))
    }

    pub(crate) fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
        // NFKD
        let mnemonic_nfkd: String = mnemonic.nfkd().collect();
        let passphrase_nfkd: String = passphrase.nfkd().collect();

        // salt = "mnemonic" + passphrase
        let mut salt = Vec::new();
        salt.extend_from_slice(b"mnemonic");
        salt.extend_from_slice(passphrase_nfkd.as_bytes());

        // PBKDF2-HMAC-SHA512 with 2048 iterations → 64-byte seed
        let password = mnemonic_nfkd.as_bytes();
        let seed = crate::crypto::pbkdf2_hmac_sha512(password, &salt, 2048, 64);

        seed.as_slice()
            .try_into()
            .expect("PBKDF2 output must be 64 bytes")
    }
    pub(crate) fn validate_mnemonic(phrase: &str) -> Result<(), MnemonicsError> {
        let words: Vec<&str> = phrase.split_whitespace().collect();

        Self::validate_word_count(words.len())?;

        for word in &words {
            if !Self::word_exists(word) {
                return Err(MnemonicsError::UnknownWord((*word).to_string()));
            }
        }

        Self::validate_checksum(&words)?;

        Ok(())
    }
    fn words_to_indices(words: &[&str]) -> Result<Vec<u16>, MnemonicsError> {
        let mut indices = Vec::with_capacity(words.len());

        for word in words {
            let index = WORD_LIST
                .iter()
                .position(|candidate| candidate == word)
                .ok_or_else(|| MnemonicsError::UnknownWord((*word).to_string()))?;

            indices.push(index as u16);
        }

        Ok(indices)
    }

    fn indices_to_bits(indices: &[u16]) -> Vec<bool> {
        let mut bits = Vec::with_capacity(indices.len() * 11);

        for index in indices {
            for shift in (0..11).rev() {
                let bit = (index >> shift) & 1;
                bits.push(bit == 1);
            }
        }

        bits
    }
    fn entropy_bits_from_word_count(word_count: usize) -> Result<usize, MnemonicsError> {
        match word_count {
            12 => Ok(128),
            16 => Ok(128),
            // 15 => Ok(160),
            // 18 => Ok(192),
            // 21 => Ok(224),
            // 24 => Ok(256),
            _ => Err(MnemonicsError::InvalidWordCount(word_count)),
        }
    }

    fn bits_to_bytes(bits: &[bool]) -> Result<Vec<u8>, MnemonicsError> {
        if !bits.len().is_multiple_of(8) {
            return Err(MnemonicsError::InvalidEntropyLength);
        }

        let mut bytes = Vec::with_capacity(bits.len() / 8);

        for chunk in bits.chunks(8) {
            let mut byte = 0u8;

            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    byte |= 1 << (7 - i);
                }
            }

            bytes.push(byte);
        }

        Ok(bytes)
    }

    fn checksum_bits(entropy: &[u8], checksum_bit_len: usize) -> Vec<bool> {
        let hash = Sha256::digest(entropy);

        let mut bits = Vec::with_capacity(checksum_bit_len);

        for i in 0..checksum_bit_len {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            let bit = (hash[byte_index] >> bit_index) & 1;
            bits.push(bit == 1);
        }

        bits
    }

    fn validate_checksum(words: &[&str]) -> Result<(), MnemonicsError> {
        let indices = Self::words_to_indices(words)?;

        let bits = Self::indices_to_bits(&indices);

        let entropy_bit_len = Self::entropy_bits_from_word_count(words.len())?;
        let checksum_bit_len = entropy_bit_len / 32;

        let entropy_bits = &bits[..entropy_bit_len];
        let checksum_bits = &bits[entropy_bit_len..entropy_bit_len + checksum_bit_len];

        let entropy_bytes = Self::bits_to_bytes(entropy_bits)?;

        let expected_checksum_bits = Self::checksum_bits(&entropy_bytes, checksum_bit_len);

        if checksum_bits != expected_checksum_bits.as_slice() {
            return Err(MnemonicsError::InvalidChecksum);
        }

        Ok(())
    }
    fn validate_word_count(count: usize) -> Result<(), MnemonicsError> {
        match count {
            12 | 15 | 18 | 21 | 24 => Ok(()),
            _ => Err(MnemonicsError::InvalidWordCount(count)),
        }
    }
    fn word_exists(word: &str) -> bool {
        WORD_LIST.binary_search(&word).is_ok()
    }
}

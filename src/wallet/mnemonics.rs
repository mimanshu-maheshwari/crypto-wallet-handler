//! Bip: https://bips.dev/39/
use crate::{
    crypto::hmac_sha512,
    error::MnemonicsError,
    wallet::mnemonics::WordCount::{Sixteen, Twelve},
};
use sha2::{Digest, Sha256};
use std::{fmt::Display, result::Result, sync::LazyLock};
use unicode_normalization::UnicodeNormalization;

/// word list taken from
/// https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
static WORD_LIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let list_str = include_str!("../../res/English.txt");
    let list: Vec<&'static str> = list_str
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    assert_eq!(list.len(), 2048, "Incomplete BIP39 list.");
    list
});

#[derive(Debug, Default)]
#[repr(usize)]
pub enum WordCount {
    #[default]
    Twelve = 12,
    Sixteen = 16,
}

impl TryFrom<usize> for WordCount {
    type Error = MnemonicsError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            12 => Ok(Twelve),
            16 => Ok(Sixteen),
            x => Err(MnemonicsError::InvalidWordCount(format!(
                "Invalid value for word count: {x}"
            ))),
        }
    }
}

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
}

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
}

pub type Fingerprint = [u8; 4];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtendedPrivKey {
    // BIP32 fields
    pub depth: u8,                       // m=0, children increment
    pub parent_fingerprint: Fingerprint, // first 4 bytes of parent public key hash
    pub child_number: u32, // the index used to derive this key (with hardened bit set if needed)
    pub chain_code: [u8; 32], // cpar

    // private key (32-byte secret scalar, 1..n-1)
    pub key: [u8; 32], // kpar
}

impl Display for ExtendedPrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Depth              : {}", self.depth)?;
        let fp = hex::encode(self.parent_fingerprint);
        writeln!(f, "Parent Fingerprint : {fp}")?;
        writeln!(f, "Child Number       : {}", self.child_number)?;
        let cc = hex::encode(self.chain_code);
        writeln!(f, "Chain Code         : {cc}")?;
        let key = hex::encode(self.key);
        writeln!(f, "Private Key        : {key}")?;
        Ok(())
    }
}

impl ExtendedPrivKey {
    pub fn is_master(&self) -> bool {
        self.depth == 0
    }

    pub fn hardened(i: u32) -> bool {
        i & (1 << 31) != 0
    }
}

#[cfg(test)]
mod test {
    use crate::wallet::mnemonics::WordCount::{Sixteen, Twelve};

    #[test]
    fn test_generate_mnemonics() {
        for wc in [Twelve, Sixteen] {
            match super::Bip39::generate_mnemonic(wc) {
                Ok(mnemonic) => println!("{mnemonic}"),
                Err(err) => {
                    eprintln!("{err}");
                    panic!("Failed to generate mnemonics.");
                }
            }
        }
    }

    #[test]
    fn test_entropy_to_mnemonics_1() {
        const WORD_COUNT: usize = 12;
        const ENTROPY_BYTE_COUNT: usize = 16;
        let entropy = [0u8; ENTROPY_BYTE_COUNT];
        match super::Bip39::entropy_to_mnemonics(&entropy, ENTROPY_BYTE_COUNT, WORD_COUNT) {
            Ok(m) => assert_eq!(
                &m,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ),
            Err(err) => {
                eprintln!("{err}");
                panic!("Failed to generate mnemonics.");
            }
        }
    }

    #[test]
    fn test_entropy_to_mnemonics_2() {
        const WORD_COUNT: usize = 12;
        const ENTROPY_BYTE_COUNT: usize = 16;
        let entropy = [
            0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0xAB, 0xCD,
        ];
        match super::Bip39::entropy_to_mnemonics(&entropy, ENTROPY_BYTE_COUNT, WORD_COUNT) {
            Ok(m) => assert_eq!(
                &m,
                "banana pencil owner attract feature move priority kangaroo target jewel turtle old"
            ),
            Err(err) => {
                eprintln!("{err}");
                panic!("Failed to generate mnemonics.");
            }
        }
    }
}

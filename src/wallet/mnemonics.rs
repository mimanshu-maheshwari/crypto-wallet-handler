//! Bip: https://bips.dev/39/

use crate::{
    error::MnemonicsError,
    wallet::mnemonics::WordCount::{Sixteen, Twelve},
};
use std::{fmt::Display, result::Result, sync::LazyLock};

pub(crate) mod bip32;
pub(crate) mod bip39;

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

impl Display for WordCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = match self {
            Self::Twelve => 12,
            Self::Sixteen => 16,
        };
        write!(f, "{count}")
    }
}

impl TryFrom<usize> for WordCount {
    type Error = MnemonicsError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            12 => Ok(Twelve),
            16 => Ok(Sixteen),
            x => Err(MnemonicsError::InvalidWordCount(x)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::wallet::{
        derivation_path::DerivationPath,
        mnemonics::{
            WordCount::{Sixteen, Twelve},
            bip32::Bip32,
            bip39::Bip39,
        },
    };

    #[test]
    fn test_generate_mnemonics() {
        for wc in [Twelve, Sixteen] {
            match super::bip39::Bip39::generate_mnemonic(wc) {
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
        match super::bip39::Bip39::entropy_to_mnemonics(&entropy, ENTROPY_BYTE_COUNT, WORD_COUNT) {
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
        match super::bip39::Bip39::entropy_to_mnemonics(&entropy, ENTROPY_BYTE_COUNT, WORD_COUNT) {
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
    #[test]
    fn derive_eth_account_private_key_should_work() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let seed = Bip39::mnemonic_to_seed(mnemonic, "");
        let master = Bip32::master_from_seed(&seed);

        let path = DerivationPath::ethereum(0);
        let child = Bip32::derive_path(&master, &path).unwrap();

        assert_eq!(child.depth, 5);
        assert_ne!(child.key, [0u8; 32]);
        assert_ne!(child.chain_code, [0u8; 32]);
    }
}

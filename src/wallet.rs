pub mod mnemonics;
use crate::{
    error::WalletError,
    wallet::mnemonics::{Bip, Bip32, Bip39, ExtendedPrivKey, WordCount},
};
use std::fmt::Display;

#[derive(Debug)]
pub struct Wallet {
    bip_algo: Bip,
    mnemonic: String,
    master: ExtendedPrivKey,
}

impl Display for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Mnemonics code: {}", self.mnemonic)?;
        writeln!(f, "Master key: {}", self.master)
    }
}

impl Wallet {
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    pub fn blip(&self) -> Bip {
        self.bip_algo
    }

    pub fn master(&self) -> &ExtendedPrivKey {
        &self.master
    }
}

#[derive(Debug, Default)]
pub struct WalletBuilder {
    bip_algo: mnemonics::Bip,
    word_count: usize,
    passphrase: Option<String>,
}

impl WalletBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn bip(mut self, bip: Bip) -> Self {
        self.bip_algo = bip;
        self
    }

    pub fn word_count(mut self, count: WordCount) -> Self {
        let count = usize::from(count);
        self.word_count = count;
        self
    }

    pub fn pass(mut self, pass: &str) -> Self {
        self.passphrase = Some(pass.to_owned());
        self
    }

    pub fn create(self) -> Result<Wallet, WalletError> {
        match self.bip_algo {
            Bip::Bip39 => {
                let mnemonic = match Bip39::generate_mnemonic(self.word_count) {
                    Ok(mnemonic) => mnemonic,
                    Err(err) => return Err(WalletError::MnemonicsError(err)),
                };
                let pass = self.passphrase.unwrap_or_default();
                let seed = Bip39::mnemonic_to_seed(&mnemonic, &pass);
                // 1) BIP32 master_from_seed(seed64)
                let master = Bip32::master_from_seed(&seed);
                Ok(Wallet {
                    bip_algo: self.bip_algo,
                    mnemonic,
                    master,
                })
            }
        }
    }

    pub fn recover(self, mnemonic: String) -> Result<Wallet, WalletError> {
        match self.bip_algo {
            Bip::Bip39 => {
                let pass = self.passphrase.unwrap_or_default();

                let seed64: [u8; 64] = Bip39::mnemonic_to_seed(&mnemonic, &pass);
                let master = Bip32::master_from_seed(&seed64);

                // derive path -> addresses/keys

                Ok(Wallet {
                    bip_algo: self.bip_algo,
                    mnemonic,
                    master,
                })
            }
        }
    }
}

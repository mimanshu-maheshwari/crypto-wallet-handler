pub mod mnemonics;
use crate::{
    error::WalletError,
    wallet::mnemonics::{
        Bip32, Bip39, ExtendedPrivKey,
        WordCount::{self, Twelve},
    },
};
use std::{fmt::Display, marker::PhantomData};

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Wallet {
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

    pub fn master(&self) -> &ExtendedPrivKey {
        &self.master
    }
}

#[derive(Debug)]
pub struct WalletBuilder<T = ()> {
    word_count: WordCount,
    passphrase: Option<String>,
    mnemonic: String,
    phantom_data: PhantomData<T>,
}

impl WalletBuilder {
    pub fn create() -> WalletBuilder<CreateFlow> {
        WalletBuilder {
            word_count: Twelve,
            passphrase: None,
            mnemonic: String::from(""),
            phantom_data: PhantomData,
        }
    }

    pub fn recover(mnemonic_str: &str) -> WalletBuilder<RecoverFlow> {
        WalletBuilder {
            word_count: Twelve,
            passphrase: None,
            mnemonic: String::from(mnemonic_str),
            phantom_data: PhantomData,
        }
    }
}
pub struct CreateFlow;

impl WalletBuilder<CreateFlow> {
    pub fn word_count(mut self, count: WordCount) -> Self {
        self.word_count = count;
        self
    }

    pub fn pass(mut self, pass: &str) -> Self {
        self.passphrase = Some(pass.to_owned());
        self
    }

    pub fn build(self) -> Result<Wallet, WalletError> {
        let mnemonic = match Bip39::generate_mnemonic(self.word_count) {
            Ok(mnemonic) => mnemonic,
            Err(err) => return Err(WalletError::MnemonicsError(err)),
        };
        let pass = self.passphrase.unwrap_or_default();
        let seed = Bip39::mnemonic_to_seed(&mnemonic, &pass);
        // 1) BIP32 master_from_seed(seed64)
        let master = Bip32::master_from_seed(&seed);
        Ok(Wallet { mnemonic, master })
    }
}
pub struct RecoverFlow;
impl WalletBuilder<RecoverFlow> {
    pub fn build(self) -> Result<Wallet, WalletError> {
        let pass = self.passphrase.unwrap_or_default();

        let seed64: [u8; 64] = Bip39::mnemonic_to_seed(&self.mnemonic, &pass);
        let master = Bip32::master_from_seed(&seed64);

        // derive path -> addresses/keys

        Ok(Wallet {
            mnemonic: self.mnemonic,
            master,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wallet_create_and_recover() -> anyhow::Result<()> {
        let wallet = WalletBuilder::create()
            .word_count(WordCount::Twelve)
            .pass("")
            .build()?;
        println!("Created wallet   :\n{wallet}\n\n");

        let phrase = wallet.mnemonic();
        let recovery_wallet = WalletBuilder::recover(phrase).build()?;
        println!("Recovered wallet :\n{recovery_wallet}");

        assert_eq!(wallet.mnemonic(), recovery_wallet.mnemonic());
        assert_eq!(wallet.master, recovery_wallet.master);
        assert_eq!(wallet, recovery_wallet);

        Ok(())
    }
}

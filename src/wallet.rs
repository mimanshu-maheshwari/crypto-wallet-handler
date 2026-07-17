pub(crate) mod derivation_path;
pub(crate) mod extended_priv_key;
pub mod mnemonics;

use crate::{
    crypto::{ethereum_address_from_public_key, public_key_from_private_key},
    error::WalletError,
    wallet::{
        derivation_path::DerivationPath,
        extended_priv_key::ExtendedPrivKey,
        mnemonics::{
            WordCount::{self, Twelve},
            bip32::Bip32,
            bip39::Bip39,
        },
    },
};
use std::{
    fmt::{self, Display},
    marker::PhantomData,
};

pub struct Exposed<'a, T: ?Sized> {
    value: &'a T,
}

impl<'a, T: ?Sized> Exposed<'a, T> {
    fn new(value: &'a T) -> Self {
        Self { value }
    }
}

pub(crate) fn redact_hex(value: &str) -> String {
    const VISIBLE_CHARS: usize = 8;

    if value.len() <= VISIBLE_CHARS * 2 {
        return value.to_owned();
    }

    format!(
        "{}…{}",
        &value[..VISIBLE_CHARS],
        &value[value.len() - VISIBLE_CHARS..]
    )
}

fn redact_mnemonic(mnemonic: &str) -> String {
    let words: Vec<_> = mnemonic.split_whitespace().collect();
    match words.as_slice() {
        [] => "<redacted>".to_owned(),
        [first] => (*first).to_owned(),
        [first, second] => format!("{first} {second}"),
        [first, second, third] => format!("{first} {second} {third}"),
        [first, second, .., penultimate, last] => {
            format!("{first} {second} … {penultimate} {last}")
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct WalletAccount {
    pub path: DerivationPath,
    pub private_key: [u8; 32],
    pub public_key: Vec<u8>,
    pub address: String,
}

impl Display for WalletAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with_secrets(f, false)
    }
}

impl WalletAccount {
    pub fn expose_secrets(&self) -> Exposed<'_, Self> {
        Exposed::new(self)
    }

    fn fmt_with_secrets(&self, f: &mut fmt::Formatter<'_>, expose_secrets: bool) -> fmt::Result {
        let private_key = hex::encode(self.private_key);
        write!(
            f,
            "WalletAccount{{path={}, address={}, public_key={}, private_key={}}}",
            self.path,
            self.address,
            hex::encode(&self.public_key),
            if expose_secrets {
                private_key
            } else {
                redact_hex(&private_key)
            },
        )
    }
}

impl Display for Exposed<'_, WalletAccount> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt_with_secrets(f, true)
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Wallet {
    mnemonic: String,
    master: ExtendedPrivKey,
    accounts: Vec<WalletAccount>,
}

impl Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with_secrets(f, false)
    }
}

impl Wallet {
    pub fn expose_secrets(&self) -> Exposed<'_, Self> {
        Exposed::new(self)
    }

    fn fmt_with_secrets(&self, f: &mut fmt::Formatter<'_>, expose_secrets: bool) -> fmt::Result {
        if !expose_secrets {
            return self.fmt_redacted(f);
        }

        write!(
            f,
            "Wallet{{mnemonic=\"{}\", master={}",
            self.mnemonic,
            self.master.expose_secrets()
        )?;
        f.write_str(", accounts=[")?;
        for (index, account) in self.accounts.iter().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", account.expose_secrets())?;
        }
        f.write_str("]}")
    }

    fn fmt_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wallet{{mnemonic=\"{}\", master={}",
            redact_mnemonic(&self.mnemonic),
            self.master
        )?;
        f.write_str(", accounts=[")?;
        for (index, account) in self.accounts.iter().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{account}")?;
        }
        f.write_str("]}")
    }

    pub fn derive_eth_account(&self, index: u32) -> Result<WalletAccount, WalletError> {
        let path = DerivationPath::ethereum(index);

        let child = Bip32::derive_path(&self.master, &path)?;

        let public_key = public_key_from_private_key(&child.key)?;

        let address = ethereum_address_from_public_key(&public_key)?;

        Ok(WalletAccount {
            path,
            private_key: child.key,
            public_key,
            address,
        })
    }

    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    pub fn address(&self) -> Option<&str> {
        self.accounts
            .first()
            .map(|account| account.address.as_str())
    }
    pub fn master(&self) -> &ExtendedPrivKey {
        &self.master
    }
}

impl Display for Exposed<'_, Wallet> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt_with_secrets(f, true)
    }
}

#[derive(Debug)]
pub struct WalletBuilder<Flow = ()> {
    word_count: WordCount,
    passphrase: Option<String>,
    mnemonic: String,
    account_index: u32,
    _flow: std::marker::PhantomData<Flow>,
}

impl WalletBuilder {
    pub fn create() -> WalletBuilder<CreateFlow> {
        WalletBuilder {
            word_count: Twelve,
            passphrase: None,
            mnemonic: String::from(""),
            account_index: 0,
            _flow: PhantomData,
        }
    }
    pub fn recover(mnemonic_str: &str) -> WalletBuilder<RecoverFlow> {
        WalletBuilder {
            word_count: Twelve,
            passphrase: None,
            mnemonic: String::from(mnemonic_str),
            account_index: 0,
            _flow: PhantomData,
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

    pub fn account_index(mut self, ac: u32) -> Self {
        self.account_index = ac;
        self
    }
    pub fn build(self) -> Result<Wallet, WalletError> {
        let mnemonic =
            Bip39::generate_mnemonic(self.word_count).map_err(WalletError::MnemonicsError)?;

        let pass = self.passphrase.unwrap_or_default();

        let seed = Bip39::mnemonic_to_seed(&mnemonic, &pass);

        let master = Bip32::master_from_seed(&seed);

        let mut wallet = Wallet {
            mnemonic,
            master,
            accounts: vec![],
        };

        let account = wallet.derive_eth_account(self.account_index)?;
        wallet.accounts.push(account);

        Ok(wallet)
    }
}
pub struct RecoverFlow;
impl WalletBuilder<RecoverFlow> {
    pub fn account_index(mut self, ac: u32) -> Self {
        self.account_index = ac;
        self
    }
    pub fn pass(mut self, pass: &str) -> Self {
        self.passphrase = Some(pass.to_owned());
        self
    }
    pub fn build(self) -> Result<Wallet, WalletError> {
        let pass = self.passphrase.unwrap_or_default();

        // important: validate mnemonic here
        Bip39::validate_mnemonic(&self.mnemonic).map_err(WalletError::MnemonicsError)?;

        let seed = Bip39::mnemonic_to_seed(&self.mnemonic, &pass);

        let master = Bip32::master_from_seed(&seed);

        let mut wallet = Wallet {
            mnemonic: self.mnemonic,
            master,
            accounts: vec![],
        };

        let account = wallet.derive_eth_account(self.account_index)?;
        wallet.accounts.push(account);

        Ok(wallet)
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
    #[test]
    fn display_redacts_secrets_unless_explicitly_exposed() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = WalletBuilder::recover(mnemonic).build().unwrap();

        let redacted = wallet.to_string();
        let exposed = wallet.expose_secrets().to_string();
        let master_key = hex::encode(wallet.master().key);
        let chain_code = hex::encode(wallet.master().chain_code);

        assert!(redacted.contains("mnemonic=\"abandon abandon … abandon about\""));
        assert!(!redacted.contains(mnemonic));
        assert!(!redacted.contains(&master_key));
        assert!(!redacted.contains(&chain_code));
        assert!(redacted.contains('…'));
        assert!(!redacted.ends_with('\n'));

        assert!(exposed.contains(mnemonic));
        assert!(exposed.contains(&master_key));
        assert!(exposed.contains(&chain_code));
        assert!(!exposed.ends_with('\n'));
    }

    #[test]
    fn different_indexes_create_different_addresses() {
        let wallet0 = WalletBuilder::create()
            .word_count(WordCount::Twelve)
            .pass("")
            .account_index(0)
            .build()
            .unwrap();

        let phrase = wallet0.mnemonic().to_string();

        let wallet1 = WalletBuilder::recover(&phrase)
            .pass("")
            .account_index(1)
            .build()
            .unwrap();

        assert_ne!(wallet0.address(), wallet1.address());
    }
    #[test]
    fn create_and_recover_same_address() {
        let wallet = WalletBuilder::create()
            .word_count(WordCount::Twelve)
            .pass("")
            .account_index(0)
            .build()
            .unwrap();

        let recovered = WalletBuilder::recover(wallet.mnemonic())
            .pass("")
            .account_index(0)
            .build()
            .unwrap();

        assert_eq!(wallet.address(), recovered.address());
    }
}

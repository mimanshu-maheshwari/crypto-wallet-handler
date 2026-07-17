use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("mnemonic error: {0}")]
    MnemonicsError(#[from] MnemonicsError),

    #[error("invalid private key")]
    InvalidPrivateKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid BIP32 child key")]
    Bip32Error,
}

#[derive(Debug, Error)]
pub enum MnemonicsError {
    #[error("invalid word count: {0}")]
    InvalidWordCount(usize),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("unknown word in word list: {0}")]
    UnknownWord(String),

    #[error("invalid checksum for mnemonic given")]
    InvalidChecksum,

    #[error("invalid entropy length")]
    InvalidEntropyLength,
}

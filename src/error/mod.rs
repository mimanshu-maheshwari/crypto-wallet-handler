use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum WalletError {
    MnemonicsError(MnemonicsError),
}
impl Error for WalletError {}
impl Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use WalletError::*;
        match self {
            MnemonicsError(err) => writeln!(f, "{err}"),
        }
    }
}

#[derive(Debug)]
pub enum MnemonicsError {
    InvalidWordCount(String),
    InvalidKey(String),
}

impl Error for MnemonicsError {}

impl Display for MnemonicsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use MnemonicsError::*;
        match self {
            InvalidWordCount(val) => writeln!(f, "{val}"),
            InvalidKey(val) => writeln!(f, "Invalid key: {val}"),
        }
    }
}

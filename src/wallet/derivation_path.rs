//! m/44'/60'/0'/0/0
//! 44'  = BIP-44 purpose
//! 60'  = Ethereum coin type
//! 0'   = account
//! 0    = external/change
//! 0    = address index
//!

use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct DerivationPath {
    pub segments: Vec<ChildNumber>,
}

impl Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m")?;
        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct ChildNumber {
    pub index: u32,
    pub hardened: bool,
}

impl Display for ChildNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.index, if self.hardened { "'" } else { "" })
    }
}
impl ChildNumber {
    pub const HARDENED_OFFSET: u32 = 0x8000_0000;

    pub fn normal(index: u32) -> Self {
        Self {
            index,
            hardened: false,
        }
    }

    pub fn hardened(index: u32) -> Self {
        Self {
            index,
            hardened: true,
        }
    }

    pub fn to_u32(self) -> u32 {
        if self.hardened {
            self.index | Self::HARDENED_OFFSET
        } else {
            self.index
        }
    }

    pub fn is_hardened(self) -> bool {
        self.hardened
    }
}

impl DerivationPath {
    pub fn ethereum(index: u32) -> Self {
        Self {
            segments: vec![
                ChildNumber::hardened(44),
                ChildNumber::hardened(60),
                ChildNumber::hardened(0),
                ChildNumber::normal(0),
                ChildNumber::normal(index),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChildNumber, DerivationPath};

    #[test]
    fn display_uses_canonical_bip32_notation() {
        assert_eq!(ChildNumber::normal(0).to_string(), "0");
        assert_eq!(ChildNumber::hardened(44).to_string(), "44'");
        assert_eq!(DerivationPath::ethereum(0).to_string(), "m/44'/60'/0'/0/0");
    }
}

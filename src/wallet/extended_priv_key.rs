use std::fmt::Display;

use super::{Exposed, derivation_path::ChildNumber, redact_hex};
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
        self.fmt_with_secrets(f, false)
    }
}

impl ExtendedPrivKey {
    pub fn expose_secrets(&self) -> Exposed<'_, Self> {
        Exposed::new(self)
    }

    fn fmt_with_secrets(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        expose_secrets: bool,
    ) -> std::fmt::Result {
        let child_number = ChildNumber {
            index: self.child_number & !ChildNumber::HARDENED_OFFSET,
            hardened: Self::hardened(self.child_number),
        };
        let chain_code = hex::encode(self.chain_code);
        let private_key = hex::encode(self.key);

        write!(
            f,
            "ExtendedPrivKey{{depth={}, parent_fingerprint={}, child_number={}, chain_code={}, private_key={}}}",
            self.depth,
            hex::encode(self.parent_fingerprint),
            child_number,
            if expose_secrets {
                chain_code
            } else {
                redact_hex(&chain_code)
            },
            if expose_secrets {
                private_key
            } else {
                redact_hex(&private_key)
            },
        )
    }

    pub fn is_master(&self) -> bool {
        self.depth == 0
    }

    pub fn hardened(i: u32) -> bool {
        i & (1 << 31) != 0
    }
}

impl Display for Exposed<'_, ExtendedPrivKey> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt_with_secrets(f, true)
    }
}

#[cfg(test)]
mod tests {
    use super::ExtendedPrivKey;

    #[test]
    fn display_redacts_secrets_unless_explicitly_exposed() {
        let key = ExtendedPrivKey {
            depth: 1,
            parent_fingerprint: [0, 1, 2, 3],
            child_number: 0x8000_0002,
            chain_code: [0xab; 32],
            key: [0xcd; 32],
        };

        assert_eq!(
            key.to_string(),
            "ExtendedPrivKey{depth=1, parent_fingerprint=00010203, child_number=2', chain_code=abababab…abababab, private_key=cdcdcdcd…cdcdcdcd}"
        );
        assert!(
            key.expose_secrets()
                .to_string()
                .contains(&hex::encode(key.key))
        );
        assert!(
            key.expose_secrets()
                .to_string()
                .contains(&hex::encode(key.chain_code))
        );
    }
}

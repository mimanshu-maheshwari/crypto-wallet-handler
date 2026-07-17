#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use bitcoin::{Network, bip32::Xpriv};

    #[test]
    fn check_bitcoin_wallet() -> anyhow::Result<()> {
        let phrase =
            "cruise dilemma canvas bundle six curtain note nothing sure lawsuit october private";

        let mnemonic = Mnemonic::parse_in(bip39::Language::English, phrase)?;
        let seed = mnemonic.to_seed("");

        let xprv = Xpriv::new_master(Network::Bitcoin, &seed)?;

        // 3) Extract components
        let depth = xprv.depth;
        let parent_fp = xprv.parent_fingerprint;
        let child_num = xprv.child_number;
        let cc = xprv.chain_code;
        let key = xprv.private_key.secret_bytes();

        assert_eq!(0, depth);
        assert_eq!("00000000", &format!("{:08x}", parent_fp));
        assert!(child_num.is_normal());
        assert_eq!(
            "5e3b18bab9ff81183ccbb762190bafe3893dba8fdd3adb601834e75f036c57d6",
            hex::encode(cc)
        );
        assert_eq!(
            "0606e91208e247e565ebb06b2bc54905ca591faeded96d13c7bec7997ba777bb",
            hex::encode(key)
        );

        Ok(())
    }
}

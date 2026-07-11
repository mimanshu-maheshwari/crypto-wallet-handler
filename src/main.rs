use wallet_app::wallet::{
    WalletBuilder,
    mnemonics::{Bip, WordCount},
};

fn main() -> anyhow::Result<()> {
    let wallet = WalletBuilder::new()
        .bip(Bip::Bip39)
        .word_count(WordCount::Twelve)
        .pass("")
        .create()?;
    println!("{wallet}");
    Ok(())
}

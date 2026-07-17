use wallet_app::wallet::{WalletBuilder, mnemonics::WordCount};

fn main() -> anyhow::Result<()> {
    let wallet = WalletBuilder::create()
        .word_count(WordCount::Twelve)
        .pass("")
        .build()?;
    println!("Created wallet   :\n{wallet}\n\n");

    let phrase = wallet.mnemonic();
    let recovery_wallet = WalletBuilder::recover(phrase).build()?;
    println!("Recovered wallet :\n{recovery_wallet}");
    Ok(())
}

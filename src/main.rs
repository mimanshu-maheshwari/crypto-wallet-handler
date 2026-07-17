use wallet_app::wallet::{WalletBuilder, mnemonics::WordCount};

fn main() -> anyhow::Result<()> {
    let wallet = WalletBuilder::create()
        .word_count(WordCount::Twelve)
        .account_index(0)
        .pass("")
        .build()?;
    println!("Created wallet   :{}\n\n", wallet.expose_secrets());

    let phrase = wallet.mnemonic();
    let recovery_wallet = WalletBuilder::recover(phrase)
        .pass("")
        .account_index(0)
        .build()?;
    println!("Recovered wallet :\n{recovery_wallet}");
    Ok(())
}

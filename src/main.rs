use std::str::FromStr;

use bitcoin::{bip32::Xpriv, consensus::serialize, hex::DisplayHex, key::Secp256k1};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use brc20_demo::{brc20, build_commit_tx, build_reveal_tx, Unspent};

fn main() {
    let secp = Secp256k1::new();
    // This is xpriv descriptor for signet test
    let xpriv_desc = "tprv8ku1y3SPM9kB9aM3RHQ9io5nzHTTWPGXEkgZPL4UC43nJWPrVUJnFBGKGa3pLLZC7W9ZrxJKU7E7Vk62KPFZ4gcQALkZXD8HHso2usVeGNA";
    let tprv = Xpriv::from_str(xpriv_desc).unwrap();
    let sk = tprv.private_key;

    let txid = "9c7236ecc2dc45c8ba7e1e7bf8198b07e7a0b95b9fe972177e79835149f7f9e4";
    let unspent_value = 701871;
    let unspent = Unspent::new(txid, unspent_value);

    let ticker = "sats".to_owned();
    let value = "10".to_owned();
    let ins = brc20::Brc20::transfer(sk.public_key(&secp).into(), ticker, value).unwrap();

    // for testnet and signet, 1 sat/vB feerate is enough
    let feerate = 1;

    // Commit transaction ID: a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    // https://mempool.space/signet/tx/a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    let commit_tx = build_commit_tx(&secp, &sk, unspent, &ins, feerate);

    eprintln!("\n Commit Transaction \n");
    eprintln!("Transaction ID: {}", commit_tx.txid());

    eprintln!(
        "Raw Transaction: {}",
        serialize(&commit_tx).to_lower_hex_string()
    );
    eprintln!("{}", "-".repeat(80));

    // Reveal transaction ID: 0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    // https://mempool.space/signet/tx/0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    let reveal_tx = build_reveal_tx(&secp, &sk, &commit_tx, &ins);

    eprintln!("\n Reveal Transaction\n");
    eprintln!("Transaction ID: {}", reveal_tx.txid());
    eprintln!(
        "Raw Transaction: {}",
        serialize(&reveal_tx).to_lower_hex_string()
    );
    eprintln!("{}", "-".repeat(80));

    let auth = Auth::UserPass("alice".to_owned(), "alice".to_owned());
    let client = Client::new("http://localhost:38332", auth).unwrap();
    client
        .send_raw_transaction(&commit_tx)
        .expect("commit transaction broadcast failed");
    client
        .send_raw_transaction(&reveal_tx)
        .expect("reveal transaction broadcast");
}

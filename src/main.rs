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

    // commit tx:
    // txid: a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    // hex: 02000000000101e4f9f7495183797e1772e99f5bb9a0e7078b19f87b1e7ebac845dcc2ec36729c0100000000fdffffff02ea020000000000002251209dd086517f25d5ee5062aae53a06054ad88ef06b19995399ca3263cde527205ffdb10a00000000002251203924d7b277700a36a751a518250495b91f883360a1767a4c25d0725a8c73af510140e811da903c3e6ff1a8e3d0ae72af8162b8d3ad590efac1e5ac5cfa7f47fd1c8a8252706ceef3ef071c4a7fd5296d10c887ac46de08e6a934e518f6eb575613ea00000000
    // https://mempool.space/signet/tx/a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    let commit_tx = build_commit_tx(&secp, &sk, unspent, &ins, feerate);

    eprintln!("{}", "=".repeat(80));
    eprintln!("Commit Transaction ID: {}", commit_tx.txid());

    eprintln!(
        "Commit Raw Transaction: {}",
        serialize(&commit_tx).to_lower_hex_string()
    );
    eprintln!("{}", "=".repeat(80));

    // Reveal Transaction ID: 0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    //  Reveal Raw Transaction: 02000000000101888399f03915bc73632a35db342f71aa8b3aba8a79ddbf27f5caf511d7bebaa70000000000fdffffff0122020000000000002251203924d7b277700a36a751a518250495b91f883360a1767a4c25d0725a8c73af510340631a1a547967b8119c16fb2f31dc7ee61d13c43fb6a4ca1e2c44ace613d086c5a8a68303c63b8d4e1da1f51665bfd0d3e1cecee6f3dd1ba521d85f463604909d550063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800317b2270223a22222c226f70223a227472616e73666572222c227469636b223a2273617473222c22616d74223a223230227d6821c0608c570af85df858abb7fd6ac1dd7a91cc1321f2a7f6e7325350956eb97844d500000000
    // https://mempool.space/signet/tx/0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    let reveal_tx = build_reveal_tx(&secp, &sk, &commit_tx, &ins);

    eprintln!("Reveal Transaction ID: {}", reveal_tx.txid());
    eprintln!(
        "Reveal Raw Transaction: {}",
        serialize(&reveal_tx).to_lower_hex_string()
    );
    eprintln!("{}", "=".repeat(80));

    let auth = Auth::UserPass("alice".to_owned(), "alice".to_owned());
    let client = Client::new("http://localhost:38332", auth).unwrap();
    client
        .send_raw_transaction(&commit_tx)
        .expect("commit transaction broadcast failed");
    client
        .send_raw_transaction(&reveal_tx)
        .expect("reveal transaction broadcast");
}

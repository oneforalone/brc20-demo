use std::str::FromStr;

use bitcoin::{
    absolute,
    bip32::Xpriv,
    consensus::serialize,
    hex::DisplayHex,
    key::{Secp256k1, Verification},
    secp256k1::{SecretKey, Signing},
    transaction, Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};

use brc20_demo::{
    brc20, inscription::OrdinalsInscription, taproot_key_path_sign, taproot_script_path_sign,
};

use bitcoincore_rpc::{Auth, Client, RpcApi};

fn main() {
    let secp = Secp256k1::new();
    // This is xpriv descriptor for signet test
    let xpriv_desc = "tprv8ku1y3SPM9kB9aM3RHQ9io5nzHTTWPGXEkgZPL4UC43nJWPrVUJnFBGKGa3pLLZC7W9ZrxJKU7E7Vk62KPFZ4gcQALkZXD8HHso2usVeGNA";
    let tprv = Xpriv::from_str(xpriv_desc).unwrap();
    let sk = tprv.private_key;

    let commit_tx = build_commit_tx(&secp, &sk);
    let reveal_tx = build_reveal_tx(&secp, &sk, &commit_tx);

    let auth = Auth::UserPass("alice".to_owned(), "alice".to_owned());
    let client = Client::new("http://localhost:38332", auth).unwrap();
    client
        .send_raw_transaction(&commit_tx)
        .expect("commit transaction broadcast failed");
    client
        .send_raw_transaction(&reveal_tx)
        .expect("reveal transaction broadcast");
}

fn build_commit_tx<C: Signing + Verification>(secp: &Secp256k1<C>, sk: &SecretKey) -> Transaction {
    // commit tx:
    // txid: a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    // hex: 02000000000101e4f9f7495183797e1772e99f5bb9a0e7078b19f87b1e7ebac845dcc2ec36729c0100000000fdffffff02ea020000000000002251209dd086517f25d5ee5062aae53a06054ad88ef06b19995399ca3263cde527205ffdb10a00000000002251203924d7b277700a36a751a518250495b91f883360a1767a4c25d0725a8c73af510140e811da903c3e6ff1a8e3d0ae72af8162b8d3ad590efac1e5ac5cfa7f47fd1c8a8252706ceef3ef071c4a7fd5296d10c887ac46de08e6a934e518f6eb575613ea00000000
    // https://mempool.space/signet/tx/a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388
    let pubkey = sk.public_key(secp);
    let txid = "9c7236ecc2dc45c8ba7e1e7bf8198b07e7a0b95b9fe972177e79835149f7f9e4";
    let unspent_amount = Amount::from_sat(701871);
    let txid = Txid::from_str(txid).unwrap();
    let outpoint = OutPoint { txid, vout: 1 };

    let input = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    // for signet testcase
    let spend_amount = 546 + 200;

    let transfer_inscription = build_brc20_transfer_inscription(&pubkey.into());

    let commit_address = Address::p2tr_tweaked(
        transfer_inscription.spend_info().output_key(),
        bitcoin::Network::Signet,
    );
    eprintln!("Commit_address: {commit_address}");

    let merkle_root = transfer_inscription.spend_info().merkle_root().unwrap();

    let spend_amount = Amount::from_sat(spend_amount);
    let spend = TxOut {
        value: spend_amount,
        script_pubkey: ScriptBuf::new_p2tr(secp, XOnlyPublicKey::from(pubkey), Some(merkle_root)),
    };

    let txfee = Amount::from_sat(200);
    let change_amount = unspent_amount
        .checked_sub(spend_amount.checked_add(txfee).unwrap())
        .unwrap();
    let change = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let prevout = TxOut {
        value: unspent_amount,
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };

    let commit_tx = taproot_key_path_sign(secp, sk, &[prevout], &mut unsigned_tx);
    eprintln!("Commit Transaction ID: {}", commit_tx.txid());

    let raw_tx = serialize(&commit_tx).to_lower_hex_string();
    eprintln!("Commit Raw Transaction: {raw_tx}");
    eprintln!("{}", "=".repeat(80));

    commit_tx
}

fn build_reveal_tx<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    commit_tx: &Transaction,
) -> Transaction {
    // Reveal Transaction ID: 0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0
    //  Reveal Raw Transaction: 02000000000101888399f03915bc73632a35db342f71aa8b3aba8a79ddbf27f5caf511d7bebaa70000000000fdffffff0122020000000000002251203924d7b277700a36a751a518250495b91f883360a1767a4c25d0725a8c73af510340631a1a547967b8119c16fb2f31dc7ee61d13c43fb6a4ca1e2c44ace613d086c5a8a68303c63b8d4e1da1f51665bfd0d3e1cecee6f3dd1ba521d85f463604909d550063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800317b2270223a22222c226f70223a227472616e73666572222c227469636b223a2273617473222c22616d74223a223230227d6821c0608c570af85df858abb7fd6ac1dd7a91cc1321f2a7f6e7325350956eb97844d500000000
    // https://mempool.space/signet/tx/0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0

    // commit tx id
    // let txid = "a7babed711f5caf527bfdd798aba3a8baa712f34db352a6373bc1539f0998388";
    // let txid = Txid::from_str(txid).unwrap();
    let pubkey = sk.public_key(secp);
    let txid = commit_tx.txid();

    let transfer_inscription = build_brc20_transfer_inscription(&pubkey.into());
    let merkle_root = transfer_inscription.spend_info().merkle_root().unwrap();

    let preoutpoint = OutPoint { txid, vout: 0 };
    let input = TxIn {
        previous_output: preoutpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };
    let spend = TxOut {
        value: Amount::from_sat(546),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend],
    };

    let prevout = TxOut {
        value: Amount::from_sat(546),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), Some(merkle_root)),
    };

    let reveal_tx = taproot_script_path_sign(
        secp,
        sk,
        &[prevout],
        &mut unsigned_tx,
        &transfer_inscription,
    );

    let txid = reveal_tx.txid();
    // eprintln!("Reveal Transaction ID: {txid}");
    assert_eq!(
        txid,
        Txid::from_str("0b9e5385023b27363033459dc5a33eb9199a758f45a055726705790811bf72b0").unwrap()
    );
    let raw_tx = serialize(&reveal_tx).to_lower_hex_string();
    eprintln!("Reveal Raw Transaction: {raw_tx}");
    eprintln!("{}", "=".repeat(80));
    reveal_tx
}

fn build_brc20_transfer_inscription(pubkey: &PublicKey) -> OrdinalsInscription {
    let ticker = "sats".to_owned();
    let amount = "20".to_owned();
    brc20::Brc20::transfer(pubkey.to_owned(), ticker, amount).unwrap()
}

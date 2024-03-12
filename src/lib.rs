use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, Signature, TaprootBuilder};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use inscription::OrdinalsInscription;

pub mod brc20;
pub mod inscription;

const REVEAL_TX_SIZE: u64 = 141;
const DUST_AMOUNT: u64 = 546;

pub struct Unspent {
    pub txid: Txid,
    pub value: Amount,
}

impl Unspent {
    pub fn new(txid: &str, value: u64) -> Self {
        let txid = Txid::from_str(txid).unwrap();
        let value = Amount::from_sat(value);
        Unspent { txid, value }
    }
}

pub fn build_commit_tx<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    unspent: Unspent,
    inscription: &OrdinalsInscription,
    feerate: u64,
) -> Transaction {
    let pubkey = sk.public_key(secp);
    // TODO: need to ajust with the vout for other txs
    let txid = unspent.txid;
    let outpoint = OutPoint { txid, vout: 1 };

    let input = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let spend_amount = DUST_AMOUNT + feerate * REVEAL_TX_SIZE;
    let spend_amount = Amount::from_sat(spend_amount);
    let merkle_root = inscription.spend_info().merkle_root().unwrap();
    let spend = TxOut {
        value: spend_amount,
        script_pubkey: ScriptBuf::new_p2tr(secp, XOnlyPublicKey::from(pubkey), Some(merkle_root)),
    };

    let mut change = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let unspent_value = unspent.value;
    let prevout = TxOut {
        value: unspent_value,
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let tmp_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input.clone()],
        output: vec![spend.clone(), change.clone()],
    };

    let txfee = Amount::from_sat(tmp_tx.vsize() as u64 * feerate);
    change.value = unspent_value
        .checked_sub(spend_amount.checked_add(txfee).unwrap())
        .unwrap();

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };

    taproot_sign(
        secp,
        sk,
        &[prevout],
        &mut unsigned_tx,
        TaprootSpendingType::KeyPath,
        Some(inscription.taproot_program().to_owned()),
    )
}

pub fn build_reveal_tx<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    commit_tx: &Transaction,
    inscription: &OrdinalsInscription,
) -> Transaction {
    let pubkey = sk.public_key(secp);
    let txid = commit_tx.txid();

    let merkle_root = inscription.spend_info().merkle_root().unwrap();

    let preoutpoint = OutPoint { txid, vout: 0 };
    let input = TxIn {
        previous_output: preoutpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };
    let spend = TxOut {
        value: Amount::from_sat(DUST_AMOUNT),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), None),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend],
    };

    let prevout = TxOut {
        value: Amount::from_sat(DUST_AMOUNT),
        script_pubkey: ScriptBuf::new_p2tr(secp, pubkey.into(), Some(merkle_root)),
    };

    taproot_sign(
        secp,
        sk,
        &[prevout],
        &mut unsigned_tx,
        TaprootSpendingType::ScriptPath,
        Some(inscription.taproot_program().to_owned()),
    )
}

pub enum TaprootSpendingType {
    KeyPath,
    ScriptPath,
}

pub fn taproot_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
    taproot_type: TaprootSpendingType,
    taproot_script: Option<ScriptBuf>,
) -> Transaction {
    let keypair = Keypair::from_secret_key(secp, sk);
    let prevouts = Prevouts::All(prevouts);
    let sighash_type = TapSighashType::Default;
    let input_index = 0;

    let mut sighash_cache = SighashCache::new(tx);
    let witness = match taproot_type {
        TaprootSpendingType::KeyPath => {
            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
                .expect("Failed to construct sighash");
            let msg = Message::from_digest(sighash.to_byte_array());
            let tweaked = keypair.tap_tweak(secp, None);
            let sig = secp.sign_schnorr(&msg, &tweaked.to_inner());
            let sig = Signature {
                sig,
                hash_ty: sighash_type,
            };
            Witness::from_slice(&[&sig.to_vec()])
        }
        TaprootSpendingType::ScriptPath => {
            let script = taproot_script.as_ref().unwrap().to_owned();
            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    input_index,
                    &prevouts,
                    TapLeafHash::from_script(&script, LeafVersion::TapScript),
                    sighash_type,
                )
                .expect("Failed to construct sighash");
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_schnorr(&msg, &keypair);
            let sig = Signature {
                sig,
                hash_ty: sighash_type,
            };

            let mut witness = Witness::new();
            witness.push(sig.to_vec());
            witness.push(script.as_bytes());

            let spend_info = TaprootBuilder::new()
                .add_leaf(0, script.clone())
                .expect("Taproot Spending info build error")
                .finalize(secp, XOnlyPublicKey::from_keypair(&keypair).0)
                .expect("Taproot Spending info build failed");

            let contronl_block = spend_info
                .control_block(&(script.to_owned(), LeafVersion::TapScript))
                .unwrap();

            witness.push(contronl_block.serialize());
            witness
        }
    };

    *sighash_cache.witness_mut(input_index).unwrap() = witness;
    sighash_cache.into_transaction().to_owned()
}

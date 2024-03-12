use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, Signature};
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

    taproot_key_path_sign(secp, sk, &[prevout], &mut unsigned_tx)
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

    taproot_script_path_sign(secp, sk, &[prevout], &mut unsigned_tx, inscription)
}

// TODO: merge two taproot sign function to one
pub fn taproot_key_path_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
) -> Transaction {
    let keypair = Keypair::from_secret_key(secp, sk);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(prevouts);

    let input_index = 0;
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed  to construct sighash");

    let tweaked = keypair.tap_tweak(secp, None);

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &tweaked.to_inner());

    let signature = Signature {
        sig,
        hash_ty: sighash_type,
    };
    *sighasher.witness_mut(input_index).unwrap() = Witness::from_slice(&[&signature.to_vec()]);

    sighasher.into_transaction().to_owned()
}

pub fn taproot_script_path_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
    inscription: &OrdinalsInscription,
) -> Transaction {
    let keypair = Keypair::from_secret_key(secp, sk);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(prevouts);
    let script = inscription.taproot_program().to_owned();
    let control_block = inscription
        .spend_info()
        .control_block(&(script.to_owned(), LeafVersion::TapScript))
        .unwrap();

    let input_index = 0;
    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_script_spend_signature_hash(
            input_index,
            &prevouts,
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            sighash_type,
        )
        .expect("failed to construct sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &keypair);
    let signature = Signature {
        sig,
        hash_ty: sighash_type,
    };

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());

    *sighasher.witness_mut(input_index).unwrap() = witness;

    sighasher.into_transaction().to_owned()
}

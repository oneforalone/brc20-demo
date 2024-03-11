use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, Signature};
use bitcoin::{TapLeafHash, Transaction, TxOut, Witness};
use inscription::OrdinalsInscription;

pub mod brc20;
pub mod inscription;

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

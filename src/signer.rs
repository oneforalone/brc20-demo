use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, Signature, TaprootBuilder};
use bitcoin::{
    EcdsaSighashType, ScriptBuf, TapLeafHash, Transaction, TxOut, Witness, XOnlyPublicKey,
};

pub fn segwit_ecdsa_sign<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
) -> Transaction {
    debug_assert_eq!(prevouts.len(), tx.input.len());
    let sighash_type = EcdsaSighashType::All;
    // TODO: need to improve for multi inputs
    let input_index = 0;

    let mut sighash_cache = SighashCache::new(tx.clone());
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            input_index,
            &prevouts[0].script_pubkey,
            tx.output[0].value,
            sighash_type,
        )
        .expect("failed to create sighash");

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, sk);
    let sig = bitcoin::ecdsa::Signature {
        sig,
        hash_ty: sighash_type,
    };
    *sighash_cache.witness_mut(input_index).unwrap() = Witness::p2wpkh(&sig, &sk.public_key(secp));

    sighash_cache.into_transaction().to_owned()
}

pub enum TaprootSpendingType {
    KeyPath,
    ScriptPath,
}

pub fn taproot_schnorr_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    prevouts: &[TxOut],
    tx: &mut Transaction,
    taproot_type: TaprootSpendingType,
    taproot_script: Option<ScriptBuf>,
) -> Transaction {
    debug_assert_eq!(prevouts.len(), tx.input.len());

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

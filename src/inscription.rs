use anyhow::Result;
use bitcoin::{
    key::Secp256k1,
    script::PushBytesBuf,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    PublicKey, Script, ScriptBuf, TapNodeHash, XOnlyPublicKey,
};
pub struct TaprootProgram {
    pub script: ScriptBuf,
    pub spend_info: TaprootSpendInfo,
}

pub struct TaprootScript {
    pub pubkey: PublicKey,
    pub merkle_root: TapNodeHash,
}
pub struct OrdinalsInscription {
    envelope: TaprootProgram,
}

impl OrdinalsInscription {
    pub fn new(mime: &[u8], data: &[u8], recipient: PublicKey) -> Result<OrdinalsInscription> {
        let envelope = create_envelope(mime, data, recipient)?;
        Ok(OrdinalsInscription { envelope })
    }
    pub fn taproot_program(&self) -> &Script {
        self.envelope.script.as_script()
    }
    pub fn spend_info(&self) -> &TaprootSpendInfo {
        &self.envelope.spend_info
    }
}

/// Creates an [Ordinals Inscription](https://docs.ordinals.com/inscriptions.html).
/// This function is used for two purposes:
///
/// 1. It creates the spending condition for the given `internal_key`. This
///    associates the public key of the recipient with the Merkle root of the
///    Inscription on-chain, but it does not actually reveal the script to
///    anyone ("commit stage").
/// 2. The same function can then be used by the spender/claimer to actually
///    transfer the Inscripion by sending a transaction with the Inscription
///    script in the Witness ("reveal stage").
///
/// Do note that the `internal_key` can be different for each stage, but it
/// could also be the same entity. Stage one, the `internal_key` is the
/// recipient. Stage two, the `internal_key` is the claimer of the transaction
/// (where the Inscription script is available in the Witness).
fn create_envelope(mime: &[u8], data: &[u8], internal_key: PublicKey) -> Result<TaprootProgram> {
    use bitcoin::opcodes::all::*;
    use bitcoin::opcodes::*;

    let mut mime_buf = PushBytesBuf::new();
    mime_buf.extend_from_slice(mime).unwrap();

    let mut builder = ScriptBuf::builder()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"ord")
        // Separator.
        .push_opcode(OP_PUSHBYTES_1)
        // MIME types require this addtional push. It seems that the original
        // creator inadvertently used `push_slice(&[1])`, which leads to
        // `<1><1>`, which denotes a length prefix followed by the value. On the
        // other hand, for the data, `push_slice(&[])` is used, producing `<0>`.
        // This denotes a length prefix followed by no data, as opposed to
        // '<1><0>', which would be a reasonable assumption. While this appears
        // inconsistent, it's the current requirement.
        .push_opcode(OP_PUSHBYTES_1)
        // MIME type identifying the data
        .push_slice(mime_buf.as_push_bytes())
        // Separator
        .push_opcode(OP_PUSHBYTES_0);

    // Push the actual data in chunks.
    for chunk in data.chunks(520) {
        // Create data buffer.
        let mut data_buf = PushBytesBuf::new();
        data_buf.extend_from_slice(chunk).unwrap();

        // Push buffer
        builder = builder.push_slice(data_buf);
    }

    // Finalize scripts.
    let script = builder.push_opcode(OP_ENDIF).into_script();

    // Generate the necessary spending information. As mentioned in the
    // documentation of this function at the top, this serves two purposes;
    // setting the spending condition and actually claiming the spending
    // condition.
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("Ordinals Inscription spending info must always build")
        .finalize(&Secp256k1::new(), XOnlyPublicKey::from(internal_key.inner))
        .expect("Ordinals Inscription spending info must always build");

    Ok(TaprootProgram { script, spend_info })
}

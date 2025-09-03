use alloy_primitives::{Address, hex::FromHex};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use noir::barretenberg::srs::setup_srs_from_bytecode;
use noir::barretenberg::verify;
use noir::{
    barretenberg::{
        prove::prove_ultra_honk_keccak, srs::setup_srs,
        verify::get_ultra_honk_keccak_verification_key,
    },
    witness::from_vec_str_to_witness_map,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, vec};
use tlsn_common::transcript;
use tlsn_core::{
    attestation::{Extension, Field, Header},
    connection::{ConnectionInfo, ServerCertCommitment, ServerEphemKey},
    hash::{Blinder, Hash, HashAlgId},
    presentation::Presentation,
    signing::{Signature, VerifyingKey},
    transcript::{
        Direction, Idx, PartialTranscript, TranscriptCommitment, hash::PlaintextHashSecret,
    },
};

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async_main());
}

async fn async_main() {
    let presentation = std::fs::read("presentation.tlsn").unwrap();

    let presentation: Presentation = bincode::deserialize(&presentation).unwrap();
    let mut witness: Vec<String> = vec![];

    let json = serde_json::to_value(&presentation).unwrap();
    let attestation: AttestationProof =
        serde_json::from_str(&json["attestation"].to_string()).unwrap();
    let transcript: TranscriptProof =
        serde_json::from_str(&json["transcript"].to_string()).unwrap();

    let key_ecdsa =
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&attestation.body.body.verifying_key.data.data)
            .unwrap();
    let key = key_ecdsa.to_encoded_point(false).as_bytes().to_vec();

    let signature = attestation.signature.data;

    let message = bcs::to_bytes(&attestation.header).unwrap();

    let header_root = bcs::to_bytes(&attestation.header.root.value).unwrap();

    let verifying_key_data = bcs::to_bytes(&attestation.body.body.verifying_key.data).unwrap();
    let connection_info_data = bcs::to_bytes(&attestation.body.body.connection_info.data).unwrap();
    let server_ephemeral_key_data =
        bcs::to_bytes(&attestation.body.body.server_ephemeral_key.data).unwrap();
    let cert_commitment_data = bcs::to_bytes(&attestation.body.body.cert_commitment.data).unwrap();
    println!("cert_commitment_data: {:?}", cert_commitment_data);
    let transcript_commitments_data =
        bcs::to_bytes(&attestation.body.body.transcript_commitments[0]).unwrap();
    println!(
        "transcript_commitments_data: {:?}",
        transcript_commitments_data
    );

    let transcript_data = transcript.transcript.received_unsafe();
    let transcript_blinder = transcript.hash_secrets[0].blinder.as_bytes();

    witness.extend(key[1..].iter().map(|n| n.to_string()));
    witness.extend(message.iter().map(|n| n.to_string()));
    witness.extend(signature.iter().map(|n| n.to_string()));
    witness.extend(header_root[1..].iter().map(|n| n.to_string()));
    witness.extend(verifying_key_data.iter().map(|n| n.to_string()));
    witness.extend(connection_info_data.iter().map(|n| n.to_string()));
    witness.extend(server_ephemeral_key_data.iter().map(|n| n.to_string()));
    witness.extend(cert_commitment_data.iter().map(|n| n.to_string()));
    witness.extend(
        transcript_commitments_data[4..]
            .iter()
            .map(|n| n.to_string()),
    );
    witness.extend(transcript_data.iter().map(|n| n.to_string()));
    witness.extend(transcript_blinder.iter().map(|n| n.to_string()));

    // Verify presentation

    println!("Witness: {:?}", witness);

    println!("Verifying presentation");

    let verify = verify_presentation(witness).await;
    println!("✔ Verification process started {:?}", verify);
}

async fn verify_presentation(witness: Vec<String>) {
    let json_content = fs::read_to_string("target/noir_verify_presentation.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    println!("✔ JSON file loaded");

    let bytecode = json["bytecode"].as_str().unwrap().to_string();
    let bytecode_clone = bytecode.clone();
    println!("✔ Bytecode loaded from JSON (length: {})", bytecode.len());

    println!("Starting SRS setup with size");

    let proof = tokio::task::spawn_blocking(move || {
        setup_srs_from_bytecode(&bytecode, None, false).unwrap();
        println!("Next step");
        setup_srs(262146, None).unwrap();
        println!("✔ SRS setup complete");

        let witness_strings: Vec<&str> = witness
            .iter()
            .as_slice()
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>();

        let witness = from_vec_str_to_witness_map(witness_strings).unwrap();
        println!("✔ Witness map created with entries");

        let vk = get_ultra_honk_keccak_verification_key(&bytecode_clone, false, false).unwrap();
        println!("✔ Verification key generated");

        println!("Starting proof generation...");
        prove_ultra_honk_keccak(&bytecode_clone, witness, vk, false, false).unwrap()
    })
    .await
    .unwrap();

    println!("✔ proof generated {}", hex::encode(&proof));

    // Remove last 32 bytes from proof
    let is_valid = verify_proof(proof).await;

    println!("✔ proof valid? {:?}", is_valid);
}

sol! {
    #[sol(rpc)]
    contract HonkVerifier {
        function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
    }
}

async fn verify_proof(proof: Vec<u8>) -> bool {
    let provider = ProviderBuilder::new()
        .connect("http://localhost:8545")
        .await
        .unwrap();

    let address = Address::from_hex("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512").unwrap();
    let contract = HonkVerifier::new(address, provider);

    println!("Original proof length: {}", proof.len());

    let public_inputs: Vec<alloy_primitives::FixedBytes<32>> = vec![];
    let call_builder = contract.verify(proof.into(), public_inputs);

    let call_result = call_builder.call().await.unwrap();

    call_result
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AttestationProof {
    pub signature: Signature,
    pub header: Header,
    pub body: BodyProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyProof {
    pub body: Body,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    alg: HashAlgId,
    leaf_count: usize,
    proof: rs_merkle::MerkleProof<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub verifying_key: Field<VerifyingKey>,
    pub connection_info: Field<ConnectionInfo>,
    pub server_ephemeral_key: Field<ServerEphemKey>,
    pub cert_commitment: Field<ServerCertCommitment>,
    pub extensions: Vec<Field<Extension>>,
    pub transcript_commitments: Vec<Field<TranscriptCommitment>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TranscriptProof {
    pub transcript: PartialTranscript,
    pub encoding_proof: Option<EncodingProof>,
    pub hash_secrets: Vec<PlaintextHashSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProof {
    pub inclusion_proof: MerkleProof,
    pub openings: HashMap<usize, Opening>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Opening {
    pub direction: Direction,
    pub idx: Idx,
    pub blinder: Blinder,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TranscriptOpening {
    pub id: usize,
    pub direction: usize,
    pub data: Vec<u8>,
    pub blinder: Vec<u8>,
    pub position: usize,
}

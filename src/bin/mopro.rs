use alloy_primitives::{Address, hex::FromHex};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use noir::{
    barretenberg::{
        prove::prove_ultra_keccak_honk,
        srs::{setup_srs, setup_srs_from_bytecode},
    },
    witness::from_vec_str_to_witness_map,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, vec};
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

#[tokio::main]
async fn main() {
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

    let commitments = attestation.body.body.transcript_commitments;
    let mut encoding_commitment = None;
    for commitment in commitments {
        match commitment.data {
            TranscriptCommitment::Encoding(commitment) => {
                if encoding_commitment.replace(commitment).is_some() {
                    return;
                }
            }
            TranscriptCommitment::Hash(_) => return,
            _ => {}
        }
    }

    let commitment_root = bcs::to_bytes(&encoding_commitment.clone().unwrap().root.value).unwrap();

    let sent = transcript.transcript.sent_unsafe();
    let received = transcript.transcript.received_unsafe();

    let mut transcript_openings = Vec::new();

    let EncodingProof {
        inclusion_proof: _,
        openings,
    } = transcript.encoding_proof.unwrap();

    let mut sorted_openings: Vec<_> = openings.into_iter().collect();
    sorted_openings.sort_by_key(|(id, _)| *id);

    for (
        id,
        Opening {
            direction,
            idx,
            blinder,
        },
    ) in sorted_openings
    {
        let data = match direction {
            Direction::Sent => sent,
            Direction::Received => received,
        };

        let direction_id = match direction {
            Direction::Sent => 0 as usize,
            Direction::Received => 1 as usize,
        };

        for range in idx.iter_ranges() {
            let data_slice = &data[range.clone()];
            transcript_openings.push(TranscriptOpening {
                id,
                direction: direction_id,
                data: data_slice.to_vec(),
                position: range.start,
                blinder: blinder.as_bytes().to_vec(),
            });
        }
    }
    println!("Transcript openings: {:?}", transcript_openings);

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
    witness.extend(commitment_root[1..].iter().map(|n| n.to_string()));
    witness.extend(transcript_openings.iter().flat_map(|o| {
        let mut opening_witness = vec![o.direction.to_string()];
        opening_witness.extend(o.data.iter().map(|n| n.to_string()));
        opening_witness.extend(o.blinder.iter().map(|n| n.to_string()));
        opening_witness.push(o.position.to_string());
        opening_witness
    }));
    witness.extend(
        encoding_commitment
            .clone()
            .unwrap()
            .secret
            .seed()
            .iter()
            .map(|n| n.to_string()),
    );
    witness.extend(
        encoding_commitment
            .clone()
            .unwrap()
            .secret
            .delta()
            .iter()
            .map(|n| n.to_string()),
    );

    println!("Witness: {:?}", witness);

    println!("Verifying presentation");
    verify_presentation(witness).await;
}

async fn verify_presentation(witness: Vec<String>) {
    let json_content = fs::read_to_string("target/noir_verify_presentation.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_content).unwrap();

    let bytecode = json["bytecode"].as_str().unwrap().to_string();
    let bytecode_clone = bytecode.clone();

    tokio::task::spawn_blocking(move || {
        setup_srs_from_bytecode(&bytecode, Some("transcript00.dat"), false).unwrap();
        setup_srs(4194304, Some("transcript00.dat")).unwrap();
    })
    .await
    .unwrap();

    println!("✔ SRS setup complete");

    let witness_strings: Vec<&str> = witness
        .iter()
        .as_slice()
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<&str>>();

    let witness = from_vec_str_to_witness_map(witness_strings).unwrap();

    let proof = tokio::task::spawn_blocking(move || {
        prove_ultra_keccak_honk(&bytecode_clone, witness, false).unwrap()
    })
    .await
    .unwrap();
    // let proof = fs::read("target/proof").unwrap();

    println!("✔ proof generated {}", hex::encode(&proof));

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

    let address = Address::from_hex("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap();
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

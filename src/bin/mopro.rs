use std::{collections::HashMap, fs, ops::Range};
use noir::{
    barretenberg::{
        prove::prove_ultra_honk,
        srs::{setup_srs, setup_srs_from_bytecode},
        utils::get_honk_verification_key,
        verify::verify_ultra_honk,
    },
    witness::from_vec_str_to_witness_map,
};
use serde::{Deserialize, Serialize};
use tlsn_core::{
    attestation::{Extension, Field, Header}, connection::{ConnectionInfo, ServerCertCommitment, ServerEphemKey}, hash::{Blinder, Hash, HashAlgId}, presentation::Presentation, signing::{Signature, VerifyingKey}, transcript::{hash::PlaintextHashSecret, Direction, Idx, PartialTranscript, TranscriptCommitment}
};

fn main() {
    let presentation = std::fs::read("presentation.tlsn").unwrap();

    let presentation: Presentation = bincode::deserialize(&presentation).unwrap();
    let mut witness: Vec<String> = vec![];

    let json = serde_json::to_value(&presentation).unwrap();
    let attestation: AttestationProof =
        serde_json::from_str(&json["attestation"].to_string()).unwrap();
    let transcript: TranscriptProof =  serde_json::from_str(&json["transcript"].to_string()).unwrap();

    let key_ecdsa = k256::ecdsa::VerifyingKey::from_sec1_bytes(&attestation.body.body.verifying_key.data.data).unwrap();
    let key = key_ecdsa.to_encoded_point(false).as_bytes().to_vec();

    let signature = attestation.signature.data;

    let message = bcs::to_bytes(&attestation.header).unwrap();

    let header_root = bcs::to_bytes(&attestation.header.root.value).unwrap();

    let verifying_key_data = bcs::to_bytes(&attestation.body.body.verifying_key.data).unwrap();
    let connection_info_data = bcs::to_bytes(&attestation.body.body.connection_info.data).unwrap();
    let server_ephemeral_key_data = bcs::to_bytes(&attestation.body.body.server_ephemeral_key.data).unwrap();
    let cert_commitment_data = bcs::to_bytes(&attestation.body.body.cert_commitment.data).unwrap();
    println!("cert_commitment_data: {:?}", cert_commitment_data);
    let transcript_commitments_data = bcs::to_bytes(&attestation.body.body.transcript_commitments[0]).unwrap();
    println!("transcript_commitments_data: {:?}", transcript_commitments_data);

    let commitments = attestation.body.body.transcript_commitments;
    let mut encoding_commitment = None;
        for commitment in commitments {
            match commitment.data {
                TranscriptCommitment::Encoding(commitment) => {
                    if encoding_commitment.replace(commitment).is_some() {
                        return
                    }
                }
                TranscriptCommitment::Hash(_) => {
                    return
                }
                _ => {}
            }
        }

    let commitment_root = bcs::to_bytes(&encoding_commitment.clone().unwrap().root.value).unwrap();

    let sent= transcript.transcript.sent_unsafe();
    let received = transcript.transcript.received_unsafe(); 

    let mut transcript_openings = Vec::new(); 

    let EncodingProof {
            inclusion_proof,
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
    witness.extend(transcript_commitments_data[4..].iter().map(|n| n.to_string()));
    witness.extend(commitment_root[1..].iter().map(|n| n.to_string()));
    witness.extend(transcript_openings.iter().flat_map(|o| {
        let mut opening_witness = vec![o.direction.to_string()];
        opening_witness.extend(o.data.iter().map(|n| n.to_string()));
        opening_witness.extend(o.blinder.iter().map(|n| n.to_string()));
        opening_witness.push(o.position.to_string());
        opening_witness
    }));
    witness.extend(encoding_commitment.clone().unwrap().secret.seed().iter().map(|n| n.to_string()));
    witness.extend(encoding_commitment.clone().unwrap().secret.delta().iter().map(|n| n.to_string()));

    println!("Witness: {:?}", witness);

    println!("Verifying presentation");
    verify_presentation(witness);
}

fn verify_presentation(witness: Vec<String>) {
    let json_content = fs::read_to_string("target/noir_verify_presentation.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_content).unwrap();

    let bytecode = json["bytecode"].as_str().unwrap();

    setup_srs_from_bytecode(bytecode, None, false).unwrap();
    setup_srs(4194304, None).unwrap();

    println!("✔ SRS setup complete");

    let witness_strings: Vec<&str> = witness.iter().as_slice()
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<&str>>();

    let witness = from_vec_str_to_witness_map(witness_strings).unwrap();

    let proof = prove_ultra_honk(bytecode, witness, false).unwrap();

    let vk = get_honk_verification_key(bytecode, false).unwrap();
    let is_valid = verify_ultra_honk(proof, vk).unwrap();
    println!("✔ proof valid? {:?}", is_valid);
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
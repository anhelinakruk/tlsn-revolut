use std::fs;

use clap::builder::Str;
use noir::{
    barretenberg::{
        prove::prove_ultra_honk,
        srs::{setup_srs, setup_srs_from_bytecode},
        utils::get_honk_verification_key,
        verify::verify_ultra_honk,
    },
    witness::from_vec_str_to_witness_map,
};

fn main() {
    let presentation = std::fs::read("presentation.tlsn").unwrap();
    let mut witness: Vec<String> = vec![];

    let json = serde_json::to_value(&presentation).unwrap();
    let attestation: AttestationProof =
        serde_json::from_str(&json["attestation"].to_string()).unwrap();

    println!("Attestation:{:?}", attestation);

    let key = attestation.body.body.verifying_key.data.data;
    println!("Verifying key: {:?}", key);

    let signature = attestation.signature.data;
    println!("Signature: {:?}", signature);

    let message = bcs::to_bytes(&attestation.header).unwrap();
    println!("Message: {:?}", message);

    let header_root = bcs::to_bytes(&attestation.header.root.value).unwrap();
    println!("Header root: {:?}", header_root);

    let body_leaves = vec![
        "141", "104", "217", "155", "2", "30", "168", "170", "185", "6", "45", "127", "65", "176",
        "175", "228", "72", "218", "81", "227", "93", "163", "206", "24", "140", "103", "224",
        "164", "152", "48", "38", "74", "216", "120", "202", "43", "151", "133", "16", "195",
        "221", "77", "11", "207", "7", "93", "224", "130", "183", "2", "47", "9", "72", "248",
        "85", "27", "219", "47", "66", "250", "186", "72", "210", "240", "105", "174", "86", "34",
        "16", "193", "174", "244", "128", "94", "26", "62", "99", "215", "54", "61", "182", "58",
        "221", "243", "57", "225", "236", "32", "110", "27", "178", "171", "3", "57", "204", "231",
        "221", "201", "199", "254", "14", "61", "213", "1", "24", "72", "19", "183", "8", "66",
        "227", "150", "117", "138", "144", "205", "125", "177", "45", "15", "149", "21", "252",
        "142", "147", "111", "79", "196", "230", "33", "57", "199", "150", "131", "62", "144",
        "32", "2", "162", "131", "154", "153", "139", "171", "103", "231", "107", "57", "102",
        "255", "146", "74", "215", "142", "121", "39", "89", "2", "112", "67",
    ];

    witness.push(key.iter().map(|n| n.to_string()).collect());
    witness.push(signature.iter().map(|n| n.to_string()).collect());
    witness.push(message.iter().map(|n| n.to_string()).collect());
    witness.push(header_root.iter().map(|n| n.to_string()).collect());
    witness.push(body_leaves.join(","));

    println!("Verifying presentation");
    verify_presentation(witness);
}

fn verify_presentation(witness: Vec<String>) {
    let json_content = fs::read_to_string("target/noir_verify_presentation.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_content).unwrap();

    let bytecode = json["bytecode"].as_str().unwrap();

    setup_srs_from_bytecode(bytecode, None, false).unwrap();
    setup_srs(131073, None).unwrap();

    println!("✔ SRS setup complete");

    let witness_strings = vec![
        // Key (64 bytes)
        "34", "165", "1", "123", "10", "127", "244", "109", "102", "23", "136", "37", "117", "232",
        "91", "114", "66", "250", "180", "155", "15", "102", "248", "186", "244", "152", "230",
        "181", "19", "68", "83", "150", "234", "202", "252", "36", "131", "215", "53", "128",
        "201", "196", "78", "149", "10", "162", "53", "110", "197", "156", "63", "123", "81", "24",
        "90", "87", "14", "212", "19", "190", "221", "241", "168", "247", //Message
        "180", "159", "174", "232", "137", "124", "67", "34", "16", "64", "72", "71", "25", "175",
        "188", "119", "0", "0", "0", "0", "2", "32", "159", "84", "217", "98", "224", "139", "152",
        "197", "11", "87", "166", "82", "38", "181", "140", "115", "86", "135", "126", "231",
        "230", "58", "104", "152", "192", "174", "80", "163", "201", "166", "74", "206",
        // Signature (64 bytes)
        "144", "37", "210", "5", "35", "178", "65", "125", "52", "242", "129", "146", "35", "165",
        "17", "18", "121", "70", "201", "93", "230", "189", "162", "123", "73", "234", "144",
        "120", "146", "185", "170", "11", "62", "83", "179", "145", "71", "92", "229", "31", "120",
        "31", "238", "43", "139", "174", "143", "26", "202", "162", "168", "19", "242", "49",
        "234", "47", "38", "225", "145", "184", "205", "166", "135", "17",
        // Header root
        "159", "84", "217", "98", "224", "139", "152", "197", "11", "87", "166", "82", "38", "181",
        "140", "115", "86", "135", "126", "231", "230", "58", "104", "152", "192", "174", "80",
        "163", "201", "166", "74", "206", // Body leaves hashes - flatten all arrays
        "141", "104", "217", "155", "2", "30", "168", "170", "185", "6", "45", "127", "65", "176",
        "175", "228", "72", "218", "81", "227", "93", "163", "206", "24", "140", "103", "224",
        "164", "152", "48", "38", "74", "216", "120", "202", "43", "151", "133", "16", "195",
        "221", "77", "11", "207", "7", "93", "224", "130", "183", "2", "47", "9", "72", "248",
        "85", "27", "219", "47", "66", "250", "186", "72", "210", "240", "105", "174", "86", "34",
        "16", "193", "174", "244", "128", "94", "26", "62", "99", "215", "54", "61", "182", "58",
        "221", "243", "57", "225", "236", "32", "110", "27", "178", "171", "3", "57", "204", "231",
        "221", "201", "199", "254", "14", "61", "213", "1", "24", "72", "19", "183", "8", "66",
        "227", "150", "117", "138", "144", "205", "125", "177", "45", "15", "149", "21", "252",
        "142", "147", "111", "79", "196", "230", "33", "57", "199", "150", "131", "62", "144",
        "32", "2", "162", "131", "154", "153", "139", "171", "103", "231", "107", "57", "102",
        "255", "146", "74", "215", "142", "121", "39", "89", "2", "112", "67",
        // Commitment root
        "17", "201", "148", "157", "99", "14", "220", "117", "64", "238", "156", "33", "126", "34",
        "131", "178", "224", "198", "179", "44", "220", "232", "159", "216", "115", "90", "246",
        "68", "245", "36", "117", "66", // Transcript leaves hashes - flatten all arrays
        "89", "213", "174", "100", "184", "37", "136", "243", "214", "156", "194", "1", "89",
        "126", "48", "163", "186", "136", "229", "132", "255", "119", "63", "14", "234", "30", "3",
        "77", "163", "212", "146", "40", "68", "169", "184", "177", "243", "187", "28", "190",
        "16", "224", "139", "4", "168", "215", "175", "122", "116", "56", "139", "217", "201",
        "243", "253", "207", "219", "211", "9", "139", "95", "10", "11", "105", "109", "161",
        "215", "124", "153", "38", "206", "196", "154", "168", "163", "58", "21", "66", "36", "97",
        "77", "188", "201", "241", "120", "124", "6", "24", "102", "144", "185", "173", "188",
        "253", "183", "156", "69", "248", "10", "26", "230", "252", "12", "41", "46", "67", "102",
        "123", "174", "32", "217", "66", "49", "114", "189", "255", "89", "233", "232", "149",
        "119", "10", "133", "130", "130", "162", "22", "49", "64", "46", "57", "207", "221", "208",
        "154", "44", "22", "224", "41", "163", "204", "96", "240", "234", "56", "20", "249", "166",
        "148", "94", "183", "146", "6", "142", "194", "235", "195", "11", "213", "162", "189",
        "112", "230", "54", "80", "112", "220", "32", "109", "129", "56", "124", "218", "82",
        "112", "91", "170", "56", "50", "122", "233", "202", "176", "141", "201", "20", "4", "67",
        "228", "0", "42", "160", "125", "204", "131", "41", "94", "159", "251", "246", "110", "86",
        "212", "249", "124", "124", "192", "134", "206", "155", "250", "47", "2", "28", "197",
        "239", "250", "186", "6", "68", "16", "134", "23", "226", "239", "93", "140", "226", "180",
        "63", "23", "240", "179", "198", "40", "0", "173", "35", "12", "67", "165", "153", "84",
        "35", "76", "127", "128", "134", "3", "18", "67", "97", "251", "148", "156", "26", "74",
        "70", "53", "238", "208", "187", "238", "80", "35", "243", "105", "111", "127", "193",
        "183", "184", "171", "21", "136", "56", "43", "62", "146", "181", "94", "75", "240", "40",
        "186", "249", "69", "93",
    ];

    let witness = from_vec_str_to_witness_map(witness).unwrap();

    let proof = prove_ultra_honk(bytecode, witness, false).unwrap();

    let vk = get_honk_verification_key(bytecode, false).unwrap();
    let is_valid = verify_ultra_honk(proof, vk).unwrap();
    println!("✔ proof valid? {:?}", is_valid);
}

use serde::{Deserialize, Serialize};
use tlsn_core::{
    attestation::{Extension, Field, Header},
    connection::{ConnectionInfo, ServerCertCommitment, ServerEphemKey},
    hash::{Hash, HashAlgId},
    signing::{Signature, VerifyingKey},
    transcript::TranscriptCommitment,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProof {
    pub signature: Signature,
    pub header: Header,
    pub body: BodyProof,
}

/// Proof of an attestation body.
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

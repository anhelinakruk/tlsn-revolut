use macro_rules_attribute::apply;
use serde::{Deserialize, Serialize};
use smol_macros::main;
use thiserror::Error;
use tls_core::verify::WebPkiVerifier;
use tlsn_core::{
    CryptoProvider,
    connection::ServerName,
    presentation::{Presentation, PresentationOutput},
    signing::VerifyingKey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevolutTransaction {
    transaction_id: String,
    state: String,
    comment: String,
    currency: String,
    amount: i64,
    beneficiary: BeneficiaryType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BeneficiaryType {
    External {
        iban: String,
        bic: String,
    },
    Internal {
        id: String,
        #[serde(rename = "type")]
        account_type: String,
        username: String,
        code: String,
    },
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Anyhow(anyhow::Error),
}

#[apply(main!)]
async fn main() {
    let presentation = std::fs::read("presentation.tlsn").unwrap();
    verify(presentation).await.unwrap();
}

pub async fn verify(presentation: Vec<u8>) -> Result<(), AppError> {
    println!("Verifying presentation");

    let presentation = bincode::deserialize(&presentation).map_err(|e| {
        println!("Failed to deserialize presentation: {}", e);
        AppError::Anyhow(anyhow::anyhow!("Failed to deserialize presentation: {}", e))
    })?;

    let (sent, received, session_info) = verify_presentation(presentation).await;

    println!("session_info: {:?}", session_info);
    let sent = bytes_to_redacted_string(&sent);
    let received = bytes_to_redacted_string(&received);

    let transaction: Option<RevolutTransaction> = parse_transaction(&sent, &received);
    println!("transaction: {:?}", transaction);

    println!("Presentation verified");

    Ok(())
}

pub async fn verify_presentation(presentation: Presentation) -> (Vec<u8>, Vec<u8>, ServerName) {
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(
            include_bytes!("../../certs/rootCA.der").to_vec(),
        ))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    println!(
        "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
        hex::encode(key_data)
    );

    // Verify the presentation.
    let PresentationOutput {
        server_name,
        transcript,
        ..
    } = presentation.verify(&crypto_provider).unwrap();

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");

    // Check sent data: check host.
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");
    sent_data.find(server_name.as_str()).unwrap_or_else(|| {
        panic!(
            "Verification failed: Expected host {}",
            server_name.as_str()
        )
    });

    // Check received data: check json and version number.
    let received = transcript.received_unsafe().to_vec();

    (sent, received, server_name)
}

// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|_| String::from("Invalid UTF-8"))
        .replace('\0', "🙈")
}

fn parse_transaction(sent: &str, received: &str) -> Option<RevolutTransaction> {
    let transaction_id = extract_required_value(sent, r"transaction/([\w-]+)")?;
    let state = extract_required_value(received, r#""state":"([^"]+)""#)?;
    let currency = extract_required_value(received, r#""currency":"([^"]+)""#)?;
    let amount: i64 = extract_required_value(received, r#""amount":(-?\d+)"#)?
        .parse()
        .ok()?;
    let comment = extract_value(received, r#""comment":"([^"]+)""#)?;

    let iban = extract_value(
        received,
        r#""account":\{(?:[^}]*,)?(?:"IBAN"|"iban"):"([^"]+)""#,
    );
    let bic = extract_value(
        received,
        r#""account":\{(?:[^}]*,)?(?:"BIC"|"bic"):"([^"]+)""#,
    );

    let beneficiary = match (iban, bic) {
        (Some(iban), Some(bic)) => BeneficiaryType::External { iban, bic },
        _ => {
            let ben_id = extract_required_value(received, r#""id":"([^"]+)""#)?;
            let ben_type = extract_required_value(received, r#""type":"([^"]+)""#)?;
            let ben_username = extract_required_value(received, r#""username":"([^"]+)""#)?;
            let ben_code = extract_required_value(received, r#""code":"([^"]+)""#)?;
            BeneficiaryType::Internal {
                id: ben_id,
                account_type: ben_type,
                username: ben_username,
                code: ben_code,
            }
        }
    };

    Some(RevolutTransaction {
        transaction_id,
        state,
        currency,
        amount,
        comment,
        beneficiary,
    })
}

fn extract_value(text: &str, pattern: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    re.captures(text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

fn extract_required_value(text: &str, pattern: &str) -> Option<String> {
    match extract_value(text, pattern) {
        Some(value) => Some(value),
        None => {
            println!(
                "Required value not found for pattern: {} in text: {}",
                pattern, text
            );
            None
        }
    }
}

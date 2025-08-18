use macro_rules_attribute::apply;
use serde::{Deserialize, Serialize};
use smol_macros::main;
use thiserror::Error;
use tlsn_core::{
    CryptoProvider,
    connection::ServerName,
    presentation::{Presentation, PresentationOutput},
    signing::VerifyingKey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinancePriceData {
    symbol: String,
    price: String,
    mins: u64,
    close_time: u64,
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

    let price_data: Option<BinancePriceData> = parse_price_data(&sent, &received);
    println!("price_data: {:?}", price_data);

    println!("Presentation verified");

    Ok(())
}

pub async fn verify_presentation(presentation: Presentation) -> (Vec<u8>, Vec<u8>, ServerName) {
    // Use default crypto provider for production APIs like Binance
    let crypto_provider = CryptoProvider::default();

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

    // Debug transcript information
    println!("\n=== TRANSCRIPT DEBUG ===");
    println!("Transcript sent length: {}", transcript.len_sent());
    println!("Transcript received length: {}", transcript.len_received());
    
    // Get authenticated (revealed) ranges
    let sent_authed = transcript.sent_authed();
    let received_authed = transcript.received_authed();
    
    println!("Sent authenticated ranges: {} ranges", sent_authed.iter_ranges().count());
    println!("Received authenticated ranges: {} ranges", received_authed.iter_ranges().count());
    
    // Check sent data: check host.
    let sent = transcript.sent_unsafe().to_vec();
    // Check received data: check json and version number.
    let received = transcript.received_unsafe().to_vec();
    
    println!("Sent data length: {}", sent.len());
    println!("Received data length: {}", received.len());
    
    // Show authenticated (revealed) ranges
    println!("\n=== SENT AUTHENTICATED RANGES ===");
    for (i, range) in sent_authed.iter_ranges().enumerate() {
        let data = &sent[range.clone()];
        let content = String::from_utf8_lossy(data);
        println!("Sent range {}: {:?} = {:?}", i, range, content);
    }
    
    println!("\n=== RECEIVED AUTHENTICATED RANGES ===");
    for (i, range) in received_authed.iter_ranges().enumerate() {
        let data = &received[range.clone()];
        let content = String::from_utf8_lossy(data);
        println!("Received range {}: {:?} = {:?}", i, range, content);
    }
    
    // Show the authenticated data directly
    println!("\n=== AUTHENTICATED DATA ===");
    let sent_authed_data: Vec<u8> = sent_authed.iter_ranges()
        .flat_map(|range| sent[range.clone()].iter().cloned())
        .collect();
    let received_authed_data: Vec<u8> = received_authed.iter_ranges()
        .flat_map(|range| received[range.clone()].iter().cloned())
        .collect();
        
    println!("Sent authenticated data: {:?}", String::from_utf8_lossy(&sent_authed_data));
    println!("Received authenticated data: {:?}", String::from_utf8_lossy(&received_authed_data));
    
    println!("========================\n");

    (sent, received, server_name)
}

// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|_| String::from("Invalid UTF-8"))
        .replace('\0', "🙈")
}

fn parse_price_data(sent: &str, received: &str) -> Option<BinancePriceData> {
    let symbol = extract_required_value(sent, r"symbol=([A-Z]+)")?;
    let price = extract_required_value(received, r#""price":"([0-9.]+)""#)?;
    let mins = extract_required_value(received, r#""mins":(\d+)"#)?
        .parse()
        .ok()?;
    let close_time = extract_required_value(received, r#""closeTime":(\d+)"#)?
        .parse()
        .ok()?;

    Some(BinancePriceData {
        symbol,
        price,
        mins,
        close_time,
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

use std::ops::Range;

use pest::Parser;
use tls_core::verify::WebPkiVerifier;
use tlsn_core::Secrets;
use tlsn_core::hash::HashAlgId;
use tlsn_core::transcript::TranscriptCommitmentKind;
use tlsn_prover::Prover;
use tlsn_prover::state::Committed;

use crate::ast::Searchable;
use crate::errors::{ProverError, Result};
use crate::request::{Request, RequestParser, Rule as RequestRule};
use crate::response::{Response, ResponseParser, Rule as ResponseRule};

use http_body_util::Empty;
use hyper::{Request as HttpRequest, StatusCode, body::Bytes};
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use smol::net::TcpStream;
use smol_hyper::rt::FuturesIo;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    CryptoProvider, attestation::Attestation, presentation::Presentation, request::RequestConfig,
    transcript::TranscriptCommitConfig,
};
use tlsn_prover::{Prover as TlsProver, ProverConfig};

/// Trait for types that provide access to transcript data
pub trait TranscriptProvider {
    fn received_data(&self) -> &[u8];
    fn sent_data(&self) -> &[u8];
}

impl TranscriptProvider for Prover<Committed> {
    fn received_data(&self) -> &[u8] {
        self.transcript().received()
    }

    fn sent_data(&self) -> &[u8] {
        self.transcript().sent()
    }
}

impl TranscriptProvider for Secrets {
    fn received_data(&self) -> &[u8] {
        self.transcript().received()
    }

    fn sent_data(&self) -> &[u8] {
        self.transcript().sent()
    }
}

/// Notarize a request and return attestation and secrets
pub async fn notarize(
    request: HttpRequest<Empty<Bytes>>,
    notary_host: &str,
    notary_port: u16,
    max_sent_data: usize,
    max_recv_data: usize,
    server_host: &str,
    server_port: u16,
) -> Result<(Attestation, Secrets)> {
    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .map_err(|e| ProverError::NotaryConnectionFailed(e.to_string()))?;

    println!("Notary client built");

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data)
        .build()
        .map_err(|e| ProverError::NotarizationFailed(e.to_string()))?;

    println!("Notarization request built");

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    println!("Notarization request sent");

    // Use default crypto provider for production APIs like Binance
    let crypto_provider = CryptoProvider::default();

    let prover_config = ProverConfig::builder()
        .server_name(server_host)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(max_sent_data)
                .max_recv_data(max_recv_data)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()
        .map_err(|e| ProverError::NotarizationFailed(e.to_string()))?;

    println!("Prover config set");
    let prover = TlsProver::new(prover_config)
        .setup(notary_connection)
        .await?;

    let client_socket = TcpStream::connect((server_host, server_port)).await?;

    println!("Connected to server");

    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket).await?;
    let mpc_tls_connection = FuturesIo::new(mpc_tls_connection);

    println!("MPC connect");

    let prover_task = smol::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    smol::spawn(connection).detach();

    println!("Starting an MPC TLS connection with the server");

    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {:?}", response);

    if response.status() != StatusCode::OK {
        return Err(ProverError::NotarizationFailed(format!(
            "Server responded with status: {}",
            response.status()
        )));
    }

    // The prover task should be done now, so we can await it.
    let prover = prover_task
        .await
        .map_err(|e| ProverError::NotarizationFailed(format!("Prover task failed: {}", e)))?;

    // Parse the transcript using your custom parsers to get ranges
    let (prover, recv_ranges) = redact_and_reveal_received_data(prover).await;
    let (mut prover, sent_ranges) = redact_and_reveal_sent_data(prover).await;

    // Commit to the transcript using your custom ranges
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // Commit the ranges identified by your parsing functions
    for range in &recv_ranges {
        builder
            .commit_recv(range)
            .map_err(|e| ProverError::NotarizationFailed(e.to_string()))?;
    }

    for range in &sent_ranges {
        builder
            .commit_sent(range)
            .map_err(|e| ProverError::NotarizationFailed(e.to_string()))?;
    }

    let transcript_commit = builder
        .build()
        .map_err(|e| ProverError::NotarizationFailed(e.to_string()))?;

    // Build an attestation request.
    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);
    let request_config = builder
        .build()
        .map_err(|e| ProverError::NotarizationFailed(e.to_string()))?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;

    println!("Notarization complete!");

    Ok((attestation, secrets))
}

/// Create a presentation from attestation and secrets
pub async fn create_presentation(
    attestation: Attestation,
    secrets: Secrets,
) -> Result<Presentation> {
    let recv_ranges = get_received_data_ranges(&secrets);
    let sent_ranges = get_sent_data_ranges(&secrets);

    println!("recv_ranges: {:?}", recv_ranges);
    println!("sent_ranges: {:?}", sent_ranges);

    let mut builder = secrets.transcript_proof_builder();

    let builder = {
        let mut builder = builder;
        for range in &recv_ranges {
            builder
                .reveal_recv(range)
                .map_err(|e| ProverError::PresentationCreationFailed(e.to_string()))?;
        }
        for range in &sent_ranges {
            builder
                .reveal_sent(range)
                .map_err(|e| ProverError::PresentationCreationFailed(e.to_string()))?;
        }
        builder
    };

    let transcript_proof = builder
        .build()
        .map_err(|e| ProverError::PresentationCreationFailed(e.to_string()))?;
    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    println!("building presentation");

    let presentation: Presentation = builder
        .build()
        .map_err(|e| ProverError::PresentationCreationFailed(e.to_string()))?;

    println!("Presentation built successfully!");

    Ok(presentation)
}

/// Redacts and reveals received data to the verifier
///
/// # Arguments
/// * `provider` - Object that provides transcript data
///
/// # Returns
/// * `Vec<Range<usize>>` - The ranges to reveal
pub fn get_received_data_ranges<T: TranscriptProvider>(provider: &T) -> Vec<Range<usize>> {
    // Get the received transcript data
    let recv_transcript = provider.received_data();

    // Convert to a UTF-8 string
    let recv_string = match String::from_utf8(recv_transcript.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to convert received data to UTF-8: {}", e);
            return Vec::new();
        }
    };

    println!("Received data: {}", recv_string);

    // Parse the response
    let parse = match ResponseParser::parse(ResponseRule::response, &recv_string) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to parse response: {}", e);
            // Fallback: try to find JSON manually for Binance API
            return get_binance_price_ranges(&recv_string);
        }
    };

    // Convert the parse result to a Response object
    let response = match Response::try_from(parse) {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to convert parse result to Response: {}", e);
            // Fallback: try to find JSON manually for Binance API
            return get_binance_price_ranges(&recv_string);
        }
    };

    // Get the ranges to reveal for Binance price data
    response.get_all_ranges_for_keypaths(
        &[
            "price",
            "mins",
            "closeTime",
        ],
        &[],
    )
}

/// Redacts and reveals sent data to the verifier
///
/// # Arguments
/// * `provider` - Object that provides transcript data
///
/// # Returns
/// * `Vec<Range<usize>>` - The ranges to reveal
pub fn get_sent_data_ranges<T: TranscriptProvider>(provider: &T) -> Vec<Range<usize>> {
    // Get the sent transcript data
    let sent_transcript = provider.sent_data();

    // Convert to a UTF-8 string
    let sent_string = match String::from_utf8(sent_transcript.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to convert sent data to UTF-8: {}", e);
            return Vec::new();
        }
    };

    // Parse the request
    let parse = match RequestParser::parse(RequestRule::request, &sent_string) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to parse request: {}", e);
            return Vec::new();
        }
    };

    // Convert the parse result to a Request object
    let request = match Request::try_from(parse) {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to convert parse result to Request: {}", e);
            return Vec::new();
        }
    };

    // Reveal symbol from URL parameter
    let mut ranges = Vec::new();
    
    // Find symbol parameter in URL
    if let Some(symbol_start) = sent_string.find("symbol=") {
        let symbol_param_start = symbol_start;
        if let Some(symbol_end) = sent_string[symbol_start..].find(" HTTP") {
            let symbol_param_end = symbol_start + symbol_end;
            ranges.push(symbol_param_start..symbol_param_end);
            println!("Revealing symbol parameter: {:?}", &sent_string[symbol_param_start..symbol_param_end]);
        }
    }
    
    ranges
}

/// Redacts and reveals received data to the verifier (legacy function for Prover)
///
/// # Arguments
/// * `prover` - The prover object to work with
///
/// # Returns
/// * `(Prover<Committed>, Vec<Range<usize>>)` - The prover and the ranges
pub async fn redact_and_reveal_received_data(
    prover: Prover<Committed>,
) -> (Prover<Committed>, Vec<Range<usize>>) {
    let ranges = get_received_data_ranges(&prover);
    (prover, ranges)
}

/// Redacts and reveals sent data to the verifier (legacy function for Prover)
///
/// # Arguments
/// * `prover` - The prover object to work with
///
/// # Returns
/// * `(Prover<Committed>, Vec<Range<usize>>)` - The prover and the ranges
pub async fn redact_and_reveal_sent_data(
    prover: Prover<Committed>,
) -> (Prover<Committed>, Vec<Range<usize>>) {
    let ranges = get_sent_data_ranges(&prover);
    (prover, ranges)
}

/// Fallback function to manually find Binance price data ranges
fn get_binance_price_ranges(response: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    
    // Find JSON data in response
    if let Some(json_start) = response.find("{") {
        if let Some(json_end) = response.rfind("}") {
            let json_content = &response[json_start..=json_end];
            
            // Find "price" field
            if let Some(price_start) = json_content.find("\"price\":\"") {
                let price_field_start = json_start + price_start;
                if let Some(price_end) = json_content[price_start..].find("\",") {
                    let price_field_end = price_field_start + price_end + 1;
                    ranges.push(price_field_start..price_field_end);
                }
            }
            
            // Find "mins" field
            if let Some(mins_start) = json_content.find("\"mins\":") {
                let mins_field_start = json_start + mins_start;
                if let Some(mins_end) = json_content[mins_start..].find(",") {
                    let mins_field_end = mins_field_start + mins_end;
                    ranges.push(mins_field_start..mins_field_end);
                }
            }
            
            // Find "closeTime" field (number value)
            if let Some(closetime_start) = json_content.find("\"closeTime\":") {
                let closetime_field_start = json_start + closetime_start;
                if let Some(closetime_end) = json_content[closetime_start..].find("}") {
                    let closetime_field_end = closetime_field_start + closetime_end;
                    ranges.push(closetime_field_start..closetime_field_end);
                }
            }
        }
    }
    
    println!("Binance fallback ranges: {:?}", ranges);
    ranges
}

use clap::Parser;
use http_body_util::Empty;
use hyper::{
    Request,
    body::Bytes,
    header::{HeaderName, HeaderValue},
};
use url::Url;

mod ast;
mod config;
mod errors;
mod prover;
mod request;
mod response;
mod utils;

pub use config::PROVER_CONFIG;
pub use errors::ProverError;
pub use prover::ProverService;

use macro_rules_attribute::apply;
use smol_macros::main;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Trading pair symbol (e.g., USDTPLN, BTCUSDT, ETHUSDT)
    #[arg(short, long, default_value = "USDTPLN")]
    symbol: String,

    /// Notary server URL
    #[arg(short, long, default_value = "http://localhost:7047")]
    notary: String,
}

#[apply(main!)]
async fn main() {
    let args = Args::parse();
    
    let api_url = format!("https://api.binance.com/api/v3/avgPrice?symbol={}", args.symbol);
    
    prove(
        api_url,
        vec![
            "user-agent: curl/8.4.0".to_string(),
        ],
        args.notary,
    )
    .await
    .unwrap();
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Input is missing or invalid
    #[error("Input is missing or invalid")]
    MissingInput,
    /// Index out of bounds error with details
    #[error("Index {index} out of bounds (size: {size})")]
    IndexOutOfBounds { index: u32, size: u32 },
    /// Generic error with a message
    #[error("{0}")]
    Generic(String),
}

pub async fn prove(
    server_url: String,
    headers: Vec<String>,
    notary_url: String,
) -> Result<Vec<u8>, ApiError> {
    // Parse the URLs to extract host and port information
    let notary_parsed = Url::parse(&notary_url)
        .map_err(|e| ApiError::Generic(format!("Failed to parse notary URL: {}", e)))?;

    let notary_host = notary_parsed
        .host_str()
        .ok_or_else(|| ApiError::Generic("No host found in notary URL".to_string()))?;

    let notary_port = notary_parsed
        .port()
        .unwrap_or(if notary_parsed.scheme() == "https" {
            443
        } else {
            80
        });

    // Parse the server URL to get host and port information for both HTTP request and TLS connection
    let server_parsed = Url::parse(&server_url)
        .map_err(|e| ApiError::Generic(format!("Failed to parse server URL: {}", e)))?;

    let server_host = server_parsed
        .host_str()
        .ok_or_else(|| ApiError::Generic("No host found in server URL".to_string()))?;

    let server_port = server_parsed
        .port()
        .unwrap_or(if server_parsed.scheme() == "https" {
            443
        } else {
            80
        });

    // Build the HTTP request
    let mut request = Request::builder()
        .method("GET")
        .uri(server_url.as_str())
        .header("connection", "close")
        .header("host", server_host.to_string())
        .header("Content-Length", "0")
        .body(Empty::<Bytes>::new())
        .map_err(|e| ApiError::Generic(format!("Failed to build request: {}", e)))?;

    // Add custom headers to the request
    let request_headers = request.headers_mut();

    for header in headers {
        if let Some((key, value)) = header.split_once(':') {
            let key = key
                .trim()
                .parse::<HeaderName>()
                .map_err(|e| ApiError::Generic(format!("Invalid header name '{}': {}", key, e)))?;

            let value = value.trim().parse::<HeaderValue>().map_err(|e| {
                ApiError::Generic(format!("Invalid header value '{}': {}", value, e))
            })?;

            request_headers.insert(key, value);
        } else {
            return Err(ApiError::Generic(format!(
                "Header '{}' is not in 'Key: Value' format",
                header
            )));
        }
    }

    println!("➡️ REQUEST:");
    println!("{:?}", request);

    // Create a prover service, notarize and create presentation
    let prover = ProverService::new();
    let presentation = prover
        .notarize_and_create_presentation(
            request,
            PROVER_CONFIG.max_sent_data,
            PROVER_CONFIG.max_recv_data,
            notary_host,
            notary_port,
            server_host,
            server_port,
        )
        .await
        .map_err(|e| ApiError::Generic(format!("Prover encountered an error: {}", e)))?;

    println!("Presentation created");

    let serialized_presentation = bincode::serialize(&presentation)
        .map_err(|e| ApiError::Generic(format!("Failed to serialize presentation: {}", e)))?;

    // Write the presentation to disk.
    std::fs::write("presentation.tlsn", serialized_presentation.clone()).unwrap();

    Ok(serialized_presentation)
}
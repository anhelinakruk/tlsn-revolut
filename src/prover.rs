use crate::errors::{ProverError, Result};
use crate::utils;
use http_body_util::Empty;
use hyper::{Request, body::Bytes};
use tlsn_core::presentation::Presentation;

/// Service responsible for generating proofs
#[derive(Debug, Default)]
pub struct ProverService;

impl ProverService {
    /// Create a new ProverService instance
    pub fn new() -> Self {
        Self {}
    }

    /// Create presentation from notarization and presentation creation
    pub async fn notarize_and_create_presentation(
        &self,
        request: Request<Empty<Bytes>>,
        max_sent_data: usize,
        max_recv_data: usize,
        notary_host: &str,
        notary_port: u16,
        server_host: &str,
        server_port: u16,
    ) -> Result<Presentation> {
        // Validate the request
        if request.uri().scheme().map(|s| s.as_str()) != Some("https") {
            return Err(ProverError::InvalidScheme);
        }

        // Notarize the request
        let (attestation, secrets) = utils::notarize(
            request,
            notary_host,
            notary_port,
            max_sent_data,
            max_recv_data,
            server_host,
            server_port,
        )
        .await?;

        // Create presentation from attestation and secrets
        let presentation = utils::create_presentation(attestation, secrets).await?;

        Ok(presentation)
    }
}

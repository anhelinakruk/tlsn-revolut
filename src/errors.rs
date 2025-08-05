use crate::request::Rule as RequestRule;
use crate::response::Rule as ResponseRule;
use hyper::Error as HyperError;
use pest::error::Error as PestError;
use std::io;
use thiserror::Error;
use tlsn_common::config::ProtocolConfigBuilderError;
use tlsn_core::ProveConfigBuilderError;
use tlsn_prover::ProverError as TlsnProverError;

/// Main error type for internal prover operations
#[derive(Error, Debug)]
pub enum ProverError {
    /// Request scheme is invalid (only HTTPS is supported)
    #[error("Invalid scheme")]
    InvalidScheme,

    /// Request URI does not have an authority or host
    #[error("Request URI does not have an authority or host")]
    MissingAuthority,

    /// Request URI does not have a port
    #[error("Request URI does not have a port")]
    MissingPort,

    /// Failed to connect to notary server
    #[error("Failed to connect to notary server: {0}")]
    NotaryConnectionFailed(String),

    /// Failed to create presentation
    #[error("Failed to create presentation: {0}")]
    PresentationCreationFailed(String),

    /// Failed to notarize request
    #[error("Failed to notarize request: {0}")]
    NotarizationFailed(String),

    /// Failed to serialize presentation
    #[error("Failed to serialize presentation: {0}")]
    SerializationFailed(String),

    /// Failed to create tokio runtime
    #[error("Failed to create tokio runtime: {0}")]
    RuntimeCreationFailed(String),

    /// Failed to parse AST node
    #[error("Failed to parse AST node: missing required element")]
    AstParsingFailed,

    /// UTF-8 conversion error
    #[error(transparent)]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),

    /// Prove  builder error
    #[error(transparent)]
    ProveConfigBuilderError(#[from] ProveConfigBuilderError),

    /// Prover error from the TLSN library
    #[error(transparent)]
    TlsnProverError(#[from] TlsnProverError),

    /// Protocol configuration builder error
    #[error(transparent)]
    ProtocolConfigBuilderError(#[from] ProtocolConfigBuilderError),

    /// IO error
    #[error(transparent)]
    IoError(#[from] io::Error),

    /// Hyper HTTP error
    #[error(transparent)]
    HyperError(#[from] HyperError),

    /// Pest parser error for request parsing
    #[error(transparent)]
    PestRequestError(#[from] PestError<RequestRule>),

    /// Pest parser error for response parsing
    #[error(transparent)]
    PestResponseError(#[from] PestError<ResponseRule>),

    /// Generic string error
    #[error("{0}")]
    StringError(String),
}

// For backward compatibility with existing code
pub type Result<T> = std::result::Result<T, ProverError>;

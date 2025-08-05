/// Configuration for the prover service
pub struct ProverConfig {
    /// Maximum bytes of data that can be sent
    pub max_sent_data: usize,
    /// Maximum bytes of data that can be received
    pub max_recv_data: usize,
}

/// Default prover configuration
pub const PROVER_CONFIG: ProverConfig = ProverConfig {
    max_sent_data: 4096,
    max_recv_data: 16384,
};

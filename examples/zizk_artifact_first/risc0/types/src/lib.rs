//! Terminology: Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK); zero-knowledge (ZK).
//!
//! Shared, experiment-local types for the ZIZK-VSTD zero-knowledge probe.

use serde::{Deserialize, Serialize};

pub const PROFILE_LABEL: &[u8] = b"ZIZK-VSTD-ZK-EXPERIMENT-0.1";
pub const PREDICATE_TEXT: &[u8] = b"A private bounded evidence payload has a nonempty byte string of at most 64 bytes, an experiment-local SUPPORTED input tag, and a private measurement greater than or equal to the public threshold.";
pub const COMMITMENT_DOMAIN: &[u8] = b"vstd-zk-evidence-commitment-v1\0";
pub const MAX_EVIDENCE_LEN: usize = 64;
pub const MAX_THRESHOLD: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CandidateState {
    Supported,
    Unknown,
    Conflicted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateWitness {
    pub evidence: Vec<u8>,
    pub salt: [u8; 32],
    pub measurement: u64,
    pub candidate_state: CandidateState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicStatement {
    pub subject_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub challenge: [u8; 32],
    pub threshold: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverInput {
    pub statement: PublicStatement,
    pub witness: PrivateWitness,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicJournal {
    pub profile_digest: [u8; 32],
    pub predicate_digest: [u8; 32],
    pub subject_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub challenge: [u8; 32],
    pub threshold: u64,
    pub evidence_commitment: [u8; 32],
    pub predicate_satisfied: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEnvelope {
    pub experiment_profile: String,
    pub proof_system: String,
    pub image_id: String,
    pub receipt_sha256: String,
    pub receipt_size: u64,
    pub journal: PublicJournal,
}

use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};
use vstd_zk_types::{
    CandidateState, ProverInput, PublicJournal, COMMITMENT_DOMAIN, MAX_EVIDENCE_LEN,
    MAX_THRESHOLD, PREDICATE_TEXT, PROFILE_LABEL,
};

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    let digest = Impl::hash_bytes(value);
    digest.as_bytes().try_into().expect("SHA-256 is 32 bytes")
}

fn main() {
    let input: ProverInput = env::read();

    assert!(!input.witness.evidence.is_empty(), "evidence must not be empty");
    assert!(
        input.witness.evidence.len() <= MAX_EVIDENCE_LEN,
        "evidence exceeds the bounded predicate"
    );
    assert!(
        input.witness.candidate_state == CandidateState::Supported,
        "UNKNOWN and CONFLICTED inputs do not satisfy this predicate"
    );
    assert!(
        input.statement.threshold <= MAX_THRESHOLD,
        "threshold exceeds the experiment bound"
    );
    assert!(
        input.witness.measurement >= input.statement.threshold,
        "private measurement is below the public threshold"
    );
    assert!(
        input.statement.subject_digest != [0_u8; 32],
        "subject digest must be explicit"
    );
    assert!(
        input.statement.policy_digest != [0_u8; 32],
        "policy digest must be explicit"
    );
    assert!(
        input.statement.challenge != [0_u8; 32],
        "challenge must be explicit"
    );

    let mut commitment_input = Vec::with_capacity(
        COMMITMENT_DOMAIN.len() + 4 + input.witness.evidence.len() + 32 + 8,
    );
    commitment_input.extend_from_slice(COMMITMENT_DOMAIN);
    commitment_input.extend_from_slice(&(input.witness.evidence.len() as u32).to_be_bytes());
    commitment_input.extend_from_slice(&input.witness.evidence);
    commitment_input.extend_from_slice(&input.witness.salt);
    commitment_input.extend_from_slice(&input.witness.measurement.to_be_bytes());

    let journal = PublicJournal {
        profile_digest: digest_bytes(PROFILE_LABEL),
        predicate_digest: digest_bytes(PREDICATE_TEXT),
        subject_digest: input.statement.subject_digest,
        policy_digest: input.statement.policy_digest,
        challenge: input.statement.challenge,
        threshold: input.statement.threshold,
        evidence_commitment: digest_bytes(&commitment_input),
        predicate_satisfied: true,
    };

    env::commit(&journal);
}

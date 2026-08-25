//! Terminology: Executable and Linkable Format (ELF); identifier (ID);
//! reduced instruction set computer (RISC); RISC Zero (RISC0);
//! Secure Hash Algorithm 256-bit (SHA-256); scalable transparent argument of knowledge (STARK);
//! Verifier Standard (VSTD); zero-knowledge (ZK).
use hex::FromHex;
use rand::{rngs::OsRng, RngCore};
use risc0_zkvm::{
    default_prover,
    sha::{Digest, Impl, Sha256},
    ExecutorEnv, InnerReceipt, Receipt,
};
use serde::Serialize;
use std::{
    env,
    error::Error,
    fs,
    io,
    path::Path,
};
use vstd_zk_methods::{VSTD_ZK_GUEST_ELF, VSTD_ZK_GUEST_ID};
use vstd_zk_types::{
    CandidateState, PrivateWitness, ProverInput, PublicEnvelope, PublicJournal,
    PublicStatement, COMMITMENT_DOMAIN, PREDICATE_TEXT, PROFILE_LABEL,
};

const PROOF_SYSTEM: &str = "risc0-zkvm-3.0.6-composite-stark";
const MAX_RECEIPT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 1024 * 1024;

type AppResult<T> = Result<T, Box<dyn Error>>;

#[derive(Serialize)]
struct SelfTestResults {
    real_proof_verified: bool,
    unsatisfied_witness_rejected: bool,
    unknown_rejected: bool,
    conflicted_rejected: bool,
    mutated_public_input_rejected: bool,
    wrong_image_id_rejected: bool,
    corrupted_proof_rejected: bool,
    tampered_journal_rejected: bool,
    statement_transplant_rejected: bool,
    private_bytes_absent_from_public_artifacts: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("generate-inputs") if args.len() == 4 => {
            generate_inputs(Path::new(&args[2]), Path::new(&args[3]))
        }
        Some("prove") if args.len() == 6 => prove_from_files(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
        ),
        Some("verify") if args.len() == 4 || args.len() == 5 => {
            let expected_id = args.get(4).map(|value| parse_digest(value)).transpose()?;
            verify_artifacts(Path::new(&args[2]), Path::new(&args[3]), expected_id)?;
            println!("PASS: real RISC Zero receipt and public statement verified");
            Ok(())
        }
        Some("image-id") if args.len() == 2 => {
            println!("{}", method_id());
            Ok(())
        }
        Some("self-test") if args.len() == 3 => self_test(Path::new(&args[2])),
        _ => Err(usage_error()),
    }
}

fn usage_error() -> Box<dyn Error> {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage:\n  vstd-zk-host generate-inputs PRIVATE.json STATEMENT.json\n  vstd-zk-host prove PRIVATE.json STATEMENT.json RECEIPT.bin PUBLIC.json\n  vstd-zk-host verify RECEIPT.bin PUBLIC.json [EXPECTED_IMAGE_ID]\n  vstd-zk-host image-id\n  vstd-zk-host self-test OUTPUT_DIR",
    )
    .into()
}

fn method_id() -> Digest {
    Digest::from(VSTD_ZK_GUEST_ID)
}

fn parse_digest(value: &str) -> AppResult<Digest> {
    Ok(Digest::from_hex(value)?)
}

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    let digest = Impl::hash_bytes(value);
    digest.as_bytes().try_into().expect("SHA-256 is 32 bytes")
}

fn digest_hex(value: &[u8]) -> String {
    hex::encode(digest_bytes(value))
}

fn evidence_commitment(witness: &PrivateWitness) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        COMMITMENT_DOMAIN.len() + 4 + witness.evidence.len() + 32 + 8,
    );
    input.extend_from_slice(COMMITMENT_DOMAIN);
    input.extend_from_slice(&(witness.evidence.len() as u32).to_be_bytes());
    input.extend_from_slice(&witness.evidence);
    input.extend_from_slice(&witness.salt);
    input.extend_from_slice(&witness.measurement.to_be_bytes());
    digest_bytes(&input)
}

fn random_array() -> [u8; 32] {
    let mut value = [0_u8; 32];
    OsRng.fill_bytes(&mut value);
    value
}

fn sample_inputs() -> (PrivateWitness, PublicStatement) {
    let mut evidence = vec![0_u8; 48];
    OsRng.fill_bytes(&mut evidence);
    let witness = PrivateWitness {
        evidence,
        salt: random_array(),
        measurement: 73,
        candidate_state: CandidateState::Supported,
    };
    let statement = PublicStatement {
        subject_digest: random_array(),
        policy_digest: digest_bytes(b"vstd-zk-fixed-threshold-policy-v1"),
        challenge: random_array(),
        threshold: 70,
    };
    (witness, statement)
}

fn generate_inputs(private_path: &Path, statement_path: &Path) -> AppResult<()> {
    let (witness, statement) = sample_inputs();
    write_json(private_path, &witness)?;
    write_json(statement_path, &statement)?;
    println!(
        "generated a local private witness and public statement; do not publish {}",
        private_path.display()
    );
    Ok(())
}

fn ensure_real_mode() -> AppResult<()> {
    if let Ok(value) = env::var("RISC0_DEV_MODE") {
        let normalized = value.trim().to_ascii_lowercase();
        if !normalized.is_empty() && normalized != "0" && normalized != "false" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "RISC0_DEV_MODE must be unset, 0, or false; this binary also compiles with disable-dev-mode",
            )
            .into());
        }
    }
    Ok(())
}

fn prove_from_files(
    private_path: &Path,
    statement_path: &Path,
    receipt_path: &Path,
    public_path: &Path,
) -> AppResult<()> {
    ensure_real_mode()?;
    let witness: PrivateWitness = read_json_bounded(private_path, MAX_ENVELOPE_BYTES)?;
    let statement: PublicStatement = read_json_bounded(statement_path, MAX_ENVELOPE_BYTES)?;
    prove_to_files(&witness, &statement, receipt_path, public_path)?;
    println!("wrote a verified real receipt and public envelope");
    Ok(())
}

fn prove_to_files(
    witness: &PrivateWitness,
    statement: &PublicStatement,
    receipt_path: &Path,
    public_path: &Path,
) -> AppResult<PublicEnvelope> {
    ensure_real_mode()?;
    let input = ProverInput {
        statement: statement.clone(),
        witness: witness.clone(),
    };
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let prove_info = default_prover().prove(env, VSTD_ZK_GUEST_ELF)?;
    let receipt = prove_info.receipt;
    require_composite_receipt(&receipt)?;
    receipt.verify(method_id())?;

    let journal: PublicJournal = receipt.journal.decode()?;
    validate_public_journal(&journal, statement)?;
    if journal.evidence_commitment != evidence_commitment(witness) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authenticated evidence commitment does not match the supplied witness",
        )
        .into());
    }

    let receipt_bytes = rmp_serde::to_vec_named(&receipt)?;
    let envelope = PublicEnvelope {
        experiment_profile: String::from_utf8(PROFILE_LABEL.to_vec())?,
        proof_system: PROOF_SYSTEM.to_string(),
        image_id: method_id().to_string(),
        receipt_sha256: digest_hex(&receipt_bytes),
        receipt_size: receipt_bytes.len() as u64,
        journal,
    };
    write_bytes(receipt_path, &receipt_bytes)?;
    write_json(public_path, &envelope)?;
    Ok(envelope)
}

fn require_composite_receipt(receipt: &Receipt) -> AppResult<()> {
    match &receipt.inner {
        InnerReceipt::Composite(_) => Ok(()),
        InnerReceipt::Fake(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fake RISC Zero receipt rejected",
        )
        .into()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt kind differs from the selected composite STARK path",
        )
        .into()),
    }
}

fn validate_public_journal(
    journal: &PublicJournal,
    expected: &PublicStatement,
) -> AppResult<()> {
    if journal.profile_digest != digest_bytes(PROFILE_LABEL)
        || journal.predicate_digest != digest_bytes(PREDICATE_TEXT)
        || journal.subject_digest != expected.subject_digest
        || journal.policy_digest != expected.policy_digest
        || journal.challenge != expected.challenge
        || journal.threshold != expected.threshold
        || !journal.predicate_satisfied
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authenticated journal does not match the expected public statement",
        )
        .into());
    }
    Ok(())
}

fn verify_artifacts(
    receipt_path: &Path,
    public_path: &Path,
    expected_id: Option<Digest>,
) -> AppResult<PublicJournal> {
    let receipt_bytes = read_bytes_bounded(receipt_path, MAX_RECEIPT_BYTES)?;
    let envelope: PublicEnvelope = read_json_bounded(public_path, MAX_ENVELOPE_BYTES)?;
    let receipt: Receipt = rmp_serde::from_slice(&receipt_bytes)?;
    require_composite_receipt(&receipt)?;

    let trusted_id = expected_id.unwrap_or_else(method_id);
    receipt.verify(trusted_id)?;
    let journal: PublicJournal = receipt.journal.decode()?;

    if trusted_id != method_id()
        || envelope.image_id != trusted_id.to_string()
        || envelope.receipt_sha256 != digest_hex(&receipt_bytes)
        || envelope.receipt_size != receipt_bytes.len() as u64
        || envelope.experiment_profile != String::from_utf8(PROFILE_LABEL.to_vec())?
        || envelope.proof_system != PROOF_SYSTEM
        || envelope.journal != journal
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "public envelope, receipt, image ID, or authenticated journal mismatch",
        )
        .into());
    }

    let expected_statement = PublicStatement {
        subject_digest: envelope.journal.subject_digest,
        policy_digest: envelope.journal.policy_digest,
        challenge: envelope.journal.challenge,
        threshold: envelope.journal.threshold,
    };
    validate_public_journal(&journal, &expected_statement)?;
    Ok(journal)
}

fn proof_attempt_rejected(
    witness: &PrivateWitness,
    statement: &PublicStatement,
) -> AppResult<bool> {
    let input = ProverInput {
        statement: statement.clone(),
        witness: witness.clone(),
    };
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    match default_prover().prove(env, VSTD_ZK_GUEST_ELF) {
        Ok(prove_info) => Ok(prove_info.receipt.verify(method_id()).is_err()),
        Err(_) => Ok(true),
    }
}

fn self_test(output_dir: &Path) -> AppResult<()> {
    ensure_real_mode()?;
    if output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(output_dir)?;

    let (witness, statement) = sample_inputs();
    let receipt_path = output_dir.join("receipt.msgpack");
    let public_path = output_dir.join("public.json");
    let envelope = prove_to_files(&witness, &statement, &receipt_path, &public_path)?;
    let real_proof_verified = verify_artifacts(&receipt_path, &public_path, None).is_ok();

    let mut low_witness = witness.clone();
    low_witness.measurement = statement.threshold.saturating_sub(1);
    let unsatisfied_witness_rejected = proof_attempt_rejected(&low_witness, &statement)?;

    let mut unknown_witness = witness.clone();
    unknown_witness.candidate_state = CandidateState::Unknown;
    let unknown_rejected = proof_attempt_rejected(&unknown_witness, &statement)?;

    let mut conflicted_witness = witness.clone();
    conflicted_witness.candidate_state = CandidateState::Conflicted;
    let conflicted_rejected = proof_attempt_rejected(&conflicted_witness, &statement)?;

    let mut mutated_envelope = envelope.clone();
    mutated_envelope.journal.threshold = mutated_envelope.journal.threshold.saturating_add(1);
    let mutated_path = output_dir.join("mutated-public.json");
    write_json(&mutated_path, &mutated_envelope)?;
    let mutated_public_input_rejected =
        verify_artifacts(&receipt_path, &mutated_path, None).is_err();

    let mut transplanted = envelope.clone();
    transplanted.journal.subject_digest[0] ^= 1;
    transplanted.journal.challenge[0] ^= 1;
    let transplanted_path = output_dir.join("transplanted-public.json");
    write_json(&transplanted_path, &transplanted)?;
    let statement_transplant_rejected =
        verify_artifacts(&receipt_path, &transplanted_path, None).is_err();

    let mut wrong_id = method_id();
    wrong_id.as_mut_bytes()[0] ^= 1;
    let wrong_image_id_rejected =
        verify_artifacts(&receipt_path, &public_path, Some(wrong_id)).is_err();

    let receipt_bytes = read_bytes_bounded(&receipt_path, MAX_RECEIPT_BYTES)?;
    let mut corrupted_bytes = receipt_bytes.clone();
    let corrupt_index = corrupted_bytes.len() / 2;
    corrupted_bytes[corrupt_index] ^= 1;
    let corrupted_path = output_dir.join("corrupted-receipt.msgpack");
    write_bytes(&corrupted_path, &corrupted_bytes)?;
    let corrupted_proof_rejected =
        verify_artifacts(&corrupted_path, &public_path, None).is_err();

    let mut tampered_receipt: Receipt = rmp_serde::from_slice(&receipt_bytes)?;
    if tampered_receipt.journal.bytes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty journal").into());
    }
    tampered_receipt.journal.bytes[0] ^= 1;
    let tampered_path = output_dir.join("tampered-journal.msgpack");
    write_bytes(&tampered_path, &rmp_serde::to_vec_named(&tampered_receipt)?)?;
    let tampered_journal_rejected =
        verify_artifacts(&tampered_path, &public_path, None).is_err();

    let private_bytes_absent_from_public_artifacts = !directory_contains(
        output_dir,
        &[witness.evidence.as_slice(), witness.salt.as_slice()],
    )?;

    let results = SelfTestResults {
        real_proof_verified,
        unsatisfied_witness_rejected,
        unknown_rejected,
        conflicted_rejected,
        mutated_public_input_rejected,
        wrong_image_id_rejected,
        corrupted_proof_rejected,
        tampered_journal_rejected,
        statement_transplant_rejected,
        private_bytes_absent_from_public_artifacts,
    };
    let all_passed = results.real_proof_verified
        && results.unsatisfied_witness_rejected
        && results.unknown_rejected
        && results.conflicted_rejected
        && results.mutated_public_input_rejected
        && results.wrong_image_id_rejected
        && results.corrupted_proof_rejected
        && results.tampered_journal_rejected
        && results.statement_transplant_rejected
        && results.private_bytes_absent_from_public_artifacts;
    write_json(&output_dir.join("self-test-results.json"), &results)?;
    println!("{}", serde_json::to_string_pretty(&results)?);
    if !all_passed {
        return Err(io::Error::new(io::ErrorKind::Other, "one or more self-tests failed").into());
    }
    Ok(())
}

fn directory_contains(directory: &Path, needles: &[&[u8]]) -> AppResult<bool> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(path)?;
        for needle in needles {
            if !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == *needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_bytes_bounded(path: &Path, maximum: u64) -> AppResult<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "input exceeds size bound").into());
    }
    Ok(fs::read(path)?)
}

fn read_json_bounded<T>(path: &Path, maximum: u64) -> AppResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = read_bytes_bounded(path, maximum)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn write_json<T>(path: &Path, value: &T) -> AppResult<()>
where
    T: Serialize,
{
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes(path, &bytes)
}

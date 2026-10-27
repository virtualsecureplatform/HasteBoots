// Opt-in masked PipFRI native workload experiment. Security remains unbudgeted.
// Uses the existing scalar four-stage wrappers, not the packed public verifier.
use algebra::{
    AsInto, NTTField,
    transformation::AbstractNTT,
    utils::{Block, Prg},
};
use fhe_core::SecretKeyPack;
use helper::{FiatShamirTranscript, Transcript};
use pcs::multilinear::masked_pipfri::{MaskedPipFRIPCS, Specification};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use snarks::{
    SnarkStatistics,
    fhe_op::{
        blind_rotation::{BlindRotationParams, BlindRotationSnarks, KeyCommitment},
        key_switching::{KeySwitchingParams, KeySwitchingSnarks},
        modulus_switch::{ModulusSwitchingParams, ModulusSwitchingSnarks},
        row_permutation::RowPermutationSignedSnarks,
    },
};
use std::time::Instant;
use trace::{SeparatelyPackableTrace, pbs_trace::PBSTrace};
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};

type Backend = MaskedPipFRIPCS<FF, EF, sha2::Sha256>;

fn argument<T: std::str::FromStr>(name: &str, default: T) -> T {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == name {
            return args
                .next()
                .expect("missing argument value")
                .parse()
                .ok()
                .expect("invalid argument value");
        }
    }
    default
}

fn main() {
    env_logger::init();
    let iterations = argument("--iterations", 1usize);
    let warmups = argument("--warmups", 0usize);
    let seed = argument("--seed", 42u64);
    let cold = std::env::args().any(|s| s == "--cold");
    assert!(iterations > 0);
    let total_iterations = warmups
        .checked_add(iterations)
        .expect("iteration count overflow");
    let opening_budget = argument("--opening-budget", 4usize);
    let fragment_vars = argument("--fragment-vars", 14usize);
    let queries = argument("--queries", 64usize);
    assert!(
        cold || total_iterations <= opening_budget,
        "reused key commitments need one mask allowance per PBS; increase the trusted geometry/budget or use --cold"
    );
    let mut seed_bytes = [0u8; 16];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let key_start = Instant::now();
    let params = *PARAMETERS;
    let sk = SecretKeyPack::with_rng(params, Prg::from_seed(Block::from(seed_bytes)));
    let enc = Encryptor::new(sk.clone());
    let evaluator = Evaluator::new(&sk);
    let dec = Decryptor::new(sk);
    let keygen_ns = key_start.elapsed().as_nanos();
    let x = enc.encrypt(1u32.as_into());
    let y = enc.encrypt(1u32.as_into());
    let code_spec = Specification::new(fragment_vars, 2, queries, opening_budget)
        .expect("supported masked geometry and disclosure capacity");
    let fhe_configuration = format!("{params:?}");
    let fhe_parameters_sha256 = format!("{:x}", Sha256::digest(fhe_configuration.as_bytes()));
    let rotation = BlindRotationSnarks::<FF, EF, Specification, Backend>::default();
    let keyswitch = KeySwitchingSnarks::<FF, EF, Specification, Backend>::default();
    let modswitch = ModulusSwitchingSnarks::<FF, EF, Specification, Backend>::default();
    let extract = RowPermutationSignedSnarks::<FF, EF, Specification, Backend>::default();
    let mut cached_key = None;
    let mut native_bsk_sha256 = String::new();
    for iteration in 0..total_iterations {
        if cold {
            cached_key = None;
        }
        let online_start = Instant::now();
        let timer = Instant::now();
        let (output, trace) = evaluator.nand(&x, &y);
        let trace_ns = timer.elapsed().as_nanos();
        assert_eq!(dec.decrypt_with_noise(&output).0, 0u32.as_into());
        let timer = Instant::now();
        let PBSTrace {
            mut modulus_switching_trace,
            mut blind_rotation_trace,
            key_switching_trace,
            sample_extraction_trace,
        } = trace;
        modulus_switching_trace.finalize(params.lwe_dimension() + 1);
        blind_rotation_trace.finalize(params.lwe_dimension());
        let finalize_ns = timer.elapsed().as_nanos();
        let timer = Instant::now();
        let new_key = cached_key.is_none();
        if new_key {
            native_bsk_sha256 = format!(
                "{:x}",
                Sha256::digest(
                    bincode::serde::encode_to_vec(
                        &blind_rotation_trace.generate_key_oracle().evaluations,
                        bincode::config::standard()
                    )
                    .unwrap()
                )
            );
            cached_key = Some(KeyCommitment::<FF, EF, Specification, Backend>::new(
                &code_spec,
                &blind_rotation_trace,
            ));
        }
        let key_commit_ns = timer.elapsed().as_nanos();
        let key_openings_before = cached_key
            .as_ref()
            .unwrap()
            .commitment_state
            .remaining_openings()
            .unwrap();
        assert!(key_openings_before > 0, "cached key mask budget exhausted");
        let timer = Instant::now();
        let rotation_table =
            FF::get_ntt_table(blind_rotation_trace.log_coeff_count as u32).unwrap();
        let key_table = FF::get_ntt_table(key_switching_trace.log_coeff_count as u32).unwrap();
        let rotation_params = BlindRotationParams::new(
            code_spec.clone(),
            rotation_table.root_powers(),
            &blind_rotation_trace,
            cached_key.as_ref().unwrap(),
        );
        let key_trace = key_switching_trace.into();
        let key_params =
            KeySwitchingParams::new(code_spec.clone(), key_table.root_powers(), &key_trace);
        let modulus_trace = modulus_switching_trace.into();
        let modulus_params = ModulusSwitchingParams::new(&code_spec);
        let preprocess_ns = timer.elapsed().as_nanos();
        let mut statistics = SnarkStatistics::default();
        let stats = &mut Some(&mut statistics);
        let mut prover = Transcript::new_direct_extension::<FF>();
        // The fixture statement, configuration, and key root are public and bound
        // before any subprotocol challenges. This is a benchmark-specific domain.
        let statement = (
            FIELD,
            &code_spec,
            &fhe_configuration,
            seed,
            params.lwe_dimension(),
            params.ring_dimension(),
            (x.a(), x.b()),
            (y.a(), y.b()),
            (output.a(), output.b()),
        );
        let public_fixture_sha256 = format!(
            "{:x}",
            Sha256::digest(
                bincode::serde::encode_to_vec(
                    (
                        &fhe_configuration,
                        seed,
                        (x.a(), x.b()),
                        (y.a(), y.b()),
                        (output.a(), output.b())
                    ),
                    bincode::config::standard()
                )
                .unwrap()
            )
        );
        let statement_sha256 = format!(
            "{:x}",
            Sha256::digest(
                bincode::serde::encode_to_vec(&statement, bincode::config::standard()).unwrap()
            )
        );
        let trusted_bsk_root = cached_key
            .as_ref()
            .unwrap()
            .commitment
            .root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        prover.append_message(b"HasteBoots masked PipFRI PBS benchmark v1", &statement);
        prover.append_message(
            b"trusted BSK commitment",
            &cached_key.as_ref().unwrap().commitment,
        );
        let proof_start = Instant::now();
        let timer = Instant::now();
        let modulus_proof = modswitch.prove(&mut prover, &modulus_trace, &modulus_params, stats);
        let modswitch_ns = timer.elapsed().as_nanos();
        let timer = Instant::now();
        let rotation_proof =
            rotation.prove(&mut prover, blind_rotation_trace, &rotation_params, stats);
        let rotation_ns = timer.elapsed().as_nanos();
        let key_openings_after = cached_key
            .as_ref()
            .unwrap()
            .commitment_state
            .remaining_openings()
            .unwrap();
        assert_eq!(key_openings_after + 1, key_openings_before);
        assert_eq!(
            rotation_proof.eval_proof_key.opening_index,
            opening_budget - key_openings_before
        );
        assert_eq!(
            rotation_proof.key_commitment.root,
            cached_key.as_ref().unwrap().commitment.root
        );
        assert_eq!(
            bincode::serde::encode_to_vec(
                &rotation_proof.key_pcs_params,
                bincode::config::standard()
            )
            .unwrap(),
            bincode::serde::encode_to_vec(
                &cached_key.as_ref().unwrap().params,
                bincode::config::standard()
            )
            .unwrap()
        );
        let timer = Instant::now();
        let key_proof = keyswitch.prove(&mut prover, &key_trace, &key_params, stats);
        let keyswitch_ns = timer.elapsed().as_nanos();
        let timer = Instant::now();
        let extraction_proof = extract.prove(&mut prover, &sample_extraction_trace.into());
        let extraction_ns = timer.elapsed().as_nanos();
        let prove_ns = proof_start.elapsed().as_nanos();
        let timer = Instant::now();
        let bytes = bincode::serde::encode_to_vec(
            (
                &modulus_proof,
                &rotation_proof,
                &key_proof,
                &extraction_proof,
            ),
            bincode::config::standard(),
        )
        .unwrap();
        let serialization_ns = timer.elapsed().as_nanos();
        let complete_ns = online_start.elapsed().as_nanos();
        let pcs_bytes = modulus_proof.pcs_proof_len()
            + rotation_proof.pcs_proof_len()
            + key_proof.pcs_proof_len()
            + extraction_proof.pcs_proof_len();
        let piop_bytes = modulus_proof.piop_proof_len()
            + rotation_proof.piop_proof_len()
            + key_proof.piop_proof_len()
            + extraction_proof.piop_proof_len();
        let mut verifier = Transcript::new_direct_extension::<FF>();
        verifier.append_message(b"HasteBoots masked PipFRI PBS benchmark v1", &statement);
        verifier.append_message(
            b"trusted BSK commitment",
            &cached_key.as_ref().unwrap().commitment,
        );
        let timer = Instant::now();
        assert!(modswitch.verify(&mut verifier, &modulus_proof, stats));
        assert!(rotation.verify(&mut verifier, &rotation_proof, stats));
        assert!(keyswitch.verify(&mut verifier, &key_proof, stats));
        assert!(extract.verify(&mut verifier, &extraction_proof, stats));
        let verify_ns = timer.elapsed().as_nanos();
        assert_eq!(
            prover.get_challenge(b"after masked PipFRI PBS"),
            verifier.get_challenge(b"after masked PipFRI PBS")
        );
        println!(
            "HB_MASKED_PIPFRI_BENCH {{\"field\":\"{FIELD}\",\"backend\":\"masked-pipfri-reference-v1\",\"security\":\"experimental-unbudgeted\",\"transcript\":\"merlin-direct-extension-canonical-rejection-v1\",\"fragment_vars\":{fragment_vars},\"blowup\":2,\"queries\":{queries},\"opening_budget\":{opening_budget},\"key_openings_before\":{key_openings_before},\"key_openings_after\":{key_openings_after},\"key_opening_index\":{},\"public_fixture_sha256\":\"{public_fixture_sha256}\",\"native_bsk_sha256\":\"{native_bsk_sha256}\",\"verification_scope\":\"legacy-four-stage-wrapper-in-memory\",\"verified\":true,\"fhe_parameters_sha256\":\"{fhe_parameters_sha256}\",\"statement_sha256\":\"{statement_sha256}\",\"trusted_bsk_root\":\"{trusted_bsk_root}\",\"seed\":{seed},\"iteration\":{iteration},\"warmup\":{},\"cold\":{cold},\"new_key_commitment\":{new_key},\"keygen_ns\":{keygen_ns},\"trace_ns\":{trace_ns},\"finalize_ns\":{finalize_ns},\"key_commit_ns\":{key_commit_ns},\"preprocess_ns\":{preprocess_ns},\"modswitch_ns\":{modswitch_ns},\"rotation_ns\":{rotation_ns},\"keyswitch_ns\":{keyswitch_ns},\"extraction_ns\":{extraction_ns},\"prove_ns\":{prove_ns},\"pcs_prove_ns\":{},\"pcs_verify_ns\":{},\"pcs_commit_ns\":{},\"pcs_open_ns\":{},\"tracked_extension_ns\":{},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"verify_ns\":{verify_ns},\"proof_bytes\":{},\"pcs_bytes\":{pcs_bytes},\"piop_bytes\":{piop_bytes},\"threads\":{}}}",
            rotation_proof.eval_proof_key.opening_index,
            iteration < warmups,
            statistics.prover_pcs_time.as_nanos(),
            statistics.verifier_pcs_time.as_nanos(),
            statistics.prover_commit_time.as_nanos(),
            statistics.prover_open_time.as_nanos(),
            statistics.prover_extension_time.as_nanos(),
            bytes.len(),
            rayon::current_num_threads()
        );
    }
}

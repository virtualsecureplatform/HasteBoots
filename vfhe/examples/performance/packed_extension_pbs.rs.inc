// Complete experimental binary NAND PBS proof and independent verification.
use algebra::{
    AbstractExtensionField, AsInto, Field,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use pcs::{
    matrix_weighted::Parameters,
    utils::code::{BlockReedSolomonCode, RowCode},
};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use snarks::packed_pbs as pbs;
use std::time::Instant;
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
fn main() {
    let full = std::env::args().any(|s| s == "--full");
    let extension = !std::env::args().any(|s| s == "--lanes");
    let aggregate_hadamard = std::env::args().any(|s| s == "--aggregate-hadamard");
    assert!(!aggregate_hadamard || extension, "aggregate Hadamard requires extension comparisons");
    let hadamard_backend = if aggregate_hadamard {"multi-root"} else {"independent"};
    let validation_batches = std::env::args().any(|s| s == "--validation-batches");
    assert!(
        !validation_batches || !std::env::args().any(|s| s == "--iterations"),
        "validation batches use a fixed 1/4/16 schedule; omit --iterations"
    );
    let iterations = std::env::args()
        .position(|s| s == "--iterations")
        .map(|i| {
            std::env::args()
                .nth(i + 1)
                .expect("iterations value")
                .parse::<usize>()
                .expect("integer iterations")
        })
        .unwrap_or(1);
    assert!(iterations > 0);
    let repetitions = if extension { 1 } else { 16 };
    let protocol_version = if aggregate_hadamard {
        pbs::AGGREGATED_PROTOCOL_VERSION
    } else if extension {
        pbs::EXTENSION_PROTOCOL_VERSION
    } else {
        pbs::PROTOCOL_VERSION
    };
    let transcript = if aggregate_hadamard {
        pbs::AGGREGATED_TRANSCRIPT_ID
    } else if extension {
        pbs::EXTENSION_TRANSCRIPT_ID
    } else {
        pbs::TRANSCRIPT_ID
    };
    let backend = if extension { "extension" } else { "lanes" };
    let extension_degree = if extension { EF::D } else { 1 };
    let width = std::env::args()
        .position(|s| s == "--width")
        .map(|i| {
            std::env::args()
                .nth(i + 1)
                .expect("width value")
                .parse::<usize>()
                .expect("integer width")
        })
        .unwrap_or(8);
    assert!(
        width.is_power_of_two() && (!extension || width >= EF::D),
        "unsupported extension/packing width"
    );
    let helper_left_extra = std::env::args()
        .position(|s| s == "--helper-left-extra")
        .map(|i| std::env::args().nth(i + 1).expect("helper-left-extra value")
            .parse::<usize>().expect("integer helper-left-extra"))
        .unwrap_or(0);
    assert!(helper_left_extra <= 1, "helper-left-extra supports 0 or 1");
    let params = if full {
        *PARAMETERS
    } else {
        FheParameters::<F>::new(ConstParameters {
            lwe_dimension: 32,
            lwe_plain_modulus: 4usize.as_into(),
            lwe_noise_standard_deviation: 1.0,
            lwe_secret_key_type: LWESecretKeyType::Binary,
            ring_dimension: 32,
            ring_modulus: F::MODULUS_VALUE,
            ring_noise_standard_deviation: 1.0,
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 8,
            key_switching_basis_bits: 5,
            key_switching_standard_deviation: 1.0,
        })
        .unwrap()
    };
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&42u64.to_le_bytes());
    let sk = SecretKeyPack::with_rng(params, Prg::from_seed(Block::from(seed)));
    let enc = Encryptor::new(sk.clone());
    let evaluator = Evaluator::new(&sk);
    let dec = Decryptor::new(sk);
    let fhe_parameters_sha256 = format!("{:x}", Sha256::digest(format!("{params:?}").as_bytes()));
    let br_data: Vec<_> = evaluator
        .binary_bootstrap_key()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r.basis().bits(),
                [r.c_neg_s_m(), r.c_m()]
                    .map(|g| g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>()),
            )
        })
        .collect();
    let ks_data: Vec<_> = evaluator
        .rlwe_key_switching_key()
        .unwrap()
        .as_slice()
        .iter()
        .map(|g| {
            (
                g.basis().bits(),
                g.data().iter().map(|p| p.a_b_slice()).collect::<Vec<_>>(),
            )
        })
        .collect();
    let native_keys_sha256 = format!(
        "{:x}",
        Sha256::digest(
            bincode::serde::encode_to_vec(&(br_data, ks_data), bincode::config::standard())
                .unwrap()
        )
    );
    let cfg = pbs::Config::new::<F>(
        params.ring_dimension(),
        params.lwe_dimension(),
        params.blind_rotation_basis().bits(),
        params.key_switching_basis_bits(),
        params.lut_step(),
        repetitions,
    )
    .unwrap();
    let dims = cfg.variables(width).unwrap();
    let codes: [_; 4] = std::array::from_fn(|role| {
        let n = dims[role];
        let balanced = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 544, 2).unwrap();
        if role % 2 == 0 || helper_left_extra == 0 {
            balanced
        } else {
            let left = balanced.left_vars().checked_add(helper_left_extra).unwrap();
            assert!(left <= n, "helper split exceeds dimension");
            let code = BlockReedSolomonCode::<F>::new(1usize << (n - left), width, 2).unwrap();
            Parameters::new_encoded::<F>(n, width, left, 544, code).unwrap()
        }
    });
    for (role, p) in ["source", "helper", "final_source", "final_helper"]
        .iter()
        .zip(&codes)
    {
        println!(
            "HB_FULL_PCS {{\"role\":\"{role}\",\"row_code\":\"block-rs\",\"prime\":{},\"width\":{},\"variables\":{},\"left_vars\":{},\"row_message_scalars\":{},\"row_message_blocks\":{},\"row_encoded_blocks\":{},\"block_width\":{},\"queries\":{}}}",
            F::MODULUS_VALUE,
            p.width(),
            p.num_vars(),
            p.left_vars(),
            p.code().message_len(),
            p.code().message_blocks(),
            p.code().codeword_blocks(),
            p.code().block_width(),
            p.queries()
        );
    }
    let pp = pbs::Parameters {
        source: &codes[0],
        helper: &codes[1],
        final_source: &codes[2],
        final_helper: &codes[3],
    };
    let timer = Instant::now();
    let setup = pbs::preprocess::<F, Sha256, _>(
        &pp,
        cfg,
        evaluator.binary_bootstrap_key().unwrap(),
        evaluator.rlwe_key_switching_key().unwrap().as_slice(),
    )
    .unwrap();
    let setup_ns = timer.elapsed().as_nanos();
    let verifier = setup.verifier();
    let x = enc.encrypt(1usize.as_into());
    let y = enc.encrypt(1usize.as_into());
    let schedule: Vec<_> = if validation_batches {
        [1, 4, 16]
            .into_iter()
            .flat_map(|size| (0..size).map(move |index| (size, index)))
            .collect()
    } else {
        (0..iterations).map(|_| (1, 0)).collect()
    };
    let validation_mode = if validation_batches { "independent-fresh-inputs" } else { "repeated-statement" };
    for (iteration, (validation_group_size, validation_group_index)) in schedule.into_iter().enumerate() {
        let (left_plaintext, right_plaintext) = if validation_batches {
            (validation_group_index & 1, (validation_group_index >> 1) & 1)
        } else {
            (1usize, 1usize)
        };
        // Keep the original repeated-statement fixture and random stream unchanged.
        // Validation encryptions are fresh, outside complete-PBS timing.
        let fresh_inputs = validation_batches.then(|| (
            enc.encrypt(left_plaintext.as_into()), enc.encrypt(right_plaintext.as_into())
        ));
        let (x, y) = fresh_inputs.as_ref().map(|(x, y)| (x, y)).unwrap_or((&x, &y));
        let expected_plaintext = 1 - left_plaintext * right_plaintext;
        let complete = Instant::now();
        let (out, trace) = evaluator.nand(&x, &y);
        let trace_ns = complete.elapsed().as_nanos();
        assert_eq!(dec.decrypt_with_noise(&out).0, expected_plaintext.as_into());
        let statement = pbs::Statement {
            left_a: x.a(),
            left_b: x.b(),
            right_a: y.a(),
            right_b: y.b(),
            output_a: out.a(),
            output_b: out.b(),
        };
        let statement_sha256 = format!(
            "{:x}",
            Sha256::digest(
                bincode::serde::encode_to_vec(&statement, bincode::config::standard()).unwrap()
            )
        );
        let mut stats = pbs::ProverStatistics::default();
        let timer = Instant::now();
        macro_rules! certificate {
            ($proof:expr, $ty:ty, $verify:expr) => {{
                let proof = $proof.unwrap();
                let prove_ns = timer.elapsed().as_nanos();
                let roots = proof.coefficients.len();
                let links = proof.ntt.len();
                drop(trace);
                let timer = Instant::now();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let serialization_ns = timer.elapsed().as_nanos();
                let complete_ns = complete.elapsed().as_nanos();
                let proof_bytes = bytes.len();
                let proof_sha256 = format!("{:x}", Sha256::digest(&bytes));
                drop(proof);
                let timer = Instant::now();
                let (proof, used): ($ty, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, proof_bytes);
                let deserialize_ns = timer.elapsed().as_nanos();
                drop(bytes);
                let timer = Instant::now();
                ($verify)(&proof).unwrap();
                let verify_ns = timer.elapsed().as_nanos();
                let inventory = snarks::packed_root_inventory::inventory(&proof);
                let categories = inventory.categories.iter().map(|(name, count)|
                    format!("\"{name}\":{count}")).collect::<Vec<_>>().join(",");
                println!("HB_FULL_ROOTS {{\"scope\":\"verified-proof-root-slots\",\"iteration\":{iteration},\"proof_sha256\":\"{proof_sha256}\",\"total\":{},\"categories\":{{{categories}}},\"trusted_key_roots_included\":false,\"whole_proof_security_certified\":false}}", inventory.total());
                (
                    prove_ns,
                    serialization_ns,
                    complete_ns,
                    proof_bytes,
                    deserialize_ns,
                    verify_ns,
                    roots,
                    links,
                    proof_sha256,
                )
            }};
        }
        let (
            prove_ns,
            serialization_ns,
            complete_ns,
            proof_bytes,
            deserialize_ns,
            verify_ns,
            private_roots,
            ntt_links,
            proof_sha256,
        ) = if aggregate_hadamard {
            certificate!(pbs::prove_aggregated_with_statistics::<F, EF, Sha256, _>(&pp, &setup, &statement, &trace, &mut stats),
            pbs::AggregatedProof<F, EF, [u8; 32]>,
            |proof| pbs::verify_aggregated::<F, EF, Sha256, _>(&pp, &verifier, &statement, proof))
        } else if extension {
            certificate!(pbs::prove_extension_with_statistics::<F, EF, Sha256, _>(&pp, &setup, &statement, &trace, &mut stats),
            pbs::ExtensionProof<F, EF, [u8; 32]>,
            |proof| pbs::verify_extension::<F, EF, Sha256, _>(&pp, &verifier, &statement, proof))
        } else {
            certificate!(pbs::prove_with_statistics::<F, Sha256, _>(&pp, &setup, &statement, &trace, &mut stats),
            pbs::Proof<F, [u8; 32]>,
            |proof| pbs::verify::<F, Sha256, _>(&pp, &verifier, &statement, proof))
        };
        println!(
            "Complete experimental NAND PBS proof verified from serialized bytes: full_parameters={full} proof_bytes={proof_bytes} complete_ms={:.3} verify_ms={:.3}; security/performance promotion pending",
            complete_ns as f64 / 1e6,
            verify_ns as f64 / 1e6
        );
        println!(
            "HB_FULL_PBS {{\"kind\":\"complete-binary-nand-pbs\",\"protocol_version\":{protocol_version},\"transcript\":\"{transcript}\",\"field\":\"{FIELD}\",\"hadamard_backend\":\"{hadamard_backend}\",\"lookup_backend\":\"{backend}\",\"lookup_field_degree\":{extension_degree},\"iteration\":{iteration},\"verification_scope\":\"complete-serialized-public-verifier\",\"verified\":true,\"statement_sha256\":\"{statement_sha256}\",\"fhe_parameters_sha256\":\"{fhe_parameters_sha256}\",\"native_keys_sha256\":\"{native_keys_sha256}\",\"proof_sha256\":\"{proof_sha256}\",\"security\":\"experimental-unbudgeted\",\"full_parameters\":{full},\"seed\":42,\"batch_size\":1,\"validation_mode\":\"{validation_mode}\",\"validation_group_size\":{validation_group_size},\"validation_group_index\":{validation_group_index},\"left_plaintext\":{left_plaintext},\"right_plaintext\":{right_plaintext},\"decrypted_plaintext\":{expected_plaintext},\"prime\":{},\"width\":{width},\"helper_left_extra\":{helper_left_extra},\"polynomial_size\":{},\"input_dimension\":{},\"output_dimension\":{},\"basis_bits\":{},\"key_switch_basis_bits\":{},\"lookup_repetitions\":{repetitions},\"private_coefficient_roots\":{},\"ntt_links\":{},\"setup_ns\":{setup_ns},\"trace_ns\":{trace_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"preparation_ns\":{},\"hadamard_ns\":{},\"ntt_ns\":{},\"decomposition_ns\":{},\"accumulator_ns\":{},\"monomial_ns\":{},\"key_switch_ns\":{},\"proof_bytes\":{proof_bytes},\"source_variables\":{},\"source_left_vars\":{},\"source_message_blocks\":{},\"source_encoded_blocks\":{},\"source_queries\":{},\"helper_variables\":{},\"helper_left_vars\":{},\"helper_message_blocks\":{},\"helper_encoded_blocks\":{},\"helper_queries\":{}}}",
            F::MODULUS_VALUE,
            params.ring_dimension(),
            params.lwe_dimension(),
            params.lwe_dimension(),
            params.blind_rotation_basis().bits(),
            params.key_switching_basis_bits(),
            private_roots,
            ntt_links,
            stats.preparation.as_nanos(),
            stats.hadamard.as_nanos(),
            stats.ntt.as_nanos(),
            stats.decomposition.as_nanos(),
            stats.accumulator.as_nanos(),
            stats.monomial.as_nanos(),
            stats.key_switch.as_nanos(),
            codes[0].num_vars(),
            codes[0].left_vars(),
            codes[0].code().message_blocks(),
            codes[0].code().codeword_blocks(),
            codes[0].queries(),
            codes[1].num_vars(),
            codes[1].left_vars(),
            codes[1].code().message_blocks(),
            codes[1].code().codeword_blocks(),
            codes[1].queries()
        );
    }
}

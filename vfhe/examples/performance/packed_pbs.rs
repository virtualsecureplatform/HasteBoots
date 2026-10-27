//! Complete experimental binary NAND PBS proof and independent verification.
use algebra::{
    BabyBear as F, Field,
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
use sha2::Sha256;
use snarks::packed_pbs as pbs;
use std::time::Instant;
use vfhe::{
    Decryptor, Encryptor,
    bfhe::{BABYBEAR_BINARY_128_BITS_PARAMETERS, Evaluator},
};
fn main() {
    let full = std::env::args().any(|s| s == "--full");
    let params = if full {
        *BABYBEAR_BINARY_128_BITS_PARAMETERS
    } else {
        FheParameters::<F>::new(ConstParameters {
            lwe_dimension: 32,
            lwe_plain_modulus: 4,
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
    let cfg = pbs::Config::new::<F>(
        params.ring_dimension(),
        params.lwe_dimension(),
        params.blind_rotation_basis().bits(),
        params.key_switching_basis_bits(),
        params.lut_step(),
        16,
    )
    .unwrap();
    let dims = cfg.variables(8).unwrap();
    let codes = dims
        .map(|n| Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, 8, 544, 2).unwrap());
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
    let x = enc.encrypt(1);
    let y = enc.encrypt(1);
    let complete = Instant::now();
    let (out, trace) = evaluator.nand(&x, &y);
    let trace_ns = complete.elapsed().as_nanos();
    assert_eq!(dec.decrypt_with_noise(&out).0, 0);
    let statement = pbs::Statement {
        left_a: x.a(),
        left_b: x.b(),
        right_a: y.a(),
        right_b: y.b(),
        output_a: out.a(),
        output_b: out.b(),
    };
    let mut stats = pbs::ProverStatistics::default();
    let timer = Instant::now();
    let proof =
        pbs::prove_with_statistics::<F, Sha256, _>(&pp, &setup, &statement, &trace, &mut stats)
            .unwrap();
    let prove_ns = timer.elapsed().as_nanos();
    drop(trace);
    let timer = Instant::now();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let serialization_ns = timer.elapsed().as_nanos();
    let complete_ns = complete.elapsed().as_nanos();
    let proof_bytes = bytes.len();
    drop(proof);
    let timer = Instant::now();
    let (proof, used): (pbs::Proof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, proof_bytes);
    let deserialize_ns = timer.elapsed().as_nanos();
    drop(bytes);
    let timer = Instant::now();
    pbs::verify::<F, Sha256, _>(&pp, &verifier, &statement, &proof).unwrap();
    let verify_ns = timer.elapsed().as_nanos();
    println!(
        "Complete experimental NAND PBS proof verified from serialized bytes: full_parameters={full} proof_bytes={proof_bytes} complete_ms={:.3} verify_ms={:.3}; security/performance promotion pending",
        complete_ns as f64 / 1e6,
        verify_ns as f64 / 1e6
    );
    println!(
        "HB_FULL_PBS {{\"kind\":\"complete-binary-nand-pbs\",\"protocol_version\":2,\"transcript\":\"merlin-direct-canonical-rejection-v1\",\"field\":\"babybear\",\"security\":\"experimental-unbudgeted\",\"full_parameters\":{full},\"seed\":42,\"batch_size\":1,\"prime\":{},\"width\":8,\"polynomial_size\":{},\"input_dimension\":{},\"output_dimension\":{},\"basis_bits\":{},\"key_switch_basis_bits\":{},\"lookup_repetitions\":16,\"private_coefficient_roots\":{},\"ntt_links\":{},\"setup_ns\":{setup_ns},\"trace_ns\":{trace_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"preparation_ns\":{},\"hadamard_ns\":{},\"ntt_ns\":{},\"decomposition_ns\":{},\"accumulator_ns\":{},\"monomial_ns\":{},\"key_switch_ns\":{},\"proof_bytes\":{proof_bytes},\"source_variables\":{},\"source_left_vars\":{},\"source_message_blocks\":{},\"source_encoded_blocks\":{},\"source_queries\":{},\"helper_variables\":{},\"helper_left_vars\":{},\"helper_message_blocks\":{},\"helper_encoded_blocks\":{},\"helper_queries\":{}}}",
        F::MODULUS_VALUE,
        params.ring_dimension(),
        params.lwe_dimension(),
        params.lwe_dimension(),
        params.blind_rotation_basis().bits(),
        params.key_switching_basis_bits(),
        proof.coefficients.len(),
        proof.ntt.len(),
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

// Native Hadamard-only comparison; no complete PBS/security promotion claim.
use algebra::{
    AsInto, Field, NTTField,
    transformation::AbstractNTT,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted, mw_basefold, utils::code::BlockReedSolomonCode};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use snarks::{packed_basefold, packed_relation};
use std::time::Instant;
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
fn argument(name: &str, default: usize) -> usize {
    std::env::args()
        .position(|s| s == name)
        .map(|i| {
            std::env::args()
                .nth(i + 1)
                .expect("argument value")
                .parse()
                .expect("integer argument")
        })
        .unwrap_or(default)
}
fn main() {
    let full = std::env::args().any(|s| s == "--full");
    let brakedown = std::env::args().any(|s| s == "--brakedown");
    let queries = argument("--queries", 544);
    let iterations = argument("--iterations", 2);
    assert!(iterations > 0 && queries > 0);
    let params = if full {
        *PARAMETERS
    } else {
        FheParameters::<F>::new(ConstParameters {
            lwe_dimension: 21,
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
    let x = enc.encrypt(1usize.as_into());
    let y = enc.encrypt(1usize.as_into());
    let (output, mut trace) = evaluator.nand(&x, &y);
    assert_eq!(dec.decrypt_with_noise(&output).0, 0usize.as_into());
    trace.blind_rotation_trace.finalize(params.lwe_dimension());
    let (shape, factors) =
        packed_relation::from_sum_hadamard(8, &trace.blind_rotation_trace.hadamard_trace).unwrap();
    let fixture_sha256 = format!(
        "{:x}",
        Sha256::digest(
            bincode::serde::encode_to_vec(
                &(&factors, x.a(), x.b(), y.a(), y.b(), output.a(), output.b()),
                bincode::config::standard()
            )
            .unwrap()
        )
    );
    let fhe_parameters_sha256 = format!("{:x}", Sha256::digest(format!("{params:?}").as_bytes()));
    drop(trace);
    let width = shape.width;
    let variables = shape.num_vars;
    let factor_count = shape.num_factors;
    let backend = if brakedown {
        "mw-brakedown"
    } else {
        "structured-mw-basefold"
    };
    macro_rules! certificate {
        ($roots:expr,$prove:expr,$root:ty,$ty:ty,$verify:expr) => {{
            let timer = Instant::now();
            let proof = $prove.unwrap();
            let prove_ns = timer.elapsed().as_nanos();
            let timer = Instant::now();
            let bytes =
                bincode::serde::encode_to_vec(&($roots, &proof), bincode::config::standard())
                    .unwrap();
            let serialization_ns = timer.elapsed().as_nanos();
            let proof_bytes = bytes.len();
            let proof_sha256 = format!("{:x}", Sha256::digest(&bytes));
            drop(proof);
            let ((roots, proof), used): ((Vec<$root>, $ty), _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            assert!(roots.iter().zip($roots).all(|(a, b)| a.root == b.root));
            drop(bytes);
            let timer = Instant::now();
            ($verify)(&roots, &proof).unwrap();
            let verify_ns = timer.elapsed().as_nanos();
            (
                prove_ns,
                serialization_ns,
                verify_ns,
                proof_bytes,
                proof_sha256,
            )
        }};
    }
    if brakedown {
        let pp = matrix_weighted::Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
            variables, width, queries, 2,
        )
        .unwrap();
        let timer = Instant::now();
        let (roots, states): (Vec<_>, Vec<_>) = factors
            .iter()
            .map(|t| pp.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let commit_ns = timer.elapsed().as_nanos();
        for iteration in 0..iterations {
            let (prove_ns, serialization_ns, verify_ns, proof_bytes, proof_sha256) = certificate!(&roots,
                packed_relation::prove::<F,Sha256,_>(&mut transcript(&fixture_sha256,&fhe_parameters_sha256),&shape,&pp,&factors,&roots,&states),
                matrix_weighted::Commitment<[u8;32]>,packed_relation::RelationProof<F,[u8;32]>,
                |r:&[_],p|packed_relation::verify::<F,Sha256,_>(&mut transcript(&fixture_sha256,&fhe_parameters_sha256),&shape,&pp,r,p));
            report(
                FIELD,
                backend,
                full,
                iteration,
                variables,
                width,
                factor_count,
                queries,
                &fixture_sha256,
                &fhe_parameters_sha256,
                commit_ns,
                prove_ns,
                serialization_ns,
                verify_ns,
                proof_bytes,
                &proof_sha256,
                0,
            );
        }
    } else {
        let n = (1usize << variables) / width * 2;
        let mut root = F::generate_ntt_table(n.max(64).ilog2()).unwrap().root();
        for _ in n.ilog2()..n.max(64).ilog2() {
            root *= root;
        }
        let pp = mw_basefold::Parameters::new(variables, width, 2, queries, root).unwrap();
        let timer = Instant::now();
        let (roots, states): (Vec<_>, Vec<_>) = factors
            .iter()
            .map(|t| mw_basefold::commit::<F, Sha256>(&pp, t).unwrap())
            .unzip();
        let commit_ns = timer.elapsed().as_nanos();
        for iteration in 0..iterations {
            let mut stats = packed_basefold::Statistics::default();
            let (prove_ns, serialization_ns, verify_ns, proof_bytes, proof_sha256) = certificate!(&roots,
                packed_basefold::prove_with_statistics::<F,Sha256>(&mut transcript(&fixture_sha256,&fhe_parameters_sha256),&pp,&shape,&factors,&roots,&states,&mut stats),
                mw_basefold::Commitment<[u8;32]>,packed_basefold::Proof<F,[u8;32]>,
                |r:&[_],p|packed_basefold::verify::<F,Sha256>(&mut transcript(&fixture_sha256,&fhe_parameters_sha256),&pp,&shape,r,p));
            report(
                FIELD,
                backend,
                full,
                iteration,
                variables,
                width,
                factor_count,
                queries,
                &fixture_sha256,
                &fhe_parameters_sha256,
                commit_ns,
                prove_ns,
                serialization_ns,
                verify_ns,
                proof_bytes,
                &proof_sha256,
                stats.oracle_folds.as_nanos(),
            );
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn report(
    field: &str,
    backend: &str,
    full: bool,
    iteration: usize,
    variables: usize,
    width: usize,
    factors: usize,
    queries: usize,
    fixture: &str,
    fhe: &str,
    commit: u128,
    prove: u128,
    serialize: u128,
    verify: u128,
    bytes: usize,
    proof_hash: &str,
    folds: u128,
) {
    println!(
        "HB_MW_COMPARISON {{\"field\":\"{field}\",\"backend\":\"{backend}\",\"verification_scope\":\"native-hadamard-only\",\"security\":\"experimental-unbudgeted\",\"verified\":true,\"full_parameters\":{full},\"iteration\":{iteration},\"seed\":42,\"variables\":{variables},\"width\":{width},\"factors\":{factors},\"queries\":{queries},\"blowup\":2,\"fixture_sha256\":\"{fixture}\",\"fhe_parameters_sha256\":\"{fhe}\",\"proof_sha256\":\"{proof_hash}\",\"commit_ns\":{commit},\"prove_ns\":{prove},\"serialization_ns\":{serialize},\"verify_ns\":{verify},\"proof_bytes\":{bytes},\"oracle_fold_ns\":{folds}}}"
    );
}

fn transcript(fixture: &str, fhe: &str) -> Transcript<F> {
    let mut t = Transcript::new_direct();
    t.append_message(
        b"native Hadamard MW comparison public fixture v1",
        &(fixture, fhe),
    );
    t
}

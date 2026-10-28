//! Deterministic PCS arithmetic comparison; public masks here are test-only controls.
use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::masked_polyfrim::{Parameters, Proof};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::time::Instant;
fn digest<T: Serialize>(v: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(bincode::serde::encode_to_vec(v, bincode::config::standard()).unwrap())
    )
}
fn run<F, E>(
    field: &str,
    width: usize,
    logical: usize,
    physical: usize,
    queries: usize,
    budget: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, E>::new(logical, width, physical, 2, queries, budget).unwrap();
    let table = PackedTable::new(
        logical,
        width,
        (0..(1usize << logical) * width)
            .map(|i| F::from((17 * i + 11) % 100003))
            .collect(),
    )
    .unwrap();
    let fixture = digest(&table);
    let context = digest(&pp);
    let mut rng = StdRng::seed_from_u64(3101);
    let start = Instant::now();
    let (root, state) = pp.commit::<Sha256, _>(&table, &mut rng).unwrap();
    let commit_s = start.elapsed().as_secs_f64();
    let rng_tail = rng.next_u64();
    let mut coins = Transcript::<F>::new_direct();
    for opening in 0..budget {
        let query: Vec<_> = (0..logical)
            .map(|_| {
                let values =
                    coins.get_vec_challenge(b"masked packed profile matrices", 2 * width * width);
                MatrixPair {
                    zero: Matrix::new(width, values[..width * width].to_vec()).unwrap(),
                    one: Matrix::new(width, values[width * width..].to_vec()).unwrap(),
                }
            })
            .collect();
        let value = state.table().evaluate(&query).unwrap();
        let query_hash = digest(&(&query, &value));
        let mut pt = Transcript::new_direct();
        let start = Instant::now();
        let proof = pp
            .open_many::<Sha256>(&mut pt, &root, &state, &[query.clone()], &[value.clone()])
            .unwrap();
        let prove_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let serialization_s = start.elapsed().as_secs_f64();
        let (proof, used): (Proof<E, [u8; 32]>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut vt = Transcript::new_direct();
        let start = Instant::now();
        pp.verify_many::<Sha256>(&mut vt, &root, &[query], &[value], &proof)
            .unwrap();
        let verify_s = start.elapsed().as_secs_f64();
        let after = pt.get_challenge(b"profile after");
        assert_eq!(after, vt.get_challenge(b"profile after"));
        assert_eq!(state.spent().unwrap(), opening + 1);
        println!(
            "HB_MASKED_PACKED_PROFILE {{\"field\":\"{}\",\"logical_vars\":{},\"physical_vars\":{},\"width\":{},\"queries\":{},\"budget\":{},\"opening\":{},\"fixture_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"root\":\"{:x}\",\"query_sha256\":\"{}\",\"proof_sha256\":\"{:x}\",\"transcript_sha256\":\"{}\",\"rng_tail\":{},\"proof_bytes\":{},\"commit_s\":{},\"prove_s\":{},\"serialization_s\":{},\"verify_s\":{},\"verified\":true,\"whole_security_matched\":false,\"complete_pbs\":false}}",
            field,
            logical,
            physical,
            width,
            queries,
            budget,
            opening,
            fixture,
            context,
            Sha256::digest(root.root),
            query_hash,
            Sha256::digest(&bytes),
            digest(&after),
            rng_tail,
            bytes.len(),
            commit_s,
            prove_s,
            serialization_s,
            verify_s
        );
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "usage: masked_packed_profile babybear|goldilocks logical_vars physical_vars queries opening_budget"
    );
    let logical = args[2].parse().unwrap();
    let physical = args[3].parse().unwrap();
    let queries = args[4].parse().unwrap();
    let budget = args[5].parse().unwrap();
    match args[1].as_str() {
        "babybear" => run::<algebra::BabyBear, algebra::BabyBearExtension6>(
            "babybear", 8, logical, physical, queries, budget,
        ),
        "goldilocks" => run::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            "goldilocks",
            4,
            logical,
            physical,
            queries,
            budget,
        ),
        _ => panic!("unsupported field"),
    }
}

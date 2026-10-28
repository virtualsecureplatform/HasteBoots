//! Deterministic source-sharing PCS comparison; public masks are test controls.
use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::masked_polyfrim::{Error, Parameters};
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
fn wire<P: Serialize + DeserializeOwned>(
    proof: P,
    verify: impl FnOnce(&P) -> Result<(), Error>,
) -> (Vec<u8>, f64, f64, f64) {
    let start = Instant::now();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let serialization = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let (decoded, used): (P, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let decode = start.elapsed().as_secs_f64();
    let start = Instant::now();
    verify(&decoded).unwrap();
    (bytes, serialization, decode, start.elapsed().as_secs_f64())
}
fn run<F, E>(field: &str, mode: &str, width: usize, logical: usize, physical: usize, count: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, E>::new(logical, width, physical, 2, 1, count).unwrap();
    let table = PackedTable::new(
        logical,
        width,
        (0..(1 << logical) * width)
            .map(|i| F::from((17 * i + 11) % 100003))
            .collect(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(3101);
    let start = Instant::now();
    let (root, state) = pp.commit::<Sha256, _>(&table, &mut rng).unwrap();
    let commit_s = start.elapsed().as_secs_f64();
    let rng_tail = rng.next_u64();
    let mut coins = Transcript::<F>::new_direct();
    let queries: Vec<Vec<_>> = (0..count)
        .map(|_| {
            (0..logical)
                .map(|_| {
                    let values = coins
                        .get_vec_challenge(b"masked joint profile matrices", 2 * width * width);
                    MatrixPair {
                        zero: Matrix::new(width, values[..width * width].to_vec()).unwrap(),
                        one: Matrix::new(width, values[width * width..].to_vec()).unwrap(),
                    }
                })
                .collect()
        })
        .collect();
    let claims: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
    let mut pt = Transcript::new_direct();
    let mut vt = Transcript::new_direct();
    let start = Instant::now();
    let (prove_s, (bytes, serialization_s, decode_s, verify_s)) = match mode {
        "joint" => {
            let proof = pp
                .open_many_joint::<Sha256>(&mut pt, &root, &state, &queries, &claims)
                .unwrap();
            let prove = start.elapsed().as_secs_f64();
            (
                prove,
                wire(proof, |p| {
                    pp.verify_many_joint::<Sha256>(&mut vt, &root, &queries, &claims, p)
                }),
            )
        }
        "independent" => {
            let proof = pp
                .open_many::<Sha256>(&mut pt, &root, &state, &queries, &claims)
                .unwrap();
            let prove = start.elapsed().as_secs_f64();
            (
                prove,
                wire(proof, |p| {
                    pp.verify_many::<Sha256>(&mut vt, &root, &queries, &claims, p)
                }),
            )
        }
        _ => panic!("mode must be independent or joint"),
    };
    let after = pt.get_challenge(b"joint profile after");
    assert_eq!(after, vt.get_challenge(b"joint profile after"));
    assert_eq!(state.spent().unwrap(), count);
    println!(
        "HB_MASKED_JOINT_PROFILE {{\"field\":\"{}\",\"mode\":\"{}\",\"logical_vars\":{},\"physical_vars\":{},\"width\":{},\"batch_size\":{},\"queries\":1,\"budget\":{},\"fixture_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"root_sha256\":\"{:x}\",\"query_sha256\":\"{}\",\"proof_sha256\":\"{:x}\",\"transcript_sha256\":\"{}\",\"rng_tail\":{},\"spent\":{},\"proof_bytes\":{},\"source_certificates\":{},\"masked_ladders\":{},\"commit_s\":{},\"prove_s\":{},\"serialization_s\":{},\"decode_s\":{},\"verify_s\":{},\"verified\":true,\"full_query_aggregation\":false,\"whole_security_matched\":false,\"complete_pbs\":false}}",
        field,
        mode,
        logical,
        physical,
        width,
        count,
        count,
        digest(&table),
        digest(&pp),
        Sha256::digest(root.root),
        digest(&(&queries, &claims)),
        Sha256::digest(&bytes),
        digest(&after),
        rng_tail,
        count,
        bytes.len(),
        if mode == "joint" { 1 } else { count },
        count,
        commit_s,
        prove_s,
        serialization_s,
        decode_s,
        verify_s
    );
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        5,
        "field independent|joint logical_vars physical_vars batch_size"
    );
    let logical = args[2].parse().unwrap();
    let physical = args[3].parse().unwrap();
    let count = args[4].parse().unwrap();
    match args[0].as_str() {
        "babybear" => run::<algebra::BabyBear, algebra::BabyBearExtension6>(
            &args[0], &args[1], 8, logical, physical, count,
        ),
        "goldilocks" => run::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            &args[0], &args[1], 4, logical, physical, count,
        ),
        _ => panic!("unknown field"),
    }
}

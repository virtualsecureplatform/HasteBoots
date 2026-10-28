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
fn resident_kib() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}
fn run<F, E>(
    field: &str,
    mode: &str,
    width: usize,
    logical: usize,
    physical: usize,
    count: usize,
    queries_count: usize,
    transient: bool,
) where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, E>::new(logical, width, physical, 2, queries_count, count).unwrap();
    let pp = if transient {
        pp.with_transient_source_values()
    } else {
        pp
    };
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
    let committed_cache = state.cached_codeword_elements().unwrap();
    let committed_rss = resident_kib();
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
    let opened_cache = state.cached_codeword_elements().unwrap();
    let opened_rss = resident_kib();
    assert_eq!(
        committed_cache,
        if transient {
            0
        } else {
            4 * (1usize << physical) * 2 * width
        }
    );
    assert_eq!(opened_cache, committed_cache);
    println!(
        "HB_MASKED_SOURCE_RESOURCES {{\"field\":\"{}\",\"transient\":{},\"queries\":{},\"committed_cache_elements\":{},\"opened_cache_elements\":{},\"extension_element_bytes\":{},\"committed_rss_kib\":{},\"opened_rss_kib\":{}}}",
        field,
        transient,
        queries_count,
        committed_cache,
        opened_cache,
        std::mem::size_of::<E>(),
        committed_rss.map_or("null".to_owned(), |v| v.to_string()),
        opened_rss.map_or("null".to_owned(), |v| v.to_string())
    );
    let after = pt.get_challenge(b"joint profile after");
    assert_eq!(after, vt.get_challenge(b"joint profile after"));
    assert_eq!(state.spent().unwrap(), count);
    println!(
        "HB_MASKED_JOINT_PROFILE {{\"field\":\"{}\",\"mode\":\"{}\",\"logical_vars\":{},\"physical_vars\":{},\"width\":{},\"batch_size\":{},\"queries\":{},\"budget\":{},\"fixture_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"root_sha256\":\"{:x}\",\"query_sha256\":\"{}\",\"proof_sha256\":\"{:x}\",\"transcript_sha256\":\"{}\",\"rng_tail\":{},\"spent\":{},\"proof_bytes\":{},\"source_certificates\":{},\"masked_ladders\":{},\"commit_s\":{},\"prove_s\":{},\"serialization_s\":{},\"decode_s\":{},\"verify_s\":{},\"verified\":true,\"full_query_aggregation\":false,\"whole_security_matched\":false,\"complete_pbs\":false}}",
        field,
        mode,
        logical,
        physical,
        width,
        count,
        queries_count,
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
    assert!(
        args.len() == 5 || args.len() == 7,
        "field independent|joint logical_vars physical_vars batch_size [queries retained|transient]"
    );
    let queries_count = args.get(5).map_or(1, |v| v.parse().unwrap());
    let transient = match args.get(6).map(String::as_str).unwrap_or("retained") {
        "retained" => false,
        "transient" => true,
        _ => panic!("cache policy must be retained or transient"),
    };
    let logical = args[2].parse().unwrap();
    let physical = args[3].parse().unwrap();
    let count = args[4].parse().unwrap();
    match args[0].as_str() {
        "babybear" => run::<algebra::BabyBear, algebra::BabyBearExtension6>(
            &args[0],
            &args[1],
            8,
            logical,
            physical,
            count,
            queries_count,
            transient,
        ),
        "goldilocks" => run::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            &args[0],
            &args[1],
            4,
            logical,
            physical,
            count,
            queries_count,
            transient,
        ),
        _ => panic!("unknown field"),
    }
}

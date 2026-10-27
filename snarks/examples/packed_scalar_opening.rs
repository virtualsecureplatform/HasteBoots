//! Synthetic ordered-matrix openings; not a PBS or security-matched comparison.
use algebra::{
    AbstractExtensionField, Field, NTTField, PrimeField,
    matrix_weighted::{BroadcastQuery, Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted, multilinear::masked_pipfri::Specification, utils::code::BlockReedSolomonCode,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use snarks::packed_scalar_opening as bridge;
use std::time::Instant;
fn digest<T: Serialize>(value: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap())
    )
}
fn transcript<F: Field + PrimeField>(fixture: &str, query: &str, backend: &str) -> Transcript<F> {
    let mut t = Transcript::new_direct();
    t.append_message(b"ordered matrix benchmark v1", &(fixture, query, backend));
    t
}
fn run<B, EF>(field: &str, backend: &str, n: usize, fri_queries: usize)
where
    B: NTTField + PrimeField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<B> + Serialize + DeserializeOwned,
{
    assert!((1..=18).contains(&n));
    assert!(fri_queries > 0);
    let k = 8;
    let table = PackedTable::new(
        n,
        k,
        (0..k << n)
            .map(|i| B::from((17 * i + 11) % 100003))
            .collect(),
    )
    .unwrap();
    let fixture_sha256 = digest(&table);
    let mut rng = StdRng::seed_from_u64(9879);
    let mut batches = Vec::new();
    for count in [1, 4, 16] {
        let queries = (0..count)
            .map(|_| BroadcastQuery {
                query: (0..n)
                    .map(|_| {
                        let mut matrix = || {
                            Matrix::new(k, (0..k * k).map(|_| B::random(&mut rng)).collect())
                                .unwrap()
                        };
                        MatrixPair {
                            zero: matrix(),
                            one: matrix(),
                        }
                    })
                    .collect(),
                post_matrix: None,
            })
            .collect::<Vec<_>>();
        let timer = Instant::now();
        let values = queries
            .iter()
            .map(|q| table.evaluate(&q.query).unwrap())
            .collect::<Vec<_>>();
        let claim_ns = timer.elapsed().as_nanos();
        let query_sha256 = digest(&(
            queries.iter().map(|q| &q.query).collect::<Vec<_>>(),
            &values,
        ));
        batches.push((queries, values, claim_ns, query_sha256));
    }
    if backend == "bridge" {
        let pp = bridge::setup::<B, EF, Sha256>(
            n,
            k,
            &Specification::new(14, 2, fri_queries, 4).unwrap(),
        )
        .unwrap();
        let timer = Instant::now();
        let (root, state) = bridge::commit::<B, EF, Sha256>(&pp, &table).unwrap();
        let commit_ns = timer.elapsed().as_nanos();
        for (iteration, (queries, values, claim_ns, query_sha256)) in
            batches.into_iter().enumerate()
        {
            let mut t = Transcript::<EF>::new_direct_extension::<B>();
            t.append_message(
                b"ordered matrix benchmark v1",
                &(&fixture_sha256, &query_sha256, backend),
            );
            let timer = Instant::now();
            let proof = bridge::prove::<B, EF, Sha256>(
                &mut t, &pp, &root, &state, &table, &queries, &values,
            )
            .unwrap();
            let prove_ns = timer.elapsed().as_nanos();
            let timer = Instant::now();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let serialization_ns = timer.elapsed().as_nanos();
            let (proof, used): (bridge::Proof<EF, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut v = Transcript::<EF>::new_direct_extension::<B>();
            v.append_message(
                b"ordered matrix benchmark v1",
                &(&fixture_sha256, &query_sha256, backend),
            );
            let timer = Instant::now();
            bridge::verify::<B, EF, Sha256>(&mut v, &pp, &root, &queries, &values, &proof).unwrap();
            let verify_ns = timer.elapsed().as_nanos();
            assert_eq!(t.get_challenge(b"after"), v.get_challenge(b"after"));
            assert_eq!(proof.opening.opening_index, iteration);
            assert_eq!(state.remaining_openings().unwrap(), 3 - iteration);
            report(
                field,
                backend,
                n,
                k,
                fri_queries,
                iteration,
                queries.len(),
                &fixture_sha256,
                &query_sha256,
                commit_ns,
                claim_ns,
                prove_ns,
                serialization_ns,
                verify_ns,
                bytes.len(),
                &root.root,
            );
        }
    } else {
        assert_eq!(backend, "brakedown");
        let pp = matrix_weighted::Parameters::<BlockReedSolomonCode<B>>::balanced_block_rs(
            n,
            k,
            fri_queries,
            2,
        )
        .unwrap();
        let timer = Instant::now();
        let (root, state) = pp.commit::<B, Sha256>(&table).unwrap();
        let commit_ns = timer.elapsed().as_nanos();
        for (iteration, (queries, values, claim_ns, query_sha256)) in
            batches.into_iter().enumerate()
        {
            let queries = queries.into_iter().map(|q| q.query).collect::<Vec<_>>();
            let mut t = transcript::<B>(&fixture_sha256, &query_sha256, backend);
            let timer = Instant::now();
            let proof = pp
                .open_many::<B, Sha256>(&mut t, &root, &state, &queries, &values)
                .unwrap();
            let prove_ns = timer.elapsed().as_nanos();
            let timer = Instant::now();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let serialization_ns = timer.elapsed().as_nanos();
            let (proof, used): (matrix_weighted::BatchOpening<B, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut v = transcript::<B>(&fixture_sha256, &query_sha256, backend);
            let timer = Instant::now();
            pp.verify_many::<B, Sha256>(&mut v, &root, &queries, &values, &proof)
                .unwrap();
            let verify_ns = timer.elapsed().as_nanos();
            assert_eq!(t.get_challenge(b"after"), v.get_challenge(b"after"));
            report(
                field,
                backend,
                n,
                k,
                fri_queries,
                iteration,
                queries.len(),
                &fixture_sha256,
                &query_sha256,
                commit_ns,
                claim_ns,
                prove_ns,
                serialization_ns,
                verify_ns,
                bytes.len(),
                &root.root,
            );
        }
    }
}
fn report(
    field: &str,
    backend: &str,
    cell_vars: usize,
    width: usize,
    oracle_queries: usize,
    iteration: usize,
    query_count: usize,
    fixture_sha256: &str,
    query_sha256: &str,
    commit_ns: u128,
    claim_ns: u128,
    prove_ns: u128,
    serialization_ns: u128,
    verify_ns: u128,
    proof_bytes: usize,
    root: &[u8; 32],
) {
    let source_root = root.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let (fragment_vars, opening_budget, opening_index, remaining_openings) = if backend == "bridge"
    {
        (
            "14",
            "4",
            iteration.to_string(),
            (3 - iteration).to_string(),
        )
    } else {
        ("null", "null", "null".to_string(), "null".to_string())
    };
    println!(
        "{{\"workload\":\"synthetic-independent-dense-ordered-matrices\",\"security\":\"experimental-unbudgeted\",\"field\":\"{field}\",\"backend\":\"{backend}\",\"cell_vars\":{cell_vars},\"width\":{width},\"oracle_queries\":{oracle_queries},\"blowup\":2,\"fragment_vars\":{fragment_vars},\"opening_budget\":{opening_budget},\"opening_index\":{opening_index},\"remaining_openings\":{remaining_openings},\"source_root\":\"{source_root}\",\"iteration\":{iteration},\"query_count\":{query_count},\"fixture_sha256\":\"{fixture_sha256}\",\"query_sha256\":\"{query_sha256}\",\"commit_ns\":{commit_ns},\"claim_ns\":{claim_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"verify_ns\":{verify_ns},\"proof_bytes\":{proof_bytes},\"verified\":true,\"threads\":{}}}",
        rayon::current_num_threads()
    );
}
fn main() {
    let a = std::env::args().collect::<Vec<_>>();
    assert_eq!(
        a.len(),
        5,
        "usage: packed_scalar_opening babybear|goldilocks bridge|brakedown cell_vars oracle_queries"
    );
    let n = a[3].parse().unwrap();
    let q = a[4].parse().unwrap();
    match a[1].as_str() {
        "babybear" => run::<algebra::BabyBear, algebra::BabyBearExtension5>(&a[1], &a[2], n, q),
        "goldilocks" => {
            run::<algebra::Goldilocks, algebra::GoldilocksExtension5>(&a[1], &a[2], n, q)
        }
        _ => panic!("unknown field"),
    }
}

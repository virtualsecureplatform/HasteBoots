//! Experimental arithmetic comparison, not a security-matched PBS benchmark.
//! Run with 16 pinned workers; one warm pair and ten alternating measured pairs.
use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::polyfrim::{Parameters, Proof},
    utils::hash::Digest512,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha512;
use std::time::Instant;

fn run<F, E>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let vars = 12;
    let pp = Parameters::<F, E>::new(vars, width, 2, 8)
        .unwrap()
        .with_parallel_oracles();
    let reference = pp.clone().with_extension_storage_reference();
    assert_eq!(
        pp.context_digest::<Sha512>(),
        reference.context_digest::<Sha512>()
    );
    let mut coins = Transcript::<F>::new_classical(&[61; 64]);
    let table = PackedTable::new(
        vars,
        width,
        coins.get_vec_challenge(b"profile source", width << vars),
    )
    .unwrap();
    let (root, state) = pp.commit::<Sha512>(&table).unwrap();
    let (old_root, old_state) = reference.commit::<Sha512>(&table).unwrap();
    assert_eq!(root.root, old_root.root);
    let commit = |base: bool| {
        let start = Instant::now();
        let (candidate, retained) = if base {
            pp.commit::<Sha512>(&table)
        } else {
            reference.commit::<Sha512>(&table)
        }
        .unwrap();
        let seconds = start.elapsed().as_secs_f64();
        assert_eq!(candidate.root, root.root);
        assert_eq!(
            retained.cached_codeword_elements(),
            state.cached_codeword_elements()
        );
        seconds
    };
    // The retained source commitments above are the one warm commit pair.
    let mut base_commit = Vec::new();
    let mut extension_commit = Vec::new();
    for i in 0..10 {
        for base in if i % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let seconds = commit(base);
            if base {
                base_commit.push(seconds);
            } else {
                extension_commit.push(seconds);
            }
        }
    }
    println!(
        "{{\"scope\":\"experimental PCS arithmetic; unqualified security\",\"phase\":\"commit\",\"prime\":\"{}\",\"vars\":{vars},\"width\":{width},\"blowup\":2,\"queries\":8,\"base_payload_bytes\":{},\"extension_payload_bytes\":{},\"base_seconds\":{base_commit:?},\"extension_seconds\":{extension_commit:?}}}",
        F::MODULUS_VALUE,
        state.cached_codeword_bytes(),
        old_state.cached_codeword_bytes()
    );
    for count in [1, 4, 16] {
        let mut queries: Vec<Vec<_>> = (0..count)
            .map(|_| {
                (0..vars)
                    .map(|_| {
                        let v =
                            coins.get_vec_challenge(b"dense profile matrices", 2 * width * width);
                        MatrixPair {
                            zero: Matrix::new(width, v[..width * width].to_vec()).unwrap(),
                            one: Matrix::new(width, v[width * width..].to_vec()).unwrap(),
                        }
                    })
                    .collect()
            })
            .collect();
        // Mix shared complete prefixes, shared shorter prefixes and distinct
        // queries. Matrices keep their original noncommutative order.
        for i in 1..count {
            let prefix = match i % 4 {
                0 | 1 => vars - 1,
                2 => vars / 2,
                _ => 0,
            };
            for j in 0..prefix {
                queries[i][j] = queries[0][j].clone();
            }
        }
        let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
        let open = |base: bool| {
            let mut trans = Transcript::<F>::new_classical(&[62; 64]);
            let start = Instant::now();
            let proof = if base {
                pp.open_many::<Sha512>(&mut trans, &root, &state, &queries, &values)
            } else {
                reference.open_many::<Sha512>(&mut trans, &old_root, &old_state, &queries, &values)
            }
            .unwrap();
            let seconds = start.elapsed().as_secs_f64();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (decoded, used): (Proof<E, Digest512>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut verifier = Transcript::<F>::new_classical(&[62; 64]);
            pp.verify_many::<Sha512>(&mut verifier, &root, &queries, &values, &decoded)
                .unwrap();
            let mut a = [0; 32];
            let mut b = [0; 32];
            trans.get_challenge_bytes(b"profile continuation", &mut a);
            verifier.get_challenge_bytes(b"profile continuation", &mut b);
            assert_eq!(a, b);
            (seconds, bytes)
        };
        let (_, expected) = open(false);
        assert_eq!(open(true).1, expected);
        let mut base_times = Vec::new();
        let mut extension_times = Vec::new();
        for i in 0..10 {
            for base in if i % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let (seconds, bytes) = open(base);
                assert_eq!(bytes, expected);
                if base {
                    base_times.push(seconds);
                } else {
                    extension_times.push(seconds);
                }
            }
        }
        println!(
            "{{\"scope\":\"experimental PCS arithmetic; unqualified security\",\"phase\":\"open\",\"prime\":\"{}\",\"vars\":{vars},\"width\":{width},\"blowup\":2,\"queries\":8,\"batch\":{count},\"proof_bytes\":{},\"base_seconds\":{base_times:?},\"extension_seconds\":{extension_times:?}}}",
            F::MODULUS_VALUE,
            expected.len()
        );
    }
}
fn main() {
    assert_eq!(rayon::current_num_threads(), 16, "set RAYON_NUM_THREADS=16");
    run::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
    run::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

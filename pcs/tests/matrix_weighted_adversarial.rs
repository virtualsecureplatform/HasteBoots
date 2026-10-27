//! Fresh malicious openings: genuine roots/paths and the requested transcript.
use algebra::{NTTField, matrix_weighted::{Matrix, MatrixPair}};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::{Column, Commitment, Opening, Parameters},
          utils::{code::{BlockReedSolomonCode, RowCode}, hash::Hash, merkle_tree::MerkleTree}};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

fn leaf<F: Serialize>(values: &[F]) -> [u8; 32] {
    let mut hash = <Sha256 as Hash>::new();
    hash.update_hash_value(b"HasteBoots/mw-column/v1");
    hash.update_hash_value(&bincode::serde::encode_to_vec(values, bincode::config::standard()).unwrap());
    hash.output_reset()
}

fn attack<F: NTTField + Serialize + DeserializeOwned>(k: usize) {
    let n = 1+k.ilog2() as usize;
    let left = 1;
    let columns = k;
    let queries = 128;
    let code = BlockReedSolomonCode::<F>::new(columns, k, 2).unwrap();
    let length = code.codeword_blocks();
    assert_eq!(code.message_blocks(), 1);
    assert_eq!(length, 32);
    let pp = Parameters::new_encoded::<F>(n, k, left, queries, code).unwrap();
    let rows = 2*k;
    // Control, far word with zero structured query, coded word with false value.
    for mode in 0..3 {
        let values: Vec<Vec<F>> = (0..length).map(|j| {
            let mut value = vec![F::zero(); rows*k];
            if mode == 1 && j < length/2 { value[0] = F::one(); }
            value
        }).collect();
        // A degree-zero RS row is constant. A half-zero/half-one row has
        // distance 16, beyond floor((D-1)/3)=10, even over the symbol field.
        let mut tree = MerkleTree::<Sha256>::new();
        tree.generate(&values.iter().map(|v| leaf(v)).collect::<Vec<_>>());
        let root = Commitment { root: tree.root };
        let zero = Matrix::new(k, vec![F::zero(); k*k]).unwrap();
        let query: Vec<_> = (0..n).map(|_| MatrixPair {
            zero: if mode == 1 { zero.clone() } else { Matrix::identity(k).unwrap() },
            one: zero.clone(),
        }).collect();
        let mut value = vec![F::zero(); k];
        let test = vec![F::zero(); k*columns];
        let mut evaluation = test.clone();
        if mode == 2 {
            value[0] = F::one();
            evaluation[0] = F::one();
        }
        let mut prover = Transcript::<F>::new_direct();
        prover.append_message(b"mw brakedown row-code v2", &pp.context_digest::<F, Sha256>().unwrap());
        prover.append_message(b"mw commitment and query", &(&root, query.as_slice(), value.as_slice()));
        let random = prover.get_vec_challenge(b"mw random linear test", k*rows);
        if mode == 1 {
            assert!((0..k).any(|a| random[a*rows] != F::zero()));
            // Every structured coefficient is zero; only the random test
            // can catch this malformed committed word with these responses.
            assert!(query.iter().all(|p| p.zero == zero && p.one == zero));
        }
        prover.append_message(b"mw linear responses", &(&test, &evaluation));
        let mut indices = Vec::new();
        let limit = (u64::MAX as u128 / length as u128)*length as u128;
        for _ in 0..queries {
            loop {
                let mut bytes = [0u8; 8];
                prover.get_challenge_bytes(b"mw unbiased column", &mut bytes);
                let draw = u64::from_le_bytes(bytes) as u128;
                if draw < limit {
                    indices.push((draw % length as u128) as usize);
                    break;
                }
            }
        }
        indices.sort_unstable();
        indices.dedup();
        if mode == 1 { assert!(indices.iter().any(|&j| j < length/2)); }
        let proof = Opening {
            test, evaluation,
            columns: indices.iter().map(|&j| Column { values: values[j].clone(), path: tree.query(j) }).collect(),
        };
        // Authenticate each actual adversarial column separately before testing
        // the verifier, so a path/root replay failure cannot explain rejection.
        for (column, &j) in proof.columns.iter().zip(&indices) {
            assert_eq!(column.path[0], leaf(&column.values));
            assert!(MerkleTree::<Sha256>::check(&root.root, j, &column.path));
        }
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Opening<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::<F>::new_direct();
        let result = pp.verify::<F, Sha256>(&mut verifier, &root, &query, &value, &proof);
        assert_eq!(prover.get_challenge(b"after malicious opening"), verifier.get_challenge(b"after malicious opening"));
        if mode == 0 { result.unwrap(); }
        else { assert_eq!(result.unwrap_err().0, "linear response inconsistent with committed block"); }
    }
}

#[test]
fn babybear_genuine_bad_words_and_false_claims_fail_equations() {
    attack::<algebra::BabyBear>(8);
}

#[test]
fn goldilocks_genuine_bad_words_and_false_claims_fail_equations() {
    attack::<algebra::Goldilocks>(4);
}

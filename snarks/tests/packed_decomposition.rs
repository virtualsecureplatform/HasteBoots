use algebra::{BabyBear, Goldilocks, NTTField, PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_decomposition::{self, Config, Proof},
    packed_oracle::ProverOracle,
};
fn roundtrip<F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>>() {
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let values = [0, 1, p - 1, p - 2, 12345, 256, 65536];
    let length = values.len();
    let config = Config::new::<F>(8, length, 2).unwrap();
    let d = config.num_digits::<F>().unwrap();
    let mut tables = vec![
        PackedTable::new(
            1,
            4,
            values
                .iter()
                .copied()
                .chain(std::iter::once(0))
                .map(|v| F::new(usize::try_from(v).unwrap().try_into().ok().unwrap()))
                .collect(),
        )
        .unwrap(),
    ];
    for i in 0..d {
        tables.push(
            PackedTable::new(
                1,
                4,
                values
                    .iter()
                    .map(|v| F::from(((v >> (8 * i)) & 255) as usize))
                    .chain(std::iter::once(F::from(0)))
                    .collect(),
            )
            .unwrap(),
        );
    }
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, 4, 32, 2).unwrap();
    let (commitments, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let oracles: Vec<_> = tables
        .iter()
        .zip(&commitments)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: &pp,
            table,
            commitment,
            state,
        })
        .collect();
    let digits: Vec<_> = oracles[1..].iter().collect();
    let mut prover = Transcript::new();
    let proof =
        packed_decomposition::prove::<F, Sha256, _>(&mut prover, &config, &oracles[0], &digits)
            .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let public: Vec<_> = oracles[1..].iter().map(|s| s.verifier()).collect();
    let mut verifier = Transcript::new();
    packed_decomposition::verify::<F, Sha256, _>(
        &mut verifier,
        &config,
        &oracles[0].verifier(),
        &public,
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(3, 4, 32, 2).unwrap();
    let mut lane_prover = Transcript::new();
    let lane_proof = packed_decomposition::prove_lanes::<F, Sha256, _>(
        &mut lane_prover,
        &config,
        &oracles[0],
        &helper,
        &digits,
    )
    .unwrap();
    let encoded = bincode::serde::encode_to_vec(&lane_proof, bincode::config::standard()).unwrap();
    let (lane_proof, used): (packed_decomposition::LaneProof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
    assert_eq!(used, encoded.len());
    let mut lane_verifier = Transcript::new();
    packed_decomposition::verify_lanes::<F, Sha256, _>(
        &mut lane_verifier,
        &config,
        &oracles[0].verifier(),
        &helper,
        &public,
        &lane_proof,
    )
    .unwrap();
    assert_eq!(
        lane_prover.get_challenge(b"after"),
        lane_verifier.get_challenge(b"after")
    );
    assert_eq!(lane_proof.comparisons[0].groups.len(), 1);
    let mut bad = lane_proof.clone();
    bad.borrow_commitments[d].root[0] ^= 1;
    assert!(
        packed_decomposition::verify_lanes::<F, Sha256, _>(
            &mut Transcript::new(),
            &config,
            &oracles[0].verifier(),
            &helper,
            &public,
            &bad
        )
        .is_err()
    );
    let wrong = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(3, 4, 33, 2).unwrap();
    assert!(
        packed_decomposition::verify_lanes::<F, Sha256, _>(
            &mut Transcript::new(),
            &config,
            &oracles[0].verifier(),
            &wrong,
            &public,
            &lane_proof
        )
        .is_err()
    );
    let reject = |bad: &Proof<F, [u8; 32]>| {
        packed_decomposition::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &config,
            &oracles[0].verifier(),
            &public,
            bad,
        )
        .is_err()
    };
    let mut bad = proof.clone();
    bad.borrow_commitments[0].root[0] ^= 1;
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.borrow_commitments[d].root[0] ^= 1;
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.borrow_commitments.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.comparisons.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.linear.values[0][0] += F::from(1);
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.comparisons[0].source_openings[0].columns.clear();
    assert!(reject(&bad));
    let changed = Config::new::<F>(8, length - 1, 2).unwrap();
    assert!(
        packed_decomposition::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &changed,
            &oracles[0].verifier(),
            &public,
            &proof
        )
        .is_err()
    );
}
#[test]
fn canonical_radix_decomposition_boundaries_babybear_and_goldilocks() {
    roundtrip::<BabyBear>();
    roundtrip::<Goldilocks>();
}
#[test]
fn modulo_equality_does_not_allow_noncanonical_integer_digits() {
    type F = BabyBear;
    let p = 2013265921u128;
    let config = Config::new::<F>(8, 4, 2).unwrap();
    let d = config.num_digits::<F>().unwrap();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, 2, 32, 2).unwrap();
    for value in [p, p + 1] {
        let mut tables =
            vec![PackedTable::new(1, 2, vec![F::from((value - p) as usize); 4]).unwrap()];
        for i in 0..d {
            tables.push(
                PackedTable::new(1, 2, vec![F::from(((value >> (8 * i)) & 255) as usize); 4])
                    .unwrap(),
            );
        }
        let (commitments, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .map(|t| pp.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let oracles: Vec<_> = tables
            .iter()
            .zip(&commitments)
            .zip(&states)
            .map(|((table, commitment), state)| ProverOracle {
                parameters: &pp,
                table,
                commitment,
                state,
            })
            .collect();
        assert!(
            packed_decomposition::prove::<F, Sha256, _>(
                &mut Transcript::new(),
                &config,
                &oracles[0],
                &oracles[1..].iter().collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    assert!(Config::new::<F>(0, 4, 2).is_err());
    assert!(Config::new::<F>(31, 4, 2).is_err());
}

#[test]
fn valid_comparison_for_another_borrow_root_cannot_bypass_canonicity() {
    use algebra::Field;
    use num_traits::One;
    use snarks::{
        packed_linear::{self, Relation},
        packed_tuple_lookup,
    };
    type F = BabyBear;
    let p = 2013265921usize;
    let config = Config::new::<F>(8, 4, 1).unwrap();
    let d = config.num_digits::<F>().unwrap();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, 2, 32, 2).unwrap();
    // x=0, but the digits represent p. The true subtraction borrow exits as 1.
    let mut tables = vec![PackedTable::new(1, 2, vec![F::from(0); 4]).unwrap()];
    for i in 0..d {
        tables.push(PackedTable::new(1, 2, vec![F::from((p >> (8 * i)) & 255); 4]).unwrap());
    }
    for i in 0..=d {
        tables.push(PackedTable::new(1, 2, vec![F::from(usize::from(i > 0 && i < d)); 4]).unwrap());
    }
    tables.push(PackedTable::new(1, 2, vec![F::from(1); 4]).unwrap()); // alternative last borrow
    let (commitments, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let oracles: Vec<_> = tables
        .iter()
        .zip(&commitments)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: &pp,
            table,
            commitment,
            state,
        })
        .collect();
    let public_digits: Vec<_> = oracles[1..d + 1].iter().map(|s| s.verifier()).collect();
    let contexts = oracles[..d + 1]
        .iter()
        .map(|s| {
            (
                s.parameters.context_digest::<F, Sha256>().unwrap(),
                s.commitment,
            )
        })
        .collect::<Vec<_>>();
    let borrows = commitments[d + 1..2 * d + 2].to_vec();
    let mut prover = Transcript::new();
    let mut verifier = Transcript::new();
    for trans in [&mut prover, &mut verifier] {
        trans.append_message(
            b"packed canonical radix decomposition v1",
            &(&config, F::MODULUS_VALUE.to_string(), &contexts),
        );
        trans.append_message(b"packed decomposition borrow roots", &borrows);
    }
    let mut terms = vec![(-F::one(), 0)];
    let mut power = F::one();
    for i in 0..d {
        terms.push((power, i + 1));
        power *= F::from(256);
    }
    let relations = vec![
        Relation { terms },
        Relation {
            terms: vec![(F::one(), d + 1)],
        },
        Relation {
            terms: vec![(F::one(), 2 * d + 1)],
        },
    ];
    // Reconstruction modulo p and both declared-zero endpoints are genuinely valid.
    let linear = packed_linear::prove::<F, Sha256, _>(
        &mut prover,
        &oracles[..2 * d + 2].iter().collect::<Vec<_>>(),
        &relations,
    )
    .unwrap();
    packed_linear::verify::<F, Sha256, _>(
        &mut verifier,
        &oracles[..2 * d + 2]
            .iter()
            .map(|s| s.verifier())
            .collect::<Vec<_>>(),
        &relations,
        &linear,
    )
    .unwrap();
    let mut comparisons = Vec::new();
    for i in 0..d {
        let lookup =
            packed_tuple_lookup::Config::new(4, config.comparison_table::<F>(i).unwrap(), 1)
                .unwrap();
        let end = if i + 1 == d { 2 * d + 2 } else { d + 2 + i };
        let columns = [&oracles[i + 1], &oracles[d + 1 + i], &oracles[end]];
        let comparison =
            packed_tuple_lookup::prove::<F, Sha256, _>(&mut prover, &lookup, &columns).unwrap();
        // Each supplied comparison is a valid proof, but the final one refers
        // to borrow=1 while the enclosing decomposition declares borrow=0.
        packed_tuple_lookup::verify::<F, Sha256, _>(
            &mut verifier,
            &lookup,
            &columns.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
            &comparison,
        )
        .unwrap();
        comparisons.push(comparison);
    }
    let forged = Proof {
        borrow_commitments: borrows,
        linear,
        comparisons,
    };
    assert!(
        packed_decomposition::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &config,
            &oracles[0].verifier(),
            &public_digits,
            &forged
        )
        .is_err()
    );
}

// Check the semantic link between canonical tuple constraints and the native
// field decomposition used by blind rotation and final negative-a key switching.
fn canonical_native_contract<F: NTTField>() {
    use algebra::{Basis, Polynomial};
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    for bits in [5u32, 8] {
        let config = Config::new::<F>(bits, 1, 1).unwrap();
        let count = config.num_digits::<F>().unwrap();
        let radix = 1u128 << bits;
        let space = 1u128 << (bits as usize * count);
        let tables: Vec<_> = (0..count)
            .map(|i| config.comparison_table::<F>(i).unwrap())
            .collect();
        for integer in [0, 1, p - 2, p - 1, p, p + 1, space - 1] {
            let mut borrow = 0usize;
            let mut reconstructed = F::zero();
            let mut power = F::one();
            for (i, table) in tables.iter().enumerate() {
                let digit = ((integer >> (bits as usize * i)) & (radix - 1)) as usize;
                let matching: Vec<_> = table
                    .iter()
                    .filter(|row| row[0] == F::from(digit) && row[1] == F::from(borrow))
                    .collect();
                assert_eq!(matching.len(), 1);
                assert!(matching[0][2] == F::zero() || matching[0][2] == F::one());
                borrow = usize::from(matching[0][2] == F::one());
                reconstructed += F::from(digit) * power;
                power *= F::from(radix as usize);
            }
            assert_eq!(reconstructed, F::from((integer % p) as usize));
            assert_eq!(borrow == 0, integer < p);
            // Thus field reconstruction alone also accepts noncanonical
            // aliases p and p+1, while the actual transition tables reject them.
        }
        let mut inputs = Vec::new();
        let mut integers = Vec::new();
        for x in [0, 1, 2, radix - 1, radix, radix + 1, p - 2, p - 1] {
            let value = F::from(x as usize);
            inputs.extend([value, -value]);
            integers.extend([x, if x == 0 { 0 } else { p - x }]);
        }
        let mut polynomial = Polynomial::new(inputs);
        let basis = Basis::<F>::new(bits);
        assert_eq!(basis.decompose_len(), count);
        let mut digit = vec![F::zero(); integers.len()];
        for i in 0..count {
            polynomial.decompose_lsb_bits_inplace(basis, &mut digit);
            for (&actual, &integer) in digit.iter().zip(&integers) {
                let expected = (integer >> (bits as usize * i)) & (radix - 1);
                assert_eq!(actual, F::from(expected as usize));
            }
        }
        assert!(
            polynomial
                .as_slice()
                .iter()
                .all(|&value| value == F::zero())
        );
    }
}

#[test]
fn babybear_canonical_native_contract() {
    canonical_native_contract::<BabyBear>();
}
#[test]
fn goldilocks_canonical_native_contract() {
    canonical_native_contract::<Goldilocks>();
}

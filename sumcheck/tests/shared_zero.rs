use algebra::{NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use serde::{Serialize, de::DeserializeOwned};
use sumcheck::{packed::PackedShape, packed_zero::batch};

fn exercise<F: NTTField + Serialize + DeserializeOwned>(k: usize) {
    for n in [1, 4] {
        for count in [1, 4, 16] {
            let mut shapes = Vec::new();
            let mut factors = Vec::new();
            for instance in 0..count {
                let power = 1 + instance % 3;
                let coefficient = F::from(instance + 1);
                let a: Vec<_> = (0..(1 << n) * k)
                    .map(|i| F::from(1 + (i + instance) % 11))
                    .collect();
                let b: Vec<_> = (0..a.len())
                    .map(|i| F::from(2 + (i * 7 + instance) % 17))
                    .collect();
                let c = a
                    .iter()
                    .zip(&b)
                    .map(|(&a, &b)| (0..power).fold(coefficient, |v, _| v * a) * b)
                    .collect();
                let mut product = vec![0; power];
                product.push(1);
                shapes.push(PackedShape {
                    num_vars: n,
                    width: k,
                    num_factors: 3,
                    terms: vec![(coefficient, product), (-F::one(), vec![2])],
                });
                factors.push(vec![
                    PackedTable::new(n, k, a).unwrap(),
                    PackedTable::new(n, k, b).unwrap(),
                    PackedTable::new(n, k, c).unwrap(),
                ]);
            }
            let refs: Vec<_> = factors.iter().map(Vec::as_slice).collect();
            let mut prover = Transcript::new_direct();
            let (proof, claims, values) = batch::prove(&mut prover, &shapes, &refs).unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (batch::Proof<F>, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let check =
                |trans: &mut Transcript<F>, shapes: &[PackedShape<F>], proof: &batch::Proof<F>| {
                    let claims = batch::verify(trans, shapes, proof)?;
                    for ((shape, tables), claim) in shapes.iter().zip(&factors).zip(&claims) {
                        let values = tables
                            .iter()
                            .map(|t| t.evaluate(&claim.query).unwrap())
                            .collect::<Vec<_>>();
                        claim.check(shape, &values)?;
                    }
                    Ok::<_, sumcheck::error::Error>(claims)
                };
            let mut verifier = Transcript::new_direct();
            let verified = check(&mut verifier, &shapes, &proof).unwrap();
            for i in 0..count {
                assert_eq!(verified[i].query, verified[0].query);
                assert_eq!(verified[i].query.len(), n);
                assert_eq!(verified[i].query, claims[i].query);
                assert_eq!(verified[i].expected, claims[i].expected);
                assert_eq!(verified[i].equality, claims[i].equality);
                for (table, value) in factors[i].iter().zip(&values[i]) {
                    assert_eq!(table.evaluate(&verified[i].query).unwrap(), *value);
                }
            }
            assert_eq!(
                prover.get_challenge(b"after shared zero"),
                verifier.get_challenge(b"after shared zero")
            );
            let reject = |shapes: &[_], proof: &_| {
                assert!(check(&mut Transcript::new_direct(), shapes, proof).is_err())
            };
            let mut bad = proof.clone();
            bad.instances.pop();
            reject(&shapes, &bad);
            let mut bad = proof.clone();
            bad.instances[0].first.pop();
            reject(&shapes, &bad);
            let mut bad = proof.clone();
            bad.instances[0].first[0].pop();
            reject(&shapes, &bad);
            let mut bad = proof.clone();
            bad.instances[0].first[0][0] += F::one();
            reject(&shapes, &bad);
            let mut wrong = shapes.clone();
            wrong[0].terms[0].0 += F::one();
            reject(&wrong, &proof);
            if n > 1 {
                let mut bad = proof.clone();
                bad.instances[0].rest.rounds.pop();
                reject(&shapes, &bad);
                let mut bad = proof.clone();
                bad.instances[0].rest.rounds[0].pop();
                reject(&shapes, &bad);
                let mut bad = proof.clone();
                bad.instances[0].rest.rounds[0][0] += F::one();
                reject(&shapes, &bad);
            }
            if count > 1 {
                let mut bad = proof.clone();
                bad.instances.swap(0, 1);
                reject(&shapes, &bad);
            }
            assert!(
                batch::prove(&mut Transcript::new_direct(), &shapes, &refs[..count - 1]).is_err()
            );
            if count > 1 {
                let mut wrong = shapes.clone();
                wrong[1].width += 1;
                assert!(batch::verify(&mut Transcript::new_direct(), &wrong, &proof).is_err());
            }
            assert!(batch::verify(&mut Transcript::new_direct(), &[], &proof).is_err());
        }
    }
}
#[test]
fn babybear_shared_zero() {
    exercise::<algebra::BabyBear>(8);
    exercise::<algebra::BabyBear>(1);
}
#[test]
fn goldilocks_shared_zero() {
    exercise::<algebra::Goldilocks>(4);
    exercise::<algebra::Goldilocks>(1);
}

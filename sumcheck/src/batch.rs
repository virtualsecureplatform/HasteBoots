//! Independent scalar sumchecks with common round challenges.
//! Bind the ordered source commitments and statements before this component.
//! Every recurrence is checked separately; terminal values still require
//! authentication. This component supplies neither hiding nor a whole proof.
use crate::{
    IPForMLSumcheck,
    error::Error,
    prover::ProverState,
    verifier::{SubClaim, VerifierMsg, interpolate_uni_poly},
};
use algebra::{Field, ListOfProductsOfPolynomials, PolynomialInfo};
use helper::{FiatShamirTranscript, Transcript};
use serde::{Deserialize, Serialize};

/// Ordered independent certificates sharing a terminal evaluation point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field> {
    /// One scalar sumcheck message sequence per caller-derived equation.
    pub instances: Vec<crate::Proof<F>>,
}
fn reject(message: &str) -> Error {
    Error::Reject(Some(message.into()))
}
fn bind<F: Field + Serialize>(
    trans: &mut Transcript<F>,
    infos: &[PolynomialInfo],
    claims: &[F],
) -> Result<(), Error> {
    let first = infos
        .first()
        .ok_or_else(|| reject("empty scalar sumcheck batch"))?;
    if infos.len() != claims.len()
        || first.num_variables == 0
        || infos.iter().any(|i| {
            i.num_variables != first.num_variables
                || i.max_multiplicands == 0
                || i.max_multiplicands.checked_add(1).is_none()
        })
    {
        return Err(reject("scalar sumcheck batch dimensions"));
    }
    for info in infos {
        let mut node = F::zero();
        for _ in 0..info.max_multiplicands {
            node += F::one();
            if node == F::zero() {
                return Err(reject("scalar sumcheck interpolation nodes collide"));
            }
        }
    }
    trans.append_message(b"independent scalar sumcheck batch v1", &(infos, claims));
    Ok(())
}
fn check<F: Field>(messages: &[&crate::prover::ProverMsg<F>], expected: &[F]) -> Result<(), Error> {
    for (message, &claim) in messages.iter().zip(expected) {
        if message.evaluations[0] + message.evaluations[1] != claim {
            return Err(reject("scalar sumcheck individual recurrence"));
        }
    }
    Ok(())
}
fn challenge<F: Field + Serialize>(
    trans: &mut Transcript<F>,
    round: usize,
    messages: &[&crate::prover::ProverMsg<F>],
) -> F {
    trans.append_message(b"scalar batch round messages", &(round, messages));
    trans.get_challenge(b"scalar batch common challenge")
}
/// Prove separate equations with one common evaluation point.
/// For extension fields the caller must configure full-coordinate transcript
/// sampling, e.g. `Transcript::new_direct_extension::<Base>()`.
pub fn prove<F: Field + Serialize>(
    trans: &mut Transcript<F>,
    polynomials: &[&ListOfProductsOfPolynomials<F>],
    claims: &[F],
) -> Result<(Proof<F>, Vec<ProverState<F>>), Error> {
    let infos: Vec<_> = polynomials.iter().map(|p| p.info()).collect();
    bind(trans, &infos, claims)?;
    for p in polynomials {
        let size = u32::try_from(p.num_variables)
            .ok()
            .and_then(|n| 1usize.checked_shl(n))
            .ok_or_else(|| reject("scalar batch variable count"))?;
        if p.products.is_empty()
            || p.products.len() != p.linear_ops.len()
            || p.products
                .iter()
                .zip(&p.linear_ops)
                .any(|((_, indices), ops)| {
                    indices.is_empty()
                        || indices.len() > p.max_multiplicands
                        || indices.len() != ops.len()
                        || indices
                            .iter()
                            .any(|&i| i >= p.flattened_ml_extensions.len())
                })
            || p.flattened_ml_extensions
                .iter()
                .any(|m| m.num_vars != p.num_variables || m.evaluations.len() != size)
        {
            return Err(reject("scalar batch polynomial shape"));
        }
    }
    let mut states: Vec<_> = polynomials
        .iter()
        .map(|p| IPForMLSumcheck::prover_init(p))
        .collect();
    let mut instances: Vec<_> = infos
        .iter()
        .map(|i| Vec::with_capacity(i.num_variables))
        .collect();
    let mut previous = None;
    let mut expected = claims.to_vec();
    for round in 0..infos[0].num_variables {
        let messages: Vec<_> = states
            .iter_mut()
            .map(|s| IPForMLSumcheck::prove_round(s, &previous))
            .collect();
        let references: Vec<_> = messages.iter().collect();
        check(&references, &expected)?;
        let r = challenge(trans, round, &references);
        for ((instance, message), value) in instances.iter_mut().zip(messages).zip(&mut expected) {
            *value = interpolate_uni_poly(&message.evaluations, r);
            instance.push(message);
        }
        previous = Some(VerifierMsg { randomness: r });
    }
    let last = previous.expect("positive variable count").randomness;
    for state in &mut states {
        state.randomness.push(last);
    }
    Ok((Proof { instances }, states))
}
/// Check all independent recurrences and derive unauthenticated terminal claims.
/// The caller supplies trusted ordered polynomial descriptions and sums.
pub fn verify<F: Field + Serialize>(
    trans: &mut Transcript<F>,
    infos: &[PolynomialInfo],
    claims: &[F],
    proof: &Proof<F>,
) -> Result<Vec<SubClaim<F>>, Error> {
    if proof.instances.len() != infos.len()
        || infos.iter().zip(&proof.instances).any(|(info, p)| {
            p.len() != info.num_variables
                || info
                    .max_multiplicands
                    .checked_add(1)
                    .is_none_or(|n| p.iter().any(|m| m.evaluations.len() != n))
        })
    {
        return Err(reject("scalar sumcheck batch proof shape"));
    }
    bind(trans, infos, claims)?;
    let mut expected = claims.to_vec();
    let mut point = Vec::with_capacity(infos[0].num_variables);
    for round in 0..infos[0].num_variables {
        let messages: Vec<_> = proof.instances.iter().map(|p| &p[round]).collect();
        check(&messages, &expected)?;
        let r = challenge(trans, round, &messages);
        for (value, message) in expected.iter_mut().zip(messages) {
            *value = interpolate_uni_poly(&message.evaluations, r);
        }
        point.push(r);
    }
    Ok(expected
        .into_iter()
        .map(|expected_evaluations| SubClaim {
            point: point.clone(),
            expected_evaluations,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{AbstractExtensionField, DenseMultilinearExtension, PrimeField};
    use serde::de::DeserializeOwned;
    use std::rc::Rc;

    fn exercise<B, E>()
    where
        B: PrimeField + Serialize + From<usize>,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        for n in [1, 3] {
            for count in [1, 4, 16] {
                let polys: Vec<_> = (0..count)
                    .map(|i| {
                        let table = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                            n,
                            (0..1 << n)
                                .map(|j| E::from_base_fn(|c| B::from(2 + i + 3 * j + 17 * c)))
                                .collect(),
                        ));
                        let mut p = ListOfProductsOfPolynomials::new(n);
                        let degree = 1 + i % 3;
                        p.add_product_with_linear_op(
                            (0..degree).map(|_| table.clone()),
                            &(0..degree)
                                .map(|j| {
                                    (E::from_base(B::from(j + 1)), E::from_base(B::from(j + 3)))
                                })
                                .collect::<Vec<_>>(),
                            E::from_base(B::from(i + 1)),
                        );
                        p
                    })
                    .collect();
                let sums: Vec<_> = polys
                    .iter()
                    .map(|p| {
                        (0..1 << n)
                            .map(|b| {
                                p.evaluate(
                                    &(0..n)
                                        .map(|j| E::from_base(B::from((b >> j) & 1)))
                                        .collect::<Vec<_>>(),
                                )
                            })
                            .fold(E::zero(), |a, b| a + b)
                    })
                    .collect();
                let infos: Vec<_> = polys.iter().map(|p| p.info()).collect();
                let refs: Vec<_> = polys.iter().collect();
                let mut prover = Transcript::<E>::new_direct_extension::<B>();
                let (proof, states) = prove(&mut prover, &refs, &sums).unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, used): (Proof<E>, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut verifier = Transcript::<E>::new_direct_extension::<B>();
                let claims = verify(&mut verifier, &infos, &sums, &proof).unwrap();
                for ((p, state), claim) in polys.iter().zip(&states).zip(&claims) {
                    assert_eq!(claim.point, claims[0].point);
                    assert_eq!(state.randomness, claim.point);
                    assert_eq!(p.evaluate(&claim.point), claim.expected_evaluations);
                    for (table, &value) in
                        p.flattened_ml_extensions.iter().zip(&state.fast_evaluate())
                    {
                        assert_eq!(table.evaluate(&claim.point), value);
                    }
                }
                assert!(
                    claims[0]
                        .point
                        .iter()
                        .any(|r| r.as_base_slice()[1..].iter().any(|&c| c != B::zero()))
                );
                assert_eq!(
                    prover.get_challenge(b"after scalar batch"),
                    verifier.get_challenge(b"after scalar batch")
                );
                let reject = |infos: &[_], sums: &[_], proof: &_| {
                    assert!(
                        verify(
                            &mut Transcript::<E>::new_direct_extension::<B>(),
                            infos,
                            sums,
                            proof
                        )
                        .is_err()
                    );
                };
                let mut bad = proof.clone();
                bad.instances.pop();
                reject(&infos, &sums, &bad);
                let mut bad = proof.clone();
                bad.instances[0].pop();
                reject(&infos, &sums, &bad);
                let mut bad = proof.clone();
                bad.instances[0][0].evaluations.pop();
                reject(&infos, &sums, &bad);
                let mut bad = proof.clone();
                bad.instances[0][0].evaluations[0] += E::one();
                reject(&infos, &sums, &bad);
                if count > 1 {
                    let mut bad = sums.clone();
                    bad[0] += E::one();
                    bad[1] -= E::one();
                    assert_eq!(
                        bad.iter().copied().fold(E::zero(), |a, b| a + b),
                        sums.iter().copied().fold(E::zero(), |a, b| a + b)
                    );
                    reject(&infos, &bad, &proof);
                    assert!(
                        prove(
                            &mut Transcript::<E>::new_direct_extension::<B>(),
                            &refs,
                            &bad
                        )
                        .is_err()
                    );
                    let mut bad = proof.clone();
                    bad.instances.swap(0, 1);
                    reject(&infos, &sums, &bad);
                }
                reject(&[], &[], &proof);
            }
        }
    }
    #[test]
    fn babybear_extension_shared_scalar_equations() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_extension_shared_scalar_equations() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}

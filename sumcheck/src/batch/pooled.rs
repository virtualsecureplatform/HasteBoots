//! Borrow the first round and fold each immutable source object once. Routes
//! are private ownership metadata; no algebraic claim or wire alias is merged.
use super::*;
use algebra::DenseMultilinearExtension;
use rayon::prelude::*;
use std::{collections::HashMap, rc::Rc};

fn sources<'a, F: Field>(
    polynomials: &[&'a ListOfProductsOfPolynomials<F>],
) -> (Vec<&'a DenseMultilinearExtension<F>>, Vec<Vec<usize>>) {
    let mut seen = HashMap::new();
    let mut tables = Vec::new();
    let routes = polynomials
        .iter()
        .map(|p| {
            p.flattened_ml_extensions
                .iter()
                .map(|table| {
                    *seen.entry(Rc::as_ptr(table)).or_insert_with(|| {
                        let i = tables.len();
                        tables.push(table.as_ref());
                        i
                    })
                })
                .collect()
        })
        .collect();
    (tables, routes)
}
fn message<F: Field>(
    p: &ListOfProductsOfPolynomials<F>,
    route: &[usize],
    tables: &[&DenseMultilinearExtension<F>],
    round: usize,
) -> crate::prover::ProverMsg<F> {
    let degree = p.max_multiplicands;
    let pairs = 1usize << (p.num_variables - round - 1);
    let evaluations = p
        .products
        .par_iter()
        .zip(p.linear_ops.par_iter())
        .map(|((coefficient, products), ops)| {
            let mut sum = vec![F::zero(); degree + 1];
            let mut product = vec![F::zero(); degree + 1];
            for b in 0..pairs {
                product.fill(*coefficient);
                for (&j, &(a, bias)) in products.iter().zip(ops) {
                    let table = tables[route[j]];
                    let left = table.evaluations[2 * b];
                    let difference = table.evaluations[2 * b + 1] - left;
                    let (mut start, step) = if a == F::one() {
                        (left, difference)
                    } else {
                        (left * a, difference * a)
                    };
                    if bias != F::zero() {
                        start += bias;
                    }
                    for value in &mut product {
                        *value *= start;
                        start += step;
                    }
                }
                for (sum, value) in sum.iter_mut().zip(&product) {
                    *sum += *value;
                }
            }
            sum
        })
        .reduce(
            || vec![F::zero(); degree + 1],
            |mut a, b| {
                for (a, b) in a.iter_mut().zip(b) {
                    *a += b;
                }
                a
            },
        );
    crate::prover::ProverMsg { evaluations }
}
pub(super) fn prove<F: Field + Serialize>(
    trans: &mut Transcript<F>,
    polynomials: &[&ListOfProductsOfPolynomials<F>],
    claims: &[F],
    infos: &[PolynomialInfo],
) -> Result<(Proof<F>, Vec<ProverState<F>>), Error> {
    let (original, routes) = sources(polynomials);
    let mut folded: Option<Vec<DenseMultilinearExtension<F>>> = None;
    let mut point = Vec::with_capacity(infos[0].num_variables);
    let mut instances: Vec<_> = infos
        .iter()
        .map(|i| Vec::with_capacity(i.num_variables))
        .collect();
    let mut expected = claims.to_vec();
    for round in 0..infos[0].num_variables {
        if let Some(&r) = point.last() {
            if let Some(tables) = &mut folded {
                tables.par_iter_mut().for_each(|table| {
                    let remaining = table.evaluations.len() / 2;
                    for b in 0..remaining {
                        let left = table.evaluations[2 * b];
                        let right = table.evaluations[2 * b + 1];
                        table.evaluations[b] = left + r * (right - left);
                    }
                    table.evaluations.truncate(remaining);
                    table.num_vars -= 1;
                });
            } else {
                folded = Some(
                    original
                        .par_iter()
                        .map(|table| {
                            DenseMultilinearExtension::from_evaluations_vec(
                                table.num_vars - 1,
                                table
                                    .evaluations
                                    .chunks_exact(2)
                                    .map(|pair| pair[0] + r * (pair[1] - pair[0]))
                                    .collect(),
                            )
                        })
                        .collect(),
                );
            }
        }
        let tables = folded.as_ref().map(|t| t.iter().collect::<Vec<_>>());
        let tables = tables.as_deref().unwrap_or(&original);
        let messages: Vec<_> = polynomials
            .iter()
            .zip(&routes)
            .map(|(p, route)| message(p, route, tables, round))
            .collect();
        let references: Vec<_> = messages.iter().collect();
        check(&references, &expected)?;
        let r = challenge(trans, round, &references);
        point.push(r);
        for ((instance, message), value) in instances.iter_mut().zip(messages).zip(&mut expected) {
            *value = interpolate_uni_poly(&message.evaluations, r);
            instance.push(message);
        }
    }
    let tables = folded.as_ref().map(|t| t.iter().collect::<Vec<_>>());
    let tables = tables.as_deref().unwrap_or(&original);
    // Preserve the existing terminal-state API. Only two entries per source
    // remain here, so copying a shared terminal into each owner is inexpensive.
    let states = polynomials
        .iter()
        .zip(&routes)
        .map(|(p, route)| ProverState {
            randomness: point.clone(),
            list_of_products: p.products.clone(),
            linear_ops: p.linear_ops.clone(),
            flattened_ml_extensions: route.iter().map(|&i| tables[i].clone()).collect(),
            num_vars: p.num_variables,
            max_multiplicands: p.max_multiplicands,
            round: p.num_variables,
        })
        .collect();
    Ok((Proof { instances }, states))
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{AbstractExtensionField, PrimeField};
    fn exercise<
        B: PrimeField + Serialize + From<usize>,
        E: AbstractExtensionField<B> + Serialize,
    >() {
        for n in [1usize, 3] {
            for count in [1usize, 4, 16] {
                let shared = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    n,
                    (0..1 << n)
                        .map(|i| E::from_base_fn(|c| B::from(i + c + 1)))
                        .collect(),
                ));
                let equal = Rc::new(shared.as_ref().clone());
                let polynomials: Vec<_> = (0..count)
                    .map(|i| {
                        let mut p = ListOfProductsOfPolynomials::new(n);
                        let own = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                            n,
                            vec![E::from_base(B::from(i + 3)); 1 << n],
                        ));
                        let h = if i % 2 == 0 { &shared } else { &equal };
                        p.add_product_with_linear_op(
                            [h.clone(), own.clone()],
                            &[
                                (E::one(), E::zero()),
                                (E::from_base(B::from(3)), E::from_base(B::from(2))),
                            ],
                            E::from_base(B::from(i + 1)),
                        );
                        if i % 3 == 0 {
                            p.add_product([h.clone()], E::one());
                        }
                        p
                    })
                    .collect();
                let refs: Vec<_> = polynomials.iter().collect();
                let (tables, routes) = sources(&refs);
                assert_eq!(tables.len(), count + if count == 1 { 1 } else { 2 });
                if count > 1 {
                    assert_ne!(routes[0][0], routes[1][0]);
                }
                if count > 2 {
                    assert_eq!(routes[0][0], routes[2][0]);
                }
                let claims: Vec<_> = polynomials
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
                let mut a = Transcript::<E>::new_direct_extension::<B>();
                let mut b = Transcript::<E>::new_direct_extension::<B>();
                let (new, states) = super::super::prove(&mut a, &refs, &claims).unwrap();
                let (old, reference) =
                    super::super::prove_reference(&mut b, &refs, &claims).unwrap();
                assert_eq!(
                    bincode::serde::encode_to_vec(&new, bincode::config::standard()).unwrap(),
                    bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap()
                );
                assert_eq!(
                    a.get_challenge(b"pooled post-proof"),
                    b.get_challenge(b"pooled post-proof")
                );
                for (state, reference) in states.iter().zip(reference) {
                    assert_eq!(state.randomness, reference.randomness);
                    assert_eq!(state.fast_evaluate(), reference.fast_evaluate());
                    assert!(
                        state
                            .flattened_ml_extensions
                            .iter()
                            .all(|t| t.evaluations.len() == 2)
                    );
                }
            }
        }
    }
    #[test]
    fn pooled_matches_independent_babybear() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn pooled_matches_independent_goldilocks() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}

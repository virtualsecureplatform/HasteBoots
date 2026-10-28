/// Shared-challenge algebra, individual claims and one joint source certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, EF, O> {
    /// Every ordered relation's independently checked algebraic messages.
    pub zero: zero::Proof<F>,
    /// Original factor claims, grouped in caller-derived relation/root order.
    pub values: Vec<Vec<Vec<F>>>,
    /// Joint authentication against the ordered original commitments.
    pub opening: pcs_batch::Proof<F, EF, O>,
}
fn bind<F, EF, H, C>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    parameters: &Parameters<C>,
    roots: &[Vec<Commitment<H::Output>>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash,
    C: RowCode<F> + Serialize,
{
    if shapes.is_empty() || shapes.len() != roots.len() {
        return Err(Error("batch relation/root count".into()));
    }
    for (shape, roots) in shapes.iter().zip(roots) {
        shape.validate().map_err(convert)?;
        if shape.num_vars == 0
            || shape.num_vars != parameters.num_vars()
            || shape.width != parameters.width()
            || shape.num_factors != roots.len()
        {
            return Err(Error("batch relation parameter/root dimensions".into()));
        }
    }
    trans.append_message(
        DOMAIN,
        &(
            shapes,
            parameters.context_digest::<F, H>().map_err(convert)?,
            EF::D,
            roots,
        ),
    );
    Ok(())
}

/// Prove independent equations with shared challenges and joint source checks.
/// The caller supplies canonical factor states; no state is cloned or serialized.
pub fn prove<F, EF, H, C>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    parameters: &Parameters<C>,
    factors: &[&[PackedTable<F>]],
    roots: &[Vec<Commitment<H::Output>>],
    states: &[Vec<&State<F, H>>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, EF, H, C>(trans, shapes, parameters, roots)?;
    if factors.len() != shapes.len()
        || states.len() != shapes.len()
        || states
            .iter()
            .zip(shapes)
            .any(|(s, shape)| s.len() != shape.num_factors)
    {
        return Err(Error("batch relation factor/state count".into()));
    }
    let (zero, claims, values) = zero::prove(trans, shapes, factors).map_err(convert)?;
    for ((shape, claim), values) in shapes.iter().zip(&claims).zip(&values) {
        claim.check(shape, values).map_err(convert)?;
    }
    trans.append_message(b"packed batch relation terminal values", &values);
    let roots: Vec<_> = roots.iter().flatten().cloned().collect();
    let states: Vec<_> = states.iter().flatten().copied().collect();
    let flat_values: Vec<_> = values.iter().flatten().cloned().collect();
    let opening = pcs_batch::prove::<F, EF, H, C>(
        parameters,
        trans,
        &roots,
        &states,
        &claims[0].query,
        &flat_values,
    )
    .map_err(convert)?;
    Ok(Proof {
        zero,
        values,
        opening,
    })
}

/// Verify every independent equation and authenticate all individual root claims.
/// Shapes and grouped roots come from the enclosing trusted statement registry.
pub fn verify<F, EF, H, C>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    parameters: &Parameters<C>,
    roots: &[Vec<Commitment<H::Output>>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, EF, H, C>(trans, shapes, parameters, roots)?;
    if proof.values.len() != shapes.len()
        || proof
            .values
            .iter()
            .zip(shapes)
            .any(|(v, s)| v.len() != s.num_factors || v.iter().any(|v| v.len() != s.width))
    {
        return Err(Error("batch relation terminal dimensions".into()));
    }
    let claims = zero::verify(trans, shapes, &proof.zero).map_err(convert)?;
    for ((shape, claim), values) in shapes.iter().zip(&claims).zip(&proof.values) {
        claim.check(shape, values).map_err(convert)?;
    }
    trans.append_message(b"packed batch relation terminal values", &proof.values);
    let roots: Vec<_> = roots.iter().flatten().cloned().collect();
    let values: Vec<_> = proof.values.iter().flatten().cloned().collect();
    pcs_batch::verify::<F, EF, H, C>(
        parameters,
        trans,
        &roots,
        &claims[0].query,
        &values,
        &proof.opening,
    )
    .map_err(convert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::NTTField;
    use pcs::utils::code::BlockReedSolomonCode;
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    fn opposite<F, EF>(k: usize)
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        let n = k.ilog2() as usize;
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, k, 32, 2).unwrap();
        let shape = PackedShape {
            num_vars: n,
            width: k,
            num_factors: 3,
            terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
        };
        let shapes = vec![shape.clone(), shape.clone()];
        for bad in [false, true] {
            let actual: Vec<Vec<_>> = (0..2)
                .map(|i| {
                    (0..3)
                        .map(|j| {
                            PackedTable::new(
                                n,
                                k,
                                vec![
                                    if j == 2 && bad {
                                        F::from(2 * i)
                                    } else {
                                        F::one()
                                    };
                                    (1 << n) * k
                                ],
                            )
                            .unwrap()
                        })
                        .collect()
                })
                .collect();
            let fake: Vec<_> = actual
                .iter()
                .map(|_| {
                    (0..3)
                        .map(|_| PackedTable::new(n, k, vec![F::one(); (1 << n) * k]).unwrap())
                        .collect::<Vec<_>>()
                })
                .collect();
            if bad {
                for row in 0..1 << n {
                    let a: Vec<_> = actual[0].iter().map(|t| t.at(row).to_vec()).collect();
                    let b: Vec<_> = actual[1].iter().map(|t| t.at(row).to_vec()).collect();
                    let a = shape.evaluate(&a).unwrap();
                    let b = shape.evaluate(&b).unwrap();
                    assert!(a.iter().any(|&v| v != F::zero()));
                    assert!(a.iter().zip(b).all(|(&a, b)| a + b == F::zero()));
                }
            }
            let pairs: Vec<Vec<_>> = actual
                .iter()
                .map(|tables| {
                    tables
                        .iter()
                        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                        .collect()
                })
                .collect();
            let roots: Vec<Vec<_>> = pairs
                .iter()
                .map(|pairs| pairs.iter().map(|(root, _)| root.clone()).collect())
                .collect();
            let states: Vec<_> = pairs.iter().flatten().map(|(_, state)| state).collect();
            let flat_roots: Vec<_> = roots.iter().flatten().cloned().collect();
            let mut prover = Transcript::new_direct();
            let mut reference = Transcript::new_direct();
            bind::<F, EF, Sha256, _>(&mut prover, &shapes, &pp, &roots).unwrap();
            bind::<F, EF, Sha256, _>(&mut reference, &shapes, &pp, &roots).unwrap();
            let (zero, claims, fake_values) = zero::prove(
                &mut prover,
                &shapes,
                &fake.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            )
            .unwrap();
            let checked = zero::verify(&mut reference, &shapes, &zero).unwrap();
            for ((shape, claim), values) in shapes.iter().zip(&checked).zip(&fake_values) {
                claim.check(shape, values).unwrap();
            }
            let values: Vec<Vec<_>> = actual
                .iter()
                .map(|tables| {
                    tables
                        .iter()
                        .map(|t| t.evaluate(&claims[0].query).unwrap())
                        .collect()
                })
                .collect();
            if bad {
                for (claim, values) in checked.iter().zip(&values) {
                    assert!(claim.check(&shape, values).is_err());
                }
            }
            prover.append_message(b"packed batch relation terminal values", &values);
            reference.append_message(b"packed batch relation terminal values", &values);
            let flat_values: Vec<_> = values.iter().flatten().cloned().collect();
            let opening = pcs_batch::prove::<F, EF, Sha256, _>(
                &pp,
                &mut prover,
                &flat_roots,
                &states,
                &claims[0].query,
                &flat_values,
            )
            .unwrap();
            pcs_batch::verify::<F, EF, Sha256, _>(
                &pp,
                &mut reference,
                &flat_roots,
                &checked[0].query,
                &flat_values,
                &opening,
            )
            .unwrap();
            let proof = Proof {
                zero,
                values,
                opening,
            };
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<F, EF, [u8; 32]>, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(
                prover.get_challenge(b"after genuine batch"),
                reference.get_challenge(b"after genuine batch")
            );
            let result = verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &shapes,
                &pp,
                &roots,
                &proof,
            );
            if bad {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("packed ZeroCheck terminal identity failed")
                );
            } else {
                result.unwrap();
            }
        }
    }
    #[test]
    fn babybear_genuine_opposite_equations_reject() {
        opposite::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
    }
    #[test]
    fn goldilocks_genuine_opposite_equations_reject() {
        opposite::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
    }
}

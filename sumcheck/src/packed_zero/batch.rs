//! Shared matrix challenges for independent packed ZeroCheck equations.
//! Every round's messages are fixed before the common challenge. Individual
//! equations remain separate; no base-field cancellation compression is used.
//! Callers must bind ordered statements/roots before proving and authenticate
//! every returned terminal value. This component is non-hiding.
use super::*;

/// One algebraic certificate per ordered instance, sharing a challenge schedule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F> {
    /// The verifier derives shapes and ordering from the caller, not this array.
    pub instances: Vec<ZeroProof<F>>,
}

fn bind<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
) -> Result<Vec<usize>, Error> {
    let first = shapes
        .first()
        .ok_or_else(|| reject("empty packed ZeroCheck batch"))?;
    let degrees = shapes
        .iter()
        .map(|s| {
            let degree = s.validate()?;
            if s.num_vars == 0 || s.num_vars != first.num_vars || s.width != first.width {
                return Err(reject("packed ZeroCheck batch geometry"));
            }
            reduced_shape(s).validate()?;
            Ok(degree)
        })
        .collect::<Result<Vec<_>, _>>()?;
    trans.append_message(b"packed shared-challenge zerocheck v1", &shapes);
    Ok(degrees)
}
fn points<F: PrimeField>(trans: &mut Transcript<F>, shapes: &[PackedShape<F>]) -> Vec<Vec<Vec<F>>> {
    shapes
        .iter()
        .enumerate()
        .map(|(i, s)| {
            trans.append_message(b"packed batch zero equality index", &i);
            sample_points(trans, s)
        })
        .collect()
}
fn reduce<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    width: usize,
    first: &[Vec<Vec<F>>],
) -> Result<(MatrixPair<F>, Vec<F>, Vec<Vec<F>>), Error> {
    trans.append_message(b"packed batch zero first messages", &first);
    let (mixing, r) = first_challenges(trans, width, true);
    let pair = packed::challenge_pair(&r).map_err(shape_error)?;
    let claims = first
        .iter()
        .map(|polynomials| {
            (0..width)
                .map(|a| {
                    (0..width).fold(F::zero(), |sum, b| {
                        sum + mixing[a * width + b] * interpolate_uni_poly(&polynomials[b], r[a])
                    })
                })
                .collect()
        })
        .collect();
    Ok((pair, mixing, claims))
}

/// Prove every pointwise equation with one shared terminal matrix query.
/// Geometry must match; coefficients, factor counts and degrees may differ.
/// Returns unauthenticated original-factor values for later PCS verification.
pub fn prove<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    factors: &[&[PackedTable<F>]],
) -> Result<(Proof<F>, Vec<ZeroSubclaim<F>>, Vec<Vec<Vec<F>>>), Error> {
    let borrowed: Vec<Vec<_>> = factors
        .iter()
        .map(|tables| tables.iter().collect())
        .collect();
    let slices: Vec<_> = borrowed.iter().map(Vec::as_slice).collect();
    prove_borrowed(trans, shapes, &slices)
}

/// Borrow canonical source tables without cloning their field buffers.
/// This uses exactly the same transcript and arithmetic as [`prove`].
pub fn prove_borrowed<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    factors: &[&[&PackedTable<F>]],
) -> Result<(Proof<F>, Vec<ZeroSubclaim<F>>, Vec<Vec<Vec<F>>>), Error> {
    let degrees = bind(trans, shapes)?;
    if factors.len() != shapes.len() {
        return Err(reject("packed ZeroCheck batch factor count"));
    }
    for (shape, tables) in shapes.iter().zip(factors) {
        validate_tables(shape, tables)?;
    }
    let points = points(trans, shapes);
    let equalities: Vec<Vec<_>> = points
        .iter()
        .map(|p| p.iter().map(|p| equality_table(p)).collect())
        .collect();
    let first: Vec<_> = shapes
        .iter()
        .zip(factors)
        .zip(&degrees)
        .zip(&equalities)
        .map(|(((s, t), &d), e)| first_evaluations(s, t, d, e))
        .collect();
    for ((shape, &degree), message) in shapes.iter().zip(&degrees).zip(&first) {
        check_first(shape, degree, message)?;
    }
    let (pair, mixing, mut expected) = reduce(trans, shapes[0].width, &first)?;
    let mut query = vec![pair.clone()];
    let reduced: Vec<_> = shapes.iter().map(reduced_shape).collect();
    let reduced_degrees = reduced
        .iter()
        .map(PackedShape::validate)
        .collect::<Result<Vec<_>, _>>()?;
    // Pointer identity is only an in-memory optimization for immutable inputs.
    // No alias map is accepted from the proof, and every equation/equality
    // remains separate. Distinct objects are never merged by claimed values.
    let mut sources = std::collections::HashMap::new();
    let mut tables = Vec::new();
    let mut routes = Vec::with_capacity(factors.len());
    for ((factors, shape), equality) in factors.iter().zip(shapes).zip(&equalities) {
        let mut route = Vec::with_capacity(factors.len() + 1);
        for &factor in *factors {
            let identity = std::ptr::from_ref(factor);
            let slot = if let Some(&slot) = sources.get(&identity) {
                slot
            } else {
                let slot = tables.len();
                tables.push(factor.fold(&pair).map_err(shape_error)?);
                sources.insert(identity, slot);
                slot
            };
            route.push(slot);
        }
        route.push(tables.len());
        tables.push(mixed_equality(shape, equality, &mixing)?);
        routes.push(route);
    }
    let mut instances: Vec<_> = first
        .into_iter()
        .map(|first| ZeroProof {
            first,
            rest: PackedProof { rounds: Vec::new() },
        })
        .collect();
    for round in 0..reduced[0].num_vars {
        let suffixes = 1usize << (reduced[0].num_vars - round - 1);
        let messages: Vec<_> = reduced
            .iter()
            .zip(&routes)
            .zip(&reduced_degrees)
            .map(|((s, route), &degree)| {
                let factors: Vec<_> = route.iter().map(|&slot| &tables[slot]).collect();
                packed::round_evaluations(s, &factors, suffixes, degree)
            })
            .collect();
        for (message, claim) in messages.iter().zip(&expected) {
            packed::check_round(shapes[0].width, message, claim)?;
        }
        trans.append_message(b"packed batch zero round messages", &(round, &messages));
        let r =
            trans.get_vec_challenge(b"packed batch zero independent challenges", shapes[0].width);
        let pair = packed::challenge_pair(&r).map_err(shape_error)?;
        for ((instance, message), claim) in instances.iter_mut().zip(messages).zip(&mut expected) {
            *claim = r
                .iter()
                .map(|&r| interpolate_uni_poly(&message, r))
                .collect();
            instance.rest.rounds.push(message);
        }
        tables
            .par_iter_mut()
            .try_for_each(|t| t.fold_in_place(&pair).map_err(shape_error))?;
        query.push(pair);
    }
    let mut subclaims = Vec::new();
    let mut values = Vec::new();
    for (((shape, route), expected), reduced) in
        shapes.iter().zip(&routes).zip(expected).zip(&reduced)
    {
        let mut terminal: Vec<_> = route
            .iter()
            .map(|&slot| tables[slot].values().to_vec())
            .collect();
        if reduced.evaluate(&terminal)? != expected {
            return Err(reject("false packed batch terminal claim"));
        }
        let equality = terminal
            .pop()
            .ok_or_else(|| reject("missing packed batch equality"))?;
        let subclaim = ZeroSubclaim {
            query: query.clone(),
            expected,
            equality,
        };
        subclaim.check(shape, &terminal)?;
        subclaims.push(subclaim);
        values.push(terminal);
    }
    Ok((Proof { instances }, subclaims, values))
}

/// Verify each independent equation and derive the shared opening obligations.
/// Success here still requires authentication of every original factor claim.
pub fn verify<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    proof: &Proof<F>,
) -> Result<Vec<ZeroSubclaim<F>>, Error> {
    let degrees = bind(trans, shapes)?;
    if proof.instances.len() != shapes.len() {
        return Err(reject("packed ZeroCheck batch proof count"));
    }
    for ((shape, &degree), instance) in shapes.iter().zip(&degrees).zip(&proof.instances) {
        check_first(shape, degree, &instance.first)?;
        let reduced = reduced_shape(shape);
        let d = reduced.validate()?;
        if instance.rest.rounds.len() != reduced.num_vars
            || instance.rest.rounds.iter().any(|p| p.len() != d + 1)
        {
            return Err(reject("packed ZeroCheck batch round shape"));
        }
    }
    let points = points(trans, shapes);
    let first: Vec<_> = proof.instances.iter().map(|p| p.first.clone()).collect();
    let (pair, mixing, mut expected) = reduce(trans, shapes[0].width, &first)?;
    let mut tail = Vec::new();
    for round in 0..shapes[0].num_vars - 1 {
        let messages: Vec<_> = proof
            .instances
            .iter()
            .map(|p| &p.rest.rounds[round])
            .collect();
        for (message, claim) in messages.iter().zip(&expected) {
            packed::check_round(shapes[0].width, message, claim)?;
        }
        trans.append_message(b"packed batch zero round messages", &(round, &messages));
        let r =
            trans.get_vec_challenge(b"packed batch zero independent challenges", shapes[0].width);
        for (message, claim) in messages.iter().zip(&mut expected) {
            *claim = r
                .iter()
                .map(|&r| interpolate_uni_poly(message, r))
                .collect();
        }
        tail.push(packed::challenge_pair(&r).map_err(shape_error)?);
    }
    let mut query = vec![pair];
    query.extend(tail.iter().cloned());
    Ok(shapes
        .iter()
        .zip(points)
        .zip(expected)
        .map(|((shape, points), expected)| ZeroSubclaim {
            query: query.clone(),
            expected,
            equality: evaluate_public_equality(shape.width, &points, &mixing, &tail),
        })
        .collect())
}

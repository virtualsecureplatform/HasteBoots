//! Shared-challenge identities over retained canonical backend sources.
//! Equations are checked individually. Authentication uses the source registry;
//! the selected backend determines whether its packets share cryptographic work.
use super::*;
use crate::{
    packed_opening_batch::{CanonicalOpeningBatch, CanonicalProof},
    packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle},
};

/// Algebraic messages and authentication of caller-derived terminal obligations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, P> {
    pub zero: zero::Proof<F>,
    pub values: Vec<Vec<Vec<F>>>,
    pub opening: CanonicalProof<P>,
}

fn prepare<'a, F, H, P>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    sources: &[Vec<CanonicalVerifierOracle<'a, H::Output, P>>],
) -> Result<(Vec<PackedShape<F>>, CanonicalOpeningBatch<'a, F, H, P>), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let first = shapes
        .first()
        .ok_or_else(|| Error("empty canonical relation batch".into()))?;
    if sources.len() != shapes.len() {
        return Err(Error("canonical relation batch source count".into()));
    }
    for (shape, sources) in shapes.iter().zip(sources) {
        shape.validate().map_err(convert)?;
        if shape.num_vars == 0
            || shape.num_vars != first.num_vars
            || shape.width != first.width
            || sources.is_empty()
            || sources.len() != shape.num_factors
            || sources.iter().any(|s| {
                s.parameters.num_vars() != shape.num_vars || s.parameters.width() != shape.width
            })
        {
            return Err(Error("canonical relation batch geometry".into()));
        }
    }
    let shapes: Vec<_> = shapes
        .iter()
        .zip(sources)
        .map(|(shape, s)| canonical_shape::<F, H, P>(shape, s[0].parameters))
        .collect();
    // Group boundaries and factor ordering are trusted statement inputs. The
    // registry then binds each parameter context and expected root before coins.
    trans.append_message(b"HasteBoots backend shared-challenge relations v1", &shapes);
    let public: Vec<_> = sources
        .iter()
        .flatten()
        .map(|s| CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    let registry = CanonicalOpeningBatch::new(trans, &public).map_err(convert)?;
    Ok((shapes, registry))
}

fn terminal<F, H, P>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    sources: &[Vec<CanonicalVerifierOracle<'_, H::Output, P>>],
    claims: &[packed_zero::ZeroSubclaim<F>],
    values: &[Vec<Vec<F>>],
    registry: &mut CanonicalOpeningBatch<'_, F, H, P>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if values.len() != shapes.len() || claims.len() != shapes.len() {
        return Err(Error("canonical batch terminal count".into()));
    }
    for (((shape, sources), claim), values) in shapes.iter().zip(sources).zip(claims).zip(values) {
        if values.len() != shape.num_factors || values.iter().any(|v| v.len() != shape.width) {
            return Err(Error("canonical batch terminal dimensions".into()));
        }
        for (source, value) in sources.iter().zip(values) {
            source.parameters.validate_values(value).map_err(convert)?;
        }
        claim.check(shape, values).map_err(convert)?;
    }
    trans.append_message(b"packed backend batch relation terminal values", &values);
    let mut slot = 0;
    for (claim, values) in claims.iter().zip(values) {
        for value in values {
            registry
                .push(trans, slot, claim.query.clone(), value.clone())
                .map_err(convert)?;
            slot += 1;
        }
    }
    Ok(())
}

/// Borrow actual retained factors and authenticate every equation's terminals.
/// All sources in a group must have the trusted shape's logical dimensions.
pub fn prove<F, H, P>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    sources: &[Vec<&CanonicalProverOracle<'_, F, H, P>>],
) -> Result<Proof<F, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let public: Vec<Vec<_>> = sources
        .iter()
        .map(|s| s.iter().map(|s| s.verifier()).collect())
        .collect();
    let (shapes, mut registry) = prepare::<F, H, P>(trans, shapes, &public)?;
    let factors: Vec<Vec<_>> = sources
        .iter()
        .map(|s| s.iter().map(|s| s.table()).collect())
        .collect();
    let slices: Vec<_> = factors.iter().map(Vec::as_slice).collect();
    let (zero, claims, values) = zero::prove_borrowed(trans, &shapes, &slices).map_err(convert)?;
    let values: Vec<Vec<_>> = public
        .iter()
        .zip(values)
        .map(|(s, v)| {
            s.iter()
                .zip(v)
                .map(|(s, v)| s.parameters.normalize_values(v))
                .collect()
        })
        .collect();
    terminal::<F, H, P>(trans, &shapes, &public, &claims, &values, &mut registry)?;
    let states: Vec<_> = sources.iter().flatten().map(|s| s.state).collect();
    let opening = registry.prove(trans, &states).map_err(convert)?;
    Ok(Proof {
        zero,
        values,
        opening,
    })
}

/// Verify each identity separately; opposite residuals cannot cancel.
/// Source grouping and relation shapes are supplied by the enclosing statement.
pub fn verify<F, H, P>(
    trans: &mut Transcript<F>,
    shapes: &[PackedShape<F>],
    sources: &[Vec<CanonicalVerifierOracle<'_, H::Output, P>>],
    proof: &Proof<F, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let (shapes, mut registry) = prepare::<F, H, P>(trans, shapes, sources)?;
    let claims = zero::verify(trans, &shapes, &proof.zero).map_err(convert)?;
    terminal::<F, H, P>(
        trans,
        &shapes,
        sources,
        &claims,
        &proof.values,
        &mut registry,
    )?;
    registry.verify(trans, &proof.opening).map_err(convert)
}

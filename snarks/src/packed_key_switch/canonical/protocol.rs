//! Canonical negative-a digits, native key products and original LWE extraction.
//! This is a final-stage component, not a complete PBS or hiding certificate.
use super::*;
use algebra::{AbstractExtensionField, Field};
use sumcheck::packed::challenge_pair;
/// Trusted logical geometries and lifetime budgets; never proof metadata.
pub struct Parameters<'a, P> {
    pub coefficients: &'a P,
    pub evaluations: &'a P,
    pub key: &'a P,
    pub input: &'a P,
    pub borrows: &'a P,
    pub helper: &'a P,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Extraction<F, S> {
    pub zero: ZeroProof<F>,
    pub value: Vec<F>,
    pub opening: S,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendProof<F: Field, O, S, B, D> {
    pub coefficients: Vec<Commitment<O>>,
    pub evaluations: Vec<Commitment<O>>,
    pub input: Commitment<O>,
    pub input_opening: S,
    pub ntt: Vec<packed_ntt::CanonicalProof<F, B>>,
    pub product: packed_relation::CanonicalRelationProof<F, S>,
    pub decomposition: D,
    pub extraction: Extraction<F, S>,
}
/// Existing per-limb proof spelling and unchanged serialized field order.
pub type Proof<F, EF, O, S, B> =
    BackendProof<F, O, S, B, packed_decomposition::canonical::Proof<F, EF, O, S, B>>;
mod comparison;
fn preflight<F, EF, H, P>(
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let cfg = &key.config;
    let width = pp.coefficients.width();
    for p in [
        pp.coefficients,
        pp.evaluations,
        pp.key,
        pp.input,
        pp.borrows,
    ] {
        cfg.validate_geometry(p.num_vars(), p.width())?;
        if p.width() != width {
            return Err(error("incompatible source widths"));
        }
        p.context().map_err(convert)?;
    }
    if width < EF::D
        || EF::D == 0
        || pp.helper.width() != width
        || pp.helper.num_vars() != pp.coefficients.num_vars() + width.ilog2() as usize
        || key.roots.len() != cfg.digits::<F>()?
        || acc.len() != 2 * cfg.n
        || a.len() != cfg.lwe
    {
        return Err(error("key, endpoint or helper dimensions"));
    }
    public_oracles::<F, H, P>(pp.key, key)?;
    pp.helper.context().map_err(convert)?;
    Ok(())
}
fn bind<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    co: &[Commitment<H::Output>],
    ev: &[Commitment<H::Output>],
    input: &Commitment<H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    preflight::<F, EF, H, P>(pp, key, acc, a)?;
    let d = key.config.digits::<F>()?;
    if co.len() != d + 1 || ev.len() != d + 1 {
        return Err(error("private source counts"));
    }
    let contexts = [
        pp.coefficients,
        pp.evaluations,
        pp.key,
        pp.input,
        pp.borrows,
        pp.helper,
    ]
    .iter()
    .map(|p| p.context().map_err(convert))
    .collect::<Result<Vec<_>, _>>()?;
    trans.append_message(
        b"packed canonical backend original key switch v1",
        &(key, EF::D, contexts, acc, a, b, co, ev, input),
    );
    Ok(())
}
fn public_input_query<F, H, P>(
    trans: &mut Transcript<F>,
    pp: &P,
    root: &Commitment<H::Output>,
    table: &PackedTable<F>,
) -> Result<Vec<algebra::matrix_weighted::MatrixPair<F>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    trans.append_message(
        b"canonical key-switch known input v1",
        &(
            pp.context().map_err(convert)?,
            root,
            pp.normalize_values(table.values().to_vec()),
        ),
    );
    (0..pp.num_vars())
        .map(|_| {
            challenge_pair(
                &trans
                    .get_vec_challenge(b"canonical key-switch public input challenges", pp.width()),
            )
            .map_err(convert)
        })
        .collect()
}
fn verify_public_input<F, H, P>(
    trans: &mut Transcript<F>,
    pp: &P,
    root: &Commitment<H::Output>,
    table: &PackedTable<F>,
    opening: &P::SingleProof,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let q = public_input_query::<F, H, P>(trans, pp, root, table)?;
    let value = pp.normalize_values(table.evaluate(&q).map_err(convert)?);
    pp.verify(trans, root, &q, &value, opening).map_err(convert)
}
fn oracles<'a, F, H, P>(
    pp: &'a P,
    roots: &'a [Commitment<H::Output>],
    states: &'a [P::State],
) -> Vec<CanonicalProverOracle<'a, F, H, P>>
where
    F: NTTField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    roots
        .iter()
        .zip(states)
        .map(|(commitment, state)| CanonicalProverOracle {
            parameters: pp,
            commitment,
            state,
        })
        .collect()
}
fn public<'a, O, P>(
    pp: &'a P,
    roots: &'a [Commitment<O>],
) -> Vec<CanonicalVerifierOracle<'a, O, P>> {
    roots
        .iter()
        .map(|commitment| CanonicalVerifierOracle {
            parameters: pp,
            commitment,
        })
        .collect()
}
/// Prove the full native final stage, with original output key and dimension.
pub fn prove<F, EF, H, P, R>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ProverKey<F, H, P>,
    acc: &[F],
    a: &[F],
    b: F,
    coefficients: &[PackedTable<F>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_inner::<F, EF, H, P, R, comparison::PerLimb>(trans, pp, key, acc, a, b, coefficients, rng)
}
fn prove_inner<F, EF, H, P, R, D>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ProverKey<F, H, P>,
    acc: &[F],
    a: &[F],
    b: F,
    coefficients: &[PackedTable<F>],
    rng: &mut R,
) -> Result<BackendProof<F, H::Output, P::SingleProof, P::BatchProof, D::Proof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
    D: comparison::Comparison<F, EF, H, P>,
{
    let acc = pp.coefficients.normalize_values(acc.to_vec());
    let a = pp.coefficients.normalize_values(a.to_vec());
    let b = pp.coefficients.normalize_values(vec![b])[0];
    preflight::<F, EF, H, P>(pp, key.expected(), &acc, &a)?;
    let cfg = &key.expected.config;
    let d = cfg.digits::<F>()?;
    if coefficients.len() != d + 1
        || coefficients.iter().any(|t| {
            t.num_vars() != pp.coefficients.num_vars() || t.width() != pp.coefficients.width()
        })
    {
        return Err(error("private coefficient source count or dimensions"));
    }
    let (roots, states): (Vec<_>, Vec<_>) = coefficients
        .iter()
        .map(|t| pp.coefficients.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    F::init_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let native = F::get_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let transformed = states
        .iter()
        .map(|s| {
            let table = P::table(s);
            let mut v = table.values().to_vec();
            for poly in v.chunks_exact_mut(cfg.n) {
                native.transform_slice(poly);
            }
            PackedTable::new(pp.evaluations.num_vars(), pp.evaluations.width(), v).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, ntt_states): (Vec<_>, Vec<_>) = transformed
        .iter()
        .map(|t| pp.evaluations.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    drop(transformed);
    let input = input_dimensions(pp.input.num_vars(), pp.input.width(), cfg, &acc)?;
    let (input_root, input_state) = pp.input.commit(&input, rng).map_err(convert)?;
    D::bind(trans);
    bind::<F, EF, H, P>(
        trans,
        pp,
        key.expected(),
        &acc,
        &a,
        b,
        &roots,
        &evaluations,
        &input_root,
    )?;
    let iq = public_input_query::<F, H, P>(trans, pp.input, &input_root, &input)?;
    let iv = pp
        .input
        .normalize_values(P::table(&input_state).evaluate(&iq).map_err(convert)?);
    let input_opening = pp
        .input
        .open(trans, &input_root, &input_state, &iq, &iv)
        .map_err(convert)?;
    let co = oracles::<F, H, P>(pp.coefficients, &roots, &states);
    let ev = oracles::<F, H, P>(pp.evaluations, &evaluations, &ntt_states);
    let ko = key.oracles(pp.key)?;
    let shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    let ntt = (0..=d)
        .map(|i| {
            packed_ntt::prove_canonical::<F, H, P>(trans, &shape, &co[i], &ev[i]).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let factors: Vec<_> = (0..d)
        .flat_map(|i| [&ev[i], &ko[i]])
        .chain(std::iter::once(&ev[d]))
        .collect();
    let product = packed_relation::prove_canonical::<F, H, P>(
        trans,
        &product_shape_dimensions(pp.evaluations.num_vars(), pp.evaluations.width(), d),
        &factors,
        &mut packed_relation::ProverStatistics::default(),
    )
    .map_err(convert)?;
    let source = CanonicalProverOracle::<F, H, P> {
        parameters: pp.input,
        commitment: &input_root,
        state: &input_state,
    };
    let decomposition = D::prove(
        trans,
        &cfg.decomposition::<F>()?,
        &source,
        pp.borrows,
        pp.helper,
        &co[..d].iter().collect::<Vec<_>>(),
        rng,
    )?;
    let (mask, target) = extraction_tables_dimensions(
        pp.coefficients.num_vars(),
        pp.coefficients.width(),
        cfg,
        &acc,
        &a,
        b,
    )?;
    let shape = extraction_shape_dimensions(pp.coefficients.num_vars(), pp.coefficients.width());
    let (zero, subclaim, terminals) = packed_zero::prove_with_borrowed_terminal_values(
        trans,
        &shape,
        &[co[d].table(), &mask, &target],
    )
    .map_err(convert)?;
    let value = pp.coefficients.normalize_values(terminals[0].clone());
    subclaim
        .check(
            &shape,
            &[
                value.clone(),
                mask.evaluate(&subclaim.query).map_err(convert)?,
                target.evaluate(&subclaim.query).map_err(convert)?,
            ],
        )
        .map_err(convert)?;
    let opening = pp
        .coefficients
        .open(trans, &roots[d], &states[d], &subclaim.query, &value)
        .map_err(convert)?;
    Ok(BackendProof {
        coefficients: roots,
        evaluations,
        input: input_root,
        input_opening,
        ntt,
        product,
        decomposition,
        extraction: Extraction {
            zero,
            value,
            opening,
        },
    })
}
/// Verify key-bound products, canonical negative-a digits and public extraction.
pub fn verify<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, comparison::PerLimb>(trans, pp, key, acc, a, b, proof)
}
fn verify_inner<F, EF, H, P, D>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &BackendProof<F, H::Output, P::SingleProof, P::BatchProof, D::Proof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    D: comparison::Comparison<F, EF, H, P>,
{
    let acc = pp.coefficients.normalize_values(acc.to_vec());
    let a = pp.coefficients.normalize_values(a.to_vec());
    let b = pp.coefficients.normalize_values(vec![b])[0];
    D::bind(trans);
    bind::<F, EF, H, P>(
        trans,
        pp,
        key,
        &acc,
        &a,
        b,
        &proof.coefficients,
        &proof.evaluations,
        &proof.input,
    )?;
    let cfg = &key.config;
    let d = cfg.digits::<F>()?;
    if proof.ntt.len() != d + 1 {
        return Err(error("NTT proof count"));
    }
    pp.coefficients
        .validate_values(&proof.extraction.value)
        .map_err(convert)?;
    let input = input_dimensions(pp.input.num_vars(), pp.input.width(), cfg, &acc)?;
    verify_public_input::<F, H, P>(trans, pp.input, &proof.input, &input, &proof.input_opening)?;
    let co = public(pp.coefficients, &proof.coefficients);
    let ev = public(pp.evaluations, &proof.evaluations);
    let ko = public_oracles::<F, H, P>(pp.key, key)?;
    let shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    for i in 0..=d {
        packed_ntt::verify_canonical::<F, H, P>(trans, &shape, &co[i], &ev[i], &proof.ntt[i])
            .map_err(convert)?;
    }
    let factors: Vec<_> = (0..d)
        .flat_map(|i| [&ev[i], &ko[i]])
        .chain(std::iter::once(&ev[d]))
        .map(|s| CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    packed_relation::verify_canonical::<F, H, P>(
        trans,
        &product_shape_dimensions(pp.evaluations.num_vars(), pp.evaluations.width(), d),
        &factors,
        &proof.product,
    )
    .map_err(convert)?;
    D::verify(
        trans,
        &cfg.decomposition::<F>()?,
        &CanonicalVerifierOracle {
            parameters: pp.input,
            commitment: &proof.input,
        },
        pp.borrows,
        pp.helper,
        &co[..d]
            .iter()
            .map(|s| CanonicalVerifierOracle {
                parameters: s.parameters,
                commitment: s.commitment,
            })
            .collect::<Vec<_>>(),
        &proof.decomposition,
    )?;
    let (mask, target) = extraction_tables_dimensions(
        pp.coefficients.num_vars(),
        pp.coefficients.width(),
        cfg,
        &acc,
        &a,
        b,
    )?;
    let shape = extraction_shape_dimensions(pp.coefficients.num_vars(), pp.coefficients.width());
    let subclaim = packed_zero::verify(trans, &shape, &proof.extraction.zero).map_err(convert)?;
    subclaim
        .check(
            &shape,
            &[
                proof.extraction.value.clone(),
                mask.evaluate(&subclaim.query).map_err(convert)?,
                target.evaluate(&subclaim.query).map_err(convert)?,
            ],
        )
        .map_err(convert)?;
    pp.coefficients
        .verify(
            trans,
            &proof.coefficients[d],
            &subclaim.query,
            &proof.extraction.value,
            &proof.extraction.opening,
        )
        .map_err(convert)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod audit;

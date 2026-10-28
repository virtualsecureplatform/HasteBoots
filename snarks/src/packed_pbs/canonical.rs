//! Versioned complete binary NAND PBS composition over canonical PCS backends.
//! This is an experimental proof path, not a whole-proof hiding/security claim.
use super::*;
use crate::packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle};
use algebra::{AbstractExtensionField, Field};
use ks::canonical::protocol as final_stage;
use pcs::matrix_weighted::backend::CanonicalPcs;
use rand::{CryptoRng, Rng};

/// Distinct complete proof framing. Backend and parameters remain caller inputs.
pub const PROTOCOL_VERSION: u32 = 10;
/// Per-role trusted logical geometries, physical capacities and opening budgets.
pub struct Parameters<'a, P> {
    pub coefficients: &'a P,
    pub evaluations: &'a P,
    pub key: &'a P,
    pub inputs: &'a P,
    pub borrows: &'a P,
    pub helper: &'a P,
    pub accumulators: [&'a P; 4],
    pub monomial: &'a P,
    pub final_stage: final_stage::Parameters<'a, P>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendProof<F: Field, O, S, B, D, K> {
    pub protocol_version: u32,
    pub coefficients: Vec<Commitment<O>>,
    pub evaluations: Vec<Commitment<O>>,
    pub decomposition_inputs: Vec<Commitment<O>>,
    pub accumulators: Vec<Commitment<O>>,
    pub final_accumulator: Vec<F>,
    pub hadamard: relation::CanonicalRelationProof<F, S>,
    pub ntt: Vec<ntt::CanonicalProof<F, B>>,
    pub decomposition: Vec<D>,
    pub accumulator: acc::CanonicalProof<F, B>,
    pub monomial: mono::canonical::Proof<F, O, B, S>,
    pub key_switch: K,
}
/// Existing complete version-10 spelling and serialized field order.
pub type Proof<F, EF, O, S, B> = BackendProof<
    F,
    O,
    S,
    B,
    decomp::canonical::Proof<F, EF, O, S, B>,
    final_stage::Proof<F, EF, O, S, B>,
>;
mod stages;
#[derive(Serialize)]
struct PublicStatement<F> {
    left_a: Vec<F>,
    left_b: F,
    right_a: Vec<F>,
    right_b: F,
    output_a: Vec<F>,
    output_b: F,
}
impl<F: Copy> PublicStatement<F> {
    fn borrowed(&self) -> Statement<'_, F> {
        Statement {
            left_a: &self.left_a,
            left_b: self.left_b,
            right_a: &self.right_a,
            right_b: self.right_b,
            output_a: &self.output_a,
            output_b: self.output_b,
        }
    }
}
fn statement<F, H, P>(pp: &P, s: &Statement<'_, F>) -> PublicStatement<F>
where
    F: NTTField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let scalars = pp.normalize_values(vec![s.left_b, s.right_b, s.output_b]);
    PublicStatement {
        left_a: pp.normalize_values(s.left_a.to_vec()),
        left_b: scalars[0],
        right_a: pp.normalize_values(s.right_a.to_vec()),
        right_b: scalars[1],
        output_a: pp.normalize_values(s.output_a.to_vec()),
        output_b: scalars[2],
    }
}
fn validate<F, EF, H, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let width = pp.coefficients.width();
    let dims = setup.config.variables(width)?;
    if EF::D == 0 || width < EF::D {
        return Err(error("extension degree/packed width"));
    }
    for p in [
        pp.coefficients,
        pp.evaluations,
        pp.key,
        pp.inputs,
        pp.borrows,
        pp.monomial,
    ]
    .into_iter()
    .chain(pp.accumulators)
    {
        if p.width() != width || p.num_vars() != dims[0] {
            return Err(error("incompatible trusted source geometry"));
        }
        p.context().map_err(convert)?;
    }
    let d = setup
        .config
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    if setup.br.roots().len() != 2 * d
        || setup.br.polynomial_size() != setup.config.n
        || setup.br.rounds() != setup.config.lwe
        || setup.br.basis_bits() != setup.config.br_bits
    {
        return Err(error("bootstrapping key/configuration mismatch"));
    }
    for p in [
        pp.final_stage.coefficients,
        pp.final_stage.evaluations,
        pp.final_stage.input,
        pp.final_stage.borrows,
    ] {
        if p.width() != width || p.num_vars() != dims[2] {
            return Err(error("incompatible trusted final-stage geometry"));
        }
        p.context().map_err(convert)?;
    }
    canonical_setup::validate::<F, H, P>(
        &canonical_setup::Parameters {
            source: pp.key,
            helper: pp.helper,
            final_source: pp.final_stage.key,
            final_helper: pp.final_stage.helper,
        },
        setup,
    )?;
    Ok(())
}
fn contexts<F, H, P>(pp: &Parameters<'_, P>) -> Result<Vec<H::Output>, Error>
where
    F: NTTField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    [
        pp.coefficients,
        pp.evaluations,
        pp.key,
        pp.inputs,
        pp.borrows,
        pp.helper,
        pp.accumulators[0],
        pp.accumulators[1],
        pp.accumulators[2],
        pp.accumulators[3],
        pp.monomial,
        pp.final_stage.coefficients,
        pp.final_stage.evaluations,
        pp.final_stage.key,
        pp.final_stage.input,
        pp.final_stage.borrows,
        pp.final_stage.helper,
    ]
    .iter()
    .map(|p| p.context().map_err(convert))
    .collect()
}
#[cfg(test)]
fn bind<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &PublicStatement<F>,
    co: &[Commitment<H::Output>],
    ev: &[Commitment<H::Output>],
    inputs: &[Commitment<H::Output>],
    acc: &[Commitment<H::Output>],
    final_acc: &[F],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind_inner::<F, EF, H, P, stages::PerLimb>(trans, pp, setup, s, co, ev, inputs, acc, final_acc)
}
fn bind_inner<F, EF, H, P, M>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &PublicStatement<F>,
    co: &[Commitment<H::Output>],
    ev: &[Commitment<H::Output>],
    inputs: &[Commitment<H::Output>],
    acc: &[Commitment<H::Output>],
    final_acc: &[F],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    M: stages::Mode,
{
    validate::<F, EF, H, P>(pp, setup)?;
    let count = 2 * setup
        .config
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?
        + 1;
    if co.len() != count
        || ev.len() != count
        || inputs.len() != 2
        || acc.len() != 4
        || final_acc.len() != 2 * setup.config.n
    {
        return Err(error("canonical source or endpoint counts"));
    }
    trans.append_message(
        M::DOMAIN,
        &(
            M::VERSION,
            EF::D,
            setup,
            contexts::<F, H, P>(pp)?,
            s,
            co,
            ev,
            inputs,
            acc,
            final_acc,
        ),
    );
    Ok(())
}
fn shape<F: NTTField>(vars: usize, width: usize, count: usize) -> PackedShape<F> {
    let mut terms = (0..count)
        .map(|i| (F::one(), vec![2 * i, 2 * i + 1]))
        .collect::<Vec<_>>();
    terms.push((-F::one(), vec![2 * count]));
    PackedShape {
        num_vars: vars,
        width,
        num_factors: 2 * count + 1,
        terms,
    }
}
fn commit<F, H, P, R>(
    pp: &P,
    tables: &[PackedTable<F>],
    rng: &mut R,
) -> Result<(Vec<Commitment<H::Output>>, Vec<P::State>), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    Ok(tables
        .iter()
        .map(|t| pp.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip())
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
/// Prove every original NAND PBS stage against trusted key owners and ciphertexts.
pub fn prove<F, EF, H, P, R>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, H, P>,
    s: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_with_statistics::<F, EF, H, P, R>(
        pp,
        setup,
        s,
        trace,
        rng,
        &mut ProverStatistics::default(),
    )
}
/// Complete phase counters; not proof data or a security-matched timing claim.
pub fn prove_with_statistics<F, EF, H, P, R>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, H, P>,
    s: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    rng: &mut R,
    stats: &mut ProverStatistics,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_inner::<F, EF, H, P, R, stages::PerLimb>(pp, setup, s, trace, rng, stats)
}
fn prove_inner<F, EF, H, P, R, D>(
    pp: &Parameters<'_, P>,
    setup: &canonical_setup::ProverSetup<F, H, P>,
    s: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    rng: &mut R,
    stats: &mut ProverStatistics,
) -> Result<
    BackendProof<F, H::Output, P::SingleProof, P::BatchProof, D::Decomposition, D::KeySwitch>,
    Error,
>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
    D: stages::Stages<F, EF, H, P>,
{
    let timer = Instant::now();
    let expected = setup.verifier();
    validate::<F, EF, H, P>(pp, &expected)?;
    let cfg = &expected.config;
    let width = pp.coefficients.width();
    let d = cfg
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    let normalized = statement::<F, H, P>(pp.coefficients, s);
    let s = normalized.borrowed();
    let (plan, initial) = public_inputs(cfg, &s)?;
    let (co_tables, ac_tables, in_tables, final_acc) = witness(cfg, width, trace)?;
    if co_tables.len() != 2 * d + 1 {
        return Err(error("native digit count"));
    }
    let final_acc = pp.coefficients.normalize_values(final_acc);
    let (coefficients, co_states) = commit::<F, H, P, R>(pp.coefficients, &co_tables, rng)?;
    drop(co_tables);
    F::init_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let native = F::get_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let tables = co_states
        .iter()
        .map(|state| {
            let mut v = P::table(state).values().to_vec();
            for poly in v.chunks_exact_mut(cfg.n) {
                native.transform_slice(poly);
            }
            PackedTable::new(pp.evaluations.num_vars(), width, v).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, ev_states) = commit::<F, H, P, R>(pp.evaluations, &tables, rng)?;
    drop(tables);
    let pairs = ac_tables
        .iter()
        .zip(pp.accumulators)
        .map(|(t, p)| p.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let (accumulators, ac_states): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    drop(ac_tables);
    let (decomposition_inputs, in_states) = commit::<F, H, P, R>(pp.inputs, &in_tables, rng)?;
    drop(in_tables);
    let mut trans = Transcript::new_direct();
    bind_inner::<F, EF, H, P, D>(
        &mut trans,
        pp,
        &expected,
        &normalized,
        &coefficients,
        &evaluations,
        &decomposition_inputs,
        &accumulators,
        &final_acc,
    )?;
    let co = oracles::<F, H, P>(pp.coefficients, &coefficients, &co_states);
    let ev = oracles::<F, H, P>(pp.evaluations, &evaluations, &ev_states);
    let ac: Vec<_> = accumulators
        .iter()
        .zip(&ac_states)
        .zip(pp.accumulators)
        .map(
            |((commitment, state), parameters)| CanonicalProverOracle::<F, H, P> {
                parameters,
                commitment,
                state,
            },
        )
        .collect();
    let input = oracles::<F, H, P>(pp.inputs, &decomposition_inputs, &in_states);
    let key = setup.br_oracles(pp.key).map_err(convert)?;
    stats.preparation += timer.elapsed();
    let timer = Instant::now();
    let factors: Vec<_> = (0..2 * d)
        .flat_map(|i| [&ev[i], &key[i]])
        .chain(std::iter::once(&ev[2 * d]))
        .collect();
    let hadamard = relation::prove_canonical::<F, H, P>(
        &mut trans,
        &shape(pp.evaluations.num_vars(), width, 2 * d),
        &factors,
        &mut relation::ProverStatistics::default(),
    )
    .map_err(convert)?;
    stats.hadamard += timer.elapsed();
    let timer = Instant::now();
    let ntt_shape =
        ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    let ntt = (0..2 * d + 1)
        .map(|i| {
            ntt::prove_canonical::<F, H, P>(&mut trans, &ntt_shape, &co[i], &ev[i]).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    stats.ntt += timer.elapsed();
    let timer = Instant::now();
    let config = cfg.decomposition::<F>()?;
    let decomposition = (0..2)
        .map(|half| {
            D::decompose(
                &mut trans,
                &config,
                &input[half],
                pp.borrows,
                pp.helper,
                &co[half * d..(half + 1) * d].iter().collect::<Vec<_>>(),
                rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    stats.decomposition += timer.elapsed();
    let timer = Instant::now();
    let sources = [
        &ac[0],
        &ac[1],
        &ac[2],
        &ac[3],
        &co[2 * d],
        &input[0],
        &input[1],
    ];
    let accumulator = acc::prove_canonical::<F, H, P>(
        &mut trans,
        &acc::Shape::new(cfg.n, cfg.lwe).map_err(convert)?,
        &initial,
        &final_acc,
        &sources,
    )
    .map_err(convert)?;
    stats.accumulator += timer.elapsed();
    let timer = Instant::now();
    let monomial = mono::canonical::prove::<F, H, P, R>(
        &mut trans,
        &plan,
        pp.monomial,
        &[&ac[0], &ac[1]],
        rng,
    )
    .map_err(convert)?;
    stats.monomial += timer.elapsed();
    let timer = Instant::now();
    let ks_tables = ks::from_native(width, &trace.key_switching_trace).map_err(convert)?;
    let key_switch = D::key_switch(
        &mut trans,
        &pp.final_stage,
        setup.switching_key(),
        &final_acc,
        s.output_a,
        s.output_b,
        &ks_tables,
        rng,
    )?;
    stats.key_switch += timer.elapsed();
    Ok(BackendProof {
        protocol_version: D::VERSION,
        coefficients,
        evaluations,
        decomposition_inputs,
        accumulators,
        final_accumulator: final_acc,
        hadamard,
        ntt,
        decomposition,
        accumulator,
        monomial,
        key_switch,
    })
}
/// Standalone complete verifier: no native trace, private state or endpoint inputs.
pub fn verify<F, EF, H, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &Statement<'_, F>,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, stages::PerLimb>(pp, setup, s, proof)
}
fn verify_inner<F, EF, H, P, D>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
    s: &Statement<'_, F>,
    proof: &BackendProof<
        F,
        H::Output,
        P::SingleProof,
        P::BatchProof,
        D::Decomposition,
        D::KeySwitch,
    >,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    D: stages::Stages<F, EF, H, P>,
{
    if proof.protocol_version != D::VERSION {
        return Err(error("unsupported canonical complete PBS protocol version"));
    }
    validate::<F, EF, H, P>(pp, setup)?;
    pp.coefficients
        .validate_values(&proof.final_accumulator)
        .map_err(convert)?;
    let cfg = &setup.config;
    let width = pp.coefficients.width();
    let d = cfg
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    let normalized = statement::<F, H, P>(pp.coefficients, s);
    let s = normalized.borrowed();
    let (plan, initial) = public_inputs(cfg, &s)?;
    let mut trans = Transcript::new_direct();
    bind_inner::<F, EF, H, P, D>(
        &mut trans,
        pp,
        setup,
        &normalized,
        &proof.coefficients,
        &proof.evaluations,
        &proof.decomposition_inputs,
        &proof.accumulators,
        &proof.final_accumulator,
    )?;
    if proof.ntt.len() != 2 * d + 1 || proof.decomposition.len() != 2 {
        return Err(error("child proof counts"));
    }
    let co = public(pp.coefficients, &proof.coefficients);
    let ev = public(pp.evaluations, &proof.evaluations);
    let input = public(pp.inputs, &proof.decomposition_inputs);
    let key = bk::canonical::public_oracles::<F, H, P>(pp.key, &setup.br).map_err(convert)?;
    let factors: Vec<_> = (0..2 * d)
        .flat_map(|i| [&ev[i], &key[i]])
        .chain(std::iter::once(&ev[2 * d]))
        .map(|s| CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    relation::verify_canonical::<F, H, P>(
        &mut trans,
        &shape(pp.evaluations.num_vars(), width, 2 * d),
        &factors,
        &proof.hadamard,
    )
    .map_err(convert)?;
    let ntt_shape =
        ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    for i in 0..2 * d + 1 {
        ntt::verify_canonical::<F, H, P>(&mut trans, &ntt_shape, &co[i], &ev[i], &proof.ntt[i])
            .map_err(convert)?;
    }
    for half in 0..2 {
        D::verify_decomposition(
            &mut trans,
            &cfg.decomposition::<F>()?,
            &input[half],
            pp.borrows,
            pp.helper,
            &co[half * d..(half + 1) * d]
                .iter()
                .map(|s| CanonicalVerifierOracle {
                    parameters: s.parameters,
                    commitment: s.commitment,
                })
                .collect::<Vec<_>>(),
            &proof.decomposition[half],
        )?;
    }
    let ac: Vec<_> = proof
        .accumulators
        .iter()
        .zip(pp.accumulators)
        .map(|(commitment, parameters)| CanonicalVerifierOracle {
            parameters,
            commitment,
        })
        .collect();
    let sources = [
        &ac[0],
        &ac[1],
        &ac[2],
        &ac[3],
        &co[2 * d],
        &input[0],
        &input[1],
    ]
    .into_iter()
    .map(|s| CanonicalVerifierOracle {
        parameters: s.parameters,
        commitment: s.commitment,
    })
    .collect::<Vec<_>>();
    acc::verify_canonical::<F, H, P>(
        &mut trans,
        &acc::Shape::new(cfg.n, cfg.lwe).map_err(convert)?,
        &initial,
        &proof.final_accumulator,
        &sources,
        &proof.accumulator,
    )
    .map_err(convert)?;
    mono::canonical::verify::<F, H, P>(
        &mut trans,
        &plan,
        pp.monomial,
        &ac[..2]
            .iter()
            .map(|s| CanonicalVerifierOracle {
                parameters: s.parameters,
                commitment: s.commitment,
            })
            .collect::<Vec<_>>(),
        &proof.monomial,
    )
    .map_err(convert)?;
    D::verify_key_switch(
        &mut trans,
        &pp.final_stage,
        &setup.ks,
        &proof.final_accumulator,
        s.output_a,
        s.output_b,
        &proof.key_switch,
    )
}

#[cfg(test)]
mod audit;

/// Complete version-11 PBS with shared canonical comparisons.
pub mod shared;

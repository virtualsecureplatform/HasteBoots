//! Complete binary NAND PBS relation composition; experimental and non-hiding.
//! This is not a whole-proof 128-bit or Fiat-Shamir security claim.
use crate::{
    packed_accumulator as acc, packed_bootstrap_key as bk, packed_decomposition as decomp,
    packed_key_switch as ks, packed_monomial as mono, packed_ntt as ntt,
    packed_oracle::{ProverOracle, VerifierOracle},
    packed_relation as relation,
};
use algebra::{NTTField, matrix_weighted::PackedTable, transformation::AbstractNTT};
use helper::{FiatShamirTranscript, Transcript};
use lattice::{NTTGadgetRLWE, NTTRGSW};
use pcs::{
    matrix_weighted::{Commitment, Parameters as PcsParameters, State},
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use sumcheck::packed::PackedShape;
use trace::pbs_trace::PBSTrace;

mod hadamard;
/// Native key ownership for statically selected canonical PCS backends.
pub mod canonical_setup;
/// Complete ordered PBS batches with joint cross-statement Hadamard authentication.
pub mod batch;

/// Complete joint-Hadamard batch and member protocol version.
pub const BATCH_PROTOCOL_VERSION:u32=6;

/// Complete packed-PBS wire/transcript protocol version.
pub const PROTOCOL_VERSION: u32 = 2;
/// Opt-in complete protocol using extension-field canonical comparisons.
pub const EXTENSION_PROTOCOL_VERSION: u32 = 3;
/// Opt-in extension-comparison protocol with aggregated Hadamard authentication.
pub const AGGREGATED_PROTOCOL_VERSION: u32 = 4;
/// Opt-in aggregated Hadamard protocol with deferred canonical lookup sources.
pub const DEFERRED_PROTOCOL_VERSION:u32=5;
/// Complete shared-query comparison protocol, opt-in and non-hiding.
pub const SHARED_PROTOCOL_VERSION:u32=8;
/// Complete batch/member format with mandatory outer comparison proofs.
pub const COMPARISON_BATCH_PROTOCOL_VERSION:u32=9;
/// Full-extension shared sum/identity comparisons and canonical authentication.
pub const SHARED_TRANSCRIPT_ID:&str="merlin-direct-shared-query-comparisons-v1";
/// Direct extension lookup children with terminal source authentication per decomposition.
pub const DEFERRED_TRANSCRIPT_ID:&str="merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1";
/// Direct parent/extension children plus multi-root Hadamard authentication.
pub const AGGREGATED_TRANSCRIPT_ID: &str = "merlin-direct-extension-comparisons-aggregated-hadamard-v1";
/// Direct prime parent with seeded direct-extension lookup children.
pub const EXTENSION_TRANSCRIPT_ID: &str = "merlin-direct-prime-parent-extension-child-v1";
/// Field-challenge sampling protocol used by this complete verifier.
pub const TRANSCRIPT_ID: &str = helper::transcript::DIRECT_TRANSCRIPT_ID;

/// Invalid trusted setup, witness, statement or rejected proof.
#[derive(Debug, thiserror::Error)]
#[error("packed PBS: {0}")]
pub struct Error(String);
/// Trusted native NAND parameters. Proofs cannot supply or change these.
#[derive(Clone, Debug, Serialize)]
pub struct Config {
    n: usize,
    lwe: usize,
    br_bits: u32,
    ks_bits: u32,
    lut_step: usize,
    repetitions: usize,
}
impl Config {
    /// Preserve the native single-PBS operation and output key/dimension.
    pub fn new<F: NTTField>(
        n: usize,
        lwe: usize,
        br_bits: u32,
        ks_bits: u32,
        lut_step: usize,
        repetitions: usize,
    ) -> Result<Self, Error> {
        acc::Shape::new(n, lwe).map_err(convert)?;
        ks::Config::new::<F>(n, lwe, ks_bits, repetitions).map_err(convert)?;
        if lut_step == 0 {
            return Err(error("zero LUT stride"));
        }
        let result = Self {
            n,
            lwe,
            br_bits,
            ks_bits,
            lut_step,
            repetitions,
        };
        result.decomposition::<F>()?;
        Ok(result)
    }
    fn decomposition<F: NTTField>(&self) -> Result<decomp::Config, Error> {
        let length = self
            .n
            .checked_mul(
                self.lwe
                    .checked_next_power_of_two()
                    .ok_or_else(|| error("round overflow"))?,
            )
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| error("source length overflow"))?;
        decomp::Config::new::<F>(self.br_bits, length, self.repetitions).map_err(convert)
    }
    /// Packed variable counts for source, helper, final-stage source and helper.
    pub fn variables(&self, width: usize) -> Result<[usize; 4], Error> {
        if !width.is_power_of_two() || width > self.n {
            return Err(error("invalid packing width"));
        }
        let short = (2 * self.n / width).ilog2() as usize;
        let source = short + self.lwe.next_power_of_two().ilog2() as usize;
        let lanes = width.ilog2() as usize;
        Ok([source, source + lanes, short, short + lanes])
    }
}
/// Trusted PCS geometries; never serialized in a proof or accepted from one.
pub struct Parameters<'a, C> {
    pub source: &'a PcsParameters<C>,
    pub helper: &'a PcsParameters<C>,
    pub final_source: &'a PcsParameters<C>,
    pub final_helper: &'a PcsParameters<C>,
}
impl<C> Parameters<'_, C> {
    fn validate(&self, cfg: &Config) -> Result<(), Error> {
        let width = self.source.width();
        let dims = cfg.variables(width)?;
        for (pp, n) in [
            self.source,
            self.helper,
            self.final_source,
            self.final_helper,
        ]
        .into_iter()
        .zip(dims)
        {
            if pp.width() != width || pp.num_vars() != n {
                return Err(error("incompatible trusted PCS geometry"));
            }
        }
        Ok(())
    }
}
/// Public NAND input and expected output ciphertexts in the original LWE key.
#[derive(Clone, Debug, Serialize)]
pub struct Statement<'a, F> {
    pub left_a: &'a [F],
    pub left_b: F,
    pub right_a: &'a [F],
    pub right_b: F,
    pub output_a: &'a [F],
    pub output_b: F,
}
/// Reusable trusted public-key setup plus prover opening states.
pub struct ProverSetup<F, H: Hash + Send + Sync> {
    verifier: VerifierSetup<H::Output>,
    br: bk::ProverKey<F, H>,
    ks: ks::ProverKey<F, H>,
}
/// Trusted key roots/configuration only. Intentionally not proof-deserializable.
#[derive(Clone, Debug, Serialize)]
pub struct VerifierSetup<O> {
    config: Config,
    br: bk::PublicKey<O>,
    ks: ks::ExpectedKey<O>,
}
impl<F, H: Hash + Send + Sync> ProverSetup<F, H> {
    /// Obtain an independent verifier setup without private PCS state.
    pub fn verifier(&self) -> VerifierSetup<H::Output> {
        self.verifier.clone()
    }
}
/// Public preprocessing uses native evaluation-key ciphertexts, never a trace.
pub fn preprocess<F, H, C>(
    pp: &Parameters<'_, C>,
    config: Config,
    br: &[NTTRGSW<F>],
    ks: &[NTTGadgetRLWE<F>],
) -> Result<ProverSetup<F, H>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    pp.validate(&config)?;
    let br = bk::prepare::<F, H, C>(pp.source, config.n, br).map_err(convert)?;
    if br.expected().rounds() != config.lwe || br.expected().basis_bits() != config.br_bits {
        return Err(error(
            "bootstrapping key does not match trusted configuration",
        ));
    }
    let ks = ks::preprocess::<F, H, C>(
        pp.final_source,
        ks::Config::new::<F>(config.n, config.lwe, config.ks_bits, config.repetitions)
            .map_err(convert)?,
        ks,
    )
    .map_err(convert)?;
    let verifier = VerifierSetup {
        config,
        br: br.expected().clone(),
        ks: ks.expected().clone(),
    };
    Ok(ProverSetup { verifier, br, ks })
}
/// Complete serializable proof. The sole shared final accumulator is a witness,
/// constrained by continuity and consumed by final key switching.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O, D = decomp::LaneProof<F, O>, A = relation::RelationProof<F, O>> {
    /// Wire/transcript version, checked before reading canonical source vectors.
    pub protocol_version: u32,
    pub coefficients: Vec<Commitment<O>>,
    pub evaluations: Vec<Commitment<O>>,
    pub decomposition_inputs: Vec<Commitment<O>>,
    pub accumulators: Vec<Commitment<O>>,
    pub final_accumulator: Vec<F>,
    pub hadamard: A,
    pub ntt: Vec<ntt::Proof<F, O>>,
    pub decomposition: Vec<D>,
    pub accumulator: acc::Proof<F, O>,
    pub monomial: mono::Proof<F, O>,
    pub key_switch: ks::Proof<F, O, D>,
}
/// Complete experimental extension-comparison proof; checked wire version 3.
pub type ExtensionProof<F, EF, O> = Proof<F, O, decomp::ExtensionProof<F, EF, O>>;
/// Complete version-4 proof; aggregation is within the Hadamard relation.
pub type AggregatedProof<F, EF, O> = Proof<F, O, decomp::ExtensionProof<F, EF, O>, relation::aggregate::Proof<F, EF, O>>;
/// Version-5 proof: shared lookup source authentication within each decomposition.
pub type DeferredProof<F,EF,O>=Proof<F,O,decomp::deferred::Proof<F,EF,O>,relation::aggregate::Proof<F,EF,O>>;
/// Version-8 complete proof with shared-query comparisons per decomposition.
pub type SharedProof<F,EF,O>=Proof<F,O,decomp::shared::Proof<F,EF,O>,relation::aggregate::Proof<F,EF,O>>;
/// Prover phase costs; public setup, native evaluation and serialization are external.
#[derive(Default, Debug)]
pub struct ProverStatistics {
    pub preparation: Duration,
    pub hadamard: Duration,
    pub ntt: Duration,
    pub decomposition: Duration,
    pub accumulator: Duration,
    pub monomial: Duration,
    pub key_switch: Duration,
}
/// Prove a complete NAND relation from a native witness (raw or padded trace).
pub fn prove<F, H, C>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statement: &Statement<'_, F>,
    trace: &PBSTrace<F>,
) -> Result<Proof<F, H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_with_statistics(
        pp,
        setup,
        statement,
        trace,
        &mut ProverStatistics::default(),
    )
}
/// Complete proof with measurements of actual prover phases.
pub fn prove_with_statistics<F, H, C>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statement: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    stats: &mut ProverStatistics,
) -> Result<Proof<F, H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, decomp::Lanes, hadamard::Independent>(pp, setup, statement, trace, stats)
}

/// Prove every native NAND PBS stage using extension-field comparisons.
/// Repetitions in trusted setup count independent extension pairs. Experimental:
/// the composed security bound and promotion requirements remain open.
pub fn prove_extension<F, EF, H, C>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statement: &Statement<'_, F>,
    trace: &PBSTrace<F>,
) -> Result<ExtensionProof<F, EF, H::Output>, Error>
where
    F: NTTField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_extension_with_statistics::<F, EF, H, C>(
        pp,
        setup,
        statement,
        trace,
        &mut ProverStatistics::default(),
    )
}

/// Complete extension-comparison proof with the actual prover phase costs.
pub fn prove_extension_with_statistics<F, EF, H, C>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statement: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    stats: &mut ProverStatistics,
) -> Result<ExtensionProof<F, EF, H::Output>, Error>
where
    F: NTTField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, decomp::Extension<EF>, hadamard::Independent>(pp, setup, statement, trace, stats)
}

/// Prove a complete NAND using extension comparisons and aggregate Hadamard PCS.
/// Experimental version 4; this is within one PBS, not cross-statement batching.
pub fn prove_aggregated<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&ProverSetup<F,H>,
    statement:&Statement<'_,F>,trace:&PBSTrace<F>) -> Result<AggregatedProof<F,EF,H::Output>,Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    prove_aggregated_with_statistics::<F,EF,H,C>(pp,setup,statement,trace,&mut ProverStatistics::default())
}

/// Version-4 prover with complete phase costs; setup and native keys are reused.
pub fn prove_aggregated_with_statistics<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&ProverSetup<F,H>,
    statement:&Statement<'_,F>,trace:&PBSTrace<F>,stats:&mut ProverStatistics)
    -> Result<AggregatedProof<F,EF,H::Output>,Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    prove_impl::<F,H,C,decomp::Extension<EF>,hadamard::Aggregated<EF>>(pp,setup,statement,trace,stats)
}

/// Prove all NAND stages with aggregated Hadamard and deferred lookup sources.
/// Experimental version 5; source sharing is within a decomposition, not across statements.
pub fn prove_deferred<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&ProverSetup<F,H>,
    statement:&Statement<'_,F>,trace:&PBSTrace<F>)->Result<DeferredProof<F,EF,H::Output>,Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    prove_deferred_with_statistics::<F,EF,H,C>(pp,setup,statement,trace,&mut ProverStatistics::default())
}
/// Version-5 complete prover phase costs, including final source authentication.
pub fn prove_deferred_with_statistics<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&ProverSetup<F,H>,
    statement:&Statement<'_,F>,trace:&PBSTrace<F>,stats:&mut ProverStatistics)
    ->Result<DeferredProof<F,EF,H::Output>,Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    prove_impl::<F,H,C,decomp::deferred::Deferred<EF>,hadamard::Aggregated<EF>>(pp,setup,statement,trace,stats)
}
/// Prove all NAND stages with aggregated Hadamard and shared lookup sources.
/// Experimental version 8; source sharing is within a decomposition, not across statements.
pub fn prove_shared<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&ProverSetup<F,H>,
    statement:&Statement<'_,F>,trace:&PBSTrace<F>)->Result<SharedProof<F,EF,H::Output>,Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    prove_shared_with_statistics::<F,EF,H,C>(pp,setup,statement,trace,&mut ProverStatistics::default())
}
/// Version-8 complete prover phase costs, including final source authentication.
pub fn prove_shared_with_statistics<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&ProverSetup<F,H>,
    statement:&Statement<'_,F>,trace:&PBSTrace<F>,stats:&mut ProverStatistics)
    ->Result<SharedProof<F,EF,H::Output>,Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    prove_impl::<F,H,C,decomp::shared::Shared<EF>,hadamard::Aggregated<EF>>(pp,setup,statement,trace,stats)
}

fn prove_impl<F, H, C, B, R>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statement: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    stats: &mut ProverStatistics,
) -> Result<Proof<F, H::Output, decomp::Proof<F, H::Output, B::Proof>, R::Proof>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: decomp::Backend<F, H, C>,
    R: hadamard::Backend<F,H,C>,
{
    prove_inner::<F,H,C,B,R>(pp,setup,statement,trace,stats,None)
}

struct EvaluationWitness<F,H:Hash+Send+Sync> {
    tables:Vec<PackedTable<F>>,
    states:Vec<State<F,H>>,
    coefficients:Vec<State<F,H>>,
    borrows:Vec<Vec<State<F,H>>>,
    key_switch:Option<ks::ComparisonWitness<F,H>>,
}

fn prove_inner<F, H, C, B, R>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statement: &Statement<'_, F>,
    trace: &PBSTrace<F>,
    stats: &mut ProverStatistics,
    retain: Option<&mut Option<EvaluationWitness<F,H>>>,
) -> Result<Proof<F, H::Output, decomp::Proof<F, H::Output, B::Proof>, R::Proof>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: decomp::Backend<F, H, C>,
    R: hadamard::Backend<F,H,C>,
{
    if B::BATCHED && (!R::BATCHED || retain.is_none()) {
        return Err(error("comparison members require a complete retaining batch prover"));
    }
    let version=if B::BATCHED { COMPARISON_BATCH_PROTOCOL_VERSION } else if R::BATCHED { BATCH_PROTOCOL_VERSION } else if B::SHARED { SHARED_PROTOCOL_VERSION } else if B::DEFERRED { DEFERRED_PROTOCOL_VERSION } else if R::AGGREGATED { AGGREGATED_PROTOCOL_VERSION } else if B::EXTENSION { EXTENSION_PROTOCOL_VERSION } else { PROTOCOL_VERSION };
    let timer = Instant::now();
    let cfg = &setup.verifier.config;
    pp.validate(cfg)?;
    let width = pp.source.width();
    let d = cfg
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    let count = 2 * d + 1;
    let (plan, initial) = public_inputs(cfg, statement)?;
    let (coefficient_tables, acc_tables, input_tables, final_accumulator) =
        witness::<F>(cfg, width, trace)?;
    if coefficient_tables.len() != count {
        return Err(error("native digit count"));
    }
    let (coefficients, co_states) = commit::<F, H, C>(pp.source, &coefficient_tables)?;
    F::init_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let native = F::get_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let evaluation_tables = coefficient_tables
        .iter()
        .map(|t| {
            let mut v = t.values().to_vec();
            for p in v.chunks_exact_mut(cfg.n) {
                native.transform_slice(p);
            }
            PackedTable::new(pp.source.num_vars(), width, v).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, ev_states) = commit::<F, H, C>(pp.source, &evaluation_tables)?;
    let (accumulators, ac_states) = commit::<F, H, C>(pp.source, &acc_tables)?;
    let (decomposition_inputs, in_states) = commit::<F, H, C>(pp.source, &input_tables)?;
    let mut trans = Transcript::new_direct();
    bind::<F, H, C>(
        &mut trans,
        version,
        pp,
        &setup.verifier,
        statement,
        &coefficients,
        &evaluations,
        &decomposition_inputs,
        &accumulators,
        &final_accumulator,
    )?;
    let co = oracles(pp.source, &coefficient_tables, &coefficients, &co_states);
    let ev = oracles(pp.source, &evaluation_tables, &evaluations, &ev_states);
    let ac = oracles(pp.source, &acc_tables, &accumulators, &ac_states);
    let input = oracles(pp.source, &input_tables, &decomposition_inputs, &in_states);
    let key = setup.br.oracles(pp.source).map_err(convert)?;
    stats.preparation += timer.elapsed();
    let timer = Instant::now();
    let hadamard=if R::BATCHED {
        R::prove(&mut trans,&hadamard_shape(pp.source,2*d),pp.source,&[],&[],&[])?
    } else {
        let mut factors = Vec::with_capacity(4 * d + 1);
        let mut roots = Vec::with_capacity(4 * d + 1);
        let mut states = Vec::with_capacity(4 * d + 1);
        for i in 0..2 * d {
            for o in [&ev[i], &key[i]] {
                factors.push(o.table.clone());
                roots.push(o.commitment.clone());
                states.push(o.state);
            }
        }
        factors.push(evaluation_tables[2 * d].clone());
        roots.push(evaluations[2 * d].clone());
        states.push(&ev_states[2 * d]);
        R::prove(&mut trans, &hadamard_shape(pp.source, 2*d), pp.source,
            &factors, &roots, &states)?
    };
    stats.hadamard+=timer.elapsed();
    let timer = Instant::now();
    let ntt_shape = ntt::Shape::new::<F, C>(pp.source, cfg.n).map_err(convert)?;
    let ntt = (0..count)
        .map(|i| ntt::prove::<F, H, C>(&mut trans, &ntt_shape, &co[i], &ev[i]).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    stats.ntt += timer.elapsed();
    let timer = Instant::now();
    let config = cfg.decomposition::<F>()?;
    let mut decomposition = Vec::with_capacity(2);
    let mut comparison_borrows = Vec::new();
    for half in 0..2 {
        let mut borrow_owner = None;
        decomposition.push(
            decomp::prove_retained::<F, H, C, B>(
                &mut trans,
                &config,
                &input[half],
                Some(pp.helper),
                &co[half * d..(half + 1) * d].iter().collect::<Vec<_>>(),
                &mut crate::packed_lane_lookup::ProverStatistics::default(),
                if B::BATCHED {Some(&mut borrow_owner)} else {None},
            )
            .map_err(convert)?,
        );
        if B::BATCHED { comparison_borrows.push(borrow_owner.ok_or_else(||error("missing blind-rotation comparison owner"))?); }
    }
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
    let accumulator = acc::prove::<F, H, C>(
        &mut trans,
        &acc::Shape::new(cfg.n, cfg.lwe).map_err(convert)?,
        &initial,
        &final_accumulator,
        &sources,
    )
    .map_err(convert)?;
    stats.accumulator += timer.elapsed();
    let timer = Instant::now();
    let monomial = mono::prove::<F, H, C>(&mut trans, &plan, &[&ac[0], &ac[1]]).map_err(convert)?;
    stats.monomial += timer.elapsed();
    let timer = Instant::now();
    let coefficients_ks = ks::from_native(width, &trace.key_switching_trace).map_err(convert)?;
    let mut key_switch_owner = None;
    let key_switch = ks::prove_retained::<F, H, C, B>(
        &mut trans,
        pp.final_source,
        pp.final_helper,
        &setup.ks,
        &final_accumulator,
        statement.output_a,
        statement.output_b,
        &coefficients_ks,
        if B::BATCHED {Some(&mut key_switch_owner)} else {None},
    )
    .map_err(convert)?;
    stats.key_switch += timer.elapsed();
    if let Some(sink)=retain {
        *sink=Some(EvaluationWitness {
            tables:if B::BATCHED {Vec::new()} else {evaluation_tables},
            states:ev_states, coefficients:if B::BATCHED {co_states} else {Vec::new()},
            borrows:comparison_borrows, key_switch:key_switch_owner,
        });
    }
    Ok(Proof {
        protocol_version: version,
        coefficients,
        evaluations,
        decomposition_inputs,
        accumulators,
        final_accumulator,
        hadamard,
        ntt,
        decomposition,
        accumulator,
        monomial,
        key_switch,
    })
}
/// Verify one complete NAND proof from trusted public setup and ciphertexts only.
/// No native trace, private PCS state, independent endpoints or prover parameters.
pub fn verify<F, H, C>(
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    statement: &Statement<'_, F>,
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, decomp::Lanes, hadamard::Independent>(pp, setup, statement, proof)
}

/// Verify version-3 complete NAND proofs from trusted public setup/ciphertexts.
/// Both blind-rotation and final key-switch decomposition use the extension
/// backend; no native trace or independent endpoint is accepted by this API.
pub fn verify_extension<F, EF, H, C>(
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    statement: &Statement<'_, F>,
    proof: &ExtensionProof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, decomp::Extension<EF>, hadamard::Independent>(pp, setup, statement, proof)
}

/// Verify complete version-4 NAND proofs using only trusted setup/ciphertexts.
pub fn verify_aggregated<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&VerifierSetup<H::Output>,
    statement:&Statement<'_,F>,proof:&AggregatedProof<F,EF,H::Output>) -> Result<(),Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    verify_impl::<F,H,C,decomp::Extension<EF>,hadamard::Aggregated<EF>>(pp,setup,statement,proof)
}

/// Verify a complete version-5 certificate using only trusted setup and ciphertexts.
pub fn verify_deferred<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&VerifierSetup<H::Output>,
    statement:&Statement<'_,F>,proof:&DeferredProof<F,EF,H::Output>)->Result<(),Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    verify_impl::<F,H,C,decomp::deferred::Deferred<EF>,hadamard::Aggregated<EF>>(pp,setup,statement,proof)
}
/// Verify a complete version-8 certificate using only trusted setup and ciphertexts.
pub fn verify_shared<F,EF,H,C>(pp:&Parameters<'_,C>,setup:&VerifierSetup<H::Output>,
    statement:&Statement<'_,F>,proof:&SharedProof<F,EF,H::Output>)->Result<(),Error>
where F:NTTField+Serialize,EF:algebra::AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    verify_impl::<F,H,C,decomp::shared::Shared<EF>,hadamard::Aggregated<EF>>(pp,setup,statement,proof)
}

fn verify_impl<F, H, C, B, R>(
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    statement: &Statement<'_, F>,
    proof: &Proof<F, H::Output, decomp::Proof<F, H::Output, B::Proof>, R::Proof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: decomp::Backend<F, H, C>,
    R: hadamard::Backend<F,H,C>,
{
    if B::BATCHED && !R::BATCHED {return Err(error("comparison members require the complete batch verifier"));}
    let version=if B::BATCHED { COMPARISON_BATCH_PROTOCOL_VERSION } else if R::BATCHED { BATCH_PROTOCOL_VERSION } else if B::SHARED { SHARED_PROTOCOL_VERSION } else if B::DEFERRED { DEFERRED_PROTOCOL_VERSION } else if R::AGGREGATED { AGGREGATED_PROTOCOL_VERSION } else if B::EXTENSION { EXTENSION_PROTOCOL_VERSION } else { PROTOCOL_VERSION };
    if proof.protocol_version
        != version
    {
        return Err(error("unsupported complete PBS protocol version"));
    }
    let cfg = &setup.config;
    pp.validate(cfg)?;
    let d = cfg
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    let count = 2 * d + 1;
    let (plan, initial) = public_inputs(cfg, statement)?;
    let mut trans = Transcript::new_direct();
    bind::<F, H, C>(
        &mut trans,
        version,
        pp,
        setup,
        statement,
        &proof.coefficients,
        &proof.evaluations,
        &proof.decomposition_inputs,
        &proof.accumulators,
        &proof.final_accumulator,
    )?;
    if proof.ntt.len() != count || proof.decomposition.len() != 2 {
        return Err(error("child proof counts"));
    }
    let co = public_oracles(pp.source, &proof.coefficients);
    let ev = public_oracles(pp.source, &proof.evaluations);
    let input = public_oracles(pp.source, &proof.decomposition_inputs);
    R::verify(&mut trans, pp.source, &setup.br, &proof.evaluations, &proof.hadamard)?;
    let shape = ntt::Shape::new::<F, C>(pp.source, cfg.n).map_err(convert)?;
    for i in 0..count {
        ntt::verify::<F, H, C>(&mut trans, &shape, &co[i], &ev[i], &proof.ntt[i])
            .map_err(convert)?;
    }
    for half in 0..2 {
        decomp::verify_impl::<F, H, C, B>(
            &mut trans,
            &cfg.decomposition::<F>()?,
            &input[half],
            Some(pp.helper),
            &public_oracles(pp.source, &proof.coefficients[half * d..(half + 1) * d]),
            &proof.decomposition[half],
        )
        .map_err(convert)?;
    }
    let sources = [
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.accumulators[0],
        },
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.accumulators[1],
        },
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.accumulators[2],
        },
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.accumulators[3],
        },
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.coefficients[2 * d],
        },
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.decomposition_inputs[0],
        },
        VerifierOracle {
            parameters: pp.source,
            commitment: &proof.decomposition_inputs[1],
        },
    ];
    acc::verify::<F, H, C>(
        &mut trans,
        &acc::Shape::new(cfg.n, cfg.lwe).map_err(convert)?,
        &initial,
        &proof.final_accumulator,
        &sources,
        &proof.accumulator,
    )
    .map_err(convert)?;
    mono::verify::<F, H, C>(
        &mut trans,
        &plan,
        &public_oracles(pp.source, &proof.accumulators[..2]),
        &proof.monomial,
    )
    .map_err(convert)?;
    ks::verify_impl::<F, H, C, B>(
        &mut trans,
        pp.final_source,
        pp.final_helper,
        &setup.ks,
        &proof.final_accumulator,
        statement.output_a,
        statement.output_b,
        &proof.key_switch,
    )
    .map_err(convert)?;
    Ok(())
}
fn public_inputs<F: NTTField>(
    cfg: &Config,
    s: &Statement<'_, F>,
) -> Result<(mono::Plan, Vec<F>), Error> {
    if [s.left_a.len(), s.right_a.len(), s.output_a.len()]
        .iter()
        .any(|&n| n != cfg.lwe)
    {
        return Err(error("public ciphertext dimensions"));
    }
    let mask = s
        .left_a
        .iter()
        .zip(s.right_a)
        .map(|(&a, &b)| a + b)
        .collect::<Vec<_>>();
    let plan = mono::Plan::from_field_mask(cfg.n, &mask).map_err(convert)?;
    let lut = mono::nand_lut::<F>(cfg.n, cfg.lut_step).map_err(convert)?;
    let initial = mono::initial_accumulator(&lut, s.left_b + s.right_b).map_err(convert)?;
    Ok((plan, initial))
}
fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    version: u32,
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    s: &Statement<'_, F>,
    coefficients: &[Commitment<H::Output>],
    evaluations: &[Commitment<H::Output>],
    inputs: &[Commitment<H::Output>],
    accumulators: &[Commitment<H::Output>],
    final_acc: &[F],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let count = 2 * setup
        .config
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?
        + 1;
    if coefficients.len() != count
        || evaluations.len() != count
        || inputs.len() != 2
        || accumulators.len() != 4
        || final_acc.len() != 2 * setup.config.n
    {
        return Err(error("canonical source or endpoint counts"));
    }
    let contexts = [pp.source, pp.helper, pp.final_source, pp.final_helper]
        .iter()
        .map(|p| p.context_digest::<F, H>().map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    trans.append_message(
        match version {
            PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS v2".as_slice(),
            EXTENSION_PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS extension comparisons v3".as_slice(),
            BATCH_PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS joint batch member v6".as_slice(),
            COMPARISON_BATCH_PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS joint comparison batch member v9".as_slice(),
            SHARED_PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS shared-query comparisons v8".as_slice(),
            DEFERRED_PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS deferred lookup sources v5".as_slice(),
            AGGREGATED_PROTOCOL_VERSION => b"HasteBoots complete binary NAND PBS aggregated Hadamard v4".as_slice(),
            _ => return Err(error("unsupported complete PBS protocol version")),
        },
        &(
            version,
            setup,
            contexts,
            s,
            coefficients,
            evaluations,
            inputs,
            accumulators,
            final_acc,
        ),
    );
    Ok(())
}
fn witness<F: NTTField>(
    cfg: &Config,
    width: usize,
    trace: &PBSTrace<F>,
) -> Result<
    (
        Vec<PackedTable<F>>,
        Vec<PackedTable<F>>,
        Vec<PackedTable<F>>,
        Vec<F>,
    ),
    Error,
> {
    let shape = acc::Shape::new(cfg.n, cfg.lwe).map_err(convert)?;
    let active = cfg.n * cfg.lwe;
    let half = cfg.n * shape.padded_rounds();
    let vars = (2 * half / width).ilog2() as usize;
    let pad = |v: &[F]| -> Result<Vec<F>, Error> {
        if v.len() != active && v.len() != half {
            return Err(error("native active/padded source length"));
        }
        let mut out = vec![F::zero(); half];
        out[..active].copy_from_slice(&v[..active]);
        Ok(out)
    };
    let pair = |a: &[F], b: &[F]| -> Result<PackedTable<F>, Error> {
        let mut v = pad(a)?;
        v.extend(pad(b)?);
        PackedTable::new(vars, width, v).map_err(convert)
    };
    let h = &trace.blind_rotation_trace.hadamard_trace;
    let d = cfg
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    if h.num_hadamard != 2 * d || h.vec_hadamard.len() != 2 * d {
        return Err(error("native blind-rotation digit count"));
    }
    let mut co = h
        .vec_hadamard
        .iter()
        .map(|h| pair(&h.bit.poly, &h.bit.poly))
        .collect::<Result<Vec<_>, _>>()?;
    co.push(pair(&h.sum_prod.poly.0, &h.sum_prod.poly.1)?);
    let a = &trace.blind_rotation_trace.acc_trace;
    let acc = [
        &a.input_acc.poly,
        &a.monomial_times_acc.poly,
        &a.external_product_input.poly,
        &a.output_acc.poly,
    ]
    .iter()
    .map(|(a, b)| pair(a, b))
    .collect::<Result<Vec<_>, _>>()?;
    let e = &acc[2];
    let input = vec![
        PackedTable::new(
            vars,
            width,
            e.values()[..half]
                .iter()
                .chain(&e.values()[..half])
                .copied()
                .collect(),
        )
        .map_err(convert)?,
        PackedTable::new(
            vars,
            width,
            e.values()[half..]
                .iter()
                .chain(&e.values()[half..])
                .copied()
                .collect(),
        )
        .map_err(convert)?,
    ];
    if a.final_acc.poly.0.len() != cfg.n || a.final_acc.poly.1.len() != cfg.n {
        return Err(error("native final accumulator length"));
    }
    Ok((
        co,
        acc,
        input,
        a.final_acc
            .poly
            .0
            .iter()
            .chain(&a.final_acc.poly.1)
            .copied()
            .collect(),
    ))
}
fn hadamard_shape<F: NTTField, C>(pp: &PcsParameters<C>, count: usize) -> PackedShape<F> {
    let mut terms = (0..count)
        .map(|i| (F::one(), vec![2 * i, 2 * i + 1]))
        .collect::<Vec<_>>();
    terms.push((-F::one(), vec![2 * count]));
    PackedShape {
        num_vars: pp.num_vars(),
        width: pp.width(),
        num_factors: 2 * count + 1,
        terms,
    }
}
fn commit<F, H, C>(
    pp: &PcsParameters<C>,
    tables: &[PackedTable<F>],
) -> Result<(Vec<Commitment<H::Output>>, Vec<State<F, H>>), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    tables
        .iter()
        .map(|t| pp.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.into_iter().unzip())
}
fn oracles<'a, F, H: Hash + Send + Sync, C>(
    pp: &'a PcsParameters<C>,
    tables: &'a [PackedTable<F>],
    roots: &'a [Commitment<H::Output>],
    states: &'a [State<F, H>],
) -> Vec<ProverOracle<'a, F, H, C>> {
    tables
        .iter()
        .zip(roots)
        .zip(states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: pp,
            table,
            commitment,
            state,
        })
        .collect()
}
fn public_oracles<'a, O, C>(
    pp: &'a PcsParameters<C>,
    roots: &'a [Commitment<O>],
) -> Vec<VerifierOracle<'a, O, C>> {
    roots
        .iter()
        .map(|commitment| VerifierOracle {
            parameters: pp,
            commitment,
        })
        .collect()
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

//! Count parent context calls in complete certificates, outside adapter internals.
use super::*;
use algebra::{PrimeField, matrix_weighted::MatrixPair};
use pcs::{
    classical_profile::{Backend, ClassicalProfile, ProfileParameters, Role, Specification},
    utils::hash::Hash,
};
use sha2::Sha512;
use std::sync::atomic::{AtomicUsize, Ordering};
static COUNTS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static PCS_CALLS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static TOTAL_CALLS: AtomicUsize = AtomicUsize::new(0);
static CORRUPT_AT: AtomicUsize = AtomicUsize::new(0);
static CORRUPTED: AtomicUsize = AtomicUsize::new(0);
fn reset_calls(corrupt_at: usize) {
    CORRUPT_AT.store(0, Ordering::Relaxed);
    TOTAL_CALLS.store(0, Ordering::Relaxed);
    CORRUPTED.store(0, Ordering::Relaxed);
    for counter in &PCS_CALLS {
        counter.store(0, Ordering::Relaxed);
    }
    CORRUPT_AT.store(corrupt_at, Ordering::Relaxed);
}
fn count_call(role: usize) -> bool {
    PCS_CALLS[role].fetch_add(1, Ordering::Relaxed);
    let ordinal = TOTAL_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if CORRUPT_AT.load(Ordering::Relaxed) == ordinal {
        CORRUPTED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}
struct Contexts<'a, P> {
    inner: &'a P,
    role: usize,
    num_vars: usize,
    width: usize,
}
impl<F: PrimeField, H: Hash + Send + Sync, P: CanonicalPcs<F, H>> CanonicalPcs<F, H>
    for Contexts<'_, P>
{
    type State = P::State;
    type SingleProof = P::SingleProof;
    type BatchProof = P::BatchProof;
    type Error = P::Error;
    const LINEAR_DOMAIN: &'static [u8] = P::LINEAR_DOMAIN;
    const NTT_DOMAIN: &'static [u8] = P::NTT_DOMAIN;
    const RELATION_DOMAIN: &'static [u8] = P::RELATION_DOMAIN;
    const ACCUMULATOR_DOMAIN: &'static [u8] = P::ACCUMULATOR_DOMAIN;
    const REGISTRY_DOMAIN: &'static [u8] = P::REGISTRY_DOMAIN;
    const CLAIM_DOMAIN: &'static [u8] = P::CLAIM_DOMAIN;
    const SEAL_DOMAIN: &'static [u8] = P::SEAL_DOMAIN;
    fn num_vars(&self) -> usize {
        self.num_vars
    }
    fn width(&self) -> usize {
        self.width
    }
    fn opening_limit(&self) -> Option<usize> {
        <P as CanonicalPcs<F, H>>::opening_limit(self.inner)
    }
    fn remaining_openings(&self, state: &Self::State) -> Result<Option<usize>, Self::Error> {
        <P as CanonicalPcs<F, H>>::remaining_openings(self.inner, state)
    }
    fn context(&self) -> Result<H::Output, Self::Error> {
        COUNTS[self.role].fetch_add(1, Ordering::Relaxed);
        <P as CanonicalPcs<F, H>>::context(self.inner)
    }
    fn normalize_claim(
        &self,
        q: Vec<MatrixPair<F>>,
        v: Vec<F>,
    ) -> Result<(Vec<MatrixPair<F>>, Vec<F>), Self::Error> {
        <P as CanonicalPcs<F, H>>::normalize_claim(self.inner, q, v)
    }
    fn normalize_values(&self, v: Vec<F>) -> Vec<F> {
        <P as CanonicalPcs<F, H>>::normalize_values(self.inner, v)
    }
    fn validate_values(&self, v: &[F]) -> Result<(), Self::Error> {
        <P as CanonicalPcs<F, H>>::validate_values(self.inner, v)
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        t: &PackedTable<F>,
        r: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Self::Error> {
        <P as CanonicalPcs<F, H>>::commit(self.inner, t, r)
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        <P as CanonicalPcs<F, H>>::table(state)
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[MatrixPair<F>],
        v: &[F],
    ) -> Result<Self::SingleProof, Self::Error> {
        <P as CanonicalPcs<F, H>>::open(self.inner, t, root, state, q, v)
    }
    fn open_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[Vec<MatrixPair<F>>],
        v: &[Vec<F>],
    ) -> Result<Self::BatchProof, Self::Error> {
        <P as CanonicalPcs<F, H>>::open_many(self.inner, t, root, state, q, v)
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[MatrixPair<F>],
        v: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Self::Error> {
        if count_call(self.role) {
            let mut altered = v.to_vec();
            assert!(!altered.is_empty());
            altered[0] += F::one();
            return <P as CanonicalPcs<F, H>>::verify(self.inner, t, root, q, &altered, proof);
        }
        <P as CanonicalPcs<F, H>>::verify(self.inner, t, root, q, v, proof)?;
        Ok(())
    }
    fn verify_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[Vec<MatrixPair<F>>],
        v: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Self::Error> {
        if count_call(self.role) {
            let mut altered = v.to_vec();
            assert!(!altered.is_empty() && !altered[0].is_empty());
            altered[0][0] += F::one();
            return <P as CanonicalPcs<F, H>>::verify_many(self.inner, t, root, q, &altered, proof);
        }
        <P as CanonicalPcs<F, H>>::verify_many(self.inner, t, root, q, v, proof)?;
        Ok(())
    }
}

fn exercise_bundle<F, E, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let roles: [Contexts<'_, P>; 4] = std::array::from_fn(|role| Contexts {
        inner: &bundle.roles()[role],
        role,
        num_vars: bundle.roles()[role].num_vars(),
        width: bundle.roles()[role].width(),
    });
    let pp = Parameters {
        coefficients: &roles[0],
        evaluations: &roles[0],
        key: &roles[0],
        inputs: &roles[0],
        borrows: &roles[0],
        helper: &roles[1],
        accumulators: [&roles[0]; 4],
        monomial: &roles[0],
        final_stage: final_stage::Parameters {
            coefficients: &roles[2],
            evaluations: &roles[2],
            key: &roles[2],
            input: &roles[2],
            borrows: &roles[2],
            helper: &roles[3],
        },
    };
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let br = vec![NTTRGSW::<F>::zero(32, Basis::new(8)); 21];
    let ks = vec![NTTGadgetRLWE::<F>::zero(32, Basis::new(5))];
    let setup = canonical_setup::preprocess::<F, Sha512, _, _>(
        &canonical_setup::Parameters {
            source: &roles[0],
            helper: &roles[1],
            final_source: &roles[2],
            final_helper: &roles[3],
        },
        cfg,
        &br,
        &ks,
        &mut StdRng::seed_from_u64(8101),
    )
    .unwrap();
    let (statement, mut proof, _) = make_with_transcript::<F, E, Sha512, _, stages::ClassicalShared>(
        &pp,
        &setup,
        Attack::Control,
        8102,
        bundle.profile().parent_transcript::<F>().unwrap(),
    );
    let transcript = bundle.profile().parent_transcript::<F>().unwrap();
    for counter in &COUNTS {
        counter.store(0, Ordering::Relaxed);
    }
    reset_calls(0);
    verify_inner::<F, E, Sha512, _, stages::ClassicalShared>(
        &pp,
        &setup.verifier(),
        &statement.borrowed(),
        &proof,
        Some(transcript),
    )
    .unwrap();
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let bits = (p - 1).ilog2() as usize + 1;
    let (d, s) = ((bits + 7) / 8, (bits + 4) / 5);
    let actual = std::array::from_fn::<_, 4, _>(|i| COUNTS[i].load(Ordering::Relaxed));
    assert_eq!(
        actual,
        [28 * d + 64, 2 * d + 7, 14 * s + 39, s + 8],
        "{:?}",
        bundle.profile().specification().backend
    );
    let caps = [16 * d + 22, 2 * d, 8 * s + 8, s];
    let calls = std::array::from_fn::<_, 4, _>(|i| PCS_CALLS[i].load(Ordering::Relaxed));
    let accepted_total: usize = calls.iter().sum();
    let version = bundle.profile().version();
    assert!(calls.iter().zip(caps).all(|(&actual, cap)| actual <= cap));
    println!(
        "HB_PARENT_CALL_RESOURCE_CONTROL {{\"kind\":\"accepted\",\"prime\":\"{p}\",\"version\":{version},\"calls\":{calls:?},\"caps\":{caps:?},\"native\":false,\"security_qualified\":false}}"
    );

    // Preserve the same valid complete proof and change only a child vector.
    // Late final-stage failures must retain earlier stage calls in the count.
    // Incrementing before delegation includes the first failing PCS invocation.
    macro_rules! rejected_vector {
        ($field:expr, $name:literal, $early:expr) => {{
            let saved = std::mem::take(&mut $field);
            reset_calls(0);
            let result = verify_inner::<F, E, Sha512, _, stages::ClassicalShared>(
                &pp, &setup.verifier(), &statement.borrowed(), &proof,
                Some(bundle.profile().parent_transcript::<F>().unwrap()),
            );
            assert!(result.is_err(), $name);
            let calls = std::array::from_fn::<_, 4, _>(|i| PCS_CALLS[i].load(Ordering::Relaxed));
            assert!(calls.iter().zip(caps).all(|(&actual, cap)| actual <= cap), $name);
            if $early { assert_eq!(calls, [0; 4]); }
            else { assert!(calls.iter().any(|&count| count > 0)); }
            println!("HB_PARENT_CALL_RESOURCE_CONTROL {{\"kind\":\"{}\",\"prime\":\"{p}\",\"version\":{version},\"calls\":{calls:?},\"caps\":{caps:?},\"native\":false,\"security_qualified\":false}}", $name);
            $field = saved;
        }};
    }
    rejected_vector!(proof.ntt, "missing_main_ntt", true);
    rejected_vector!(proof.decomposition, "missing_main_decomposition", true);
    rejected_vector!(proof.key_switch.ntt, "missing_final_ntt", false);
    rejected_vector!(
        proof.key_switch.decomposition.borrow_commitments,
        "missing_final_borrows",
        false
    );
    // Use the same valid parent proof. Only the chosen delegated claim is
    // perturbed, so earlier calls have the accepted execution's full history.
    for corrupt_at in [1, accepted_total / 2, accepted_total] {
        reset_calls(corrupt_at);
        let result = verify_inner::<F, E, Sha512, _, stages::ClassicalShared>(
            &pp,
            &setup.verifier(),
            &statement.borrowed(),
            &proof,
            Some(bundle.profile().parent_transcript::<F>().unwrap()),
        );
        CORRUPT_AT.store(0, Ordering::Relaxed);
        assert!(result.is_err());
        assert_eq!(CORRUPTED.load(Ordering::Relaxed), 1);
        let calls = std::array::from_fn::<_, 4, _>(|i| PCS_CALLS[i].load(Ordering::Relaxed));
        assert_eq!(calls.iter().sum::<usize>(), corrupt_at);
        assert!(calls.iter().zip(caps).all(|(&actual, cap)| actual <= cap));
        println!(
            "HB_PARENT_CALL_RESOURCE_CONTROL {{\"kind\":\"corrupt_delegated_claim\",\"prime\":\"{p}\",\"version\":{version},\"corrupt_at\":{corrupt_at},\"calls\":{calls:?},\"caps\":{caps:?},\"native\":false,\"security_qualified\":false}}"
        );
    }
}
fn exercise<F, E>(width: usize)
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use Backend::*;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    for backend in [
        Brakedown,
        Polyfrim,
        PolyfrimDictionary,
        FragmentedPipfri,
        FragmentedPipfriVirtual,
    ] {
        let roles = cfg.variables(width).unwrap().map(|num_vars| Role {
            num_vars,
            width,
            queries: 8,
            left_vars: (backend == Brakedown).then_some(num_vars / 2),
            block_width: (backend == Brakedown).then_some(width),
        });
        let profile = ClassicalProfile::new_atomic_zerocheck::<F, E>(Specification {
            backend,
            roles,
            blowup: 2,
            fragment_vars: matches!(backend, FragmentedPipfri | FragmentedPipfriVirtual)
                .then_some(4),
        })
        .unwrap();
        match backend {
            Brakedown => {
                exercise_bundle::<F, E, _>(profile.brakedown_parameters::<F, E>().unwrap())
            }
            Polyfrim => exercise_bundle::<F, E, _>(profile.polyfrim_parameters::<F, E>().unwrap()),
            PolyfrimDictionary => exercise_bundle::<F, E, _>(
                profile.polyfrim_dictionary_parameters::<F, E>().unwrap(),
            ),
            FragmentedPipfri => {
                exercise_bundle::<F, E, _>(profile.fragmented_parameters::<F, E>().unwrap())
            }
            FragmentedPipfriVirtual => {
                exercise_bundle::<F, E, _>(profile.fragmented_virtual_parameters::<F, E>().unwrap())
            }
        }
    }
}
#[test]
#[ignore = "complete ten-profile context audit with synthetic keys"]
fn complete_classical_parent_context_counts_match_stage_inventory() {
    // One test owns all counters; cryptographic adapter internals are delegated.
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

#[test]
#[ignore = "focused complete-PBS accepted/rejected PCS call resource control"]
fn complete_classical_parent_call_bounds_focused() {
    for atomic in [false, true] {
        exercise_focused::<algebra::BabyBear, algebra::BabyBearExtension6>(8, atomic);
        exercise_focused::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, atomic);
    }
}

fn exercise_focused<F, E>(width: usize, atomic: bool)
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize,
{
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let roles = cfg.variables(width).unwrap().map(|num_vars| Role {
        num_vars,
        width,
        queries: 8,
        left_vars: Some(num_vars / 2),
        block_width: Some(width),
    });
    let specification = Specification {
        backend: Backend::Brakedown,
        roles,
        blowup: 2,
        fragment_vars: None,
    };
    let profile = if atomic {
        ClassicalProfile::new_atomic_columns::<F, E>(specification)
    } else {
        ClassicalProfile::new_atomic_zerocheck::<F, E>(specification)
    }
    .unwrap();
    exercise_bundle::<F, E, _>(profile.brakedown_parameters::<F, E>().unwrap());
}

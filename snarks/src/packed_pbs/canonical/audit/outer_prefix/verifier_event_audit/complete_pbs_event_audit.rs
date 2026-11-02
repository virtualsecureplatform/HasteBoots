//! Streamed full-protocol controls; synthetic keys, not native qualification.
use super::*;
use crate::packed_pbs::{canonical::classical as protocol, canonical_setup};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Default)]
struct Counts {
    hashes: u64,
    xofs: u64,
    hash_bytes: u64,
    xof_bytes: u64,
    max_hash: usize,
    max_xof: usize,
}
struct Stream {
    writer: BufWriter<File>,
    digest: Sha512,
    phase: usize,
    counts: [Counts; 3],
    readers: Option<ReaderStream>,
}

/// Companion stream: legacy source/receipt audits retain their original file.
struct ReaderStream {
    writer: BufWriter<File>,
    digest: Sha512,
    starts: [u64; 3],
    reads: [u64; 3],
    output_bytes: [u64; 3],
}
impl ReaderStream {
    fn new(path: &Path) -> Self {
        let file = OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        let mut stream = Self { writer: BufWriter::new(file), digest: Sha512::default(),
            starts: [0; 3], reads: [0; 3], output_bytes: [0; 3] };
        stream.bytes(b"HB_ORACLE_READER_STREAM_V1\n");
        stream
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
        Digest::update(&mut self.digest, bytes);
    }
    fn hash(&mut self, phase: usize, output: Digest512, input: &[u8]) {
        self.bytes(&[1, phase as u8]);
        self.bytes(&u64::try_from(input.len()).unwrap().to_le_bytes());
        self.bytes(input);
        self.bytes(&output.0);
    }
    fn start(&mut self, phase: usize, reader: u64, input: &[u8]) {
        self.starts[phase] += 1;
        self.bytes(&[2, phase as u8]);
        self.bytes(&reader.to_le_bytes());
        self.bytes(&u64::try_from(input.len()).unwrap().to_le_bytes());
        self.bytes(input);
    }
    fn output(&mut self, phase: usize, reader: u64, offset: u128, bytes: &[u8]) {
        self.reads[phase] += 1;
        self.output_bytes[phase] += u64::try_from(bytes.len()).unwrap();
        self.bytes(&[3, phase as u8]);
        self.bytes(&reader.to_le_bytes());
        self.bytes(&offset.to_le_bytes());
        self.bytes(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
        self.bytes(bytes);
    }
    fn finish(&mut self) -> String {
        self.writer.flush().unwrap();
        self.digest.clone().finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}
impl Stream {
    fn new(path: &Path) -> Self {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let mut stream = Self {
            writer: BufWriter::new(file),
            digest: Sha512::default(),
            phase: 0,
            counts: [Counts::default(); 3],
            readers: None,
        };
        stream.bytes(b"HB_ORACLE_EVENT_STREAM_V1\n");
        stream
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
        Digest::update(&mut self.digest, bytes);
    }
    fn event(&mut self, output: Option<Digest512>, input: &[u8]) {
        let length = u64::try_from(input.len()).unwrap();
        let counts = &mut self.counts[self.phase];
        if output.is_some() {
            counts.hashes += 1;
            counts.hash_bytes += length;
            counts.max_hash = counts.max_hash.max(input.len());
        } else {
            counts.xofs += 1;
            counts.xof_bytes += length;
            counts.max_xof = counts.max_xof.max(input.len());
        }
        self.bytes(&[u8::from(output.is_none()) + 1, self.phase as u8]);
        self.bytes(&length.to_le_bytes());
        self.bytes(input);
        if let Some(output) = output {
            self.bytes(&output.0);
            if let Some(readers) = &mut self.readers {
                readers.hash(self.phase, output, input);
            }
        }
    }
    fn reader_event(&mut self, event: helper::classical_transcript::audit::ReaderEvent<'_>) {
        use helper::classical_transcript::audit::ReaderEvent;
        match event {
            ReaderEvent::Start { reader, input } => {
                self.event(None, input);
                self.readers.as_mut().unwrap().start(self.phase, reader, input);
            }
            ReaderEvent::Output { reader, offset, bytes } => {
                self.readers.as_mut().unwrap().output(self.phase, reader, offset, bytes);
            }
        }
    }
    fn finish(&mut self) -> String {
        self.writer.flush().unwrap();
        self.digest
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
static STREAM: LazyLock<Mutex<Option<Arc<Mutex<Stream>>>>> = LazyLock::new(|| Mutex::new(None));
struct StreamGuard;
impl Drop for StreamGuard {
    fn drop(&mut self) {
        *STREAM.lock().unwrap() = None;
    }
}
pub(super) fn record_hash(output: Digest512, input: &[u8]) {
    let stream = STREAM.lock().unwrap().clone();
    if let Some(stream) = stream {
        stream.lock().unwrap().event(Some(output), input);
    }
}
fn exercise<F, EF, P>(bundle: ProfileParameters<P>, directory: &Path)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, EventHash>,
    <P as CanonicalPcs<F, Sha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, Sha512>>::BatchProof: DeserializeOwned,
{
    exercise_stream::<F, EF, P>(bundle, directory, false);
}
fn exercise_stream<F, EF, P>(bundle: ProfileParameters<P>, directory: &Path, reader_outputs: bool)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, EventHash>,
    <P as CanonicalPcs<F, Sha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, Sha512>>::BatchProof: DeserializeOwned,
{
    let profile = bundle.profile();
    let pp = protocol::parameters(&bundle);
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let br = vec![NTTRGSW::<F>::zero(32, algebra::Basis::new(8)); 21];
    let ks = vec![NTTGadgetRLWE::<F>::zero(32, algebra::Basis::new(5))];
    let baseline = protocol::preprocess::<F, EF, P, _>(
        &bundle,
        cfg.clone(),
        &br,
        &ks,
        &mut rand::rngs::StdRng::seed_from_u64(12051),
    )
    .unwrap();
    let path = directory.join(format!(
        "{}-v{}-{:?}.events",
        F::MODULUS_VALUE,
        profile.version(),
        profile.specification().backend
    ));
    let reader_path = path.with_extension("reader-events");
    let mut trace = Stream::new(&path);
    if reader_outputs { trace.readers = Some(ReaderStream::new(&reader_path)); }
    let stream = Arc::new(Mutex::new(trace));
    {
        let mut active = STREAM.lock().unwrap();
        assert!(active.is_none());
        *active = Some(Arc::clone(&stream));
    }
    let hash_guard = StreamGuard;
    let xof_stream = Arc::clone(&stream);
    let xof_guard = if reader_outputs {
        helper::classical_transcript::audit::observe_with_reader_events(|_| {}, move |event| {
            xof_stream.lock().unwrap().reader_event(event)
        }).unwrap()
    } else {
        helper::classical_transcript::audit::observe(move |input| {
            xof_stream.lock().unwrap().event(None, input)
        }).unwrap()
    };
    let roles = bundle.roles();
    let setup = canonical_setup::preprocess::<F, EventHash, P, _>(
        &canonical_setup::Parameters {
            source: &roles[0],
            helper: &roles[1],
            final_source: &roles[2],
            final_helper: &roles[3],
        },
        cfg,
        &br,
        &ks,
        &mut rand::rngs::StdRng::seed_from_u64(12051),
    )
    .unwrap();
    assert_eq!(
        encoded(&setup.verifier()),
        encoded(&baseline.inner.verifier())
    );
    stream.lock().unwrap().phase = 1;
    let (statement, payload, continuation) = super::super::super::make_with_transcript::<
        F,
        EF,
        EventHash,
        P,
        crate::packed_pbs::canonical::stages::ClassicalShared,
    >(
        &pp,
        &setup,
        Attack::Control,
        12052,
        profile.parent_transcript::<F>().unwrap(),
    );
    // Bincode struct and tuple field order agree: expected profile ID, payload.
    let bytes = encoded(&(profile.id(), &payload));
    let (decoded, used): (
        protocol::Proof<
            F,
            EF,
            <P as CanonicalPcs<F, Sha512>>::SingleProof,
            <P as CanonicalPcs<F, Sha512>>::BatchProof,
        >,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    stream.lock().unwrap().phase = 2;
    crate::packed_pbs::canonical::verify_inner::<
        F,
        EF,
        EventHash,
        P,
        crate::packed_pbs::canonical::stages::ClassicalShared,
    >(
        &pp,
        &setup.verifier(),
        &statement.borrowed(),
        &payload,
        Some(profile.parent_transcript::<F>().unwrap()),
    )
    .unwrap();
    drop(xof_guard);
    drop(hash_guard);
    protocol::verify::<F, EF, P>(
        &bundle,
        &baseline.verifier(),
        &statement.borrowed(),
        &decoded,
    )
    .unwrap();
    let mut audit_parent = profile.parent_transcript::<F>().unwrap();
    let (report, complete_queries) = super::super::super::reference_transcript_queries::<
        F,
        EF,
        Sha512,
        P,
        crate::packed_pbs::canonical::stages::ClassicalShared,
    >(
        &pp,
        &baseline.inner.verifier(),
        &statement.borrowed(),
        &decoded.payload,
        &mut audit_parent,
    )
    .unwrap();
    let final_queries = &complete_queries.final_stage;
    assert_eq!(report.decomposition, [[true; 3]; 2]);
    assert_eq!(report.switch_decomposition, [true; 3]);
    assert_eq!(report.lookups, [true; 2]);
    assert!(
        report.switch_lookup
            && report.key_product
            && report.switch_key_product
            && report.accumulator
            && report.monomial
            && report.extraction
    );
    let audit_digest = audit_parent.get_challenge(b"fresh complete canonical certificate after");
    let mut audit_bytes = [0; 32];
    audit_parent.get_challenge_bytes(
        b"fresh complete canonical certificate bytes after",
        &mut audit_bytes,
    );
    assert_eq!((audit_digest, audit_bytes), continuation);
    assert_eq!(
        final_queries.ntt.len(),
        decoded.payload.key_switch.ntt.len()
    );
    assert_eq!(
        final_queries.decomposition.len(),
        decoded.payload.key_switch.decomposition.linear.values.len()
    );
    assert!(final_queries.lookup.is_some());
    assert_eq!(
        complete_queries.primary_ntt.len(),
        decoded.payload.ntt.len()
    );
    assert_eq!(complete_queries.primary_decompositions.len(), 2);
    assert_eq!(complete_queries.accumulator.len(), 7);
    assert_eq!(
        complete_queries.primary_product.query.len(),
        <P as CanonicalPcs<F, Sha512>>::num_vars(pp.evaluations)
    );

    println!(
        "HB_COMPLETE_FINAL_OBLIGATIONS {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"ntt_components\":{},\"linear_sources\":{},\"complete_transcript_match\":true,\"source_words_checked\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        final_queries.ntt.len(),
        final_queries.decomposition.len()
    );
    let mut stream = stream.lock().unwrap();
    let digest = stream.finish();
    let reader_digest = stream.readers.as_mut().map(ReaderStream::finish);
    let temporal =
        super::temporal_child_stream_audit::check::<F, EF>(profile, &path, &digest).unwrap();
    assert_eq!(temporal.identities[0], 0);
    assert_eq!(temporal.identities[1], temporal.identities[2]);
    assert_eq!(temporal.later[1], temporal.later[2]);
    assert!(temporal.seeds[2] >= 3 && temporal.same_prover_verifier_seeds);
    assert_eq!(temporal.captured_availability_hits, [0, 0]);
    assert!(temporal.replayed_receipt_frames > 0);
    println!(
        "HB_COMPLETE_TEMPORAL_ORIGINS {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"initial_identity_requests\":{:?},\"later_child_requests\":{:?},\"unique_child_seeds\":{:?},\"captured_availability_hits\":{:?},\"replayed_receipt_frames\":{},\"generic_completed_phase_streams_checked\":true,\"all_captured_input_windows_checked\":true,\"same_prover_verifier_seed_sets\":true,\"xof_output_collisions\":0,\"all_input_windows_registered\":false,\"availability_filter_checked\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        temporal.identities,
        temporal.later,
        temporal.seeds,
        temporal.captured_availability_hits,
        temporal.replayed_receipt_frames
    );
    let final_proof = &decoded.payload.key_switch;
    let mut selected = final_proof
        .coefficients
        .iter()
        .chain(&final_proof.evaluations)
        .chain(std::iter::once(&final_proof.input))
        .chain(&final_proof.decomposition.borrow_commitments)
        .chain(&final_proof.decomposition.comparisons.helper_roots)
        .map(|root| root.root)
        .collect::<Vec<_>>();
    selected.extend(
        baseline
            .inner
            .verifier()
            .ks
            .roots()
            .iter()
            .map(|root| root.root),
    );
    selected.extend(
        decoded
            .payload
            .coefficients
            .iter()
            .chain(&decoded.payload.evaluations)
            .chain(&decoded.payload.decomposition_inputs)
            .chain(&decoded.payload.accumulators)
            .map(|root| root.root),
    );
    for decomposition in &decoded.payload.decomposition {
        selected.extend(
            decomposition
                .borrow_commitments
                .iter()
                .chain(&decomposition.comparisons.helper_roots)
                .map(|root| root.root),
        );
    }
    selected.extend(
        decoded
            .payload
            .monomial
            .evaluations
            .iter()
            .map(|root| root.root),
    );
    let expected_setup = baseline.inner.verifier();
    let primary_keys =
        bk::canonical::public_oracles::<F, Sha512, P>(pp.key, &expected_setup.br).unwrap();
    selected.extend(primary_keys.iter().map(|source| source.commitment.root));
    let projection =
        classical_projection::replay(&path, &digest, selected.iter().copied()).unwrap();
    assert_eq!(
        projection.events() as u64,
        stream.counts.iter().map(|c| c.hashes + c.xofs).sum::<u64>()
    );
    for root in selected {
        assert!(projection.first(root).is_some());
    }
    let checked = super::key_switch_event_audit::assert_source_words::<F, EF, P>(
        profile,
        &pp.final_stage,
        &baseline.inner.verifier().ks,
        final_proof,
        &final_queries,
        |root| projection.view(root),
        &decoded.payload.final_accumulator,
        &statement.output,
        statement.output_b,
        false,
    );
    let primary_claims = check_primary_sources::<F, EF, P>(
        profile,
        &pp,
        &decoded.payload,
        &complete_queries,
        &primary_keys
            .iter()
            .map(|source| source.commitment.clone())
            .collect::<Vec<_>>(),
        &projection,
    );
    println!(
        "HB_COMPLETE_PRIMARY_SOURCE_WORDS {{\"claims\":{},\"monomial_checked\":true,\"security_qualified\":false}}",
        primary_claims
    );
    println!(
        "HB_COMPLETE_FINAL_SOURCE_WORDS {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"ntt_source_claims\":{},\"product_source_claims\":{},\"decomposition_source_claims\":{},\"lookup_source_claims\":{},\"lookup_helper_claims\":{},\"events_replayed\":{},\"all_pbs_stages_coupled\":true,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        checked.0,
        checked.1,
        checked.2,
        checked.3,
        checked.4,
        projection.events()
    );
    let verifier = stream.counts[2];
    assert!(verifier.hashes > 0 && verifier.xofs > 0);
    if let Some(readers) = &stream.readers {
        println!("HB_COMPLETE_READER_EVENT_TRACE {{\"trace_path\":\"{}\",\"trace_sha512\":\"{}\",\"reader_starts\":{:?},\"read_calls\":{:?},\"output_bytes\":{:?},\"native\":false,\"security_qualified\":false}}",
            reader_path.display(), reader_digest.as_ref().unwrap(), readers.starts, readers.reads, readers.output_bytes);
    }
    println!(
        "HB_COMPLETE_PBS_EVENT_TRACE {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"n\":32,\"lwe\":21,\"queries\":8,\"proof_bytes\":{},\"verifier_hash_queries\":{},\"verifier_xof_queries\":{},\"verifier_hash_input_bytes\":{},\"verifier_xof_input_bytes\":{},\"verifier_max_hash_input\":{},\"verifier_max_xof_input\":{},\"trace_path\":\"{}\",\"trace_sha512\":\"{}\",\"encrypted_native\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        bytes.len(),
        verifier.hashes,
        verifier.xofs,
        verifier.hash_bytes,
        verifier.xof_bytes,
        verifier.max_hash,
        verifier.max_xof,
        path.display(),
        digest
    );
}
fn field<F, EF>(directory: &Path)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    for version in [4, 5] {
        for backend in [
            Backend::Brakedown,
            Backend::Polyfrim,
            Backend::PolyfrimDictionary,
            Backend::FragmentedPipfri,
            Backend::FragmentedPipfriVirtual,
        ] {
            let roles = cfg.variables(8).unwrap().map(|num_vars| Role {
                num_vars,
                width: 8,
                queries: 8,
                left_vars: (backend == Backend::Brakedown).then_some(num_vars / 2),
                block_width: (backend == Backend::Brakedown).then_some(8),
            });
            let spec = Specification {
                backend,
                roles,
                blowup: 2,
                fragment_vars: matches!(
                    backend,
                    Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
                )
                .then_some(8),
            };
            let profile = if version == 4 {
                ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
            } else {
                ClassicalProfile::new_atomic_columns::<F, EF>(spec)
            }
            .unwrap();
            match backend {
                Backend::Brakedown => exercise::<F, EF, _>(
                    profile.brakedown_parameters::<F, EF>().unwrap(),
                    directory,
                ),
                Backend::Polyfrim => {
                    exercise::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap(), directory)
                }
                Backend::PolyfrimDictionary => exercise::<F, EF, _>(
                    profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
                    directory,
                ),
                Backend::FragmentedPipfri => exercise::<F, EF, _>(
                    profile.fragmented_parameters::<F, EF>().unwrap(),
                    directory,
                ),
                Backend::FragmentedPipfriVirtual => exercise::<F, EF, _>(
                    profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
                    directory,
                ),
            }
        }
    }
}
#[test]
fn production_complete_pbs_oracle_events() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/performance/complete-pbs-event-traces")
        .join(format!("run-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    field::<algebra::BabyBear, algebra::BabyBearExtension6>(&directory);
    field::<algebra::Goldilocks, algebra::GoldilocksExtension3>(&directory);
}

#[test]
fn production_complete_pbs_final_obligations_focused() {
    focused(false, "final-obligations");
}
#[test]
fn production_complete_pbs_reader_events_focused() {
    focused(true, "reader-events");
}
fn focused(reader_outputs: bool, label: &str) {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    type F = algebra::BabyBear;
    type EF = algebra::BabyBearExtension6;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let roles = cfg.variables(8).unwrap().map(|num_vars| Role {
        num_vars,
        width: 8,
        queries: 8,
        left_vars: Some(num_vars / 2),
        block_width: Some(2),
    });
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
        backend: Backend::Brakedown,
        roles,
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/performance/complete-pbs-event-traces")
        .join(format!("{label}-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    exercise_stream::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap(), &directory, reader_outputs);
}

fn check_primary_sources<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &crate::packed_pbs::canonical::Parameters<'a, P>,
    proof: &crate::packed_pbs::canonical::shared::Proof<
        F,
        EF,
        Digest512,
        P::SingleProof,
        P::BatchProof,
    >,
    claims: &crate::packed_pbs::canonical::audit::CompleteQueries<F>,
    keys: &[Commitment<Digest512>],
    history: &classical_projection::Projection,
) -> usize
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    // One immutable source can be queried by several stages. Batch all its
    // claims, retaining duplicates, before reconstructing its frozen word.
    // Role remains part of the key even when two roles share geometry.
    let mut groups = Vec::<(
        monomial_word_audit::SourceRole,
        &'a P,
        Commitment<Digest512>,
        Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
        Vec<Vec<F>>,
    )>::new();
    let mut indices = std::collections::HashMap::new();
    let mut check = |role: monomial_word_audit::SourceRole,
                     parameters: &'a P,
                     root: &Commitment<Digest512>,
                     queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
                     expected: &[Vec<F>]| {
        assert_eq!(queries.len(), expected.len());
        let context = parameters.context().ok().unwrap();
        let index = *indices
            .entry((role as u8, context, root.root))
            .or_insert_with(|| {
                groups.push((role, parameters, root.clone(), Vec::new(), Vec::new()));
                groups.len() - 1
            });
        groups[index].3.extend_from_slice(queries);
        groups[index].4.extend_from_slice(expected);
        expected.len()
    };
    use monomial_word_audit::SourceRole::{Main, MainHelper};
    let mut checked = 0;
    let count = proof.evaluations.len() - 1;
    assert_eq!(keys.len(), count);
    assert_eq!(proof.hadamard.values.len(), 2 * count + 1);
    for (index, expected) in proof.hadamard.values.iter().enumerate() {
        let root = if index == 2 * count {
            &proof.evaluations[count]
        } else if index % 2 == 0 {
            &proof.evaluations[index / 2]
        } else {
            &keys[index / 2]
        };
        checked += check(
            Main,
            pp.evaluations,
            root,
            &[claims.primary_product.query.clone()],
            &[expected.clone()],
        );
    }
    assert_eq!(claims.primary_ntt.len(), proof.ntt.len());
    for (i, (queries, co, ev)) in claims.primary_ntt.iter().enumerate() {
        checked += check(Main, pp.coefficients, &proof.coefficients[i], queries, co);
        checked += check(Main, pp.evaluations, &proof.evaluations[i], queries, ev);
    }
    let digits = count / 2;
    for (half, (queries, lookup)) in claims.primary_decompositions.iter().enumerate() {
        let decomposition = &proof.decomposition[half];
        let roots = std::iter::once(&proof.decomposition_inputs[half])
            .chain(&proof.coefficients[half * digits..(half + 1) * digits])
            .chain(&decomposition.borrow_commitments)
            .collect::<Vec<_>>();
        assert_eq!(roots.len(), queries.len());
        assert_eq!(roots.len(), decomposition.linear.values.len());
        for ((root, query), expected) in roots.iter().zip(queries).zip(&decomposition.linear.values)
        {
            checked += check(
                Main,
                pp.coefficients,
                root,
                &[query.clone()],
                &[expected.clone()],
            );
        }
        let lookup = lookup.as_ref().expect("shared primary lookup obligations");
        let roots = proof.coefficients[half * digits..(half + 1) * digits]
            .iter()
            .chain(&decomposition.borrow_commitments)
            .collect::<Vec<_>>();
        assert_eq!(roots.len(), lookup.used.len());
        assert_eq!(roots.len(), decomposition.comparisons.source_values.len());
        for (index, root) in roots.iter().enumerate() {
            if lookup.used[index] {
                checked += check(
                    Main,
                    pp.coefficients,
                    root,
                    &[lookup.source_query.clone()],
                    &[decomposition.comparisons.source_values[index].clone()],
                );
            }
        }
        assert_eq!(
            decomposition.comparisons.helper_roots.len(),
            lookup.helper_values.len()
        );
        for (root, expected) in decomposition
            .comparisons
            .helper_roots
            .iter()
            .zip(&lookup.helper_values)
        {
            checked += check(
                MainHelper,
                pp.helper,
                root,
                &[lookup.helper_query.clone()],
                &[expected.clone()],
            );
        }
    }
    let roots = [
        &proof.accumulators[0],
        &proof.accumulators[1],
        &proof.accumulators[2],
        &proof.accumulators[3],
        &proof.coefficients[count],
        &proof.decomposition_inputs[0],
        &proof.decomposition_inputs[1],
    ];
    assert_eq!(claims.accumulator.len(), roots.len());
    assert_eq!(proof.accumulator.values.len(), roots.len());
    for (index, root) in roots.iter().enumerate() {
        checked += check(
            Main,
            pp.coefficients,
            root,
            &claims.accumulator[index],
            &proof.accumulator.values[index],
        );
    }
    assert_eq!(claims.monomial.ntt.len(), 2);
    for (i, (queries, co, ev)) in claims.monomial.ntt.iter().enumerate() {
        checked += check(
            Main,
            pp.accumulators[i],
            &proof.accumulators[i],
            queries,
            co,
        );
        checked += check(
            Main,
            pp.monomial,
            &proof.monomial.evaluations[i],
            queries,
            ev,
        );
        checked += check(
            Main,
            pp.monomial,
            &proof.monomial.evaluations[i],
            &[claims.monomial.product.query.clone()],
            &[proof.monomial.values[i].clone()],
        );
    }
    drop(check);
    let mut compared = 0;
    for (role, parameters, root, queries, expected) in groups {
        let context = parameters.context().ok().unwrap();
        let sources = vec![(context, root.clone()), (context, root)];
        let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
            role,
            profile,
            parameters,
            &sources,
            &queries,
            |source| history.view(source.1.root),
        )
        .unwrap();
        assert!(promises.iter().all(|&promise| promise));
        assert_eq!(values[0].len(), expected.len());
        for (actual, expected) in values[0].iter().zip(&expected) {
            assert_eq!(
                encoded(actual),
                encoded(&parameters.normalize_values(expected.clone()))
            );
            compared += 1;
        }
    }
    assert_eq!(compared, checked);
    checked
}

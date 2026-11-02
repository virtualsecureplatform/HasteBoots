//! Length-framed SHAKE256 transcript foundation, separate from legacy Merlin.
//! This primitive does not itself supply a Fiat–Shamir security theorem.
use crate::transcript::CanonicalSampler;
use algebra::{AbstractExtensionField, AsFrom, AsInto, PrimeField};
use serde::Serialize;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    any::TypeId,
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
};

/// Optional scoped SHAKE-input observer for analysis traces.
/// New root transcripts on the registering thread inherit it; descendants keep
/// the observer when moved to workers. Disabled by default.
#[cfg(feature = "transcript-audit")]
pub mod audit {
    use std::{
        cell::RefCell,
        marker::PhantomData,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
    };
    type Callback = Arc<dyn Fn(&[u8]) + Send + Sync>;
    /// Observational resource events; never absorbed into a transcript.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ResourceEvent {
        /// A zero or forbidden-denominator reciprocal candidate was discarded.
        LookupReciprocalRejected,
        /// Bytes consumed by one XOF reader, including receipt/checkpoint readers.
        XofOutput {
            /// Bytes returned by this read operation.
            bytes: u128,
            /// Cumulative bytes returned by this particular reader.
            total_for_query: u128,
        },
        /// Completed sequential Brakedown column sampling before deduplication.
        ColumnSampling {
            /// Number of accepted draws, including repeated column indices.
            values: u128,
            /// Number of candidates, including rejected candidates.
            candidates: u128,
            /// Largest candidate count for one accepted draw.
            max_candidates_per_value: u128,
        },
        /// Completed canonical field sampling, with no candidate cutoff.
        FieldSampling {
            /// Number of accepted base-field values.
            values: u128,
            /// Total candidate draws, including rejected draws.
            candidates: u128,
            /// Largest candidate count for one accepted value.
            max_candidates_per_value: u128,
            /// Bytes actually consumed from the field XOF reader.
            consumed_bytes: u128,
        },
    }
    type ResourceCallback = Arc<dyn Fn(ResourceEvent) + Send + Sync>;
    type OutputCallback = Arc<dyn Fn(&[u8], u128, &[u8]) + Send + Sync>;
    /// Scope-local reader-instance identities. Repeated inputs get different
    /// IDs but remain the same oracle input for first-query accounting.
    pub enum ReaderEvent<'a> {
        /// A newly constructed reader and its exact oracle input.
        Start {
            /// Identifier unique within this observer scope.
            reader: u64,
            /// Complete bytes absorbed before finalizing this reader.
            input: &'a [u8],
        },
        /// Bytes returned by one read operation.
        Output {
            /// Identifier from the preceding start event.
            reader: u64,
            /// Number of bytes returned by earlier reads of this reader.
            offset: u128,
            /// Borrowed returned bytes, including an empty slice for empty reads.
            bytes: &'a [u8],
        },
    }
    type ReaderCallback = Arc<dyn Fn(ReaderEvent<'_>) + Send + Sync>;
    pub(super) struct Observer {
        enabled: AtomicBool,
        callback: Callback,
        resource_callback: ResourceCallback,
        output_callback: Option<OutputCallback>,
        reader_callback: Option<ReaderCallback>,
        next_reader: AtomicU64,
    }
    impl Observer {
        pub(super) fn resource(&self, event: ResourceEvent) {
            if self.enabled.load(Ordering::Acquire) {
                (self.resource_callback)(event);
            }
        }
        pub(super) fn emit(&self, input: &[u8]) {
            if self.enabled.load(Ordering::Acquire) {
                (self.callback)(input);
            }
        }
    }
    pub(super) struct Reader<R> {
        reader: R,
        observer: Option<Arc<Observer>>,
        consumed: u128,
        input: Option<Vec<u8>>,
        reader_id: Option<u64>,
    }
    impl<R> Reader<R> {
        pub(super) fn new(reader: R, observer: Option<Arc<Observer>>, input: Vec<u8>) -> Self {
            let reader_id = observer.as_ref().and_then(|observer| {
                observer.reader_callback.as_ref().map(|callback| {
                    let id = observer
                        .next_reader
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                            value.checked_add(1)
                        })
                        .expect("transcript audit reader ID overflow");
                    if observer.enabled.load(Ordering::Acquire) {
                        callback(ReaderEvent::Start {
                            reader: id,
                            input: &input,
                        });
                    }
                    id
                })
            });
            let input = observer
                .as_ref()
                .and_then(|observer| observer.output_callback.as_ref().map(|_| input));
            Self {
                reader,
                observer,
                consumed: 0,
                input,
                reader_id,
            }
        }
    }
    impl<R: sha3::digest::XofReader> sha3::digest::XofReader for Reader<R> {
        fn read(&mut self, output: &mut [u8]) {
            self.reader.read(output);
            let offset = self.consumed;
            self.consumed += output.len() as u128;
            if let Some(observer) = &self.observer {
                observer.resource(ResourceEvent::XofOutput {
                    bytes: output.len() as u128,
                    total_for_query: self.consumed,
                });
                if observer.enabled.load(Ordering::Acquire) {
                    if let (Some(callback), Some(input)) = (&observer.output_callback, &self.input)
                    {
                        callback(input, offset, output);
                    }
                    if let (Some(callback), Some(reader)) =
                        (&observer.reader_callback, self.reader_id)
                    {
                        callback(ReaderEvent::Output {
                            reader,
                            offset,
                            bytes: output,
                        });
                    }
                }
            }
        }
    }
    thread_local! { static CURRENT: RefCell<Option<Arc<Observer>>> = const { RefCell::new(None) }; }
    pub(super) fn current() -> Option<Arc<Observer>> {
        CURRENT.with(|slot| slot.borrow().clone())
    }
    /// Disables this observer and removes its registration when the scope ends.
    /// Keep and drop the guard on its registering thread.
    pub struct ObservationGuard {
        observer: Arc<Observer>,
        _thread: PhantomData<Rc<()>>,
    }
    impl Drop for ObservationGuard {
        fn drop(&mut self) {
            self.observer.enabled.store(false, Ordering::Release);
            let _ = CURRENT.try_with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &self.observer))
                {
                    *slot = None;
                }
            });
        }
    }
    /// Observe root transcripts created in this scope and their children.
    /// Registration is exclusive on this thread; callbacks run before output
    /// readers are constructed and must not recursively query observed states.
    pub fn observe(
        callback: impl Fn(&[u8]) + Send + Sync + 'static,
    ) -> Result<ObservationGuard, &'static str> {
        observe_with_resources(callback, |_| {})
    }
    /// Observe actual stopping-condition events in the same inherited scope.
    pub fn observe_with_resources(
        callback: impl Fn(&[u8]) + Send + Sync + 'static,
        resources: impl Fn(ResourceEvent) + Send + Sync + 'static,
    ) -> Result<ObservationGuard, &'static str> {
        install(Arc::new(callback), Arc::new(resources), None, None)
    }
    /// Observe actual reader chunks, identified by exact input and byte offset.
    /// Offsets restart at zero for each reader of a repeated input. Chunks are
    /// borrowed only during the callback, after the read; empty reads are
    /// reported too. Callbacks must not recursively query observed states.
    /// This is opt-in: input-only/resource-only observers do not retain reader
    /// inputs or copy output chunks. No virtual completion bytes are emitted.
    pub fn observe_with_output_chunks(
        callback: impl Fn(&[u8]) + Send + Sync + 'static,
        resources: impl Fn(ResourceEvent) + Send + Sync + 'static,
        outputs: impl Fn(&[u8], u128, &[u8]) + Send + Sync + 'static,
    ) -> Result<ObservationGuard, &'static str> {
        install(
            Arc::new(callback),
            Arc::new(resources),
            Some(Arc::new(outputs)),
            None,
        )
    }
    /// Stream starts and chunks using IDs without retaining a full input per
    /// reader. Start precedes all outputs for that ID, including on workers.
    /// IDs count reader instances, not distinct inputs. No regular input
    /// callback or virtual output completion is emitted by this interface.
    /// Callbacks must not recursively query observed states.
    pub fn observe_with_reader_events(
        resources: impl Fn(ResourceEvent) + Send + Sync + 'static,
        events: impl Fn(ReaderEvent<'_>) + Send + Sync + 'static,
    ) -> Result<ObservationGuard, &'static str> {
        install(
            Arc::new(|_| {}),
            Arc::new(resources),
            None,
            Some(Arc::new(events)),
        )
    }
    fn install(
        callback: Callback,
        resource_callback: ResourceCallback,
        output_callback: Option<OutputCallback>,
        reader_callback: Option<ReaderCallback>,
    ) -> Result<ObservationGuard, &'static str> {
        CURRENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err("transcript audit observer already installed on this thread");
            }
            let observer = Arc::new(Observer {
                enabled: AtomicBool::new(true),
                callback,
                resource_callback,
                output_callback,
                reader_callback,
                next_reader: AtomicU64::new(0),
            });
            *slot = Some(Arc::clone(&observer));
            Ok(ObservationGuard {
                observer,
                _thread: PhantomData,
            })
        })
    }

    #[cfg(test)]
    mod output_reader_tests {
        use super::*;
        use sha3::{
            Shake256,
            digest::{ExtendableOutput, XofReader},
        };
        use std::sync::Mutex;

        #[test]
        fn reader_ids_bind_starts_split_reads_and_repeated_inputs() {
            let events = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&events);
            let guard = observe_with_reader_events(
                |_| {},
                move |event| {
                    let value = match event {
                        ReaderEvent::Start { reader, input } => (0, reader, 0, input.to_vec()),
                        ReaderEvent::Output {
                            reader,
                            offset,
                            bytes,
                        } => (1, reader, offset, bytes.to_vec()),
                    };
                    sink.lock().unwrap().push(value);
                },
            )
            .unwrap();
            let reader = Reader::new(Shake256::default().finalize_xof(), current(), vec![]);
            assert!(reader.input.is_none());
            let (mut reader, actual) = std::thread::spawn(move || {
                let mut reader = reader;
                let mut output = [0; 12];
                reader.read(&mut output[..5]);
                reader.read(&mut []);
                reader.read(&mut output[5..]);
                (reader, output)
            })
            .join()
            .unwrap();
            let mut expected = [0; 12];
            Shake256::default().finalize_xof().read(&mut expected);
            assert_eq!(actual, expected);
            let mut repeat = Reader::new(Shake256::default().finalize_xof(), current(), vec![]);
            repeat.read(&mut [0; 3]);
            let recorded = events.lock().unwrap().clone();
            assert_eq!(
                recorded,
                vec![
                    (0, 0, 0, vec![]),
                    (1, 0, 0, expected[..5].to_vec()),
                    (1, 0, 5, vec![]),
                    (1, 0, 5, expected[5..].to_vec()),
                    (0, 1, 0, vec![]),
                    (1, 1, 0, expected[..3].to_vec()),
                ]
            );
            drop(guard);
            reader.read(&mut [0; 1]);
            repeat.read(&mut [0; 1]);
            assert_eq!(*events.lock().unwrap(), recorded);
        }

        #[test]
        fn xof_output_reader_counts_split_reads_and_disables_on_drop() {
            let events = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&events);
            let guard = observe_with_resources(
                |_| {},
                move |event| {
                    observed.lock().unwrap().push(event);
                },
            )
            .unwrap();
            let mut reader = Reader::new(Shake256::default().finalize_xof(), current(), Vec::new());
            assert!(reader.input.is_none());
            let mut actual = [0; 12];
            reader.read(&mut actual[..5]);
            reader.read(&mut []);
            reader.read(&mut actual[5..]);
            let mut expected = [0; 12];
            Shake256::default().finalize_xof().read(&mut expected);
            assert_eq!(actual, expected);
            let mut second = Reader::new(Shake256::default().finalize_xof(), current(), Vec::new());
            second.read(&mut [0; 3]);
            let recorded = events.lock().unwrap().clone();
            assert_eq!(
                recorded,
                [(5, 5), (0, 5), (7, 12), (3, 3)].map(|(bytes, total_for_query)| {
                    ResourceEvent::XofOutput {
                        bytes,
                        total_for_query,
                    }
                })
            );
            drop(guard);
            reader.read(&mut [0; 7]);
            assert_eq!(*events.lock().unwrap(), recorded);
        }

        #[test]
        fn output_chunks_bind_input_offsets_and_inherit_across_workers() {
            use super::super::TranscriptShake;
            use sha3::digest::Update;
            let inputs = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let chunks = Arc::new(Mutex::new(Vec::<(Vec<u8>, u128, Vec<u8>)>::new()));
            let input_sink = Arc::clone(&inputs);
            let known_inputs = Arc::clone(&inputs);
            let chunk_sink = Arc::clone(&chunks);
            let guard = observe_with_output_chunks(
                move |input| input_sink.lock().unwrap().push(input.to_vec()),
                |_| {},
                move |input, offset, output| {
                    assert!(
                        known_inputs
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|known| known == input)
                    );
                    chunk_sink
                        .lock()
                        .unwrap()
                        .push((input.to_vec(), offset, output.to_vec()));
                },
            )
            .unwrap();
            assert!(observe(|_| {}).is_err());
            let mut state = TranscriptShake::default();
            state.update(b"actual reader");
            let saved = state.clone();
            let (mut reader, actual) = std::thread::spawn(move || {
                let mut reader = state.finalize_xof();
                let mut actual = vec![0; 4096];
                reader.read(&mut actual[..5]);
                reader.read(&mut []);
                reader.read(&mut actual[5..]);
                (reader, actual)
            })
            .join()
            .unwrap();
            let mut expected = vec![0; actual.len()];
            let mut reference = Shake256::default();
            reference.update(b"actual reader");
            reference.finalize_xof().read(&mut expected);
            assert_eq!(actual, expected);
            let mut repeat = [0; 8];
            saved.clone().finalize_xof().read(&mut repeat);
            assert_eq!(repeat, expected[..8]);
            let mut child = saved.fresh();
            child.update(b"fresh child");
            std::thread::spawn(move || child.finalize_xof().read(&mut [0; 3]))
                .join()
                .unwrap();
            let recorded = chunks.lock().unwrap().clone();
            assert_eq!(recorded.len(), 5);
            assert_eq!(
                recorded[0],
                (b"actual reader".to_vec(), 0, expected[..5].to_vec())
            );
            assert_eq!(recorded[1], (b"actual reader".to_vec(), 5, vec![]));
            assert_eq!(
                recorded[2],
                (b"actual reader".to_vec(), 5, expected[5..].to_vec())
            );
            assert_eq!(
                recorded[3],
                (b"actual reader".to_vec(), 0, expected[..8].to_vec())
            );
            assert_eq!(
                (&recorded[4].0[..], recorded[4].1, recorded[4].2.len()),
                (&b"fresh child"[..], 0, 3)
            );
            let input_count = inputs.lock().unwrap().len();
            drop(guard);
            reader.read(&mut [0; 7]);
            saved.finalize_xof().read(&mut [0; 2]);
            assert_eq!(*chunks.lock().unwrap(), recorded);
            assert_eq!(inputs.lock().unwrap().len(), input_count);
        }
    }
}

#[derive(Clone)]
struct TranscriptShake {
    hash: Shake256,
    #[cfg(feature = "transcript-audit")]
    input: Vec<u8>,
    #[cfg(feature = "transcript-audit")]
    observer: Option<Arc<audit::Observer>>,
}
impl Default for TranscriptShake {
    fn default() -> Self {
        Self {
            hash: Shake256::default(),
            #[cfg(feature = "transcript-audit")]
            input: Vec::new(),
            #[cfg(feature = "transcript-audit")]
            observer: audit::current(),
        }
    }
}
impl Update for TranscriptShake {
    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        self.hash.update(bytes);
        #[cfg(feature = "transcript-audit")]
        self.input.extend_from_slice(bytes);
    }
}
impl TranscriptShake {
    fn fresh(&self) -> Self {
        Self {
            hash: Shake256::default(),
            #[cfg(feature = "transcript-audit")]
            input: Vec::new(),
            #[cfg(feature = "transcript-audit")]
            observer: self.observer.clone(),
        }
    }
    #[inline]
    fn finalize_xof(self) -> impl XofReader {
        #[cfg(feature = "transcript-audit")]
        if let Some(observer) = &self.observer {
            observer.emit(&self.input);
        }
        let reader = self.hash.finalize_xof();
        #[cfg(feature = "transcript-audit")]
        {
            audit::Reader::new(reader, self.observer, self.input)
        }
        #[cfg(not(feature = "transcript-audit"))]
        {
            reader
        }
    }
}

/// Versioned byte transcript. Field/basis framing belongs to its typed caller.
/// All methods share the same input-indexed SHAKE stream model in a security
/// argument; method labels do not independently justify fresh randomness.
pub struct ClassicalTranscript {
    state: TranscriptShake,
    profile: [u8; 64],
}

fn frame(state: &mut impl Update, kind: u8, label: &[u8], message: &[u8]) {
    state.update(&[kind]);
    state.update(&(label.len() as u64).to_le_bytes());
    state.update(label);
    state.update(&(message.len() as u64).to_le_bytes());
    state.update(message);
}

fn extension_basis<B: PrimeField, E: AbstractExtensionField<B>>() -> Result<Arc<[u8]>, &'static str>
{
    type Cache = RwLock<HashMap<TypeId, Arc<[u8]>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let key = TypeId::of::<(B, E)>();
    if let Some(bytes) = cache.read().map_err(|_| "extension basis cache")?.get(&key) {
        return Ok(Arc::clone(bytes));
    }
    // Compute outside the lock. Concurrent cold requests may duplicate this
    // work, but all callers retain the same immutable winning entry.
    let mut basis = (E::D as u64).to_le_bytes().to_vec();
    for i in 0..E::D {
        for j in 0..E::D {
            let product = E::monomial(i) * E::monomial(j);
            if product.as_base_slice().len() > E::D {
                return Err("invalid extension basis");
            }
            for k in 0..E::D {
                let v: u128 = product
                    .as_base_slice()
                    .get(k)
                    .copied()
                    .unwrap_or_else(B::zero)
                    .value()
                    .as_into();
                basis.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    let mut entries = cache.write().map_err(|_| "extension basis cache")?;
    Ok(Arc::clone(
        entries.entry(key).or_insert_with(|| basis.into()),
    ))
}

impl ClassicalTranscript {
    /// Emit an audit event without modifying transcript bytes or challenges.
    #[cfg(feature = "transcript-audit")]
    pub fn audit_resource_event(&self, event: audit::ResourceEvent) {
        if let Some(observer) = &self.state.observer {
            observer.resource(event);
        }
    }
    fn field_values<T>(
        &mut self,
        label: &[u8],
        p: u128,
        count: usize,
        mut convert: impl FnMut(u128) -> T,
    ) -> Vec<T> {
        self.field_build(label, p, count, |sample| {
            (0..count).map(|_| convert(sample())).collect()
        })
    }

    fn field_build<T>(
        &mut self,
        label: &[u8],
        p: u128,
        count: usize,
        build: impl FnOnce(&mut dyn FnMut() -> u128) -> T,
    ) -> T {
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend_from_slice(&(count as u64).to_le_bytes());
        frame(&mut self.state, 4, label, &descriptor);
        let mut reader = self.state.clone().finalize_xof();
        let mut consumed = self.state.fresh();
        consumed.update(b"HasteBoots consumed field bytes v1");
        let mut length = 0u128;
        let sampler = CanonicalSampler::new(p);
        #[cfg(feature = "transcript-audit")]
        let (mut sampled_values, mut candidates, mut maximum_candidates) = (0u128, 0u128, 0u128);
        let values = build(&mut || {
            #[cfg(feature = "transcript-audit")]
            let mut attempts = 0u128;
            let value = sampler.sample(&mut |bytes| {
                reader.read(bytes);
                consumed.update(bytes);
                length += bytes.len() as u128;
                #[cfg(feature = "transcript-audit")]
                {
                    attempts += 1;
                }
            });
            #[cfg(feature = "transcript-audit")]
            {
                sampled_values += 1;
                candidates += attempts;
                maximum_candidates = maximum_candidates.max(attempts);
            }
            value
        });
        #[cfg(feature = "transcript-audit")]
        self.audit_resource_event(audit::ResourceEvent::FieldSampling {
            values: sampled_values,
            candidates,
            max_candidates_per_value: maximum_candidates,
            consumed_bytes: length,
        });
        let mut receipt = [0u8; 80];
        receipt[..16].copy_from_slice(&length.to_le_bytes());
        consumed.finalize_xof().read(&mut receipt[16..]);
        frame(&mut self.state, 5, label, &receipt);
        values
    }

    /// Sample independent canonical prime-field values in one SHAKE phase.
    /// The field implementation is trusted to describe a valid prime field.
    pub fn challenge_prime<F: PrimeField>(&mut self, label: &[u8], count: usize) -> Vec<F> {
        self.append_bytes(b"field challenge kind", b"prime vector");
        self.field_values(label, F::MODULUS_VALUE.as_into(), count, |v| {
            F::new(F::Value::as_from(v))
        })
    }

    /// Sample extension coefficients in ascending polynomial-basis order.
    /// Bind the complete basis multiplication table; irreducibility remains
    /// an assumption on the trusted field type, not on the sampler.
    pub fn challenge_extension<B: PrimeField, E: AbstractExtensionField<B>>(
        &mut self,
        label: &[u8],
        count: usize,
    ) -> Result<Vec<E>, &'static str> {
        if E::D == 0 {
            return Err("zero extension degree");
        }
        let total = count
            .checked_mul(E::D)
            .ok_or("extension request overflow")?;
        let basis = extension_basis::<B, E>()?;
        self.append_bytes(b"field challenge kind", b"extension vector");
        self.append_bytes(b"extension basis", &basis);
        Ok(
            self.field_build(label, B::MODULUS_VALUE.as_into(), total, |sample| {
                // All selected native extensions fit on the stack. Retain the
                // generic fallback and indexed constructor semantics: a field may
                // request coefficients in an order different from sampling order.
                let mut native = [B::zero(); 8];
                let mut larger = if E::D > native.len() {
                    vec![B::zero(); E::D]
                } else {
                    Vec::new()
                };
                let coefficients = if E::D <= native.len() {
                    &mut native[..E::D]
                } else {
                    larger.as_mut_slice()
                };
                (0..count)
                    .map(|_| {
                        for coefficient in coefficients.iter_mut() {
                            *coefficient = B::new(B::Value::as_from(sample()));
                        }
                        E::from_base_fn(|i| coefficients[i])
                    })
                    .collect()
            }),
        )
    }

    /// Bind a protocol namespace and independently expected trusted profile ID.
    pub fn new(protocol: &[u8], profile: &[u8; 64]) -> Self {
        let mut state = TranscriptShake::default();
        frame(&mut state, 0, b"protocol", b"HasteBoots framed SHAKE256 v1");
        frame(&mut state, 0, b"application", protocol);
        frame(&mut state, 0, b"trusted profile", profile);
        Self {
            state,
            profile: *profile,
        }
    }

    /// Execute a profile-inheriting child while the parent is exclusively
    /// borrowed. Context precedes the seed; the final child fingerprint is
    /// absorbed even if the closure returns an error. As elsewhere, callers
    /// discard a failed verification transcript; panics are not recoverable
    /// protocol errors.
    pub fn with_child<R>(
        &mut self,
        label: &[u8],
        context: &[u8],
        run: impl FnOnce(&mut Self) -> R,
    ) -> R {
        self.with_owned_child(label, context, |mut child| {
            let result = run(&mut child);
            (child, result)
        })
    }

    pub(crate) fn with_owned_child<R>(
        &mut self,
        label: &[u8],
        context: &[u8],
        run: impl FnOnce(Self) -> (Self, R),
    ) -> R {
        let child = self.fork_child(label, context);
        let (mut child, result) = run(child);
        self.finish_linked_child(label, &mut child);
        result
    }

    pub(crate) fn profile_id(&self) -> [u8; 64] {
        self.profile
    }

    pub(crate) fn checkpoint(&self) -> [u8; 64] {
        let mut state = self.state.clone();
        frame(&mut state, 8, b"parent checkpoint", &[]);
        let mut out = [0; 64];
        state.finalize_xof().read(&mut out);
        out
    }

    pub(crate) fn fork_child(&mut self, label: &[u8], context: &[u8]) -> Self {
        frame(&mut self.state, 6, label, context);
        let mut seed = [0; 64];
        self.challenge_bytes(b"classical child seed", &mut seed);
        let mut child = Self::new(b"HasteBoots framed SHAKE256 child v1", &self.profile);
        #[cfg(feature = "transcript-audit")]
        {
            child.state.observer = self.state.observer.clone();
        }
        child.append_bytes(b"child label", label);
        child.append_bytes(b"child context", context);
        child.append_bytes(b"parent seed", &seed);
        child
    }

    pub(crate) fn finish_linked_child(&mut self, label: &[u8], child: &mut Self) {
        let mut finish = [0; 64];
        child.challenge_bytes(b"classical child finish", &mut finish);
        frame(&mut self.state, 7, label, &finish);
    }

    /// Absorb public bytes with explicit label and message lengths.
    pub fn append_bytes(&mut self, label: &[u8], message: &[u8]) {
        frame(&mut self.state, 1, label, message);
    }

    /// Absorb standard bincode serialization. Callers normalize field values
    /// according to their protocol before serialization.
    pub fn append_message<T: Serialize>(
        &mut self,
        label: &[u8],
        message: &T,
    ) -> Result<(), bincode::error::EncodeError> {
        let bytes = bincode::serde::encode_to_vec(message, bincode::config::standard())?;
        self.append_bytes(label, &bytes);
        Ok(())
    }

    /// Draw one challenge phase, binding its label, requested length and output.
    pub fn challenge_bytes(&mut self, label: &[u8], output: &mut [u8]) {
        frame(
            &mut self.state,
            2,
            label,
            &(output.len() as u64).to_le_bytes(),
        );
        self.state.clone().finalize_xof().read(output);
        frame(&mut self.state, 3, label, output);
    }

    /// Draw all positions in one phase, uniformly with replacement on a
    /// power-of-two domain. Invalid dimensions leave the transcript unchanged.
    pub fn challenge_indices(
        &mut self,
        label: &[u8],
        domain: usize,
        count: usize,
    ) -> Result<Vec<usize>, &'static str> {
        if !domain.is_power_of_two() {
            return Err("index domain must be a power of two");
        }
        let length = count.checked_mul(8).ok_or("index request overflow")?;
        self.append_bytes(b"index domain", &(domain as u64).to_le_bytes());
        let mut bytes = vec![0; length];
        self.challenge_bytes(label, &mut bytes);
        Ok(bytes
            .chunks_exact(8)
            .map(|b| {
                (u64::from_le_bytes(b.try_into().expect("eight index bytes")) & (domain as u64 - 1))
                    as usize
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn extension_reference<B: PrimeField, E: AbstractExtensionField<B>>(nonresidue: u128) {
        for count in [0, 1, 17, 257] {
            let mut actual = ClassicalTranscript::new(b"extension reference", &[4; 64]);
            let mut expected = ClassicalTranscript::new(b"extension reference", &[4; 64]);
            // Independent binomial basis: X^D = nonresidue. Do not use the
            // implementation's multiplication or from_base_fn ordering.
            let mut basis = (E::D as u64).to_le_bytes().to_vec();
            for i in 0..E::D {
                for j in 0..E::D {
                    for k in 0..E::D {
                        let degree = i + j;
                        let coefficient: u128 = if k == degree % E::D {
                            if degree >= E::D { nonresidue } else { 1 }
                        } else {
                            0
                        };
                        basis.extend_from_slice(&coefficient.to_le_bytes());
                    }
                }
            }
            expected.append_bytes(b"field challenge kind", b"extension vector");
            expected.append_bytes(b"extension basis", &basis);
            let raw =
                expected.field_values(b"values", B::MODULUS_VALUE.as_into(), count * E::D, |v| v);
            let values = actual
                .challenge_extension::<B, E>(b"values", count)
                .unwrap();
            let coefficients: Vec<u128> = values
                .iter()
                .flat_map(|v| v.as_base_slice())
                .map(|c| c.value().as_into())
                .collect();
            assert_eq!(coefficients, raw);
            assert_eq!(fingerprint(&mut actual), fingerprint(&mut expected));
        }
    }
    #[test]
    fn extension_basis_and_coefficient_order_match_binomial_reference() {
        extension_reference::<algebra::BabyBear, algebra::BabyBearExetension>(11);
        extension_reference::<algebra::BabyBear, algebra::BabyBearExtension5>(2);
        extension_reference::<algebra::BabyBear, algebra::BabyBearExtension6>(31);
        extension_reference::<algebra::BabyBear, algebra::BabyBearExtension8>(11);
        extension_reference::<algebra::Goldilocks, algebra::GoldilocksExtension>(7);
        extension_reference::<algebra::Goldilocks, algebra::GoldilocksExtension3>(7);
        extension_reference::<algebra::Goldilocks, algebra::GoldilocksExtension4>(7);
        extension_reference::<algebra::Goldilocks, algebra::GoldilocksExtension5>(3);
    }
    #[test]
    fn extension_basis_cache_reuses_type_specific_entries_concurrently() {
        let entries = std::thread::scope(|scope| {
            let workers: Vec<_> =
                (0..8)
                    .map(|_| {
                        scope.spawn(|| {
                (extension_basis::<algebra::BabyBear, algebra::BabyBearExtension6>().unwrap(),
                 extension_basis::<algebra::Goldilocks, algebra::GoldilocksExtension3>().unwrap())
            })
                    })
                    .collect();
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .collect::<Vec<_>>()
        });
        for entry in &entries {
            assert!(Arc::ptr_eq(&entry.0, &entries[0].0));
            assert!(Arc::ptr_eq(&entry.1, &entries[0].1));
            assert!(!Arc::ptr_eq(&entry.0, &entry.1));
        }
    }
    #[test]
    fn child_replay_context_and_finish_are_bound() {
        fn execute(context: &[u8], message: &[u8]) -> ([u8; 32], [u8; 32]) {
            let mut parent = ClassicalTranscript::new(b"parent", &[9; 64]);
            let coins = parent.with_child(b"lookup", context, |child| {
                child.append_bytes(b"proof message", message);
                fingerprint(child)
            });
            (coins, fingerprint(&mut parent))
        }
        let original = execute(b"root A", b"message A");
        assert_eq!(original, execute(b"root A", b"message A"));
        assert_ne!(original.0, execute(b"root B", b"message A").0);
        assert_ne!(original.1, execute(b"root A", b"message B").1);
        let mut parent = ClassicalTranscript::new(b"parent", &[9; 64]);
        let error: Result<(), &str> = parent.with_child(b"lookup", b"root A", |child| {
            child.append_bytes(b"proof message", b"message A");
            let _ = fingerprint(child);
            Err("rejected")
        });
        assert_eq!(error, Err("rejected"));
        assert_eq!(original.1, fingerprint(&mut parent));
    }
    fn prime_reference<F: PrimeField>() {
        for count in [0, 1, 73] {
            let mut actual = ClassicalTranscript::new(b"field reference", &[7; 64]);
            let mut expected = ClassicalTranscript::new(b"field reference", &[7; 64]);
            expected.append_bytes(b"field challenge kind", b"prime vector");
            let p: u128 = F::MODULUS_VALUE.as_into();
            let mut descriptor = p.to_le_bytes().to_vec();
            descriptor.extend_from_slice(&(count as u64).to_le_bytes());
            frame(&mut expected.state, 4, b"values", &descriptor);
            let mut reader = expected.state.clone().finalize_xof();
            let bits = 128 - (p - 1).leading_zeros();
            let width = bits.div_ceil(8) as usize;
            let mask = u128::MAX >> (128 - bits);
            let mut raw = Vec::new();
            let mut values = Vec::new();
            while values.len() < count {
                let mut candidate = [0; 16];
                reader.read(&mut candidate[..width]);
                raw.extend_from_slice(&candidate[..width]);
                let value = u128::from_le_bytes(candidate) & mask;
                if value < p {
                    values.push(value);
                }
            }
            let got: Vec<u128> = actual
                .challenge_prime::<F>(b"values", count)
                .into_iter()
                .map(|v| v.value().as_into())
                .collect();
            assert_eq!(got, values);
            let mut digest = Shake256::default();
            digest.update(b"HasteBoots consumed field bytes v1");
            digest.update(&raw);
            let mut receipt = [0; 80];
            receipt[..16].copy_from_slice(&(raw.len() as u128).to_le_bytes());
            digest.finalize_xof().read(&mut receipt[16..]);
            frame(&mut expected.state, 5, b"values", &receipt);
            assert_eq!(fingerprint(&mut actual), fingerprint(&mut expected));
        }
    }
    #[test]
    fn prime_phases_match_raw_shake_rejection_and_receipt() {
        prime_reference::<algebra::BabyBear>();
        prime_reference::<algebra::Goldilocks>();
    }

    fn fingerprint(t: &mut ClassicalTranscript) -> [u8; 32] {
        let mut out = [0; 32];
        t.challenge_bytes(b"after", &mut out);
        out
    }
    #[test]
    fn shake256_empty_known_answer() {
        let mut bytes = [0; 64];
        Shake256::default().finalize_xof().read(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }
    #[test]
    fn framing_and_profile_separate_transcripts() {
        let mut a = ClassicalTranscript::new(b"test", &[0; 64]);
        let mut b = ClassicalTranscript::new(b"test", &[0; 64]);
        a.append_bytes(b"a", b"bc");
        b.append_bytes(b"ab", b"c");
        assert_ne!(fingerprint(&mut a), fingerprint(&mut b));
        let mut a = ClassicalTranscript::new(b"test", &[0; 64]);
        let mut b = ClassicalTranscript::new(b"test", &[1; 64]);
        assert_ne!(fingerprint(&mut a), fingerprint(&mut b));
    }
    #[test]
    fn indices_match_independent_single_phase_and_reject_before_mutation() {
        let mut a = ClassicalTranscript::new(b"test", &[0; 64]);
        let mut b = ClassicalTranscript::new(b"test", &[0; 64]);
        assert!(a.challenge_indices(b"samples", 3, 4).is_err());
        let indices = a.challenge_indices(b"samples", 16, 7).unwrap();
        b.append_bytes(b"index domain", &16u64.to_le_bytes());
        let mut bytes = [0; 56];
        b.challenge_bytes(b"samples", &mut bytes);
        let expected: Vec<_> = bytes
            .chunks_exact(8)
            .map(|v| (u64::from_le_bytes(v.try_into().unwrap()) & 15) as usize)
            .collect();
        assert_eq!(indices, expected);
        assert_eq!(fingerprint(&mut a), fingerprint(&mut b));
    }
}

#[cfg(test)]
mod receipt_recovery_tests {
    use super::*;
    use std::collections::HashMap;

    const DOMAIN: &[u8] = b"HasteBoots consumed field bytes v1";

    #[derive(Default)]
    struct QueryHistory {
        inputs: Vec<Vec<u8>>,
        outputs: Vec<[u8; 64]>,
        first: HashMap<Vec<u8>, usize>,
        declarations: HashMap<[u8; 64], usize>,
    }

    impl QueryHistory {
        fn query(&mut self, input: Vec<u8>) -> [u8; 64] {
            if let Some(&index) = self.first.get(&input) {
                return self.outputs[index];
            }
            for window in input.windows(64) {
                self.declarations
                    .entry(window.try_into().unwrap())
                    .or_insert(self.inputs.len());
            }
            let mut state = Shake256::default();
            state.update(&input);
            let mut output = [0; 64];
            state.finalize_xof().read(&mut output);
            self.first.insert(input.clone(), self.inputs.len());
            self.inputs.push(input);
            self.outputs.push(output);
            output
        }

        fn before(&self, input: &[u8]) -> Option<HashMap<[u8; 64], Vec<u8>>> {
            self.before_bounded(input, usize::MAX)
        }

        fn before_bounded(
            &self,
            input: &[u8],
            maximum_input: usize,
        ) -> Option<HashMap<[u8; 64], Vec<u8>>> {
            let &first = self.first.get(input)?;
            Some(
                self.outputs[..first]
                    .iter()
                    .copied()
                    .zip(self.inputs[..first].iter().cloned())
                    .filter(|(_, producer)| producer.len() <= maximum_input)
                    .collect(),
            )
        }

        // Structural dependency replay only, outside output collisions. Each
        // recursion uses the producer's own first-query snapshot. Application
        // stages and trusted typed-field admissibility are not established.
        fn dependencies(&self, input: &[u8], root_application: &[u8]) -> Option<()> {
            self.dependencies_bounded(input, root_application, usize::MAX)
        }

        fn dependencies_bounded(
            &self,
            input: &[u8],
            root_application: &[u8],
            maximum_input: usize,
        ) -> Option<()> {
            let mut visited = std::collections::HashSet::new();
            self.dependencies_inner(input, root_application, maximum_input, &mut visited)
        }

        fn inherited_declarations(
            &self,
            input: &[u8],
            application: &[u8],
            limit: usize,
        ) -> Option<HashMap<[u8; 64], usize>> {
            let mut visited = std::collections::HashSet::new();
            self.dependencies_inner(input, application, limit, &mut visited)?;
            // Freeze at the first eligible declaration for this fixed bound.
            // Ineligible queries still retain their global oracle indices and
            // output-collision accounting; their windows are not charged here.
            let mut eligible = HashMap::new();
            for (index, producer) in self.inputs.iter().enumerate() {
                if producer.len() <= limit {
                    for window in producer.windows(64) {
                        eligible
                            .entry(<[u8; 64]>::try_from(window).ok()?)
                            .or_insert(index);
                    }
                }
            }
            let mut declarations = HashMap::new();
            for index in visited {
                for window in self.inputs[index].windows(64) {
                    let root: [u8; 64] = window.try_into().ok()?;
                    let first = *eligible.get(&root)?;
                    if first > index {
                        return None;
                    }
                    declarations.insert(root, first);
                }
            }
            Some(declarations)
        }

        fn dependencies_inner(
            &self,
            input: &[u8],
            root_application: &[u8],
            maximum_input: usize,
            visited: &mut std::collections::HashSet<usize>,
        ) -> Option<()> {
            if input.len() > maximum_input {
                return None;
            }
            let &index = self.first.get(input)?;
            if visited.contains(&index) {
                return Some(());
            }
            let known = self.before_bounded(input, maximum_input)?;
            let decoded = frames(input)?;
            phase_receipts(input, &known)?;
            if decoded.get(1)?
                == &(
                    0,
                    b"application".as_slice(),
                    b"HasteBoots framed SHAKE256 child v1".as_slice(),
                )
            {
                let parent = linked_parent(input, &known)?;
                self.dependencies_inner(parent, root_application, maximum_input, visited)?;
            } else if decoded.get(1)? != &(0, b"application".as_slice(), root_application) {
                return None;
            }
            for (at, &(kind, _, _)) in decoded.iter().enumerate() {
                if kind == 7 {
                    let child = linked_child(input, at, &known)?;
                    self.dependencies_inner(child, root_application, maximum_input, visited)?;
                }
            }
            // Dependencies were queried strictly earlier, so recursion is
            // acyclic. Memoize only successfully checked inputs.
            visited.insert(index);
            Some(())
        }
    }

    // Structural decoding only. Protocol stage/label admissibility and linked
    // child replay are separate obligations; arbitrary decoded frames are not
    // an admissible verifier execution.
    fn frames(mut input: &[u8]) -> Option<Vec<(u8, &[u8], &[u8])>> {
        fn take<'a>(input: &mut &'a [u8], size: usize) -> Option<&'a [u8]> {
            let value = input.get(..size)?;
            *input = input.get(size..)?;
            Some(value)
        }
        fn sized<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
            let length = u64::from_le_bytes(take(input, 8)?.try_into().ok()?);
            take(input, usize::try_from(length).ok()?)
        }
        let mut result = Vec::new();
        while !input.is_empty() {
            let kind = take(&mut input, 1)?[0];
            if kind > 8 {
                return None;
            }
            let label = sized(&mut input)?;
            let message = sized(&mut input)?;
            result.push((kind, label, message));
        }
        Some(result)
    }

    // Recover only a parent seed producer already present at the candidate
    // child's first query. The database is the ideal-XOF query view outside
    // output collisions; recovering this link does not validate its stages.
    fn linked_parent<'a>(
        child_input: &[u8],
        known: &'a HashMap<[u8; 64], Vec<u8>>,
    ) -> Option<&'a [u8]> {
        let child = frames(child_input)?;
        if child.len() < 6
            || child[0] != (0, b"protocol", b"HasteBoots framed SHAKE256 v1")
            || child[1] != (0, b"application", b"HasteBoots framed SHAKE256 child v1")
            || child[2].0 != 0
            || child[2].1 != b"trusted profile"
            || child[2].2.len() != 64
            || child[3].0 != 1
            || child[3].1 != b"child label"
            || child[4].0 != 1
            || child[4].1 != b"child context"
            || child[5].0 != 1
            || child[5].1 != b"parent seed"
        {
            return None;
        }
        let seed: [u8; 64] = child[5].2.try_into().ok()?;
        let input = known.get(&seed)?;
        let parent = frames(input)?;
        if parent.len() < 5
            || parent[0] != child[0]
            || parent[1].0 != 0
            || parent[1].1 != b"application"
            || parent[2] != child[2]
            || parent[parent.len() - 2] != (6, child[3].2, child[4].2)
            || parent[parent.len() - 1] != (2, b"classical child seed", &64u64.to_le_bytes())
        {
            return None;
        }
        Some(input)
    }

    fn linked_child<'a>(
        parent_input: &[u8],
        finish_index: usize,
        known: &'a HashMap<[u8; 64], Vec<u8>>,
    ) -> Option<&'a [u8]> {
        let parent = frames(parent_input)?;
        let &(kind, label, finish) = parent.get(finish_index)?;
        let fork = finish_index.checked_sub(3)?;
        if kind != 7
            || parent[fork].0 != 6
            || parent[fork].1 != label
            || parent[fork + 1] != (2, b"classical child seed", &64u64.to_le_bytes())
            || parent[fork + 2].0 != 3
            || parent[fork + 2].1 != b"classical child seed"
            || parent[fork + 2].2.len() != 64
        {
            return None;
        }
        let digest: [u8; 64] = finish.try_into().ok()?;
        let child_input = known.get(&digest)?;
        let child = frames(child_input)?;
        if child.last()?
            != &(
                2,
                b"classical child finish".as_slice(),
                64u64.to_le_bytes().as_slice(),
            )
        {
            return None;
        }
        let producer = linked_parent(child_input, known)?;
        // Reconstruct the exact parent query prefix, not just a matching
        // label/context. A child from another parent execution cannot return.
        let end = parent[..fork + 2]
            .iter()
            .try_fold(0usize, |size, (_, label, body)| {
                size.checked_add(17)?
                    .checked_add(label.len())?
                    .checked_add(body.len())
            })?;
        if producer != parent_input.get(..end)? || child[5].2 != parent[fork + 2].2 {
            return None;
        }
        Some(child_input)
    }

    #[test]
    fn nested_links_inherit_first_global_root_declarations() {
        fn emit(raw: &mut Vec<u8>, kind: u8, label: &[u8], body: &[u8]) {
            raw.push(kind);
            raw.extend((label.len() as u64).to_le_bytes());
            raw.extend(label);
            raw.extend((body.len() as u64).to_le_bytes());
            raw.extend(body);
        }
        fn initial(application: &[u8], profile: &[u8; 64]) -> Vec<u8> {
            let mut raw = Vec::new();
            emit(&mut raw, 0, b"protocol", b"HasteBoots framed SHAKE256 v1");
            emit(&mut raw, 0, b"application", application);
            emit(&mut raw, 0, b"trusted profile", profile);
            raw
        }
        fn same(production: &ClassicalTranscript, raw: &[u8]) {
            let mut expected = Shake256::default();
            expected.update(raw);
            let mut a = [0; 64];
            let mut b = [0; 64];
            expected.finalize_xof().read(&mut a);
            production.state.clone().finalize_xof().read(&mut b);
            assert_eq!(a, b);
        }
        fn append(
            production: &mut ClassicalTranscript,
            raw: &mut Vec<u8>,
            label: &[u8],
            body: &[u8],
        ) {
            production.append_bytes(label, body);
            emit(raw, 1, label, body);
            same(production, raw);
        }
        fn fork(
            production: &mut ClassicalTranscript,
            raw: &mut Vec<u8>,
            history: &mut QueryHistory,
            label: &[u8],
            context: &[u8],
        ) -> (ClassicalTranscript, Vec<u8>) {
            emit(raw, 6, label, context);
            emit(raw, 2, b"classical child seed", &64u64.to_le_bytes());
            let seed = history.query(raw.clone());
            let child = production.fork_child(label, context);
            emit(raw, 3, b"classical child seed", &seed);
            same(production, raw);
            let mut child_raw =
                initial(b"HasteBoots framed SHAKE256 child v1", &production.profile);
            emit(&mut child_raw, 1, b"child label", label);
            emit(&mut child_raw, 1, b"child context", context);
            emit(&mut child_raw, 1, b"parent seed", &seed);
            same(&child, &child_raw);
            (child, child_raw)
        }
        fn query(
            production: &mut ClassicalTranscript,
            raw: &mut Vec<u8>,
            history: &mut QueryHistory,
            label: &[u8],
        ) -> Vec<u8> {
            emit(raw, 2, label, &64u64.to_le_bytes());
            let input = raw.clone();
            let expected = history.query(input.clone());
            let mut actual = [0; 64];
            production.challenge_bytes(label, &mut actual);
            assert_eq!(actual, expected);
            emit(raw, 3, label, &actual);
            same(production, raw);
            input
        }
        fn finish(
            parent: &mut ClassicalTranscript,
            parent_raw: &mut Vec<u8>,
            child: &mut ClassicalTranscript,
            child_raw: &mut Vec<u8>,
            history: &mut QueryHistory,
            label: &[u8],
        ) {
            emit(
                child_raw,
                2,
                b"classical child finish",
                &64u64.to_le_bytes(),
            );
            let digest = history.query(child_raw.clone());
            parent.finish_linked_child(label, child);
            emit(child_raw, 3, b"classical child finish", &digest);
            emit(parent_raw, 7, label, &digest);
            same(child, child_raw);
            same(parent, parent_raw);
        }
        let profile = [31; 64];
        let application = b"root declaration audit";
        let primary = [41; 64];
        let auxiliary = [43; 64];
        let nested = [47; 64];
        let mut history = QueryHistory::default();
        // This oversized query owns unfiltered declaration zero; bounded
        // declarations exclude its windows without renumbering later queries.
        let mut oversized = vec![255; 4096];
        oversized[17..81].copy_from_slice(&primary);
        history.query(oversized);
        let mut parent = ClassicalTranscript::new(application, &profile);
        let mut raw = initial(application, &profile);
        append(&mut parent, &mut raw, b"primary source root", &primary);
        let (mut child, mut child_raw) = fork(
            &mut parent,
            &mut raw,
            &mut history,
            b"PCS child",
            b"trusted role context",
        );
        append(&mut child, &mut child_raw, b"auxiliary root", &auxiliary);
        let (mut grand, mut grand_raw) = fork(
            &mut child,
            &mut child_raw,
            &mut history,
            b"rolling child",
            b"trusted rolling context",
        );
        append(&mut grand, &mut grand_raw, b"derived root", &nested);
        let grand_input = query(
            &mut grand,
            &mut grand_raw,
            &mut history,
            b"nested challenge",
        );
        let limit = 2048;
        let inherited = history
            .inherited_declarations(&grand_input, application, limit)
            .unwrap();
        assert_eq!(history.declarations.get(&primary), Some(&0));
        assert_eq!(
            history
                .inherited_declarations(&grand_input, application, usize::MAX)
                .unwrap()
                .get(&primary),
            Some(&0)
        );
        assert_eq!(inherited.get(&primary), Some(&1));
        assert_eq!(inherited.get(&auxiliary), Some(&2));
        assert_eq!(inherited.get(&nested), Some(&3));
        assert!(!grand_input.windows(64).any(|window| window == primary));
        finish(
            &mut child,
            &mut child_raw,
            &mut grand,
            &mut grand_raw,
            &mut history,
            b"rolling child",
        );
        finish(
            &mut parent,
            &mut raw,
            &mut child,
            &mut child_raw,
            &mut history,
            b"PCS child",
        );
        let resumed = query(
            &mut parent,
            &mut raw,
            &mut history,
            b"resumed parent challenge",
        );
        let resumed_roots = history
            .inherited_declarations(&resumed, application, limit)
            .unwrap();
        for root in [primary, auxiliary, nested] {
            assert_eq!(resumed_roots[&root], inherited[&root]);
        }
        // Observing the candidate before its seed producers cannot be repaired
        // by querying those producers afterwards, or by re-querying candidate.
        let mut reversed = QueryHistory::default();
        reversed.query(grand_input.clone());
        for input in &history.inputs {
            reversed.query(input.clone());
        }
        reversed.query(grand_input.clone());
        assert!(
            reversed
                .inherited_declarations(&grand_input, application, limit)
                .is_none()
        );
        let mut early_return = QueryHistory::default();
        early_return.query(resumed.clone());
        for input in &history.inputs {
            early_return.query(input.clone());
        }
        assert!(
            early_return
                .inherited_declarations(&resumed, application, limit)
                .is_none()
        );
    }

    #[test]
    fn child_finish_recovery_requires_same_parent_and_frozen_producers() {
        fn encode(items: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
            let mut out = Vec::new();
            for &(kind, label, body) in items {
                out.push(kind);
                out.extend_from_slice(&(label.len() as u64).to_le_bytes());
                out.extend_from_slice(label);
                out.extend_from_slice(&(body.len() as u64).to_le_bytes());
                out.extend_from_slice(body);
            }
            out
        }
        fn digest(input: &[u8]) -> [u8; 64] {
            let mut state = Shake256::default();
            state.update(input);
            let mut out = [0; 64];
            state.finalize_xof().read(&mut out);
            out
        }
        let profile = [19; 64];
        let parent = encode(&[
            (0, b"protocol", b"HasteBoots framed SHAKE256 v1"),
            (0, b"application", b"parent fixture"),
            (0, b"trusted profile", &profile),
            (6, b"bridge", b"context"),
            (2, b"classical child seed", &64u64.to_le_bytes()),
        ]);
        let seed = digest(&parent);
        let child = encode(&[
            (0, b"protocol", b"HasteBoots framed SHAKE256 v1"),
            (0, b"application", b"HasteBoots framed SHAKE256 child v1"),
            (0, b"trusted profile", &profile),
            (1, b"child label", b"bridge"),
            (1, b"child context", b"context"),
            (1, b"parent seed", &seed),
            (1, b"child proof messages", b"fixed payload"),
            (2, b"classical child finish", &64u64.to_le_bytes()),
        ]);
        let finish = digest(&child);
        let make_parent = |seed: &[u8], label: &[u8]| {
            let mut input = parent.clone();
            input.extend(encode(&[
                (3, b"classical child seed", seed),
                (7, label, &finish),
                (2, b"current", &8u64.to_le_bytes()),
            ]));
            input
        };
        let input = make_parent(&seed, b"bridge");
        let mut chronological = QueryHistory::default();
        let irrelevant = chronological.query(vec![255; 4096]);
        assert_eq!(chronological.query(parent.clone()), seed);
        assert_eq!(chronological.query(child.clone()), finish);
        chronological.query(input.clone());
        assert_eq!(
            chronological.dependencies(&input, b"parent fixture"),
            Some(())
        );
        let limit = parent.len().max(child.len()).max(input.len());
        assert!(limit < 4096);
        assert!(
            chronological
                .before(&input)
                .unwrap()
                .contains_key(&irrelevant)
        );
        assert!(
            !chronological
                .before_bounded(&input, limit)
                .unwrap()
                .contains_key(&irrelevant)
        );
        assert_eq!(
            chronological.dependencies_bounded(&input, b"parent fixture", limit),
            Some(())
        );
        assert!(
            chronological
                .dependencies_bounded(&input, b"parent fixture", limit - 1)
                .is_none()
        );
        assert!(
            chronological
                .dependencies(&input, b"other application")
                .is_none()
        );
        let mut late = QueryHistory::default();
        late.query(parent.clone());
        let first_output = late.query(input.clone());
        late.query(child.clone());
        assert_eq!(late.query(input.clone()), first_output);
        assert_eq!(late.inputs.len(), 3); // Repeat is not a fresh opportunity.
        assert!(late.dependencies(&input, b"parent fixture").is_none());
        assert!(!late.before(&input).unwrap().contains_key(&finish));
        let mut known = HashMap::new();
        known.insert(seed, parent.clone());
        let frozen = known.clone();
        assert!(linked_child(&input, 6, &frozen).is_none());
        known.insert(finish, child.clone());
        assert_eq!(linked_child(&input, 6, &known), Some(child.as_slice()));
        assert!(linked_child(&input, 6, &frozen).is_none());
        assert!(linked_child(&make_parent(&[0; 64], b"bridge"), 6, &known).is_none());
        assert!(linked_child(&make_parent(&seed, b"other"), 6, &known).is_none());
        let mut foreign = input.clone();
        let at = foreign
            .windows(b"parent fixture".len())
            .position(|window| window == b"parent fixture")
            .unwrap();
        foreign[at] ^= 1;
        assert!(linked_child(&foreign, 6, &known).is_none());
        known.remove(&seed);
        assert!(linked_child(&input, 6, &known).is_none());
    }

    #[test]
    fn child_seed_recovery_requires_frozen_producer_context_and_profile() {
        fn encode(items: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
            let mut out = Vec::new();
            for &(kind, label, body) in items {
                out.push(kind);
                out.extend_from_slice(&(label.len() as u64).to_le_bytes());
                out.extend_from_slice(label);
                out.extend_from_slice(&(body.len() as u64).to_le_bytes());
                out.extend_from_slice(body);
            }
            out
        }
        let profile = [17; 64];
        let parent = encode(&[
            (0, b"protocol", b"HasteBoots framed SHAKE256 v1"),
            (0, b"application", b"parent fixture"),
            (0, b"trusted profile", &profile),
            (6, b"bridge", b"context"),
            (2, b"classical child seed", &64u64.to_le_bytes()),
        ]);
        let mut oracle = Shake256::default();
        oracle.update(&parent);
        let mut seed = [0; 64];
        oracle.finalize_xof().read(&mut seed);
        let make_child = |profile: &[u8], label: &[u8], context: &[u8]| {
            encode(&[
                (0, b"protocol", b"HasteBoots framed SHAKE256 v1"),
                (0, b"application", b"HasteBoots framed SHAKE256 child v1"),
                (0, b"trusted profile", profile),
                (1, b"child label", label),
                (1, b"child context", context),
                (1, b"parent seed", &seed),
                (2, b"current phase", &8u64.to_le_bytes()),
            ])
        };
        let child = make_child(&profile, b"bridge", b"context");
        let frozen = HashMap::new();
        assert!(linked_parent(&child, &frozen).is_none());
        let mut later = frozen.clone();
        later.insert(seed, parent.clone());
        assert_eq!(linked_parent(&child, &later), Some(parent.as_slice()));
        assert!(linked_parent(&child, &frozen).is_none());
        for invalid in [
            make_child(&[18; 64], b"bridge", b"context"),
            make_child(&profile, b"other", b"context"),
            make_child(&profile, b"bridge", b"other"),
        ] {
            assert!(linked_parent(&invalid, &later).is_none());
        }
    }

    #[test]
    fn first_query_frames_decode_exact_production_hash_input() {
        let items: &[(u8, &[u8], &[u8])] = &[
            (0, b"protocol", b"HasteBoots framed SHAKE256 v1"),
            (0, b"application", b"prefix decoding fixture"),
            (0, b"trusted profile", &[7; 64]),
            (1, b"message", b"\0\x04arbitrary prover bytes\xff"),
            (2, b"candidate phase", &32u64.to_le_bytes()),
        ];
        let mut input = Vec::new();
        let mut boundaries = vec![0];
        let mut production = Shake256::default();
        for &(kind, label, message) in items {
            frame(&mut production, kind, label, message);
            input.push(kind);
            input.extend_from_slice(&(label.len() as u64).to_le_bytes());
            input.extend_from_slice(label);
            input.extend_from_slice(&(message.len() as u64).to_le_bytes());
            input.extend_from_slice(message);
            boundaries.push(input.len());
        }
        assert_eq!(frames(&input).unwrap(), items);
        let mut expected = [0; 64];
        let mut actual = [0; 64];
        production.finalize_xof().read(&mut expected);
        let mut replay = Shake256::default();
        replay.update(&input);
        replay.finalize_xof().read(&mut actual);
        assert_eq!(actual, expected);
        for end in 0..input.len() {
            assert_eq!(frames(&input[..end]).is_some(), boundaries.contains(&end));
        }
        let mut invalid = input.clone();
        invalid[0] = 9;
        assert!(frames(&invalid).is_none());
        invalid = input.clone();
        invalid[1..9].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(frames(&invalid).is_none());
        let mut with_trailing = input;
        with_trailing.push(0);
        assert!(frames(&with_trailing).is_none());
    }

    fn producer(raw: &[u8]) -> ([u8; 80], Vec<u8>) {
        let mut input = DOMAIN.to_vec();
        input.extend_from_slice(raw);
        let mut hash = Shake256::default();
        hash.update(&input);
        let mut receipt = [0; 80];
        receipt[..16].copy_from_slice(&(raw.len() as u128).to_le_bytes());
        hash.finalize_xof().read(&mut receipt[16..]);
        (receipt, input)
    }

    // Test-only oracle-query view: interpret a candidate's proposed earlier
    // coins from a producer preimage already known at the candidate query.
    // This does not assert that its earlier phase input has been queried, or
    // that the candidate is consistent with that phase's eventual output.
    fn recover(
        p: u128,
        count: usize,
        receipt: &[u8; 80],
        known: &HashMap<[u8; 64], Vec<u8>>,
    ) -> Option<Vec<u128>> {
        let digest: [u8; 64] = receipt[16..].try_into().ok()?;
        let raw = known.get(&digest)?.strip_prefix(DOMAIN)?;
        if u128::from_le_bytes(receipt[..16].try_into().ok()?) != raw.len() as u128 || p < 2 {
            return None;
        }
        let bits = 128 - (p - 1).leading_zeros();
        let width = bits.div_ceil(8) as usize;
        if raw.len() % width != 0 {
            return None;
        }
        let mut values = Vec::new();
        for chunk in raw.chunks_exact(width) {
            if values.len() == count {
                return None;
            }
            let mut candidate = [0; 16];
            candidate[..width].copy_from_slice(chunk);
            let value = u128::from_le_bytes(candidate) & (u128::MAX >> (128 - bits));
            if value < p {
                values.push(value);
            }
        }
        (values.len() == count).then_some(values)
    }

    #[derive(Debug, PartialEq)]
    enum ProposedCoins {
        Field(Vec<u128>),
        Bytes(Vec<u8>),
    }

    // Decode completed phases from a candidate prefix using only the
    // supplied frozen producer database. A terminal request is the current
    // phase, whose output is deliberately not interpreted here. Typed basis
    // markers and protocol labels need separate admissibility. Inline bytes
    // are proposed coins, not evidence of an earlier oracle query.
    fn phase_receipts(
        input: &[u8],
        known: &HashMap<[u8; 64], Vec<u8>>,
    ) -> Option<Vec<ProposedCoins>> {
        let decoded = frames(input)?;
        let mut phases = Vec::new();
        let mut index = 0;
        while index < decoded.len() {
            let (kind, label, descriptor) = decoded[index];
            if kind == 3 || kind == 5 {
                return None; // No preceding request.
            }
            if kind != 2 && kind != 4 {
                index += 1;
                continue;
            }
            if descriptor.len() != if kind == 2 { 8 } else { 24 } {
                return None;
            }
            let count = usize::try_from(u64::from_le_bytes(
                descriptor[descriptor.len() - 8..].try_into().ok()?,
            ))
            .ok()?;
            let prime = if kind == 4 {
                u128::from_le_bytes(descriptor[..16].try_into().ok()?)
            } else {
                0
            };
            if kind == 4 && prime < 2 {
                return None;
            }
            if index + 1 == decoded.len() {
                break;
            }
            let (receipt_kind, receipt_label, receipt) = decoded[index + 1];
            if receipt_kind != kind + 1 || receipt_label != label {
                return None;
            }
            if kind == 2 {
                if receipt.len() != count {
                    return None;
                }
                phases.push(ProposedCoins::Bytes(receipt.to_vec()));
            } else {
                phases.push(ProposedCoins::Field(recover(
                    prime,
                    count,
                    receipt.try_into().ok()?,
                    known,
                )?));
            }
            index += 2;
        }
        Some(phases)
    }

    fn typed_phase_receipts<B: PrimeField, E: AbstractExtensionField<B>>(
        input: &[u8],
        known: &HashMap<[u8; 64], Vec<u8>>,
        extension: bool,
    ) -> Option<Vec<ProposedCoins>> {
        let phases = phase_receipts(input, known)?;
        let decoded = frames(input)?;
        for (index, &(kind, _, descriptor)) in decoded.iter().enumerate() {
            if kind != 4 {
                continue;
            }
            let prime = u128::from_le_bytes(descriptor[..16].try_into().ok()?);
            if prime != B::MODULUS_VALUE.as_into() {
                return None;
            }
            let marker = if extension {
                let basis = extension_basis::<B, E>().ok()?;
                let &(k, label, body) = decoded.get(index.checked_sub(1)?)?;
                if k != 1 || label != b"extension basis" || body != basis.as_ref() {
                    return None;
                }
                let count = u64::from_le_bytes(descriptor[16..].try_into().ok()?);
                if E::D == 0 || count % u64::try_from(E::D).ok()? != 0 {
                    return None;
                }
                decoded.get(index.checked_sub(2)?)?
            } else {
                decoded.get(index.checked_sub(1)?)?
            };
            let expected_kind: &[u8] = if extension {
                b"extension vector"
            } else {
                b"prime vector"
            };
            if marker.0 != 1 || marker.1 != b"field challenge kind" || marker.2 != expected_kind {
                return None;
            }
        }
        Some(phases)
    }

    #[test]
    fn typed_candidate_phases_bind_trusted_modulus_and_complete_basis() {
        fn check<B: PrimeField, E: AbstractExtensionField<B>>() {
            fn encode(items: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
                let mut bytes = Vec::new();
                for &(kind, label, body) in items {
                    bytes.push(kind);
                    bytes.extend_from_slice(&(label.len() as u64).to_le_bytes());
                    bytes.extend_from_slice(label);
                    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
                    bytes.extend_from_slice(body);
                }
                bytes
            }
            let prime: u128 = B::MODULUS_VALUE.as_into();
            let mut descriptor = prime.to_le_bytes().to_vec();
            descriptor.extend_from_slice(&(E::D as u64).to_le_bytes());
            let basis = extension_basis::<B, E>().unwrap();
            let make = |table: &[u8], request: &[u8]| {
                encode(&[
                    (1, b"field challenge kind", b"extension vector"),
                    (1, b"extension basis", table),
                    (4, b"current", request),
                ])
            };
            let known = HashMap::new();
            let prefix = make(&basis, &descriptor);
            assert_eq!(
                typed_phase_receipts::<B, E>(&prefix, &known, true),
                Some(vec![])
            );
            assert!(typed_phase_receipts::<B, E>(&prefix, &known, false).is_none());
            let mut wrong = basis.to_vec();
            wrong[8] ^= 1;
            assert!(
                typed_phase_receipts::<B, E>(&make(&wrong, &descriptor), &known, true).is_none()
            );
            let mut wrong = descriptor.clone();
            wrong[..16].copy_from_slice(&(prime + 2).to_le_bytes());
            assert!(typed_phase_receipts::<B, E>(&make(&basis, &wrong), &known, true).is_none());
            wrong = descriptor.clone();
            wrong[16..].copy_from_slice(&1u64.to_le_bytes());
            assert!(typed_phase_receipts::<B, E>(&make(&basis, &wrong), &known, true).is_none());
            let prime_prefix = encode(&[
                (1, b"field challenge kind", b"prime vector"),
                (4, b"current", &descriptor),
            ]);
            assert_eq!(
                typed_phase_receipts::<B, E>(&prime_prefix, &known, false),
                Some(vec![])
            );
        }
        check::<algebra::BabyBear, algebra::BabyBearExetension>();
        check::<algebra::BabyBear, algebra::BabyBearExtension5>();
        check::<algebra::BabyBear, algebra::BabyBearExtension6>();
        check::<algebra::BabyBear, algebra::BabyBearExtension8>();
        check::<algebra::Goldilocks, algebra::GoldilocksExtension>();
        check::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
        check::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
        check::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }

    #[test]
    fn framed_field_receipts_use_frozen_producers_and_matching_requests() {
        fn encode(items: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
            let mut bytes = Vec::new();
            for &(kind, label, body) in items {
                bytes.push(kind);
                bytes.extend_from_slice(&(label.len() as u64).to_le_bytes());
                bytes.extend_from_slice(label);
                bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
                bytes.extend_from_slice(body);
            }
            bytes
        }
        for prime in [2013265921u128, 18446744069414584321] {
            let width = (128 - (prime - 1).leading_zeros()).div_ceil(8) as usize;
            let raw: Vec<_> = [prime, 1, 7]
                .iter()
                .flat_map(|v| v.to_le_bytes()[..width].to_vec())
                .collect();
            let (receipt, producer) = producer(&raw);
            let mut descriptor = prime.to_le_bytes().to_vec();
            descriptor.extend_from_slice(&2u64.to_le_bytes());
            let prefix = encode(&[
                (4, b"earlier", &descriptor),
                (5, b"earlier", &receipt),
                (4, b"current", &descriptor),
            ]);
            let frozen = HashMap::new();
            assert!(phase_receipts(&prefix, &frozen).is_none());
            let mut later = frozen.clone();
            later.insert(receipt[16..].try_into().unwrap(), producer);
            assert_eq!(
                phase_receipts(&prefix, &later),
                Some(vec![ProposedCoins::Field(vec![1, 7])])
            );
            assert!(phase_receipts(&prefix, &frozen).is_none());
            let byte_request = 3u64.to_le_bytes();
            let mixed = encode(&[
                (2, b"bytes", &byte_request),
                (3, b"bytes", b"abc"),
                (4, b"earlier", &descriptor),
                (5, b"earlier", &receipt),
                (2, b"current", &byte_request),
            ]);
            assert_eq!(
                phase_receipts(&mixed, &later),
                Some(vec![
                    ProposedCoins::Bytes(b"abc".to_vec()),
                    ProposedCoins::Field(vec![1, 7]),
                ])
            );
            for invalid in [
                encode(&[(4, b"earlier", &descriptor), (5, b"other", &receipt)]),
                encode(&[(5, b"orphan", &receipt)]),
                encode(&[(4, b"earlier", &descriptor[..23])]),
                encode(&[(4, b"earlier", &descriptor), (1, b"interposed", b"")]),
                encode(&[
                    (4, b"earlier", &descriptor),
                    (5, b"earlier", &receipt[..79]),
                ]),
                encode(&[(2, b"bytes", &byte_request), (3, b"bytes", b"ab")]),
                encode(&[(2, b"bytes", &byte_request), (3, b"other", b"abc")]),
                encode(&[(3, b"orphan", b"abc")]),
                encode(&[(2, b"bytes", &byte_request), (5, b"bytes", &receipt)]),
            ] {
                assert!(phase_receipts(&invalid, &later).is_none());
            }
        }
    }

    #[test]
    fn receipts_recover_proposed_coins_and_enforce_first_query_snapshot() {
        for p in [2013265921u128, 18446744069414584321] {
            let width = (128 - (p - 1).leading_zeros()).div_ceil(8) as usize;
            let mut raw = Vec::new();
            for value in [p, 1, 7] {
                // First candidate is rejected.
                raw.extend_from_slice(&value.to_le_bytes()[..width]);
            }
            let (receipt, input) = producer(&raw);
            // The fixture deliberately supplies a matching proposed receipt
            // to model a late-target hit; this test assigns no probability.
            let digest: [u8; 64] = receipt[16..].try_into().unwrap();
            let mut oracle = HashMap::new();
            let frozen = oracle.clone();
            assert_eq!(recover(p, 2, &receipt, &frozen), None);
            oracle.insert(digest, input);
            // Adding the producer later cannot change the earlier snapshot.
            assert_eq!(recover(p, 2, &receipt, &frozen), None);
            assert_eq!(recover(p, 2, &receipt, &oracle), Some(vec![1, 7]));
            assert_eq!(oracle.len(), 1); // Only the receipt producer is known.
            assert_eq!(recover(p, 1, &receipt, &oracle), None); // Surplus raw bytes.
            assert_eq!(recover(p, 3, &receipt, &oracle), None); // Too few acceptances.
            let mut wrong = receipt;
            wrong[0] ^= 1;
            assert_eq!(recover(p, 2, &wrong, &oracle), None);
            let (empty, input) = producer(&[]);
            oracle.insert(empty[16..].try_into().unwrap(), input);
            assert_eq!(recover(p, 0, &empty, &oracle), Some(vec![]));
        }
    }
}

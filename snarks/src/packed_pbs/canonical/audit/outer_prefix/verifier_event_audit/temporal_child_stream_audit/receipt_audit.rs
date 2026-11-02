//! Replay completed generic transcript phases at their observed query prefix.
//! Application messages and algebra/PCS semantics remain caller obligations.
use super::*;

#[derive(Default)]
pub(super) struct History {
    previous: [Vec<u8>; 3],
    basis: Vec<u8>,
}

fn output_matches(state: &sha3::Shake256, expected: &[u8]) -> bool {
    let mut reader = sha3::digest::ExtendableOutput::finalize_xof(state.clone());
    let mut buffer = [0; 8192];
    for chunk in expected.chunks(buffer.len()) {
        sha3::digest::XofReader::read(&mut reader, &mut buffer[..chunk.len()]);
        if chunk != &buffer[..chunk.len()] {
            return false;
        }
    }
    true
}

fn request_available(
    request: &[u8],
    state: &sha3::Shake256,
    file: &mut File,
    producers: &HashMap<[u8; 64], Span>,
) -> io::Result<()> {
    let mut digest = [0; 64];
    sha3::digest::XofReader::read(
        &mut sha3::digest::ExtendableOutput::finalize_xof(state.clone()),
        &mut digest,
    );
    let span = *producers
        .get(&digest)
        .ok_or_else(|| invalid("receipt request producer unavailable"))?;
    if !same_input(file, span, request)? {
        return Err(invalid("receipt request producer input"));
    }
    Ok(())
}

impl History {
    pub(super) fn check<F: NTTField, EF: AbstractExtensionField<F>>(
        &mut self,
        profile: &ClassicalProfile,
        input: &[u8],
        file: &mut File,
        producers: &HashMap<[u8; 64], Span>,
    ) -> io::Result<usize> {
        let mut header = Vec::new();
        frame(
            &mut header,
            0,
            b"protocol",
            b"HasteBoots framed SHAKE256 v1",
        );
        let Some(mut rest) = input.strip_prefix(header.as_slice()) else {
            return Ok(0);
        };
        let application = message(&mut rest, 0, b"application")
            .ok_or_else(|| invalid("receipt transcript application"))?;
        if ![
            b"HasteBoots typed classical prime v1".as_slice(),
            b"HasteBoots typed classical extension v1".as_slice(),
            b"HasteBoots framed SHAKE256 child v1".as_slice(),
        ]
        .contains(&application)
            || message(&mut rest, 0, b"trusted profile") != Some(profile.id().0.as_slice())
        {
            return Err(invalid("receipt transcript profile/application"));
        }
        let prime: u128 = F::MODULUS_VALUE
            .to_string()
            .parse()
            .map_err(|_| invalid("trusted field modulus"))?;
        let extension = application != b"HasteBoots typed classical prime v1";
        if !extension
            && message(&mut rest, 1, b"typed prime field") != Some(prime.to_le_bytes().as_slice())
        {
            return Err(invalid("typed prime field identity"));
        }
        if self.basis.is_empty() {
            self.basis = raw_basis::<F, EF>();
        }
        let family = framed_family(input).ok_or_else(|| invalid("typed input namespace"))?;
        let previous = &self.previous[family];
        let shared = if input.starts_with(previous) {
            previous.len()
        } else if previous.starts_with(input) {
            input.len()
        } else {
            previous
                .iter()
                .zip(input)
                .take_while(|(a, b)| a == b)
                .count()
        };
        let mut previous = None::<(u8, &[u8], &[u8], usize)>;
        let mut prior = std::collections::VecDeque::<(u8, &[u8], &[u8])>::new();
        let mut first_field = true;
        // Absorb this input once. A request snapshot includes exactly its
        // request frame, before the following response is absorbed. Cloning a
        // SHAKE state preserves the exact prefix without rehashing that prefix
        // for every completed phase embedded in a large parent transcript.
        let mut prefix_state = sha3::Shake256::default();
        sha3::digest::Update::update(&mut prefix_state, &input[..input.len() - rest.len()]);
        let mut request_state = None::<sha3::Shake256>;
        let mut fork = None::<(&[u8], &[u8])>;
        let mut seed = None::<&[u8]>;
        let mut checked = 0;
        while !rest.is_empty() {
            let start = input.len() - rest.len();
            let kind = *take(&mut rest, 1)
                .and_then(|bytes| bytes.first())
                .ok_or_else(|| invalid("receipt frame kind"))?;
            if !matches!(kind, 1..=8) {
                return Err(invalid("unsupported or repeated domain frame kind"));
            }
            let label = sized(&mut rest).ok_or_else(|| invalid("receipt frame label"))?;
            let body = sized(&mut rest).ok_or_else(|| invalid("receipt frame body"))?;
            let end = input.len() - rest.len();
            sha3::digest::Update::update(&mut prefix_state, &input[start..end]);
            if let Some((request_kind @ (2 | 4), request_label, _, _)) = previous {
                if kind != request_kind + 1 || label != request_label {
                    return Err(invalid("transcript advanced before request response"));
                }
            }
            if fork.is_some() {
                if seed.is_some() {
                    if !matches!(kind, 7 | 8) {
                        return Err(invalid("parent advanced before child finish"));
                    }
                } else {
                    match previous {
                        Some((6, _, _, _))
                            if kind == 2
                                && label == b"classical child seed"
                                && body == 64u64.to_le_bytes() => {}
                        Some((2, b"classical child seed", _, _))
                            if kind == 3 && label == b"classical child seed" => {}
                        _ => return Err(invalid("parent fork seed sequence")),
                    }
                }
            } else if kind == 3 && label == b"classical child seed" {
                return Err(invalid("child seed response without fork"));
            }
            if kind == 8
                && (fork.is_none()
                    || seed.is_none()
                    || label != b"parent checkpoint"
                    || !body.is_empty()
                    || !rest.is_empty())
            {
                return Err(invalid("parent checkpoint position"));
            }
            if kind == 2 && body.len() != 8 {
                return Err(invalid("byte request descriptor"));
            }
            if kind == 4 {
                if body.len() != 24 || u128::from_le_bytes(body[..16].try_into().unwrap()) != prime
                {
                    return Err(invalid("typed field request descriptor"));
                }
                let count = u64::from_le_bytes(body[16..].try_into().unwrap());
                let preceding = |n: usize| {
                    prior
                        .len()
                        .checked_sub(n)
                        .and_then(|i| prior.get(i))
                        .copied()
                };
                let marker = if extension {
                    let degree = u64::try_from(EF::D)
                        .ok()
                        .filter(|&d| d > 0)
                        .ok_or_else(|| invalid("trusted extension degree"))?;
                    if count % degree != 0
                        || preceding(1)
                            != Some((1, b"extension basis".as_slice(), self.basis.as_slice()))
                        || preceding(2)
                            != Some((
                                1,
                                b"field challenge kind".as_slice(),
                                b"extension vector".as_slice(),
                            ))
                    {
                        return Err(invalid("typed extension request identity"));
                    }
                    if first_field {
                        if label != b"typed extension identity" || count != 0 {
                            return Err(invalid("missing initial extension identity"));
                        }
                        None
                    } else {
                        if label == b"typed extension identity" {
                            return Err(invalid("repeated extension identity"));
                        }
                        Some((preceding(3), degree))
                    }
                } else {
                    if preceding(1)
                        != Some((
                            1,
                            b"field challenge kind".as_slice(),
                            b"prime vector".as_slice(),
                        ))
                    {
                        return Err(invalid("typed prime request marker"));
                    }
                    Some((preceding(2), 1))
                };
                if let Some((marker, scalar_count)) = marker {
                    match marker {
                        Some((1, b"typed request kind", b"vector")) => {}
                        Some((1, b"typed request kind", b"scalar")) if count == scalar_count => {}
                        _ => return Err(invalid("typed scalar/vector request")),
                    }
                }
                first_field = false;
            }
            if kind == 6 {
                fork = Some((label, body));
                seed = None;
            }
            if matches!(kind, 3 | 5) && end > shared {
                let (request_kind, request_label, descriptor, request_end) =
                    previous.ok_or_else(|| invalid("orphan transcript receipt"))?;
                if request_kind != kind - 1 || request_label != label {
                    return Err(invalid("receipt request kind/label"));
                }
                let request = &input[..request_end];
                let state = request_state
                    .as_ref()
                    .ok_or_else(|| invalid("receipt request hash state"))?;
                request_available(request, state, file, producers)?;
                if kind == 3 {
                    let count = u64::from_le_bytes(
                        descriptor
                            .try_into()
                            .map_err(|_| invalid("byte request descriptor"))?,
                    );
                    if body.len() as u128 != count as u128 || !output_matches(state, body) {
                        return Err(invalid("byte receipt stream/length"));
                    }
                } else {
                    if descriptor.len() != 24 || body.len() != 80 {
                        return Err(invalid("field receipt descriptor/length"));
                    }
                    let modulus = u128::from_le_bytes(descriptor[..16].try_into().unwrap());
                    let trusted: u128 = F::MODULUS_VALUE
                        .to_string()
                        .parse()
                        .map_err(|_| invalid("trusted field modulus"))?;
                    if modulus != trusted || modulus < 2 {
                        return Err(invalid("field receipt modulus"));
                    }
                    let count = u64::from_le_bytes(descriptor[16..].try_into().unwrap());
                    let fingerprint: [u8; 64] = body[16..].try_into().unwrap();
                    let span = *producers
                        .get(&fingerprint)
                        .ok_or_else(|| invalid("field receipt producer unavailable"))?;
                    let producer = read_span(file, span)?;
                    let raw = producer
                        .strip_prefix(b"HasteBoots consumed field bytes v1")
                        .ok_or_else(|| invalid("field receipt producer domain"))?;
                    if u128::from_le_bytes(body[..16].try_into().unwrap()) != raw.len() as u128
                        || !output_matches(state, raw)
                    {
                        return Err(invalid("field receipt stream/length"));
                    }
                    let bits = 128 - (modulus - 1).leading_zeros() as usize;
                    let bytes = (bits + 7) / 8;
                    if raw.len() % bytes != 0 {
                        return Err(invalid("field receipt candidate width"));
                    }
                    let mut accepted = 0u64;
                    for chunk in raw.chunks_exact(bytes) {
                        if accepted == count {
                            return Err(invalid("surplus field receipt bytes"));
                        }
                        let mut word = [0; 16];
                        word[..bytes].copy_from_slice(chunk);
                        let value = u128::from_le_bytes(word) & (u128::MAX >> (128 - bits));
                        if value < modulus {
                            accepted += 1;
                        }
                    }
                    if accepted != count {
                        return Err(invalid("field receipt acceptance count"));
                    }
                }
                checked += 1;
            }
            if kind == 3 && label == b"classical child seed" {
                seed = Some(body);
            }
            if kind == 7 {
                let (child_label, child_context) =
                    fork.ok_or_else(|| invalid("child finish without parent fork"))?;
                let child_seed = seed.ok_or_else(|| invalid("child finish without parent seed"))?;
                if label != child_label || child_seed.len() != 64 {
                    return Err(invalid("child finish fork identity"));
                }
                if end > shared {
                    let finish: [u8; 64] = body
                        .try_into()
                        .map_err(|_| invalid("child finish length"))?;
                    let span = *producers
                        .get(&finish)
                        .ok_or_else(|| invalid("child finish producer unavailable"))?;
                    let producer = read_span(file, span)?;
                    let mut child = producer.as_slice();
                    if message(&mut child, 0, b"protocol")
                        != Some(b"HasteBoots framed SHAKE256 v1".as_slice())
                        || message(&mut child, 0, b"application")
                            != Some(b"HasteBoots framed SHAKE256 child v1".as_slice())
                        || message(&mut child, 0, b"trusted profile")
                            != Some(profile.id().0.as_slice())
                        || message(&mut child, 1, b"child label") != Some(child_label)
                        || message(&mut child, 1, b"child context") != Some(child_context)
                        || message(&mut child, 1, b"parent seed") != Some(child_seed)
                    {
                        return Err(invalid("child finish producer identity"));
                    }
                    let mut tail = Vec::new();
                    frame(
                        &mut tail,
                        2,
                        b"classical child finish",
                        &64u64.to_le_bytes(),
                    );
                    if !producer.ends_with(&tail) {
                        return Err(invalid("child finish producer request"));
                    }
                    checked += 1;
                }
                fork = None;
                seed = None;
            }
            previous = Some((kind, label, body, end));
            request_state = matches!(kind, 2 | 4).then(|| prefix_state.clone());
            if prior.len() == 3 {
                prior.pop_front();
            }
            prior.push_back((kind, label, body));
        }
        if !matches!(previous, Some((2 | 4 | 8, _, _, _))) {
            return Err(invalid(
                "framed XOF input must end at a request or checkpoint",
            ));
        }
        self.previous[family].clear();
        self.previous[family].extend_from_slice(input);
        Ok(checked)
    }
}

#[test]
fn typed_phase_metadata_requires_trusted_prime_basis_and_cardinality() {
    fn run<F: NTTField, EF: AbstractExtensionField<F>>() {
        let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
            backend: Backend::Brakedown,
            roles: std::array::from_fn(|_| Role {
                num_vars: 3,
                width: 8,
                queries: 8,
                left_vars: Some(1),
                block_width: Some(2),
            }),
            blowup: 2,
            fragment_vars: None,
        })
        .unwrap();
        let prime: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut header = Vec::new();
        frame(
            &mut header,
            0,
            b"protocol",
            b"HasteBoots framed SHAKE256 v1",
        );
        frame(
            &mut header,
            0,
            b"application",
            b"HasteBoots typed classical extension v1",
        );
        frame(&mut header, 0, b"trusted profile", &profile.id().0);
        let basis = raw_basis::<F, EF>();
        let append_request = |prefix: &mut Vec<u8>,
                              label: &[u8],
                              kind: Option<&[u8]>,
                              table: &[u8],
                              modulus: u128,
                              count: u64| {
            if let Some(kind) = kind {
                frame(prefix, 1, b"typed request kind", kind);
            }
            frame(prefix, 1, b"field challenge kind", b"extension vector");
            frame(prefix, 1, b"extension basis", table);
            let mut descriptor = modulus.to_le_bytes().to_vec();
            descriptor.extend(count.to_le_bytes());
            frame(prefix, 4, label, &descriptor);
        };
        let mut identity = header;
        append_request(
            &mut identity,
            b"typed extension identity",
            None,
            &basis,
            prime,
            0,
        );
        let empty_producer = b"HasteBoots consumed field bytes v1".to_vec();
        let mut bytes = identity.clone();
        bytes.extend(&empty_producer);
        let producers = HashMap::from([
            (
                shake64(&identity),
                Span {
                    offset: 0,
                    length: identity.len(),
                },
            ),
            (
                shake64(&empty_producer),
                Span {
                    offset: identity.len() as u64,
                    length: empty_producer.len(),
                },
            ),
        ]);
        let path = std::env::temp_dir().join(format!(
            "hb-typed-phase-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, &bytes).unwrap();
        drop(file);
        let mut file = File::open(&path).unwrap();
        assert_eq!(
            History::default()
                .check::<F, EF>(&profile, &identity, &mut file, &HashMap::new())
                .unwrap(),
            0
        );
        let mut completed = identity;
        frame(
            &mut completed,
            5,
            b"typed extension identity",
            &receipt(&[]).0,
        );
        let make = |kind: Option<&[u8]>, table: &[u8], modulus: u128, count: u64| {
            let mut input = completed.clone();
            append_request(&mut input, b"current", kind, table, modulus, count);
            input
        };
        let degree = EF::D as u64;
        for (kind, count) in [
            (b"scalar".as_slice(), degree),
            (b"vector".as_slice(), 0),
            (b"vector".as_slice(), 2 * degree),
            (b"vector".as_slice(), u64::MAX - u64::MAX % degree),
        ] {
            assert!(
                History::default()
                    .check::<F, EF>(
                        &profile,
                        &make(Some(kind), &basis, prime, count),
                        &mut file,
                        &producers
                    )
                    .is_ok()
            );
        }
        let mut wrong_basis = basis.clone();
        wrong_basis[8] ^= 1;
        let invalid = [
            make(Some(b"vector"), &wrong_basis, prime, degree),
            make(Some(b"vector"), &basis, prime + 2, degree),
            make(Some(b"vector"), &basis, prime, degree + 1),
            make(Some(b"scalar"), &basis, prime, 2 * degree),
            make(Some(b"scalar"), &basis, prime, 0),
            make(Some(b"other"), &basis, prime, degree),
            make(None, &basis, prime, degree),
        ];
        for input in invalid {
            assert!(
                History::default()
                    .check::<F, EF>(&profile, &input, &mut file, &producers)
                    .is_err()
            );
        }
        // Prefix caching must not hide a changed basis or request descriptor.
        let mut history = History::default();
        history
            .check::<F, EF>(
                &profile,
                &make(Some(b"vector"), &basis, prime, degree),
                &mut file,
                &producers,
            )
            .unwrap();
        assert!(
            history
                .check::<F, EF>(
                    &profile,
                    &make(Some(b"vector"), &wrong_basis, prime, degree),
                    &mut file,
                    &producers
                )
                .is_err()
        );
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
    run::<algebra::BabyBear, algebra::BabyBearExtension6>();
    run::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn receipt_streams_require_both_prior_producers_and_exact_consumption() {
    type F = algebra::BabyBear;
    type EF = algebra::BabyBearExtension6;
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
        backend: Backend::Brakedown,
        roles: std::array::from_fn(|_| Role {
            num_vars: 3,
            width: 8,
            queries: 8,
            left_vars: Some(1),
            block_width: Some(2),
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    let mut header = Vec::new();
    frame(
        &mut header,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut header,
        0,
        b"application",
        b"HasteBoots typed classical prime v1",
    );
    frame(&mut header, 0, b"trusted profile", &profile.id().0);
    frame(
        &mut header,
        1,
        b"typed prime field",
        &2013265921u128.to_le_bytes(),
    );
    let modulus = 2013265921u128;
    let mut descriptor = modulus.to_le_bytes().to_vec();
    descriptor.extend(1u64.to_le_bytes());
    let mut request = header.clone();
    frame(&mut request, 1, b"typed request kind", b"vector");
    frame(&mut request, 1, b"field challenge kind", b"prime vector");
    frame(&mut request, 4, b"coins", &descriptor);
    let mut state = sha3::Shake256::default();
    sha3::digest::Update::update(&mut state, &request);
    let mut reader = sha3::digest::ExtendableOutput::finalize_xof(state);
    let mut raw = Vec::new();
    loop {
        let mut word = [0; 4];
        sha3::digest::XofReader::read(&mut reader, &mut word);
        raw.extend(word);
        if (u32::from_le_bytes(word) & 0x7fffffff) < modulus as u32 {
            break;
        }
    }
    let make = |raw: &[u8]| {
        let mut producer = b"HasteBoots consumed field bytes v1".to_vec();
        producer.extend(raw);
        let mut receipt = (raw.len() as u128).to_le_bytes().to_vec();
        receipt.extend(shake64(&producer));
        let mut completed = request.clone();
        frame(&mut completed, 5, b"coins", &receipt);
        frame(&mut completed, 2, b"next phase", &64u64.to_le_bytes());
        (producer, completed)
    };
    let (producer, completed) = make(&raw);
    let mut wrong_raw = raw.clone();
    wrong_raw[0] ^= 1;
    let (wrong_producer, wrong_completed) = make(&wrong_raw);
    let mut surplus_raw = raw.clone();
    let mut next = [0; 4];
    sha3::digest::XofReader::read(&mut reader, &mut next);
    surplus_raw.extend(next);
    let (surplus_producer, surplus_completed) = make(&surplus_raw);
    let path = std::env::temp_dir().join(format!(
        "hb-receipt-stream-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut bytes = Vec::new();
    let mut producers = HashMap::new();
    for input in [&request, &producer, &wrong_producer, &surplus_producer] {
        producers.insert(
            shake64(input),
            Span {
                offset: bytes.len() as u64,
                length: input.len(),
            },
        );
        bytes.extend(input);
    }
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut writer, &bytes).unwrap();
    drop(writer);
    let mut file = File::open(&path).unwrap();
    assert_eq!(
        History::default()
            .check::<F, EF>(&profile, &completed, &mut file, &producers)
            .unwrap(),
        1
    );
    let mut history = History::default();
    assert_eq!(
        history
            .check::<F, EF>(&profile, &completed, &mut file, &producers)
            .unwrap(),
        1
    );
    assert_eq!(
        history
            .check::<F, EF>(&profile, &completed, &mut file, &producers)
            .unwrap(),
        0
    );
    // An intervening extension-root query must not evict a previously checked
    // prime-root prefix. This pending identity consumes no oracle output yet.
    let mut extension = Vec::new();
    frame(
        &mut extension,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut extension,
        0,
        b"application",
        b"HasteBoots typed classical extension v1",
    );
    frame(&mut extension, 0, b"trusted profile", &profile.id().0);
    frame(
        &mut extension,
        1,
        b"field challenge kind",
        b"extension vector",
    );
    frame(&mut extension, 1, b"extension basis", &raw_basis::<F, EF>());
    let mut zero_descriptor = modulus.to_le_bytes().to_vec();
    zero_descriptor.extend(0u64.to_le_bytes());
    frame(
        &mut extension,
        4,
        b"typed extension identity",
        &zero_descriptor,
    );
    assert_eq!(
        history
            .check::<F, EF>(&profile, &extension, &mut file, &producers)
            .unwrap(),
        0
    );
    assert_eq!(
        history
            .check::<F, EF>(&profile, &completed, &mut file, &producers)
            .unwrap(),
        0
    );
    for missing in [shake64(&request), shake64(&producer)] {
        let mut partial = producers.clone();
        partial.remove(&missing);
        // A failed first query cannot be repaired by repeating it after adding
        // producers: the caller must stop on the original error.
        assert!(
            History::default()
                .check::<F, EF>(&profile, &completed, &mut file, &partial)
                .is_err()
        );
    }
    // These fingerprints are genuine, available SHAKE outputs. Availability
    // alone must not authenticate bytes from a different request/consumption.
    assert!(
        History::default()
            .check::<F, EF>(&profile, &wrong_completed, &mut file, &producers)
            .is_err()
    );
    assert!(
        History::default()
            .check::<F, EF>(&profile, &surplus_completed, &mut file, &producers)
            .is_err()
    );
    for kind in [0, 9, 255] {
        let mut invalid = header.clone();
        frame(&mut invalid, kind, b"unsupported domain/kind", &[]);
        frame(&mut invalid, 2, b"current", &64u64.to_le_bytes());
        let error = History::default()
            .check::<F, EF>(&profile, &invalid, &mut file, &producers)
            .unwrap_err();
        assert!(error.to_string().contains("unsupported or repeated domain"));
    }
    let mut request_tail = Vec::new();
    frame(&mut request_tail, 2, b"next phase", &64u64.to_le_bytes());
    let response_only = completed.strip_suffix(request_tail.as_slice()).unwrap();
    let mut message_only = header.clone();
    frame(&mut message_only, 1, b"body", b"no request");
    for input in [response_only, header.as_slice(), message_only.as_slice()] {
        let error = History::default()
            .check::<F, EF>(&profile, input, &mut file, &producers)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must end at a request or checkpoint")
        );
    }
    let mut orphan = header;
    frame(&mut orphan, 255, b"coins", &[]);
    frame(&mut orphan, 5, b"coins", &[0; 80]);
    assert!(
        History::default()
            .check::<F, EF>(&profile, &orphan, &mut file, &producers)
            .is_err()
    );
    drop(file);
    std::fs::remove_file(path).unwrap();
}

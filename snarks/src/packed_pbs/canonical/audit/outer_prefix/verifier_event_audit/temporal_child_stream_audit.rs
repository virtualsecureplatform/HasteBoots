//! File-backed positive-control child origins, not an availability filter proof.
use super::*;
mod receipt_audit;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

const HEADER: &[u8] = b"HB_ORACLE_EVENT_STREAM_V1\n";
#[derive(Clone, Copy)]
struct Span {
    offset: u64,
    length: usize,
}
struct Identity {
    label: Vec<u8>,
    context: Vec<u8>,
    raw: Vec<u8>,
}
#[derive(Debug, Default)]
pub(super) struct Report {
    pub identities: [usize; 3],
    pub later: [usize; 3],
    pub seeds: [usize; 3],
    pub same_prover_verifier_seeds: bool,
    /// First returned H/XOF values already present in captured input windows.
    pub captured_availability_hits: [usize; 2],
    pub replayed_receipt_frames: usize,
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn read_span(file: &mut File, span: Span) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(span.offset))?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(span.length)
        .map_err(|_| invalid("producer input allocation"))?;
    input.resize(span.length, 0);
    file.read_exact(&mut input)?;
    Ok(input)
}
fn same_input(file: &mut File, span: Span, input: &[u8]) -> io::Result<bool> {
    if span.length != input.len() {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(span.offset))?;
    let mut buffer = [0u8; 8192];
    for chunk in input.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..chunk.len()])?;
        if &buffer[..chunk.len()] != chunk {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Validate every observed typed child at its first occurrence, before answering
/// that request. Only input spans and compact identities persist in memory.
/// All SHAKE first-64-byte output collisions are checked by exact input replay;
/// no claim is made about arbitrary-input window availability here.
pub(super) fn check<F, EF>(
    profile: &ClassicalProfile,
    path: &Path,
    expected: &str,
) -> io::Result<Report>
where
    F: NTTField,
    EF: AbstractExtensionField<F>,
{
    let mut source = File::open(path)?;
    let mut lookup = File::open(path)?;
    let size = source.metadata()?.len();
    let mut header = vec![0; HEADER.len()];
    source.read_exact(&mut header)?;
    if header != HEADER {
        return Err(invalid("trace header"));
    }
    let mut digest = Sha512::default();
    Digest::update(&mut digest, &header);
    let mut cursor = HEADER.len() as u64;
    let mut previous_phase = 0;
    let mut producers = HashMap::<[u8; 64], Span>::new();
    let mut first_answers = HashMap::<[u8; 64], [Option<u64>; 2]>::new();
    let mut identities = HashMap::<[u8; 64], Identity>::new();
    let mut seeds: [std::collections::HashSet<[u8; 64]>; 3] =
        std::array::from_fn(|_| Default::default());
    let mut report = Report::default();
    let mut receipts = receipt_audit::History::default();
    let mut child_header = Vec::new();
    frame(
        &mut child_header,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut child_header,
        0,
        b"application",
        b"HasteBoots framed SHAKE256 child v1",
    );
    let profile_id = profile.id().0;
    let empty = receipt(&[]).0;
    let empty_digest: [u8; 64] = empty[16..].try_into().unwrap();
    let mut empty_frame = Vec::new();
    frame(&mut empty_frame, 5, b"typed extension identity", &empty);
    while cursor < size {
        let mut record = [0u8; 10];
        source.read_exact(&mut record)?;
        let (kind, phase) = (record[0], record[1] as usize);
        if !matches!(kind, 1 | 2) || phase > 2 || phase < previous_phase {
            return Err(invalid("event kind/phase"));
        }
        previous_phase = phase;
        let length = u64::from_le_bytes(record[2..].try_into().unwrap());
        let offset = cursor
            .checked_add(10)
            .ok_or_else(|| invalid("event offset"))?;
        let end = offset
            .checked_add(length)
            .and_then(|n| n.checked_add(if kind == 1 { 64 } else { 0 }))
            .filter(|&n| n <= size)
            .ok_or_else(|| invalid("event length"))?;
        let length = usize::try_from(length).map_err(|_| invalid("host input length"))?;
        let mut input = Vec::new();
        input
            .try_reserve_exact(length)
            .map_err(|_| invalid("input allocation"))?;
        input.resize(length, 0);
        source.read_exact(&mut input)?;
        Digest::update(&mut digest, record);
        Digest::update(&mut digest, &input);
        if kind == 1 {
            let mut output = [0; 64];
            source.read_exact(&mut output)?;
            Digest::update(&mut digest, output);
            if output != <[u8; 64]>::from(Sha512::digest(&input)) {
                return Err(invalid("hash preimage"));
            }
            first_answers.entry(output).or_insert([None, None])[0].get_or_insert(cursor);
        } else {
            report.replayed_receipt_frames +=
                receipts.check::<F, EF>(profile, &input, &mut lookup, &producers)?;
            if let Some(mut rest) = input.strip_prefix(child_header.as_slice()) {
                if message(&mut rest, 0, b"trusted profile") != Some(profile_id.as_slice()) {
                    return Err(invalid("foreign or malformed child profile"));
                }
                let label =
                    message(&mut rest, 1, b"child label").ok_or_else(|| invalid("child label"))?;
                let context = message(&mut rest, 1, b"child context")
                    .ok_or_else(|| invalid("child context"))?;
                let seed: [u8; 64] = message(&mut rest, 1, b"parent seed")
                    .ok_or_else(|| invalid("child seed"))?
                    .try_into()
                    .map_err(|_| invalid("seed size"))?;
                let producer = *producers
                    .get(&seed)
                    .ok_or_else(|| invalid("seed producer unavailable before child request"))?;
                if !identities.contains_key(&seed) {
                    let parent = read_span(&mut lookup, producer)?;
                    super::temporal_child_audit::seed_origin(
                        profile, &parent, label, context, &seed,
                    )
                    .ok_or_else(|| invalid("typed seed producer origin"))?;
                    identities.insert(
                        seed,
                        Identity {
                            label: label.to_vec(),
                            context: context.to_vec(),
                            raw: raw_child::<F, EF>(profile, label, context, &seed),
                        },
                    );
                }
                let identity = &identities[&seed];
                if identity.label != label || identity.context != context {
                    return Err(invalid("seed origin substitution"));
                }
                if input == identity.raw.strip_suffix(empty_frame.as_slice()).unwrap() {
                    report.identities[phase] += 1;
                } else {
                    if !input.starts_with(&identity.raw) || !producers.contains_key(&empty_digest) {
                        return Err(invalid("child initialization or receipt producer"));
                    }
                    report.later[phase] += 1;
                }
                seeds[phase].insert(seed);
            }
            let answer = shake64(&input);
            first_answers.entry(answer).or_insert([None, None])[1].get_or_insert(cursor);
            if let Some(&earlier) = producers.get(&answer) {
                if !same_input(&mut lookup, earlier, &input)? {
                    return Err(invalid("distinct-input XOF output collision"));
                }
            } else {
                producers.insert(answer, Span { offset, length });
            }
        }
        cursor = end;
    }
    let fingerprint: String = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if source.metadata()?.len() != size {
        return Err(invalid("trace size changed"));
    }
    if fingerprint != expected {
        return Err(invalid("trace fingerprint"));
    }
    report.seeds = std::array::from_fn(|i| seeds[i].len());
    report.same_prover_verifier_seeds = seeds[1] == seeds[2];
    report.captured_availability_hits = availability(path, expected, &first_answers)?;
    Ok(report)
}

/// Three fixed namespace caches, independent of the number of oracle queries.
fn framed_family(input: &[u8]) -> Option<usize> {
    let mut rest = input;
    if message(&mut rest, 0, b"protocol")? != b"HasteBoots framed SHAKE256 v1" {
        return None;
    }
    match message(&mut rest, 0, b"application")? {
        b"HasteBoots typed classical prime v1" => Some(0),
        b"HasteBoots typed classical extension v1" => Some(1),
        b"HasteBoots framed SHAKE256 child v1" => Some(2),
        _ => None,
    }
}

/// Retrospective projection is exact for this finite trace: only values actually
/// returned can witness a late target hit. No general game filter is proved.
fn availability(
    path: &Path,
    expected: &str,
    answers: &HashMap<[u8; 64], [Option<u64>; 2]>,
) -> io::Result<[usize; 2]> {
    let mut prefixes = vec![false; 1usize << 24];
    let prefix =
        |bytes: &[u8]| ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize;
    for answer in answers.keys() {
        prefixes[prefix(answer)] = true;
    }
    let mut hits: [std::collections::HashSet<[u8; 64]>; 2] =
        std::array::from_fn(|_| Default::default());
    let mut source = File::open(path)?;
    let size = source.metadata()?.len();
    let mut header = vec![0; HEADER.len()];
    source.read_exact(&mut header)?;
    if header != HEADER {
        return Err(invalid("availability trace header"));
    }
    let mut digest = Sha512::default();
    Digest::update(&mut digest, &header);
    let mut cursor = HEADER.len() as u64;
    let mut phase = 0;
    // A child query must not evict its parent's prefix. The three fixed
    // namespaces bound retained inputs independently of the number of queries.
    let mut previous_framed: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
    while cursor < size {
        let mut record = [0; 10];
        source.read_exact(&mut record)?;
        let kind = record[0];
        if !matches!(kind, 1 | 2) || record[1] > 2 || record[1] < phase {
            return Err(invalid("availability event kind/phase"));
        }
        phase = record[1];
        let length = u64::from_le_bytes(record[2..].try_into().unwrap());
        let end = cursor
            .checked_add(10)
            .and_then(|n| n.checked_add(length))
            .and_then(|n| n.checked_add(if kind == 1 { 64 } else { 0 }))
            .filter(|&n| n <= size)
            .ok_or_else(|| invalid("availability event length"))?;
        let length = usize::try_from(length).map_err(|_| invalid("availability host length"))?;
        let mut input = Vec::new();
        input
            .try_reserve_exact(length)
            .map_err(|_| invalid("availability allocation"))?;
        input.resize(length, 0);
        source.read_exact(&mut input)?;
        Digest::update(&mut digest, record);
        Digest::update(&mut digest, &input);
        let family = framed_family(&input);
        let shared = if let Some(family) = family {
            let previous = &previous_framed[family];
            if input.starts_with(previous) {
                previous.len()
            } else if previous.starts_with(&input) {
                input.len()
            } else {
                previous
                    .iter()
                    .zip(&input)
                    .take_while(|(a, b)| a == b)
                    .count()
            }
        } else {
            0
        };
        // A shared prefix was checked at an earlier record, so omitting its
        // wholly-contained windows cannot lose an earliest target occurrence.
        for window in input[shared.saturating_sub(63)..].windows(64) {
            if !prefixes[prefix(window)] {
                continue;
            }
            let key: [u8; 64] = window.try_into().unwrap();
            if let Some(first) = answers.get(&key) {
                for family in 0..2 {
                    if first[family].is_some_and(|at| cursor <= at) {
                        hits[family].insert(key);
                    }
                }
            }
        }
        if let Some(family) = family {
            previous_framed[family] = input;
        }
        if kind == 1 {
            let mut output = [0; 64];
            source.read_exact(&mut output)?;
            Digest::update(&mut digest, output);
        }
        cursor = end;
    }
    let fingerprint: String = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if fingerprint != expected || source.metadata()?.len() != size {
        return Err(invalid("availability trace fingerprint"));
    }
    Ok([hits[0].len(), hits[1].len()])
}

#[test]
fn streamed_availability_prefix_reuse_matches_every_window() {
    // Differentially test the scanner alone: supplied answers intentionally
    // cover both sides of every shared-prefix boundary and both time orders.
    let mut framed = Vec::new();
    frame(
        &mut framed,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut framed,
        0,
        b"application",
        b"HasteBoots typed classical prime v1",
    );
    let mut other = Vec::new();
    frame(&mut other, 0, b"protocol", b"HasteBoots framed SHAKE256 v1");
    frame(
        &mut other,
        0,
        b"application",
        b"HasteBoots framed SHAKE256 child v1",
    );
    other.extend((0..320).map(|i| ((i * 73 + i / 7) % 251) as u8));
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
    extension.extend((0..320).map(|i| ((i * 73 + i / 7) % 251) as u8));
    let mut base = framed.clone();
    base.extend((0..320).map(|i| ((i * 73 + i / 7) % 251) as u8));
    let mut inputs = Vec::new();
    for cut in 0..=256 {
        inputs.push(base.clone());
        inputs.push(other.clone());
        let mut changed = base.clone();
        changed[framed.len() + cut] ^= 0x80;
        inputs.push(changed);
        inputs.push(extension.clone());
        inputs.push(base[..framed.len() + cut].to_vec());
        inputs.push(vec![cut as u8; 65]);
    }
    let mut data = HEADER.to_vec();
    let mut records = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let at = data.len() as u64;
        let kind = if i % 2 == 0 { 1 } else { 2 };
        data.extend([kind, 1]);
        data.extend((input.len() as u64).to_le_bytes());
        data.extend(input);
        if kind == 1 {
            data.extend(Sha512::digest(input));
        }
        records.push((at, input));
    }
    let mut answers = HashMap::new();
    for (i, (at, input)) in records.iter().enumerate() {
        for window in input.windows(64).step_by(31) {
            let key: [u8; 64] = window.try_into().unwrap();
            answers.entry(key).or_insert(if i % 2 == 0 {
                [Some(*at), Some(0)]
            } else {
                [Some(0), Some(data.len() as u64)]
            });
        }
    }
    let mut naive: [std::collections::HashSet<[u8; 64]>; 2] =
        std::array::from_fn(|_| Default::default());
    for (at, input) in &records {
        for window in input.windows(64) {
            let key: [u8; 64] = window.try_into().unwrap();
            if let Some(first) = answers.get(&key) {
                for family in 0..2 {
                    if first[family].is_some_and(|answer_at| *at <= answer_at) {
                        naive[family].insert(key);
                    }
                }
            }
        }
    }
    let path = std::env::temp_dir().join(format!(
        "hb-availability-differential-{}-{}",
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
    std::io::Write::write_all(&mut file, &data).unwrap();
    drop(file);
    let digest: String = Sha512::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let actual = availability(&path, &digest, &answers).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(actual, [naive[0].len(), naive[1].len()]);
    assert!(actual.iter().all(|count| *count > 0));
}

#[test]
fn streamed_child_origins_require_earlier_seed_and_receipt_producers() {
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
    let mut parent = Vec::new();
    frame(
        &mut parent,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut parent,
        0,
        b"application",
        b"HasteBoots typed classical prime v1",
    );
    frame(&mut parent, 0, b"trusted profile", &profile.id().0);
    frame(
        &mut parent,
        1,
        b"typed prime field",
        &2013265921u128.to_le_bytes(),
    );
    frame(&mut parent, 6, b"lookup", b"context");
    frame(
        &mut parent,
        2,
        b"classical child seed",
        &64u64.to_le_bytes(),
    );
    let seed = shake64(&parent);
    let raw = raw_child::<F, EF>(&profile, b"lookup", b"context", &seed);
    let mut empty_frame = Vec::new();
    frame(
        &mut empty_frame,
        5,
        b"typed extension identity",
        &receipt(&[]).0,
    );
    let initial = raw.strip_suffix(empty_frame.as_slice()).unwrap().to_vec();
    let mut later = raw;
    frame(&mut later, 1, b"body", b"positive control");
    frame(
        &mut later,
        2,
        b"positive control coins",
        &64u64.to_le_bytes(),
    );
    let receipt_input = b"HasteBoots consumed field bytes v1".to_vec();
    let encode = |inputs: &[(u8, u8, Vec<u8>)]| {
        let mut data = HEADER.to_vec();
        for (kind, phase, input) in inputs {
            data.extend([*kind, *phase]);
            data.extend((input.len() as u64).to_le_bytes());
            data.extend(input);
            if *kind == 1 {
                data.extend(Sha512::digest(input));
            }
        }
        data
    };
    let run = |data: Vec<u8>, expected: Option<&str>| {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "hb-child-stream-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, &data).unwrap();
        drop(file);
        let fingerprint: String = Sha512::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let result = check::<F, EF>(&profile, &path, expected.unwrap_or(&fingerprint));
        std::fs::remove_file(path).unwrap();
        result
    };
    let mut events = vec![(1, 0, b"setup".to_vec())];
    for phase in [1, 2] {
        for input in [&parent, &initial, &receipt_input, &later] {
            events.push((2, phase, input.clone()));
        }
    }
    let report = run(encode(&events), None).unwrap();
    assert_eq!(report.identities, [0, 1, 1]);
    assert_eq!(report.later, [0, 1, 1]);
    assert_eq!(report.seeds, [0, 1, 1]);
    assert!(report.same_prover_verifier_seeds);
    assert_eq!(report.captured_availability_hits, [0, 0]);
    // Deliberately publish each future answer as an input before its producer.
    // Counting only first answers must not charge their repeated queries again.
    let h_input = b"future H producer".to_vec();
    let x_input = b"future XOF producer".to_vec();
    let h_answer: [u8; 64] = Sha512::digest(&h_input).into();
    let x_answer = shake64(&x_input);
    let published = vec![
        (2, 1, h_answer.to_vec()),
        (2, 1, x_answer.to_vec()),
        (1, 1, h_input.clone()),
        (2, 1, x_input.clone()),
        (1, 1, h_input),
        (2, 1, x_input),
    ];
    assert_eq!(
        run(encode(&published), None)
            .unwrap()
            .captured_availability_hits,
        [1, 1]
    );
    let mut finish_request = raw_child::<F, EF>(&profile, b"lookup", b"context", &seed);
    frame(
        &mut finish_request,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    let finish = shake64(&finish_request);
    let completed_parent = |finish: &[u8; 64]| {
        let mut input = parent.clone();
        frame(&mut input, 3, b"classical child seed", &seed);
        frame(&mut input, 7, b"lookup", finish);
        frame(&mut input, 2, b"after child finish", &64u64.to_le_bytes());
        input
    };
    let finished = vec![
        (2, 1, parent.clone()),
        (2, 1, initial.clone()),
        (2, 1, receipt_input.clone()),
        (2, 1, finish_request),
        (2, 1, completed_parent(&finish)),
    ];
    assert!(
        run(encode(&finished), None)
            .unwrap()
            .replayed_receipt_frames
            > 0
    );
    let mut missing_finish = finished.clone();
    missing_finish.remove(3);
    assert!(run(encode(&missing_finish), None).is_err());
    // A genuine available answer from this same child is insufficient if the
    // producer queried an ordinary child phase rather than the finish request.
    let mut wrong_finish = finished;
    wrong_finish[3].2 = later.clone();
    wrong_finish[4].2 = completed_parent(&shake64(&later));
    assert!(run(encode(&wrong_finish), None).is_err());
    let mut advanced_parent = parent.clone();
    frame(&mut advanced_parent, 3, b"classical child seed", &seed);
    frame(
        &mut advanced_parent,
        1,
        b"parent advanced",
        b"forbidden before finish",
    );
    frame(&mut advanced_parent, 7, b"lookup", &finish);
    frame(
        &mut advanced_parent,
        2,
        b"after child finish",
        &64u64.to_le_bytes(),
    );
    let mut advanced = wrong_finish.clone();
    advanced[3].2 = raw_child::<F, EF>(&profile, b"lookup", b"context", &seed);
    frame(
        &mut advanced[3].2,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    advanced[4].2 = advanced_parent;
    assert!(run(encode(&advanced), None).is_err());
    let mut missing_response = parent.clone();
    frame(
        &mut missing_response,
        1,
        b"parent advanced",
        b"seed response omitted",
    );
    frame(
        &mut missing_response,
        2,
        b"next request",
        &64u64.to_le_bytes(),
    );
    assert!(run(encode(&[(2, 1, missing_response)]), None).is_err());
    let mut request_tail = Vec::new();
    frame(
        &mut request_tail,
        2,
        b"classical child seed",
        &64u64.to_le_bytes(),
    );
    let mut double_fork = parent
        .strip_suffix(request_tail.as_slice())
        .unwrap()
        .to_vec();
    frame(&mut double_fork, 6, b"lookup", b"another context");
    double_fork.extend(&request_tail);
    assert!(run(encode(&[(2, 1, double_fork)]), None).is_err());
    let mut checkpoint = parent.clone();
    frame(&mut checkpoint, 3, b"classical child seed", &seed);
    frame(&mut checkpoint, 8, b"parent checkpoint", &[]);
    assert!(
        run(
            encode(&[(2, 1, parent.clone()), (2, 1, checkpoint.clone())]),
            None
        )
        .is_ok()
    );
    frame(
        &mut checkpoint,
        1,
        b"after checkpoint",
        b"not part of a checkpoint query",
    );
    frame(
        &mut checkpoint,
        2,
        b"after checkpoint",
        &64u64.to_le_bytes(),
    );
    assert!(run(encode(&[(2, 1, parent.clone()), (2, 1, checkpoint)]), None).is_err());
    let late = vec![
        (2, 1, initial.clone()),
        (2, 1, parent.clone()),
        (2, 1, initial.clone()),
    ];
    assert!(run(encode(&late), None).is_err());
    let mut foreign = initial.clone();
    let profile_id = profile.id().0;
    let at = foreign
        .windows(profile_id.len())
        .position(|window| window == profile_id.as_slice())
        .unwrap();
    foreign[at] ^= 1;
    assert!(run(encode(&[(2, 1, parent.clone()), (2, 1, foreign)]), None).is_err());
    let missing = vec![(2, 1, parent), (2, 1, initial), (2, 1, later)];
    assert!(run(encode(&missing), None).is_err());
    assert!(run(encode(&events), Some("wrong fingerprint")).is_err());
    let mut corrupt = encode(&events);
    corrupt[HEADER.len() + 10 + 5] ^= 1;
    assert!(run(corrupt, None).is_err());
    let mut truncated = encode(&events);
    truncated.pop();
    assert!(run(truncated, None).is_err());
    let mut huge = HEADER.to_vec();
    huge.extend([2, 1]);
    huge.extend(u64::MAX.to_le_bytes());
    assert!(run(huge, None).is_err());
}

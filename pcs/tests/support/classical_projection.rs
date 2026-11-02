//! Selected-root projection of an uncapped oracle history, for audit controls.
//! This does not establish a full adaptive reduction or global availability bound.
use pcs::utils::hash::Digest512;
use sha2::{Digest, Sha512};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
type Preimages = HashMap<Digest512, Vec<u8>>;

pub(crate) struct Projection {
    selected: HashSet<Digest512>,
    selected_prefixes: Vec<bool>,
    known: Preimages,
    frozen: HashMap<Digest512, Arc<Preimages>>,
    first: HashMap<Digest512, usize>,
    events: usize,
}
impl Projection {
    pub(crate) fn new(roots: impl IntoIterator<Item = Digest512>) -> Self {
        let selected: HashSet<_> = roots.into_iter().collect();
        let mut selected_prefixes = vec![false; 1 << 16];
        for root in &selected {
            selected_prefixes[u16::from_le_bytes([root.0[0], root.0[1]]) as usize] = true;
        }
        Self {
            selected,
            selected_prefixes,
            known: HashMap::new(),
            frozen: HashMap::new(),
            first: HashMap::new(),
            events: 0,
        }
    }
    fn register(&mut self, input: &[u8]) {
        for window in input.windows(64) {
            if !self.selected_prefixes[u16::from_le_bytes([window[0], window[1]]) as usize] {
                continue;
            }
            let root = Digest512(window.try_into().unwrap());
            if !self.selected.contains(&root) || self.frozen.contains_key(&root) {
                continue;
            }
            // Keep the entire known preimage closure reachable from this root.
            // Every 64-byte window is conservative, including framed child roots.
            let mut closure = Preimages::new();
            let mut visited = HashSet::new();
            let mut pending = vec![root];
            while let Some(digest) = pending.pop() {
                if !visited.insert(digest) {
                    continue;
                }
                let Some(preimage) = self.known.get(&digest) else {
                    continue;
                };
                pending.extend(
                    preimage
                        .windows(64)
                        .map(|w| Digest512(w.try_into().unwrap())),
                );
                closure.insert(digest, preimage.clone());
            }
            self.frozen.insert(root, Arc::new(closure));
            self.first.insert(root, self.events);
        }
    }
    pub(crate) fn expose(&mut self, digest: Digest512, input: Vec<u8>) {
        assert_eq!(digest.0, <[u8; 64]>::from(Sha512::digest(&input)));
        self.register(&input); // Before this answer becomes available.
        if let Some(previous) = self.known.insert(digest, input.clone()) {
            assert_eq!(previous, input, "excluded global output collision");
        }
        self.events += 1;
    }
    pub(crate) fn declare_input(&mut self, input: &[u8]) {
        self.register(input);
        self.events += 1;
    }
    pub(crate) fn view(&self, root: Digest512) -> Option<Arc<Preimages>> {
        self.frozen.get(&root).map(Arc::clone)
    }
    pub(crate) fn first(&self, root: Digest512) -> Option<usize> {
        self.first.get(&root).copied()
    }
    pub(crate) fn events(&self) -> usize {
        self.events
    }
}

/// Read every event and authenticate the complete file before returning views.
pub(crate) fn replay(
    path: &std::path::Path,
    expected_sha512: &str,
    roots: impl IntoIterator<Item = Digest512>,
) -> std::io::Result<Projection> {
    use std::io::{BufReader, Error, ErrorKind, Read};
    let invalid = |message| Error::new(ErrorKind::InvalidData, message);
    let mut source = BufReader::new(std::fs::File::open(path)?);
    let header = b"HB_ORACLE_EVENT_STREAM_V1\n";
    let mut actual = vec![0; header.len()];
    source.read_exact(&mut actual)?;
    if actual != header {
        return Err(invalid("oracle stream header"));
    }
    let mut fingerprint = Sha512::new();
    fingerprint.update(&actual);
    let mut history = Projection::new(roots);
    let mut previous_phase = 0;
    loop {
        let mut frame = [0; 10];
        if source.read(&mut frame[..1])? == 0 {
            break;
        }
        source.read_exact(&mut frame[1..])?;
        let (kind, phase) = (frame[0], frame[1]);
        if ![1, 2].contains(&kind) || phase > 2 || phase < previous_phase {
            return Err(invalid("oracle stream event or phase"));
        }
        previous_phase = phase;
        fingerprint.update(frame);
        let length = usize::try_from(u64::from_le_bytes(frame[2..].try_into().unwrap()))
            .map_err(|_| invalid("event length does not fit host"))?;
        if kind == 1 {
            // Hash preimages remain available to the selected roots' closure.
            let mut input = Vec::new();
            input
                .try_reserve_exact(length)
                .map_err(|_| invalid("event input allocation"))?;
            input.resize(length, 0);
            source.read_exact(&mut input)?;
            fingerprint.update(&input);
            let mut output = [0; 64];
            source.read_exact(&mut output)?;
            fingerprint.update(output);
            if output != <[u8; 64]>::from(Sha512::digest(&input)) {
                return Err(invalid("oracle stream hash mismatch"));
            }
            history.expose(Digest512(output), input);
        } else {
            // IO chunk size is not a query-length limit. Retain the last 63
            // bytes so windows crossing chunk boundaries are declared too.
            let mut remaining = length;
            let mut overlap = Vec::new();
            let mut buffer = vec![0; 1 << 20];
            while remaining != 0 {
                let size = remaining.min(buffer.len());
                source.read_exact(&mut buffer[..size])?;
                fingerprint.update(&buffer[..size]);
                overlap.extend_from_slice(&buffer[..size]);
                history.register(&overlap);
                let keep = overlap.len().saturating_sub(63);
                overlap.drain(..keep);
                remaining -= size;
            }
            history.events += 1;
        }
    }
    let fingerprint = fingerprint
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if fingerprint != expected_sha512 {
        return Err(invalid("oracle stream fingerprint"));
    }
    Ok(history)
}

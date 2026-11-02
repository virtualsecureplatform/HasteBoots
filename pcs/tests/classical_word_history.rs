//! Executable first-declaration word completion; not a full ROM reduction.
#[path = "support/classical_assignment.rs"]
mod classical_assignment;
#[path = "support/classical_history.rs"]
mod classical_history;
use classical_history::History;
#[path = "support/classical_decode.rs"]
mod classical_decode;
use algebra::transformation::AbstractNTT;
use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use classical_assignment::{brakedown_assignment, fragment_assignment, polyfrim_assignment};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted,
    utils::{
        code::{BlockReedSolomonCode, RowCode},
        hash::{Digest512, Hash},
        merkle_tree::MerkleTree,
    },
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha512};
use std::sync::Mutex;

static RECORDS: Mutex<Vec<(Digest512, Vec<u8>)>> = Mutex::new(Vec::new());

#[test]
fn lazy_history_views_match_eager_declaration_snapshots() {
    use std::collections::HashMap;
    let leaf = vec![29; 80];
    let leaf_hash = Digest512(Sha512::digest(&leaf).into());
    let node = [leaf_hash.0, leaf_hash.0].concat();
    let root = Digest512(Sha512::digest(&node).into());
    let late = vec![47; 80];
    let late_hash = Digest512(Sha512::digest(&late).into());
    let events = vec![
        (false, late_hash.0.to_vec()),
        (true, leaf),
        (true, node),
        (false, root.0.to_vec()),
        (true, late.clone()),
        (false, late_hash.0.to_vec()),
        (true, late),
        (false, [root.0.to_vec(), vec![9; 256]].concat()),
        (
            false,
            [root.0.to_vec(), b"fresh boundary".to_vec()].concat(),
        ),
        (false, root.0.to_vec()),
    ];
    for (hash_limit, xof_limit) in [(256, 256), (96, 256), (256, 64)] {
        let mut history = History::bounded(hash_limit, xof_limit);
        let mut known = classical_history::Preimages::new();
        let mut eager = HashMap::<Digest512, classical_history::Preimages>::new();
        let mut first = HashMap::new();
        for (epoch, (is_hash, input)) in events.iter().enumerate() {
            if input.len() <= if *is_hash { hash_limit } else { xof_limit } {
                for window in input.windows(64) {
                    let digest = Digest512(window.try_into().unwrap());
                    first.entry(digest).or_insert(epoch);
                    eager.entry(digest).or_insert_with(|| {
                        known
                            .iter()
                            .filter(|(_, bytes)| bytes.len() <= hash_limit)
                            .map(|(&digest, bytes)| (digest, bytes.clone()))
                            .collect()
                    });
                }
            }
            if *is_hash {
                let digest = Digest512(Sha512::digest(input).into());
                history.expose(digest, input.clone());
                known.insert(digest, input.clone());
            } else {
                history.declare_input(input);
            }
            assert_eq!(history.first_declarations(), &first);
            for (&digest, expected) in &eager {
                let view = history.view(digest).unwrap();
                assert_eq!(view.as_ref(), expected);
                assert!(std::sync::Arc::ptr_eq(
                    &view,
                    &history.view(digest).unwrap()
                ));
            }
        }
        assert!(history.view(late_hash).unwrap().is_empty());
    }
}
#[derive(Clone, Debug, Default)]
struct Recorded {
    hash: Sha512,
    input: Vec<u8>,
}
impl Hash for Recorded {
    type Output = Digest512;
    fn update_hash_value(&mut self, bytes: &[u8]) {
        Digest::update(&mut self.hash, bytes);
        self.input.extend(bytes);
    }
    fn output_reset(&mut self) -> Digest512 {
        let output = Digest512(self.hash.finalize_reset().into());
        RECORDS
            .lock()
            .unwrap()
            .push((output, std::mem::take(&mut self.input)));
        output
    }
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
}
fn column<F: Serialize + DeserializeOwned>(input: &[u8], cells: usize) -> Option<Vec<F>> {
    vector(input.strip_prefix(b"HasteBoots/mw-column/v1")?, cells)
}
fn vector<F: Serialize + DeserializeOwned>(mut rest: &[u8], cells: usize) -> Option<Vec<F>> {
    let (count, used): (usize, usize) =
        bincode::serde::decode_from_slice(rest, bincode::config::standard()).ok()?;
    if count != cells || rest.get(..used)? != encode(&count) {
        return None;
    }
    rest = rest.get(used..)?;
    let mut values = Vec::with_capacity(cells);
    for _ in 0..cells {
        let (value, used): (F, usize) =
            bincode::serde::decode_from_slice(rest, bincode::config::standard()).ok()?;
        if rest.get(..used)? != encode(&value) {
            return None;
        }
        values.push(value);
        rest = rest.get(used..)?;
    }
    rest.is_empty().then_some(values)
}
fn right_padding<F: NTTField>(code: &BlockReedSolomonCode<F>, message: usize) -> bool {
    code.message_blocks() * code.block_width() > message
}

fn projected_view(
    records: &[(Digest512, Vec<u8>)],
    root: Digest512,
    declaration: &[u8],
    full: &History,
) -> std::sync::Arc<std::collections::HashMap<Digest512, Vec<u8>>> {
    let mut projected = classical_projection::Projection::new([root]);
    for (digest, input) in records {
        projected.expose(*digest, input.clone());
    }
    projected.declare_input(declaration);
    assert_eq!(
        projected.first(root),
        full.first_declarations().get(&root).copied()
    );
    assert_eq!(projected.events(), full.events());
    projected.view(root).unwrap()
}

// Fixed assignment under the Brakedown joint-nearness and padding promise.

fn check<F: NTTField + Serialize + DeserializeOwned>(width: usize, vars: usize, left: usize) {
    RECORDS.lock().unwrap().clear();
    let blowup = 2;
    let code = BlockReedSolomonCode::<F>::new(1 << (vars - left), width, blowup).unwrap();
    let count = code.codeword_blocks();
    let block = code.block_width();
    let rows = (1 << left) * width;
    let cells = rows * block;
    let depth = count.ilog2() as usize;
    let pp = matrix_weighted::Parameters::new_encoded::<F>(vars, width, left, 7, code).unwrap();
    let table = PackedTable::new(
        vars,
        width,
        (0..width << vars).map(|i| F::from(i * i + 3)).collect(),
    )
    .unwrap();
    let (root, _) = pp.commit::<F, Recorded>(&table).unwrap();
    let records = std::mem::take(&mut *RECORDS.lock().unwrap());
    let mut history = History::default();
    for (digest, input) in &records {
        history.expose(*digest, input.clone());
    }
    // Root can occur at an unaligned window in a candidate input.
    let mut input = b"candidate prefix".to_vec();
    input.extend(root.root.0);
    input.extend(b"suffix");
    assert!(history.columns::<F>(root.root, depth, cells).is_none());
    assert_eq!(history.availability_hits(), 0);
    history.declare_input(&input);
    let word = history.columns::<F>(root.root, depth, cells).unwrap();
    // The shared completion consumes exactly the frozen map and verifies
    // internal/leaf preimages rather than trusting map keys as hash evidence.
    let frozen = history.view(root.root).unwrap();
    let projected = projected_view(&records, root.root, &input, &history);
    assert_eq!(
        classical_assignment::frozen_brakedown_columns::<F>(&projected, root.root, depth, cells)
            .unwrap(),
        word
    );
    assert_eq!(
        classical_assignment::frozen_brakedown_columns::<F>(&frozen, root.root, depth, cells)
            .unwrap(),
        word,
    );
    let mut inconsistent = frozen.as_ref().clone();
    inconsistent.get_mut(&root.root).unwrap()[0] ^= 1;
    let completed =
        classical_assignment::frozen_brakedown_columns::<F>(&inconsistent, root.root, depth, cells)
            .unwrap();
    assert!(completed.iter().flatten().all(|&value| value == F::zero()));
    let reference_code = BlockReedSolomonCode::<F>::new(1 << (vars - left), width, blowup).unwrap();
    let mut expected = vec![Vec::new(); count];
    for row in 0..rows {
        let message: Vec<_> = (0..1 << (vars - left))
            .map(|right| table.at(row / width + (right << left))[row % width])
            .collect();
        let mut encoded = vec![F::zero(); count * block];
        reference_code.encode_row(&message, &mut encoded);
        for col in 0..count {
            expected[col].extend_from_slice(&encoded[col * block..(col + 1) * block]);
        }
    }
    assert_eq!(encode(&word), encode(&expected));
    let (promised, assigned) = brakedown_assignment(&word, vars, width, left, &reference_code);
    assert!(promised);
    assert_eq!(assigned.values(), table.values());
    let radius = (count - reference_code.message_blocks()) / 3;
    // Correct up to the full supported radius, including rank-deficient
    // locator systems when the actual number of errors is smaller.
    for errors in [1, radius] {
        let mut noisy = word.clone();
        for (index, column) in noisy.iter_mut().take(errors).enumerate() {
            column[index % cells] += F::one();
        }
        let (promised, assigned) = brakedown_assignment(&noisy, vars, width, left, &reference_code);
        assert!(promised);
        assert_eq!(assigned.values(), table.values());
    }
    // Every coordinate is individually near, but their union exceeds radius.
    let mut disjoint = word.clone();
    for (index, column) in disjoint.iter_mut().take(radius + 1).enumerate() {
        column[index % cells] += F::one();
    }
    let (promised, assigned) = brakedown_assignment(&disjoint, vars, width, left, &reference_code);
    assert!(!promised);
    assert!(assigned.values().iter().all(|&v| v == F::zero()));
    if right_padding(&reference_code, 1 << (vars - left)) {
        let mut points = vec![F::zero(); count];
        points[1] = F::one();
        F::get_ntt_table(count.ilog2())
            .unwrap()
            .transform_slice(&mut points);
        let mut invalid_padding = word.clone();
        // The missing second-block coordinate is a real degree-one RS
        // codeword, but violates the original source's zero-padding promise.
        for (column, &x) in invalid_padding.iter_mut().zip(&points) {
            column[block - 1] += if reference_code.message_blocks() > 1 {
                x
            } else {
                F::one()
            };
        }
        let (promised, assigned) =
            brakedown_assignment(&invalid_padding, vars, width, left, &reference_code);
        assert!(!promised);
        assert!(assigned.values().iter().all(|&v| v == F::zero()));
    }
    let leaves: Vec<_> = word
        .iter()
        .map(|values| {
            let mut input = b"HasteBoots/mw-column/v1".to_vec();
            input.extend(encode(values));
            Digest512(Sha512::digest(input).into())
        })
        .collect();
    let mut tree = MerkleTree::<Sha512>::new();
    tree.generate(&leaves);
    assert_eq!(tree.root, root.root);
    for index in 0..count {
        assert!(MerkleTree::<Sha512>::check(
            &root.root,
            index,
            &tree.query(index)
        ));
    }
    // A different trusted geometry has its own interpretation of this root.
    assert!(
        history
            .columns::<F>(root.root, depth, cells + 1)
            .unwrap()
            .iter()
            .flatten()
            .all(|&v| v == F::zero())
    );
    let mut late = History::default();
    // Expose the root-to-leaf graph but withhold all leaf preimages.
    for (digest, input) in &records {
        if !input.starts_with(b"HasteBoots/mw-column/v1") {
            late.expose(*digest, input.clone());
        }
    }
    late.declare_input(&input);
    let unavailable = late.columns::<F>(root.root, depth, cells).unwrap();
    assert!(unavailable.iter().flatten().all(|&v| v == F::zero()));
    for (digest, input) in records {
        late.expose(digest, input);
    }
    assert!(
        late.availability_hits() > 0,
        "late repairs hit previously declared roots or child targets"
    );
    late.declare_input(&input);
    assert_eq!(
        encode(&late.columns::<F>(root.root, depth, cells).unwrap()),
        encode(&unavailable)
    );
    assert_ne!(encode(&unavailable), encode(&word));
    let mut malformed = b"HasteBoots/mw-column/v1".to_vec();
    malformed.extend(encode(&usize::MAX));
    assert!(column::<F>(&malformed, cells).is_none());
    let mut surplus = b"HasteBoots/mw-column/v1".to_vec();
    surplus.extend(encode(&word[0]));
    surplus.push(0);
    assert!(column::<F>(&surplus, cells).is_none());
}
fn power<F: algebra::Field>(mut base: F, mut exponent: usize) -> F {
    let mut result = F::one();
    while exponent > 0 {
        if exponent & 1 != 0 {
            result *= base;
        }
        base *= base;
        exponent >>= 1;
    }
    result
}

fn packed_pairs<B, E>(vars: usize)
where
    B: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
{
    use pcs::packed_polyfrim::{Polynomial, authenticated as core};
    RECORDS.lock().unwrap().clear();
    let (width, blowup) = (4, 2);
    let physical = vars.max(1);
    let mut native = B::generate_ntt_table(5).unwrap().root();
    for _ in physical + 1..5 {
        native *= native;
    }
    let root = E::from_base(native);
    let pp = core::Parameters::new(1 << physical, width, blowup, 7, root).unwrap();
    let table = PackedTable::new(
        vars,
        width,
        (0..width << vars)
            .map(|i| E::from_base_fn(|j| B::from(1 + i + 7 * j)))
            .collect(),
    )
    .unwrap();
    let shift = root;
    let lifted = PackedTable::new(
        physical,
        width,
        table
            .values()
            .iter()
            .copied()
            .cycle()
            .take(width << physical)
            .collect(),
    )
    .unwrap();
    let state = core::commit::<E, Recorded>(&pp, Polynomial::from_table(&lifted).unwrap()).unwrap();
    let mut history = History::default();
    let records = std::mem::take(&mut *RECORDS.lock().unwrap());
    for (digest, input) in &records {
        history.expose(*digest, input.clone());
    }
    let root = state.root();
    history.declare_input(&root.0);
    let count = ((1 << physical) * blowup) / 2;
    let depth = count.ilog2() as usize;
    let mut leaves = Vec::new();
    let mut symbols = Vec::new();
    for index in 0..count {
        let raw = history.leaf(root, depth, index).unwrap();
        let prefix = encode(&(b"packed PolyFRIM pair leaf v2", &pp, 0usize, index));
        let values = vector::<E>(raw.strip_prefix(prefix.as_slice()).unwrap(), 2 * width).unwrap();
        symbols.push(values[..width].to_vec());
        symbols.push(values[width..].to_vec());
        let reconstructed = encode(&(b"packed PolyFRIM pair leaf v2", &pp, 0usize, index, &values));
        assert_eq!(raw, reconstructed);
        leaves.push(Digest512(Sha512::digest(&reconstructed).into()));
        let wrong = encode(&(b"packed PolyFRIM pair leaf v2", &pp, 1usize, index));
        assert!(raw.strip_prefix(wrong.as_slice()).is_none());
        let wrong = encode(&(b"packed PolyFRIM pair leaf v2", &pp, 0usize, index ^ 1));
        assert!(raw.strip_prefix(wrong.as_slice()).is_none());
    }
    let mut tree = MerkleTree::<Sha512>::new();
    tree.generate(&leaves);
    assert_eq!(tree.root, root);
    let n = 2 * count;
    let frozen = history.view(root).unwrap();
    let projected = projected_view(&records, root, &root.0, &history);
    assert_eq!(
        classical_assignment::frozen_polyfrim_symbols::<E>(&projected, root, &pp, n, width)
            .unwrap(),
        symbols
    );
    assert_eq!(
        classical_assignment::frozen_polyfrim_symbols::<E>(&frozen, root, &pp, n, width).unwrap(),
        symbols
    );
    let wrong = core::Parameters::new(1 << physical, width, blowup, 8, shift).unwrap();
    assert!(
        classical_assignment::frozen_polyfrim_symbols::<E>(&frozen, root, &wrong, n, width)
            .unwrap()
            .iter()
            .flatten()
            .all(|&v| v == E::zero())
    );
    let mut inconsistent = frozen.as_ref().clone();
    inconsistent.get_mut(&root).unwrap()[0] ^= 1;
    assert!(
        classical_assignment::frozen_polyfrim_symbols::<E>(&inconsistent, root, &pp, n, width)
            .unwrap()
            .iter()
            .flatten()
            .all(|&v| v == E::zero())
    );
    assert!(
        classical_assignment::frozen_polyfrim_symbols::<E>(&frozen, root, &pp, n + 1, width)
            .is_none()
    );
    let points: Vec<_> = (0usize..n)
        .map(|index| {
            shift
                * power(
                    shift * shift,
                    index.reverse_bits() >> (usize::BITS - n.ilog2()),
                )
        })
        .collect();
    let polynomial = Polynomial::from_table(&lifted).unwrap();
    for (&point, symbol) in points.iter().zip(&symbols) {
        assert_eq!(&polynomial.evaluate(point), symbol);
    }
    let radius = (n - (1 << physical)) / 4;
    let (promised, assigned) = polyfrim_assignment::<B, E>(&points, &symbols, vars, width, radius);
    assert!(promised);
    let expected: Vec<_> = table
        .values()
        .iter()
        .map(|value| value.as_base_slice()[0])
        .collect();
    assert_eq!(assigned.values(), expected);
    if vars == 0 {
        let mut invalid = symbols.clone();
        let hidden = E::from_base_fn(|j| if j == 1 { B::one() } else { B::zero() });
        for (symbol, &point) in invalid.iter_mut().zip(&points) {
            symbol[0] += (E::one() + hidden) * point;
        }
        let (promised, assigned) =
            polyfrim_assignment::<B, E>(&points, &invalid, vars, width, radius);
        assert!(promised);
        assert_eq!(assigned.values(), expected);
    }
    let mut noisy = symbols.clone();
    for (i, symbol) in noisy.iter_mut().take(radius).enumerate() {
        symbol[i % width] += E::one();
    }
    let (promised, assigned) = polyfrim_assignment::<B, E>(&points, &noisy, vars, width, radius);
    assert!(promised);
    assert_eq!(assigned.values(), expected);
    noisy[radius][radius % width] += E::one();
    let (promised, assigned) = polyfrim_assignment::<B, E>(&points, &noisy, vars, width, radius);
    assert!(!promised);
    assert!(assigned.values().iter().all(|&v| v == B::zero()));
}

fn fragment_pairs<B, E>(constant: bool)
where
    B: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
{
    use pcs::{pipfri, rolling_fri};
    RECORDS.lock().unwrap().clear();
    let (length, fragments, blowup, queries) = if constant {
        (2usize, 1usize, 2usize, 7usize)
    } else {
        (4, 4, 2, 7)
    };
    let mut native = B::generate_ntt_table(5).unwrap().root();
    for _ in (length * blowup).ilog2()..5 {
        native *= native;
    }
    let root = E::from_base(native);
    let pp = pipfri::Parameters::new(
        length,
        fragments,
        blowup,
        queries,
        root,
        pipfri::Basis::BooleanEvaluations,
    )
    .unwrap();
    let data: Vec<_> = (0..length * fragments)
        .map(|i| E::from_base_fn(|j| B::from(3 + if constant { 0 } else { i } + 11 * j)))
        .collect();
    let shift = root;
    let state = pipfri::commit::<E, Recorded>(&pp, &data).unwrap();
    // Reconstruct the exact trusted scalar context independently of private
    // PCS helpers; same leaf grammar is shared by ordinary/virtual adapters.
    let fri = rolling_fri::Parameters::new(length, blowup, queries, root).unwrap();
    let fri_context = Digest512(
        Sha512::digest(encode(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            E::MODULUS_VALUE.to_string(),
            &fri,
        )))
        .into(),
    );
    let context = Digest512(
        Sha512::digest(encode(&(
            b"HasteBoots scalar PipFRI parameters v1".as_slice(),
            fri_context,
            &pp,
        )))
        .into(),
    );
    let mut history = History::default();
    let records = std::mem::take(&mut *RECORDS.lock().unwrap());
    for (digest, input) in &records {
        history.expose(*digest, input.clone());
    }
    let root = state.commitment().root;
    history.declare_input(&root.0);
    let count = length * blowup / 2;
    let mut leaves = Vec::new();
    let mut symbols = Vec::new();
    for index in 0..count {
        let raw = history.leaf(root, count.ilog2() as usize, index).unwrap();
        let prefix = encode(&(b"PipFRI packed pair leaf v1", context, index));
        let pairs =
            vector::<[E; 2]>(raw.strip_prefix(prefix.as_slice()).unwrap(), fragments).unwrap();
        symbols.push(pairs.iter().map(|pair| pair[0]).collect::<Vec<_>>());
        symbols.push(pairs.iter().map(|pair| pair[1]).collect::<Vec<_>>());
        let reconstructed = encode(&(b"PipFRI packed pair leaf v1", context, index, &pairs));
        assert_eq!(raw, reconstructed);
        leaves.push(Digest512(Sha512::digest(reconstructed).into()));
        let wrong = encode(&(b"PipFRI packed pair leaf v1", context, index ^ 1));
        assert!(raw.strip_prefix(wrong.as_slice()).is_none());
    }
    let mut tree = MerkleTree::<Sha512>::new();
    tree.generate(&leaves);
    assert_eq!(tree.root, root);
    let n = 2 * count;
    let frozen = history.view(root).unwrap();
    let projected = projected_view(&records, root, &root.0, &history);
    assert_eq!(
        classical_assignment::frozen_fragment_symbols::<E>(&projected, root, context, n, fragments)
            .unwrap(),
        symbols
    );
    assert_eq!(
        classical_assignment::frozen_fragment_symbols::<E>(&frozen, root, context, n, fragments)
            .unwrap(),
        symbols
    );
    let mut wrong_context = context;
    wrong_context.0[0] ^= 1;
    assert!(
        classical_assignment::frozen_fragment_symbols::<E>(
            &frozen,
            root,
            wrong_context,
            n,
            fragments
        )
        .unwrap()
        .iter()
        .flatten()
        .all(|&v| v == E::zero())
    );
    let mut inconsistent = frozen.as_ref().clone();
    inconsistent.get_mut(&root).unwrap()[0] ^= 1;
    assert!(
        classical_assignment::frozen_fragment_symbols::<E>(
            &inconsistent,
            root,
            context,
            n,
            fragments
        )
        .unwrap()
        .iter()
        .flatten()
        .all(|&v| v == E::zero())
    );
    assert!(
        classical_assignment::frozen_fragment_symbols::<E>(
            &frozen,
            root,
            context,
            n + 1,
            fragments
        )
        .is_none()
    );
    assert!(
        classical_assignment::frozen_fragment_symbols::<E>(&frozen, root, context, n, 0).is_none()
    );
    let points: Vec<_> = (0usize..n)
        .map(|index| {
            shift
                * power(
                    shift * shift,
                    index.reverse_bits() >> (usize::BITS - n.ilog2()),
                )
        })
        .collect();
    for (symbol, &point) in symbols.iter().zip(&points) {
        for (fragment, &value) in symbol.iter().enumerate() {
            let expected = data[fragment * length..(fragment + 1) * length]
                .iter()
                .rev()
                .fold(E::zero(), |v, &c| v * point + c);
            assert_eq!(value, expected);
        }
    }
    let (vars, width) = if constant { (0, 1) } else { (2, 4) };
    let radius = (n - length) / 4;
    let expected: Vec<_> = data
        .iter()
        .take(width << vars)
        .map(|value| value.as_base_slice()[0])
        .collect();
    let (promised, assigned) =
        fragment_assignment::<B, E>(&points, &symbols, length, vars, width, radius);
    assert!(promised);
    assert_eq!(assigned.values(), expected);
    // A virtual identifier does not supply an independent completed word.
    // Recover the actual virtual word from the frozen fragment symbols and
    // the gamma sampled after binding the source root and fragment claims.
    let child = || {
        let mut parent = Transcript::<B>::new_classical_atomic_columns(&[87; 64]);
        parent
            .fork_classical_extension::<B, E>(
                b"word history virtual audit",
                b"fixed scalar context",
            )
            .unwrap()
    };
    let point: Vec<E> = (0..pp.num_vars())
        .map(|i| E::from_base(B::from(i + 2)))
        .collect();
    let commitment = state.commitment();
    let mut prover = child();
    let (value, proof) = pipfri::virtual_source::open_at::<E, Recorded>(
        &mut prover,
        &pp,
        &commitment,
        &state,
        &point,
    )
    .unwrap();
    let mut verifier = child();
    pipfri::virtual_source::verify::<E, Recorded>(
        &mut verifier,
        &pp,
        &commitment,
        &point,
        value,
        &proof,
    )
    .unwrap();
    let mut replay = child();
    replay.append_message(
        b"unmasked scalar PipFRI virtual v2",
        &(
            2u32,
            context,
            &commitment,
            &point,
            value,
            &proof.fragment_evaluations,
        ),
    );
    let gamma: E = replay.get_challenge(b"virtual PipFRI fragment batch v2");
    let identifier_input = encode(&(
        b"unmasked PipFRI virtual initial v2".as_slice(),
        context,
        &commitment,
        &point,
        gamma,
    ));
    let identifier = Digest512(Sha512::digest(&identifier_input).into());
    assert!(
        RECORDS
            .lock()
            .unwrap()
            .iter()
            .any(|(digest, input)| *digest == identifier && *input == identifier_input)
    );
    // The identifier's actual preimage is metadata, not a Merkle node/leaf.
    // Even if declared as a candidate root, it cannot supply the virtual word.
    history.expose(identifier, identifier_input);
    history.declare_input(&identifier.0);
    assert!(
        history
            .leaf(identifier, count.ilog2() as usize, 0)
            .is_none()
    );
    let weights: Vec<E> = (0..fragments).map(|i| power(gamma, i)).collect();
    let derived: Vec<E> = symbols
        .iter()
        .map(|symbol| {
            symbol
                .iter()
                .zip(&weights)
                .fold(E::zero(), |v, (&x, &w)| v + x * w)
        })
        .collect();
    for (&x, &actual) in points.iter().zip(&derived) {
        let expected = (0..length).rev().fold(E::zero(), |v, j| {
            v * x + (0..fragments).fold(E::zero(), |s, c| s + weights[c] * data[c * length + j])
        });
        assert_eq!(actual, expected);
    }
    for (source, query) in proof.sources.iter().zip(&proof.low_degree.queries) {
        let positions: Vec<_> = (0..count)
            .filter(|&i| {
                let leaf = Digest512(
                    Sha512::digest(encode(&(
                        b"PipFRI packed pair leaf v1",
                        context,
                        i,
                        &source.values,
                    )))
                    .into(),
                );
                leaf == source.path[0] && MerkleTree::<Sha512>::check(&root, i, &source.path)
            })
            .collect();
        assert_eq!(positions.len(), 1);
        let index = positions[0];
        for side in 0..2 {
            for fragment in 0..fragments {
                assert_eq!(
                    source.values[fragment][side],
                    symbols[2 * index + side][fragment]
                );
            }
        }
        assert!(query.originals[0].path.is_empty());
        assert_eq!(
            query.originals[0].values,
            [derived[2 * index], derived[2 * index + 1]]
        );
    }
    let mut changed = proof.clone();
    changed.low_degree.queries[0].originals[0].values[0] += E::one();
    let error = pipfri::virtual_source::verify::<E, Recorded>(
        &mut child(),
        &pp,
        &commitment,
        &point,
        value,
        &changed,
    )
    .unwrap_err();
    assert!(error.to_string().contains("virtual fragment combination"));
    let mut a = [0; 64];
    let mut b = [0; 64];
    prover.get_challenge_bytes(b"virtual history continuation", &mut a);
    verifier.get_challenge_bytes(b"virtual history continuation", &mut b);
    assert_eq!(a, b);
    let mut noisy = symbols.clone();
    for symbol in noisy.iter_mut().take(radius) {
        symbol[0] += E::one();
    }
    let (promised, assigned) =
        fragment_assignment::<B, E>(&points, &noisy, length, vars, width, radius);
    assert!(promised);
    assert_eq!(assigned.values(), expected);
    if constant {
        let hidden = E::from_base_fn(|j| if j == 1 { B::one() } else { B::zero() });
        let invalid: Vec<_> = points
            .iter()
            .map(|&x| vec![data[0] + (data[0] + E::one() + hidden) * x])
            .collect();
        let (promised, assigned) =
            fragment_assignment::<B, E>(&points, &invalid, length, vars, width, radius);
        assert!(promised);
        assert_eq!(assigned.values(), expected);
    }
    noisy[radius][usize::from(!constant)] += E::one();
    let (promised, assigned) =
        fragment_assignment::<B, E>(&points, &noisy, length, vars, width, radius);
    assert!(!promised);
    assert!(assigned.values().iter().all(|&v| v == B::zero()));
}

fn joint_filtered_declarations() {
    use algebra::BabyBear;
    let mut leaf = b"HasteBoots/mw-column/v1".to_vec();
    leaf.extend(encode(&vec![BabyBear::from(7usize)]));
    let root = Digest512(Sha512::digest(&leaf).into());
    let mut carrier = vec![231u8; 512];
    carrier[13..77].copy_from_slice(&root.0);
    let carrier_hash = Digest512(Sha512::digest(&carrier).into());
    let mut bounded = History::bounded(256, 256);
    bounded.expose(carrier_hash, carrier.clone());
    bounded.declare_input(&carrier);
    assert_eq!(
        (
            bounded.hash_queries(),
            bounded.xof_queries(),
            bounded.events()
        ),
        (1, 1, 2)
    );
    assert!(!bounded.first_declarations().contains_key(&root));
    assert!(bounded.known().contains_key(&carrier_hash));
    bounded.expose(root, leaf.clone());
    let mut eligible = b"SHA source declaration".to_vec();
    eligible.extend(root.0);
    let declaration_hash = Digest512(Sha512::digest(&eligible).into());
    bounded.expose(declaration_hash, eligible.clone());
    assert_eq!(bounded.first_declarations()[&root], 3);
    assert_eq!(
        bounded.columns::<BabyBear>(root, 0, 1).unwrap()[0],
        vec![BabyBear::from(7usize)]
    );
    bounded.declare_input(&root.0);
    assert_eq!(bounded.first_declarations()[&root], 3);
    assert_eq!((bounded.hash_queries(), bounded.xof_queries()), (3, 2));
    assert_eq!(bounded.availability_hits(), 0);
    // In the unfiltered game, the earlier oversized SHA query freezes the
    // source before its leaf preimage is exposed. Its late exposure is a hit.
    let mut unfiltered = History::default();
    unfiltered.expose(carrier_hash, carrier);
    unfiltered.expose(root, leaf.clone());
    assert_eq!(unfiltered.first_declarations()[&root], 0);
    assert_eq!(
        unfiltered.columns::<BabyBear>(root, 0, 1).unwrap()[0],
        vec![BabyBear::from(0usize)]
    );
    assert_eq!(unfiltered.availability_hits(), 1);
    // Eligible XOF declarations are equally binding: a later SHA preimage
    // cannot repair this frozen word, including after repeated declarations.
    let mut late = History::bounded(256, 256);
    late.declare_input(&root.0);
    let first_view = late.view(root).unwrap();
    assert!(!first_view.contains_key(&root));
    late.expose(root, leaf);
    late.declare_input(&eligible);
    assert!(std::sync::Arc::ptr_eq(
        &first_view,
        &late.view(root).unwrap()
    ));
    assert!(!late.view(root).unwrap().contains_key(&root));
    assert!(late.known().contains_key(&root));
    assert_eq!(late.availability_hits(), 1);
    assert_eq!(
        late.columns::<BabyBear>(root, 0, 1).unwrap()[0],
        vec![BabyBear::from(0usize)]
    );
}

#[test]
fn classical_source_words_freeze_and_decode_production_leaf_grammars() {
    joint_filtered_declarations();
    check::<algebra::BabyBear>(4, 3, 1);
    check::<algebra::Goldilocks>(4, 3, 1);
    check::<algebra::BabyBear>(3, 3, 1);
    check::<algebra::Goldilocks>(3, 3, 1);
    check::<algebra::BabyBear>(4, 0, 0);
    check::<algebra::Goldilocks>(4, 0, 0);
    fn extensions<B, E>()
    where
        B: NTTField + Serialize + DeserializeOwned,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        packed_pairs::<B, E>(3);
        packed_pairs::<B, E>(0);
        fragment_pairs::<B, E>(false);
        fragment_pairs::<B, E>(true);
    }
    extensions::<algebra::BabyBear, algebra::BabyBearExetension>();
    extensions::<algebra::BabyBear, algebra::BabyBearExtension5>();
    extensions::<algebra::BabyBear, algebra::BabyBearExtension6>();
    extensions::<algebra::BabyBear, algebra::BabyBearExtension8>();
    extensions::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    extensions::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    extensions::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
    extensions::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

#[test]
fn immutable_snapshots_share_until_eligible_hash_answer() {
    use std::sync::Arc;
    let mut history = History::bounded(128, usize::MAX);
    let preimage = vec![9; 128];
    let digest = Digest512(Sha512::digest(&preimage).into());
    history.expose(digest, preimage.clone());
    let a = Digest512([1; 64]);
    let b = Digest512([2; 64]);
    history.declare_input(&a.0);
    history.declare_input(&b.0);
    let first = history.view(a).unwrap();
    assert!(Arc::ptr_eq(&first, &history.view(b).unwrap()));
    assert_eq!(first.get(&digest), Some(&preimage));
    // A duplicate answer and a producer outside the eligibility selector do
    // not change the eligible snapshot. All oracle requests still count.
    history.expose(digest, preimage);
    let excluded = vec![8; 129];
    history.expose(Digest512(Sha512::digest(&excluded).into()), excluded);
    let c = Digest512([3; 64]);
    history.declare_input(&c.0);
    assert!(Arc::ptr_eq(&first, &history.view(c).unwrap()));
    let next = vec![7; 128];
    let next_digest = Digest512(Sha512::digest(&next).into());
    history.expose(next_digest, next.clone());
    let d = Digest512([4; 64]);
    history.declare_input(&d.0);
    let second = history.view(d).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(!first.contains_key(&next_digest));
    assert_eq!(second.get(&next_digest), Some(&next));
    history.declare_input(&a.0);
    assert!(Arc::ptr_eq(&first, &history.view(a).unwrap()));
    assert_eq!(history.hash_queries(), 4);
    assert_eq!(history.xof_queries(), 5);
    assert_eq!(history.events(), 9);
}

#[path = "support/classical_projection.rs"]
mod classical_projection;
#[test]
fn projected_roots_keep_first_declarations_and_reachable_preimages() {
    use std::sync::Arc;
    let leaf = vec![13; 80];
    let leaf_hash = Digest512(Sha512::digest(&leaf).into());
    let node = [leaf_hash.0, leaf_hash.0].concat();
    let root = Digest512(Sha512::digest(&node).into());
    let premature = Digest512([19; 64]);
    let mut projected = classical_projection::Projection::new([root, premature]);
    let mut full = History::default();
    projected.declare_input(&premature.0);
    full.declare_input(&premature.0);
    for (digest, input) in [(leaf_hash, leaf.clone()), (root, node)] {
        projected.expose(digest, input.clone());
        full.expose(digest, input);
    }
    projected.declare_input(&root.0);
    full.declare_input(&root.0);
    let view = projected.view(root).unwrap();
    let full_view = full.view(root).unwrap();
    for digest in [root, leaf_hash] {
        assert_eq!(view.get(&digest), full_view.get(&digest));
    }
    assert_eq!(
        projected.first(root),
        full.first_declarations().get(&root).copied()
    );
    // Later answers and repeated declarations cannot repair a missing word.
    projected.expose(leaf_hash, leaf);
    projected.declare_input(&premature.0);
    assert!(projected.view(premature).unwrap().is_empty());
    projected.declare_input(&root.0);
    assert!(Arc::ptr_eq(&view, &projected.view(root).unwrap()));
    assert_eq!(projected.events(), 7);
}

#[test]
fn projection_prefix_prefilter_keeps_exact_targets_at_every_boundary() {
    let a = Digest512([1; 64]);
    let mut bytes = [3; 64];
    bytes[..2].copy_from_slice(&a.0[..2]);
    let b = Digest512(bytes);
    let mut bytes = [7; 64];
    bytes[..2].copy_from_slice(&a.0[..2]);
    let unselected = Digest512(bytes);
    for offset in [0, 1, 31, 63, 64, 65, 127] {
        let mut projection = classical_projection::Projection::new([a, b]);
        let mut full = History::default();
        let mut input = vec![9; offset];
        input.extend(unselected.0);
        input.extend(a.0);
        input.push(23);
        input.extend(b.0);
        projection.declare_input(&input);
        full.declare_input(&input);
        for root in [a, b] {
            assert_eq!(
                projection.first(root),
                full.first_declarations().get(&root).copied()
            );
            assert_eq!(
                projection.view(root).unwrap().as_ref(),
                full.view(root).unwrap().as_ref()
            );
        }
        assert!(projection.first(unselected).is_none());
        assert!(full.first_declarations().contains_key(&unselected));
    }
}

#[test]
fn projected_stream_replay_checks_frames_hashes_and_fingerprint() {
    let input = vec![37; 80];
    let output = Digest512(Sha512::digest(&input).into());
    let mut bytes = b"HB_ORACLE_EVENT_STREAM_V1\n".to_vec();
    let header = bytes.len();
    bytes.extend([1, 0]);
    bytes.extend(80u64.to_le_bytes());
    bytes.extend(&input);
    bytes.extend(output.0);
    bytes.extend([2, 2]);
    bytes.extend(64u64.to_le_bytes());
    bytes.extend(output.0);
    let boundary_root = Digest512([42; 64]);
    let mut boundary_input = vec![55; (1 << 20) - 31];
    boundary_input.extend(boundary_root.0);
    boundary_input.extend([73; 17]);
    bytes.extend([2, 2]);
    bytes.extend((boundary_input.len() as u64).to_le_bytes());
    bytes.extend(boundary_input);
    let path = std::env::temp_dir().join(format!(
        "hasteboots-projection-{}-{}.events",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let fingerprint = |data: &[u8]| {
        Sha512::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    std::fs::write(&path, &bytes).unwrap();
    let projected =
        classical_projection::replay(&path, &fingerprint(&bytes), [output, boundary_root]).unwrap();
    assert_eq!(projected.events(), 3);
    assert_eq!(projected.first(boundary_root), Some(2));
    assert!(projected.view(boundary_root).unwrap().is_empty());
    assert_eq!(projected.first(output), Some(1));
    assert_eq!(projected.view(output).unwrap().get(&output), Some(&input));
    assert!(classical_projection::replay(&path, &"0".repeat(128), [output]).is_err());
    let mut malformed = bytes.clone();
    malformed[header + 10 + input.len()] ^= 1;
    std::fs::write(&path, &malformed).unwrap();
    assert!(classical_projection::replay(&path, &fingerprint(&malformed), [output]).is_err());
    std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
    assert!(
        classical_projection::replay(&path, &fingerprint(&bytes[..bytes.len() - 1]), [output])
            .is_err()
    );
    let mut malformed = bytes.clone();
    malformed[header + 1] = 2;
    malformed[header + 10 + input.len() + 64 + 1] = 1;
    std::fs::write(&path, &malformed).unwrap();
    assert!(classical_projection::replay(&path, &fingerprint(&malformed), [output]).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn authenticated_paths_preserve_first_missing_preimages() {
    use classical_history::FrozenPathStatus;
    let leaf = b"canonical leaf input for the left branch".to_vec();
    let other = b"canonical leaf input for the right branch".to_vec();
    let left = Digest512(Sha512::digest(&leaf).into());
    let right = Digest512(Sha512::digest(&other).into());
    let parent_input = [left.0, right.0].concat();
    let root = Digest512(Sha512::digest(&parent_input).into());
    let path = [left, right];
    let mut history = History::default();
    history.expose(root, parent_input.clone());
    history.declare_input(&root.0);
    // The parent was known, but its left child was declared before it was
    // answered. The witness must descend past the known root to that child.
    let boundary = history.first_declarations()[&root];
    let first = history.frozen_path_status(root, 0, &path, &leaf).unwrap();
    assert_eq!(first, FrozenPathStatus::Missing {
        digest: left, input: leaf.clone(), declared_at: 0,
        answered_at: None, root_boundary: boundary,
    });
    let hits = history.availability_hits();
    let answer_event = history.events();
    history.expose(left, leaf.clone());
    assert_eq!(history.availability_hits(), hits+1);
    assert_eq!(history.frozen_path_status(root, 0, &path, &leaf), Some(FrozenPathStatus::Missing {
        digest: left, input: leaf.clone(), declared_at: 0,
        answered_at: Some(answer_event), root_boundary: boundary,
    }));
    // A complete graph before declaration has no missing witness.
    let mut complete = History::default();
    complete.expose(left, leaf.clone());
    complete.expose(right, other.clone());
    complete.expose(root, parent_input.clone());
    complete.declare_input(&root.0);
    assert_eq!(complete.frozen_path_status(root, 0, &path, &leaf), Some(FrozenPathStatus::Known));
    assert_eq!(complete.frozen_path_status(root, 1, &[right, left], &other), Some(FrozenPathStatus::Known));
    assert!(complete.frozen_path_status(root, 0, &[], &leaf).is_none());
    assert!(complete.frozen_path_status(root, 2, &path, &leaf).is_none());
    assert!(complete.frozen_path_status(root, 1, &path, &leaf).is_none());
    assert!(complete.frozen_path_status(root, 0, &path, &other).is_none());
    // A length filter is a separate obligation, not a missing-answer hit.
    let mut filtered = History::bounded(0, usize::MAX);
    filtered.expose(root, parent_input.clone());
    filtered.declare_input(&root.0);
    assert_eq!(filtered.frozen_path_status(root, 0, &path, &leaf), Some(FrozenPathStatus::Ineligible {
        digest: root, input_bytes: 128,
    }));
}

#[test]
fn missing_root_witness_does_not_disappear_after_answer() {
    use classical_history::FrozenPathStatus;
    let leaf = vec![13; 80];
    let digest = Digest512(Sha512::digest(&leaf).into());
    let mut history = History::default();
    history.declare_input(&digest.0);
    assert_eq!(history.frozen_path_status(digest, 0, &[digest], &leaf), Some(FrozenPathStatus::Missing {
        digest, input: leaf.clone(), declared_at: 0, answered_at: None, root_boundary: 0,
    }));
    history.expose(digest, leaf.clone());
    assert_eq!(history.availability_hits(), 1);
    assert_eq!(history.frozen_path_status(digest, 0, &[digest], &leaf), Some(FrozenPathStatus::Missing {
        digest, input: leaf.clone(), declared_at: 0, answered_at: Some(1), root_boundary: 0,
    }));
}

#[test]
fn hash_exposure_uses_pre_answer_targets_and_conservatively_charges_repeats() {
    use classical_history::HashExposure;
    let a = vec![31; 64];
    let a_hash = Digest512(Sha512::digest(&a).into());
    let b = b"new hash input".to_vec();
    let b_hash = Digest512(Sha512::digest(&b).into());
    let mut history = History::default();
    history.declare_input(&[47; 65]); // Two equal windows, one target.
    assert_eq!(history.exposure(), HashExposure::default());
    history.expose(a_hash, a.clone());
    assert_eq!(history.exposure(), HashExposure {
        queries: 1, target_pairs: 2, prior_output_pairs: 0,
    });
    history.expose(a_hash, a.clone());
    assert_eq!(history.exposure(), HashExposure {
        queries: 2, target_pairs: 4, prior_output_pairs: 1,
    });
    // A later declaration is not retroactively charged to an earlier answer.
    history.declare_input(&a_hash.0);
    assert_eq!(history.exposure().target_pairs, 4);
    history.expose(b_hash, b.clone());
    assert_eq!(history.exposure(), HashExposure {
        queries: 3, target_pairs: 7, prior_output_pairs: 2,
    });
    assert_eq!(history.availability_hits(), 0);
    // Filtered inputs still produce outputs, which count for later collisions.
    let mut filtered = History::bounded(0, 0);
    filtered.declare_input(&a_hash.0);
    filtered.expose(a_hash, a);
    filtered.expose(b_hash, b);
    assert_eq!(filtered.exposure(), HashExposure {
        queries: 2, target_pairs: 0, prior_output_pairs: 1,
    });
}

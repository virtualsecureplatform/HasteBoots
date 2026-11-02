//! Executable outer-binding interpretation, not a full verifier-prefix theorem.
use super::*;
use algebra::transformation::AbstractNTT;
use pcs::{
    classical_profile::{Backend, ClassicalProfile, ProfileParameters, Role, Specification},
    utils::hash::Digest512,
};
use sha2::{Digest, Sha512};
#[path = "../../../../../pcs/tests/support/classical_decode.rs"]
mod classical_decode;
// Backends share this support module; this audit currently consumes Brakedown.
#[allow(dead_code)]
#[path = "../../../../../pcs/tests/support/classical_assignment.rs"]
mod classical_assignment;
#[allow(dead_code)]
#[path = "../../../../../pcs/tests/support/classical_history.rs"]
mod classical_history;
#[path = "../../../../../pcs/tests/support/classical_projection.rs"]
mod classical_projection;
#[cfg(feature = "transcript-audit")]
mod verifier_event_audit;
mod monomial_entry_audit;
mod monomial_public_audit;
mod monomial_terminal_audit;
mod monomial_word_audit;
mod monomial_ntt_audit;
mod monomial_ntt_prefix_audit;
mod key_switch_entry_audit;
mod key_switch_extraction_audit;
mod accumulator_alias_audit;
#[cfg(feature = "transcript-audit")]
#[path = "../../../../../helper/tests/support/classical_xof_history.rs"]
mod classical_xof_history;
#[cfg(feature = "transcript-audit")]
mod xof_producer_history_audit;
#[cfg(feature = "transcript-audit")]
mod ordered_claim_audit;

type Primary<F> = (
    Vec<Commitment<Digest512>>,
    Vec<Commitment<Digest512>>,
    Vec<Commitment<Digest512>>,
    Vec<Commitment<Digest512>>,
    Vec<F>,
);

fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
}

struct Raw<'a>(&'a [u8]);
impl Serialize for Raw<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(self.0.len())?;
        for byte in self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

fn vector<T: Serialize + DeserializeOwned>(input: &mut &[u8], expected: usize) -> Option<Vec<T>> {
    let (length, used): (usize, usize) =
        bincode::serde::decode_from_slice(input, bincode::config::standard()).ok()?;
    if length != expected || encoded(&length) != input.get(..used)? {
        return None;
    }
    *input = input.get(used..)?;
    // Allocate only the trusted count, never the candidate's declared count.
    let mut result = Vec::with_capacity(expected);
    for _ in 0..expected {
        let (value, used): (T, usize) =
            bincode::serde::decode_from_slice(input, bincode::config::standard()).ok()?;
        if encoded(&value) != input.get(..used)? {
            return None;
        }
        *input = input.get(used..)?;
        result.push(value);
    }
    Some(result)
}

fn recover<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    bytes: &[u8],
) -> Option<Primary<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let prefix = encoded(&(
        12u32,
        EF::D,
        setup,
        contexts::<F, Sha512, P>(pp).ok()?,
        statement,
    ));
    let mut remaining = bytes.strip_prefix(prefix.as_slice())?;
    let digits = setup
        .config
        .decomposition::<F>()
        .ok()?
        .num_digits::<F>()
        .ok()?;
    let co = vector(&mut remaining, 2 * digits + 1)?;
    let ev = vector(&mut remaining, 2 * digits + 1)?;
    let inputs = vector(&mut remaining, 2)?;
    let accumulators = vector(&mut remaining, 4)?;
    let endpoint: Vec<F> = vector(&mut remaining, 2 * setup.config.n)?;
    pp.coefficients.validate_values(&endpoint).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    Some((co, ev, inputs, accumulators, endpoint))
}

struct InitialProduct<F> {
    shape: sumcheck::packed::PackedShape<F>,
    sources: Vec<(Digest512, Commitment<Digest512>)>,
}

fn frame(out: &mut Vec<u8>, kind: u8, label: &[u8], body: &[u8]) {
    out.push(kind);
    out.extend((label.len() as u64).to_le_bytes());
    out.extend(label);
    out.extend((body.len() as u64).to_le_bytes());
    out.extend(body);
}

fn initial_header<F: NTTField>(profile: &ClassicalProfile) -> Option<Vec<u8>> {
    if !matches!(profile.version(), 4 | 5) {
        return None;
    }
    let mut out = Vec::new();
    frame(&mut out, 0, b"protocol", b"HasteBoots framed SHAKE256 v1");
    frame(
        &mut out,
        0,
        b"application",
        b"HasteBoots typed classical prime v1",
    );
    frame(&mut out, 0, b"trusted profile", &profile.id().0);
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    frame(&mut out, 1, b"typed prime field", &p.to_le_bytes());
    for marker in [
        b"atomic NTT row phase v2".as_slice(),
        b"atomic joint projections v3",
        b"atomic packed zerocheck v4",
    ] {
        frame(&mut out, 1, b"classical challenge schedule", marker);
    }
    if profile.version() == 5 {
        frame(
            &mut out,
            1,
            b"classical challenge schedule",
            b"atomic Brakedown columns v5",
        );
    }
    frame(&mut out, 1, b"classical trusted profile", &encoded(profile));
    Some(out)
}

fn initial_tail<F, P>(task: &InitialProduct<F>) -> Option<Vec<u8>>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let mut out = Vec::new();
    let (contexts, roots): (Vec<_>, Vec<_>) = task.sources.iter().cloned().unzip();
    frame(
        &mut out,
        1,
        P::RELATION_DOMAIN,
        &encoded(&(&task.shape, contexts, roots)),
    );
    frame(&mut out, 1, b"packed zerocheck v1", &encoded(&task.shape));
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let count = task
        .shape
        .width
        .checked_mul(task.shape.num_vars.checked_sub(1)?)?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(&mut out, 4, b"packed zero atomic equality v4", &descriptor);
    Some(out)
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let value = input.get(..n)?;
    *input = input.get(n..)?;
    Some(value)
}
fn sized<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = u64::from_le_bytes(take(input, 8)?.try_into().ok()?);
    take(input, usize::try_from(n).ok()?)
}
fn message<'a>(input: &mut &'a [u8], kind: u8, label: &[u8]) -> Option<&'a [u8]> {
    if take(input, 1)? != [kind] || sized(input)? != label {
        return None;
    }
    sized(input)
}

fn initial_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
) -> Option<(InitialProduct<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    profile.validate_field::<F, EF>().ok()?;
    let header = initial_header::<F>(profile)?;
    let mut remaining = input.strip_prefix(header.as_slice())?;
    let outer = message(
        &mut remaining,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let task = first_product::<F, EF, P>(pp, setup, statement, outer)?;
    Some((task, remaining))
}

fn initial_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
) -> Option<InitialProduct<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, remaining) = initial_prefix::<F, EF, P>(profile, pp, setup, statement, input)?;
    if remaining != initial_tail::<F, P>(&task)? {
        return None;
    }
    Some(task)
}

fn raw_prime_phase<F: NTTField>(input: &[u8], count: usize) -> (Vec<u128>, Vec<u8>) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let bits = 128 - (p - 1).leading_zeros() as usize;
    let bytes = (bits + 7) / 8;
    let mut state = sha3::Shake256::default();
    Update::update(&mut state, input);
    let mut reader = state.finalize_xof();
    let mut values = Vec::new();
    let mut consumed = Vec::new();
    while values.len() < count {
        let mut raw = [0u8; 16];
        reader.read(&mut raw[..bytes]);
        consumed.extend(&raw[..bytes]);
        let v = u128::from_le_bytes(raw) & (u128::MAX >> (128 - bits));
        if v < p {
            values.push(v);
        }
    }
    (values, consumed)
}

const RECEIPT_DOMAIN: &[u8] = b"HasteBoots consumed field bytes v1";
type Producers = std::collections::HashMap<[u8; 64], Vec<u8>>;

fn replay_receipt<F: NTTField>(receipt: &[u8], count: usize, known: &Producers) -> Option<Vec<F>> {
    if receipt.len() != 80 {
        return None;
    }
    let fingerprint: [u8; 64] = receipt[16..].try_into().ok()?;
    let raw = known.get(&fingerprint)?.strip_prefix(RECEIPT_DOMAIN)?;
    if u128::from_le_bytes(receipt[..16].try_into().ok()?) != raw.len() as u128 {
        return None;
    }
    replay_raw_prime_values::<F>(raw, count)
}

fn replay_raw_prime_values<F: NTTField>(raw: &[u8], count: usize) -> Option<Vec<F>> {
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let bits = 128 - (p - 1).leading_zeros() as usize;
    let bytes = (bits + 7) / 8;
    if raw.len() % bytes != 0 || count > raw.len() / bytes {
        return None;
    }
    let mut values = Vec::with_capacity(count);
    for (index, chunk) in raw.chunks_exact(bytes).enumerate() {
        if values.len() == count {
            return None;
        }
        let mut word = [0u8; 16];
        word[..bytes].copy_from_slice(chunk);
        let value = u128::from_le_bytes(word) & (u128::MAX >> (128 - bits));
        if value < p {
            values.push(F::from(usize::try_from(value).ok()?));
            if values.len() == count && (index + 1) * bytes != raw.len() {
                return None;
            }
        }
    }
    (values.len() == count).then_some(values)
}

struct InitialMixing<F> {
    task: InitialProduct<F>,
    equality: Vec<F>,
    first: Vec<Vec<F>>,
}
fn mixing_tail<F: NTTField>(width: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let count = width.checked_mul(width)?.checked_add(width)?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(
        &mut out,
        4,
        b"packed zero atomic first coins v4",
        &descriptor,
    );
    Some(out)
}
fn mixing_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    known: &Producers,
) -> Option<(InitialMixing<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, remaining) = initial_prefix::<F, EF, P>(profile, pp, setup, statement, input)?;
    let prefix = initial_tail::<F, P>(&task)?;
    let mut remaining = remaining.strip_prefix(prefix.as_slice())?;
    let receipt = message(&mut remaining, 5, b"packed zero atomic equality v4")?;
    let equality = replay_receipt::<F>(
        receipt,
        task.shape
            .width
            .checked_mul(task.shape.num_vars.checked_sub(1)?)?,
        known,
    )?;
    let body = message(&mut remaining, 1, b"packed zero first message")?;
    let width = task.shape.width;
    let outer_count = encoded(&width);
    let mut body = body.strip_prefix(outer_count.as_slice())?;
    let degree = task.shape.validate().ok()?;
    let mut first = Vec::with_capacity(width);
    for _ in 0..width {
        let row = vector::<F>(&mut body, degree + 1)?;
        if row.get(..2 * width)?.iter().any(|&v| v != F::zero()) {
            return None;
        }
        first.push(row);
    }
    if !body.is_empty() {
        return None;
    }
    let tail = mixing_tail::<F>(width)?;
    remaining = remaining.strip_prefix(tail.as_slice())?;
    Some((
        InitialMixing {
            task,
            equality,
            first,
        },
        remaining,
    ))
}

fn mixing_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    known: &Producers,
) -> Option<InitialMixing<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = mixing_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
    rest.is_empty().then_some(task)
}

fn reduced<F: NTTField>(
    shape: &sumcheck::packed::PackedShape<F>,
) -> sumcheck::packed::PackedShape<F> {
    let mut out = shape.clone();
    out.num_vars -= 1;
    out.num_factors += 1;
    for (_, factors) in &mut out.terms {
        factors.push(shape.num_factors);
    }
    out
}

fn round_tail<F: NTTField>(width: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(width).ok()?.to_le_bytes());
    frame(&mut out, 4, b"packed independent challenges", &descriptor);
    Some(out)
}

// Conditional interface: callers supply a fixed table assignment for each
// (trusted context, root). Establishing that assignment from Merkle history is
// a separate obligation; this helper does not infer a word from a root alone.
struct RoundTask<F> {
    initial: InitialMixing<F>,
    evaluations: Vec<F>,
    expected: Vec<F>,
    mixing: Vec<F>,
    query: Vec<algebra::matrix_weighted::MatrixPair<F>>,
}
impl<F: NTTField> RoundTask<F> {
    fn equality_table(&self) -> Option<PackedTable<F>> {
        let k = self.initial.task.shape.width;
        let vars = self.initial.task.shape.num_vars.checked_sub(1)?;
        let cells = 1usize.checked_shl(u32::try_from(vars).ok()?)?;
        let mut values = vec![F::zero(); cells.checked_mul(k)?];
        for b in 0..cells {
            for c in 0..k {
                let mut weight = F::one();
                for j in 0..vars {
                    let r = self.initial.equality[c * vars + j];
                    weight *= if (b >> j) & 1 == 0 { F::one() - r } else { r };
                }
                for a in 0..k {
                    values[b * k + a] += self.mixing[a * k + c] * weight;
                }
            }
        }
        let mut table = PackedTable::new(vars, k, values).ok()?;
        // The first matrix folds original factors; equality already starts on
        // the remaining variables and receives only subsequent matrices.
        for pair in &self.query[1..] {
            table = table.fold(pair).ok()?;
        }
        Some(table)
    }

    fn assigned_factors(
        &self,
        mut assignment: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<PackedTable<F>>,
    ) -> Option<Vec<PackedTable<F>>> {
        let shape = &self.initial.task.shape;
        let mut factors = Vec::with_capacity(shape.num_factors + 1);
        for source in &self.initial.task.sources {
            let mut table = assignment(source)?;
            table.validate().ok()?;
            if table.num_vars() != shape.num_vars || table.width() != shape.width {
                return None;
            }
            for pair in &self.query {
                table = table.fold(pair).ok()?;
            }
            factors.push(table);
        }
        factors.push(self.equality_table()?);
        Some(factors)
    }

    fn assigned_residual(
        &self,
        assignment: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<PackedTable<F>>,
    ) -> Option<Vec<F>> {
        let factors = self.assigned_factors(assignment)?;
        let mut shape = reduced(&self.initial.task.shape);
        shape.num_vars = factors.first()?.num_vars();
        let sum = sumcheck::packed::sum(&shape, &factors).ok()?;
        Some(
            sum.iter()
                .zip(&self.expected)
                .map(|(&actual, &expected)| actual - expected)
                .collect(),
        )
    }
}

fn interpolate_uni_poly<F: NTTField>(values: &[F], point: F) -> F {
    values
        .iter()
        .enumerate()
        .fold(F::zero(), |sum, (i, &value)| {
            let node = F::from(i);
            let (numerator, denominator) = (0..values.len())
                .filter(|&j| j != i)
                .fold((F::one(), F::one()), |(n, d), j| {
                    (n * (point - F::from(j)), d * (node - F::from(j)))
                });
            sum + value * numerator / denominator
        })
}

// Interpret any remaining sumcheck round at its query, replaying only receipts
// already resolvable in the frozen producer view supplied by the caller.
fn first_reduced_prefix<'a, F: NTTField + Serialize + DeserializeOwned>(
    task: InitialMixing<F>,
    mut remaining: &'a [u8],
    known: &Producers,
) -> Option<(RoundTask<F>, &'a [u8])> {
    let shape = reduced(&task.task.shape);
    let k = shape.width;
    let coins = replay_receipt::<F>(
        message(&mut remaining, 5, b"packed zero atomic first coins v4")?,
        k * k + k,
        known,
    )?;
    let mixing = coins[..k * k].to_vec();
    let query = vec![sumcheck::packed::challenge_pair(&coins[k * k..]).ok()?];
    let expected: Vec<F> = (0..k)
        .map(|a| {
            (0..k).fold(F::zero(), |v, b| {
                v + coins[a * k + b] * interpolate_uni_poly(&task.first[b], coins[k * k + a])
            })
        })
        .collect();
    if message(&mut remaining, 1, b"packed sumcheck v1")? != encoded(&shape) {
        return None;
    }
    if message(&mut remaining, 1, b"packed claimed sum")? != encoded(&expected) {
        return None;
    }
    Some((RoundTask { initial: task, evaluations: Vec::new(), expected, mixing, query }, remaining))
}

fn round_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    known: &Producers,
    round: usize,
) -> Option<(RoundTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, remaining) = mixing_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
    let (mut task, mut remaining) = first_reduced_prefix(task, remaining, known)?;
    let shape = reduced(&task.initial.task.shape);
    if round >= shape.num_vars { return None; }
    let k = shape.width;
    let degree = shape.validate().ok()?;
    let tail = round_tail::<F>(k)?;
    for index in 0..=round {
        let mut body = message(&mut remaining, 1, b"packed round")?;
        let evaluations = vector::<F>(&mut body, degree + 1)?;
        if !body.is_empty() || (0..k).any(|a| evaluations[2*a]+evaluations[2*a+1]!=task.expected[a]) { return None; }
        remaining = remaining.strip_prefix(tail.as_slice())?;
        task.evaluations = evaluations;
        if index == round { return Some((task, remaining)); }
        let coins = replay_receipt::<F>(message(&mut remaining, 5, b"packed independent challenges")?, k, known)?;
        task.query.push(sumcheck::packed::challenge_pair(&coins).ok()?);
        task.expected = coins.iter().map(|&r| interpolate_uni_poly(&task.evaluations, r)).collect();
    }
    None
}

fn round_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    known: &Producers,
    round: usize,
) -> Option<RoundTask<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        round_prefix::<F, EF, P>(profile, pp, setup, statement, input, known, round)?;
    rest.is_empty().then_some(task)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpeningFamily {
    Primary,
    Decomposition,
    SecondDecomposition,
    LookupHelper,
    SecondLookupHelper,
    LookupSource { slot: usize, digits: usize },
    SecondLookupSource { slot: usize, digits: usize },
}
struct FirstOpening<F> {
    family: OpeningFamily,
    selected: usize,
    sources: Vec<(Digest512, Commitment<Digest512>)>,
    query: Vec<algebra::matrix_weighted::MatrixPair<F>>,
    values: Vec<Vec<F>>,
}
impl<F> FirstOpening<F> {
    fn role(&self) -> usize {
        if matches!(
            self.family,
            OpeningFamily::LookupHelper | OpeningFamily::SecondLookupHelper
        ) {
            1
        } else {
            0
        }
    }
    fn parameters<'a, P>(&self, pp: &Parameters<'a, P>, index: usize) -> Option<&'a P> {
        self.sources.get(index)?;
        Some(match self.family {
            OpeningFamily::Primary => {
                if index % 2 == 1 {
                    pp.key
                } else {
                    pp.evaluations
                }
            }
            OpeningFamily::LookupHelper | OpeningFamily::SecondLookupHelper => pp.helper,
            OpeningFamily::LookupSource { slot, digits }
            | OpeningFamily::SecondLookupSource { slot, digits } => {
                if index != 0 || slot >= 2 * digits + 1 {
                    return None;
                }
                if slot < digits {
                    pp.coefficients
                } else {
                    pp.borrows
                }
            }
            OpeningFamily::Decomposition | OpeningFamily::SecondDecomposition => {
                let count = self.sources.len().checked_sub(2)?;
                if count % 2 != 0 {
                    return None;
                }
                decomposition_source_parameters(pp, count / 2, index)
            }
        })
    }
}
// Interpret the boundary before the first PCS body. This establishes the
// inherited opening obligation, not the backend's complete query grammar.
fn first_opening_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    known: &Producers,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (initial, _) = initial_prefix::<F, EF, P>(profile, pp, setup, statement, input)?;
    let (task, expected, mut rest) = if initial.shape.num_vars == 1 {
        let (task, rest) = mixing_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
        let (task, rest) = first_reduced_prefix(task, rest, known)?;
        let expected = task.expected.clone();
        (task, expected, rest)
    } else {
        let last = initial.shape.num_vars.checked_sub(2)?;
        let (mut task, mut rest) = round_prefix::<F, EF, P>(profile, pp, setup, statement, input, known, last)?;
        let k = task.initial.task.shape.width;
        let coins = replay_receipt::<F>(message(&mut rest, 5, b"packed independent challenges")?, k, known)?;
        let expected = coins.iter().map(|&r| interpolate_uni_poly(&task.evaluations, r)).collect::<Vec<_>>();
        task.query.push(sumcheck::packed::challenge_pair(&coins).ok()?);
        (task, expected, rest)
    };
    let k = task.initial.task.shape.width;
    let equality = task.equality_table()?;
    let mut body = message(&mut rest, 1, b"packed relation terminal values")?;
    let count = task.initial.task.shape.num_factors;
    body = body.strip_prefix(encoded(&count).as_slice())?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let value = vector::<F>(&mut body, k)?;
        let parameters = if index % 2 == 1 {
            pp.key
        } else {
            pp.evaluations
        };
        parameters.validate_values(&value).ok()?;
        values.push(value);
    }
    if !body.is_empty() {
        return None;
    }
    let actual = task.initial.task.shape.evaluate(&values).ok()?;
    if actual
        .iter()
        .zip(equality.values())
        .zip(&expected)
        .any(|((&actual, &eq), &expected)| actual * eq != expected)
    {
        return None;
    }
    Some((
        FirstOpening {
            family: OpeningFamily::Primary,
            selected: 0,
            sources: task.initial.task.sources,
            query: task.query,
            values,
        },
        rest,
    ))
}

fn first_opening_task<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    known: &Producers,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
    rest.is_empty().then_some(task)
}
fn brakedown_first_tail<F: NTTField + Serialize>(
    profile: &ClassicalProfile,
    task: &FirstOpening<F>,
) -> Option<(Vec<u8>, usize)> {
    brakedown_row_tail_for_role(profile, task, task.role())
}
fn brakedown_row_tail_for_role<F: NTTField + Serialize>(
    profile: &ClassicalProfile,
    task: &FirstOpening<F>,
    role_index: usize,
) -> Option<(Vec<u8>, usize)> {
    if profile.specification().backend != Backend::Brakedown {
        return None;
    }
    let role = profile.specification().roles.get(role_index)?;
    let rows =
        (1usize.checked_shl(u32::try_from(role.left_vars?).ok()?)?).checked_mul(role.width)?;
    let count = rows.checked_mul(role.width)?;
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"mw brakedown row-code v2",
        &encoded(&task.sources.get(task.selected)?.0),
    );
    frame(
        &mut out,
        1,
        b"mw commitment and query",
        &encoded(&(
            &task.sources[task.selected].1,
            &task.query,
            &task.values[task.selected],
        )),
    );
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(&mut out, 4, b"mw random linear test", &descriptor);
    Some((out, count))
}
fn brakedown_first_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    known: &Producers,
) -> Option<(FirstOpening<F>, usize)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
    let (tail, count) = brakedown_first_tail::<F>(profile, &task)?;
    if rest != tail
        || task.query.len() != profile.specification().roles[0].num_vars
        || task.values[0].len() != profile.specification().roles[0].width
    {
        return None;
    }
    Some((task, count))
}

fn brakedown_column_tail(profile: &ClassicalProfile) -> Option<(Vec<u8>, usize, usize)> {
    brakedown_column_tail_for_role(profile, 0)
}
fn brakedown_column_tail_for_role(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<(Vec<u8>, usize, usize)> {
    if profile.version() != 5 || profile.specification().backend != Backend::Brakedown {
        return None;
    }
    let role = profile.specification().roles.get(role_index)?;
    let cols =
        1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(role.left_vars?)?).ok()?)?;
    let blocks = cols
        .div_ceil(role.block_width?)
        .checked_next_power_of_two()?;
    let domain = blocks.checked_mul(profile.specification().blowup)?.max(32);
    if !domain.is_power_of_two() {
        return None;
    }
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"index domain",
        &u64::try_from(domain).ok()?.to_le_bytes(),
    );
    frame(
        &mut out,
        2,
        b"mw atomic column block v5",
        &u64::try_from(role.queries.checked_mul(8)?)
            .ok()?
            .to_le_bytes(),
    );
    Some((out, domain, cols.checked_mul(role.width)?))
}
struct BrakedownColumns<F> {
    opening: FirstOpening<F>,
    random: Vec<F>,
    test: Vec<F>,
    evaluation: Vec<F>,
    domain: usize,
}
fn brakedown_column_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    known: &Producers,
) -> Option<BrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
    let (first_tail, count) = brakedown_first_tail::<F>(profile, &opening)?;
    let mut rest = rest.strip_prefix(first_tail.as_slice())?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw random linear test")?,
        count,
        known,
    )?;
    let (tail, domain, cells) = brakedown_column_tail(profile)?;
    let mut body = message(&mut rest, 1, b"mw linear responses")?;
    let test = vector::<F>(&mut body, cells)?;
    let evaluation = vector::<F>(&mut body, cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(BrakedownColumns {
        opening,
        random,
        test,
        evaluation,
        domain,
    })
}

fn brakedown_completed_body<'a, F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    rest: &'a [u8],
) -> Option<&'a [u8]> {
    brakedown_completed_body_for_role::<F>(profile, rest, 0)
}
fn brakedown_completed_body_for_role<'a, F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    mut rest: &'a [u8],
    role_index: usize,
) -> Option<&'a [u8]> {
    let (columns, _, cells) = brakedown_column_tail_for_role(profile, role_index)?;
    if message(&mut rest, 5, b"mw random linear test")?.len() != 80 {
        return None;
    }
    let mut body = message(&mut rest, 1, b"mw linear responses")?;
    let _test = vector::<F>(&mut body, cells)?;
    let _evaluation = vector::<F>(&mut body, cells)?;
    if !body.is_empty() {
        return None;
    }
    rest = rest.strip_prefix(columns.as_slice())?;
    if message(&mut rest, 3, b"mw atomic column block v5")?.len()
        != profile
            .specification()
            .roles
            .get(role_index)?
            .queries
            .checked_mul(8)?
    {
        return None;
    }
    Some(rest)
}

// Version-five continuation tasks skip completed earlier sampling phases as
// fixed bytes. Their validity is separate; source/claim selection is fixed by
// the trusted primary factor order rather than by those earlier responses.
fn brakedown_factor_row_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    index: usize,
) -> Option<(FirstOpening<F>, usize, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.version() != 5 {
        return None;
    }
    let (mut task, mut rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    if index >= task.sources.len() {
        return None;
    }
    for factor in 0..=index {
        task.selected = factor;
        let (row, count) = brakedown_first_tail(profile, &task)?;
        rest = rest.strip_prefix(row.as_slice())?;
        if factor == index {
            return Some((task, count, rest));
        }
        rest = brakedown_completed_body::<F>(profile, rest)?;
    }
    None
}
fn brakedown_factor_row_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    index: usize,
) -> Option<(FirstOpening<F>, usize)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, count, rest) = brakedown_factor_row_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, index,
    )?;
    rest.is_empty().then_some((task, count))
}

fn brakedown_factor_column_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    index: usize,
) -> Option<BrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, count, mut rest) = brakedown_factor_row_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, index,
    )?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw random linear test")?,
        count,
        before,
    )?;
    let mut body = message(&mut rest, 1, b"mw linear responses")?;
    let (tail, domain, cells) = brakedown_column_tail(profile)?;
    let test = vector::<F>(&mut body, cells)?;
    let evaluation = vector::<F>(&mut body, cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(BrakedownColumns {
        opening,
        random,
        test,
        evaluation,
        domain,
    })
}

fn pcs_child_labels(backend: Backend) -> Option<(&'static [u8], &'static [u8], &'static [u8])> {
    Some(match backend {
        Backend::Polyfrim | Backend::PolyfrimDictionary => (
            b"unmasked packed matrix ordered claims v1",
            b"classical packed matrix child v1",
            b"unmasked ordered matrix PCS",
        ),
        Backend::FragmentedPipfri => (
            b"fragmented ordered claims v1",
            b"fragmented matrix child v1",
            b"unmasked scalar bridge",
        ),
        Backend::FragmentedPipfriVirtual => (
            b"fragmented virtual ordered claims v2",
            b"fragmented virtual child v2",
            b"unmasked shared-query scalar bridge",
        ),
        Backend::Brakedown => return None,
    })
}

fn factor_seed_tail<F, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    opening: &FirstOpening<F>,
    index: usize,
) -> Option<(Vec<u8>, &'static [u8], &'static [u8])>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let (binding, label, context) = pcs_child_labels(profile.specification().backend)?;
    let (query, value) = if matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        parameters
            .normalize_claim(opening.query.clone(), opening.values.get(index)?.clone())
            .ok()?
    } else {
        (opening.query.clone(), opening.values.get(index)?.clone())
    };
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        binding,
        &encoded(&(
            opening.sources.get(index)?.0,
            &opening.sources.get(index)?.1,
            vec![query],
            vec![value],
        )),
    );
    frame(&mut out, 6, label, context);
    frame(&mut out, 2, b"classical child seed", &64u64.to_le_bytes());
    Some((out, label, context))
}
fn pcs_seed_tail<F, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    opening: &FirstOpening<F>,
) -> Option<(Vec<u8>, &'static [u8], &'static [u8])>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    factor_seed_tail(profile, parameters, opening, 0)
}

// Compile any ordered factor's parent seed task. Completed earlier children
// are opaque fixed bytes here: authenticating them is an earlier obligation,
// and their contents cannot select a different inherited source or claim.
fn factor_seed_any<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (mut opening, mut rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    for factor in 0..opening.sources.len() {
        let parameters = if factor % 2 == 1 {
            pp.key
        } else {
            pp.evaluations
        };
        let (tail, label, _) = factor_seed_tail(profile, parameters, &opening, factor)?;
        rest = rest.strip_prefix(tail.as_slice())?;
        if rest.is_empty() {
            opening.selected = factor;
            return Some(opening);
        }
        if message(&mut rest, 3, b"classical child seed")?.len() != 64
            || message(&mut rest, 7, label)?.len() != 64
        {
            return None;
        }
    }
    None
}

fn factor_seed_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    index: usize,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let opening = factor_seed_any::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    (opening.selected == index).then_some(opening)
}

fn pcs_seed_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    known: &Producers,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, known)?;
    let (tail, _, _) = pcs_seed_tail::<F, P>(profile, pp.evaluations, &opening)?;
    (rest == tail).then_some(opening)
}
fn primary_completed_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
) -> Option<&'a [u8]>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (mut opening, mut rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    for factor in 0..opening.sources.len() {
        if profile.specification().backend == Backend::Brakedown {
            opening.selected = factor;
            let (tail, _) = brakedown_first_tail(profile, &opening)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            rest = brakedown_completed_body::<F>(profile, rest)?;
        } else {
            let parameters = if factor % 2 == 1 {
                pp.key
            } else {
                pp.evaluations
            };
            let (tail, label, _) = factor_seed_tail(profile, parameters, &opening, factor)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            if message(&mut rest, 3, b"classical child seed")?.len() != 64
                || message(&mut rest, 7, label)?.len() != 64
            {
                return None;
            }
        }
    }
    Some(rest)
}
#[derive(Clone)]
struct NttRowTask {
    component: usize,
    coefficients: (Digest512, Commitment<Digest512>),
    evaluations: (Digest512, Commitment<Digest512>),
    shape: ntt::Shape,
}
fn ntt_first_row_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
) -> Option<(NttRowTask, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let mut rest =
        primary_completed_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let header = initial_header::<F>(profile)?;
    let mut outer = input.strip_prefix(header.as_slice())?;
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let (co, ev, _, _, _) = recover::<F, EF, P>(pp, setup, statement, primary)?;
    let shape = ntt::Shape::new_canonical::<F, Sha512, P>(pp.coefficients, setup.config.n).ok()?;
    if pp.evaluations.num_vars() != pp.coefficients.num_vars()
        || pp.evaluations.width() != shape.width()
    {
        return None;
    }
    let contexts = (
        pp.coefficients.context().ok()?,
        pp.evaluations.context().ok()?,
    );
    let root = F::get_ntt_table(shape.polynomial_size().ilog2())
        .ok()?
        .root();
    let mut tail = Vec::new();
    frame(&mut tail, 1, b"typed request kind", b"vector");
    frame(&mut tail, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let count = shape.width().checked_mul(shape.row_variables())?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(
        &mut tail,
        4,
        b"packed NTT atomic row points v2",
        &descriptor,
    );
    if co.len() != ev.len() {
        return None;
    }
    for component in 0..co.len() {
        if message(&mut rest, 1, P::NTT_DOMAIN)?
            != encoded(&(
                F::MODULUS_VALUE.to_string(),
                &shape,
                root,
                contexts,
                &co[component],
                &ev[component],
            ))
        {
            return None;
        }
        rest = rest.strip_prefix(tail.as_slice())?;
        let row = NttRowTask {
            component,
            coefficients: (contexts.0, co[component].clone()),
            evaluations: (contexts.1, ev[component].clone()),
            shape: shape.clone(),
        };
        let completed = (|| {
            let last = shape.coefficient_variables().checked_sub(1)?;
            let (ntt, next) = ntt_compression_body::<F, P>(pp, row.clone(), rest, before, last)?;
            let (batch, next) = ntt_batch_body(ntt, next, before)?;
            ntt_completed_openings::<F, P>(profile, pp, batch, next)
        })();
        match completed {
            Some(next) if !next.is_empty() && component + 1 < co.len() => rest = next,
            _ => return Some((row, rest)),
        }
    }
    None
}

fn ntt_first_row_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<NttRowTask>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        ntt_first_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    rest.is_empty().then_some(task)
}
fn rectangular<F: Serialize + DeserializeOwned>(
    input: &mut &[u8],
    rows: usize,
    columns: usize,
) -> Option<Vec<Vec<F>>> {
    *input = input.strip_prefix(encoded(&rows).as_slice())?;
    (0..rows).map(|_| vector::<F>(input, columns)).collect()
}
fn ntt_compression_tail<F: NTTField>(width: usize) -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend((width as u64).to_le_bytes());
    frame(
        &mut out,
        4,
        b"packed NTT coefficient compression",
        &descriptor,
    );
    out
}
struct NttCompression<F> {
    row: NttRowTask,
    points: Vec<Vec<F>>,
    coefficients: Vec<Vec<F>>,
    evaluations: Vec<Vec<F>>,
    compression: Vec<algebra::matrix_weighted::MatrixPair<F>>,
}
fn ntt_compression_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    round: usize,
) -> Option<(NttCompression<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (row, rest) =
        ntt_first_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    ntt_compression_body::<F, P>(pp, row, rest, before, round)
}
fn ntt_compression_body<'a, F, P>(
    pp: &Parameters<'_, P>,
    row: NttRowTask,
    mut rest: &'a [u8],
    before: &Producers,
    round: usize,
) -> Option<(NttCompression<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let k = row.shape.width();
    let rows = row.shape.row_variables();
    if round >= row.shape.coefficient_variables() {
        return None;
    }
    let coins = replay_receipt::<F>(
        message(&mut rest, 5, b"packed NTT atomic row points v2")?,
        k.checked_mul(rows)?,
        before,
    )?;
    let points = if rows == 0 {
        vec![vec![]; k]
    } else {
        coins.chunks_exact(rows).map(<[F]>::to_vec).collect()
    };
    let mut body = message(&mut rest, 1, b"packed NTT folded polynomials")?;
    let coefficients = rectangular::<F>(&mut body, k, row.shape.polynomial_size())?;
    let evaluations = rectangular::<F>(&mut body, k, row.shape.polynomial_size())?;
    if !body.is_empty() {
        return None;
    }
    let table = F::get_ntt_table(row.shape.polynomial_size().ilog2()).ok()?;
    for (co, ev) in coefficients.iter().zip(&evaluations) {
        pp.coefficients.validate_values(co).ok()?;
        pp.evaluations.validate_values(ev).ok()?;
        let mut transformed = co.clone();
        table.transform_slice(&mut transformed);
        if transformed != *ev {
            return None;
        }
    }
    let tail = ntt_compression_tail::<F>(k);
    let mut compression = Vec::new();
    for index in 0..=round {
        rest = rest.strip_prefix(tail.as_slice())?;
        if index == round {
            return Some((
                NttCompression {
                    row,
                    points,
                    coefficients,
                    evaluations,
                    compression,
                },
                rest,
            ));
        }
        let coins = replay_receipt::<F>(
            message(&mut rest, 5, b"packed NTT coefficient compression")?,
            k,
            before,
        )?;
        compression.push(sumcheck::packed::challenge_pair(&coins).ok()?);
    }
    None
}
fn ntt_compression_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    round: usize,
) -> Option<NttCompression<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        ntt_compression_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, round)?;
    rest.is_empty().then_some(task)
}

struct NttBatchTask<F> {
    evaluation: bool,
    ntt: NttCompression<F>,
    queries: Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
    coefficient_values: Vec<Vec<F>>,
    evaluation_values: Vec<Vec<F>>,
}
impl<F> NttBatchTask<F> {
    fn source(&self) -> &(Digest512, Commitment<Digest512>) {
        if self.evaluation {
            &self.ntt.row.evaluations
        } else {
            &self.ntt.row.coefficients
        }
    }
    fn values(&self) -> &Vec<Vec<F>> {
        if self.evaluation {
            &self.evaluation_values
        } else {
            &self.coefficient_values
        }
    }
    fn parameters<'a, P>(&self, pp: &Parameters<'a, P>) -> &'a P {
        if self.evaluation {
            pp.evaluations
        } else {
            pp.coefficients
        }
    }
}
fn ntt_batch_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
) -> Option<(NttBatchTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (row, _) = ntt_first_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let last = row.shape.coefficient_variables().checked_sub(1)?;
    let (ntt, rest) =
        ntt_compression_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, last)?;
    ntt_batch_body(ntt, rest, before)
}
fn ntt_batch_body<'a, F>(
    mut ntt: NttCompression<F>,
    mut rest: &'a [u8],
    before: &Producers,
) -> Option<(NttBatchTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
{
    let k = ntt.row.shape.width();
    let coins = replay_receipt::<F>(
        message(&mut rest, 5, b"packed NTT coefficient compression")?,
        k,
        before,
    )?;
    ntt.compression
        .push(sumcheck::packed::challenge_pair(&coins).ok()?);
    let queries = ntt
        .points
        .iter()
        .map(|point| {
            let mut query = ntt.compression.clone();
            for &r in point {
                let diagonal = |value| {
                    let mut values = vec![F::zero(); k.checked_mul(k)?];
                    for i in 0..k {
                        values[i * k + i] = value;
                    }
                    algebra::matrix_weighted::Matrix::new(k, values).ok()
                };
                query.push(algebra::matrix_weighted::MatrixPair {
                    zero: diagonal(F::one() - r)?,
                    one: diagonal(r)?,
                });
            }
            Some(query)
        })
        .collect::<Option<Vec<_>>>()?;
    let compress = |rows: &[Vec<F>]| {
        rows.iter()
            .map(|row| {
                PackedTable::new(ntt.row.shape.coefficient_variables(), k, row.clone())
                    .ok()?
                    .evaluate(&ntt.compression)
                    .ok()
            })
            .collect::<Option<Vec<_>>>()
    };
    let coefficient_values = compress(&ntt.coefficients)?;
    let evaluation_values = compress(&ntt.evaluations)?;
    Some((
        NttBatchTask {
            evaluation: false,
            ntt,
            queries,
            coefficient_values,
            evaluation_values,
        },
        rest,
    ))
}
fn ntt_batch_seed_tail<F, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    task: &NttBatchTask<F>,
) -> Option<Vec<u8>>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let (binding, label, context) = pcs_child_labels(profile.specification().backend)?;
    let mut queries = task.queries.clone();
    let mut values = task.values().clone();
    if matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        for (query, value) in queries.iter_mut().zip(&mut values) {
            (*query, *value) = parameters
                .normalize_claim(query.clone(), value.clone())
                .ok()?;
        }
    }
    let (source_context, root) = task.source();
    let mut tail = Vec::new();
    frame(
        &mut tail,
        1,
        binding,
        &encoded(&(source_context, root, &queries, &values)),
    );
    frame(&mut tail, 6, label, context);
    frame(&mut tail, 2, b"classical child seed", &64u64.to_le_bytes());
    Some(tail)
}
fn ntt_completed_openings<'a, F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    mut task: NttBatchTask<F>,
    mut rest: &'a [u8],
) -> Option<&'a [u8]>
where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    for evaluation in [false, true] {
        task.evaluation = evaluation;
        if profile.specification().backend != Backend::Brakedown {
            let tail = ntt_batch_seed_tail(profile, task.parameters(pp), &task)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            let (_, label, _) = pcs_child_labels(profile.specification().backend)?;
            if message(&mut rest, 3, b"classical child seed")?.len() != 64
                || message(&mut rest, 7, label)?.len() != 64
            {
                return None;
            }
        } else {
            if profile.version() != 5 {
                return None;
            }
            let (context, root) = task.source();
            if message(&mut rest, 1, b"mw batched row-code v1")?
                != encoded(&(context, root, &task.queries, task.values()))
            {
                return None;
            }
            let role = &profile.specification().roles[0];
            let left = role.left_vars?;
            let count = 1usize
                .checked_shl(u32::try_from(left).ok()?)?
                .checked_mul(role.width)?
                .checked_mul(role.width)?;
            if message(&mut rest, 1, b"typed request kind")? != b"vector"
                || message(&mut rest, 1, b"field challenge kind")? != b"prime vector"
            {
                return None;
            }
            let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
            let mut descriptor = p.to_le_bytes().to_vec();
            descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
            if message(&mut rest, 4, b"mw batch random linear test")? != descriptor
                || message(&mut rest, 5, b"mw batch random linear test")?.len() != 80
            {
                return None;
            }
            let mut representatives: Vec<usize> = Vec::new();
            for (i, query) in task.queries.iter().enumerate() {
                if query.len() < left {
                    return None;
                }
                if !representatives
                    .iter()
                    .any(|&j| task.queries[j][..left] == query[..left])
                {
                    representatives.push(i);
                }
            }
            let (columns, _, cells) = brakedown_column_tail(profile)?;
            let mut body = message(&mut rest, 1, b"mw batch linear responses")?;
            vector::<F>(&mut body, cells)?;
            rectangular::<F>(&mut body, representatives.len(), cells)?;
            if !body.is_empty() {
                return None;
            }
            rest = rest.strip_prefix(columns.as_slice())?;
            if message(&mut rest, 3, b"mw atomic column block v5")?.len()
                != role.queries.checked_mul(8)?
            {
                return None;
            }
        }
    }
    Some(rest)
}

fn ntt_batch_seed_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<NttBatchTask<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (mut task, mut rest) =
        ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let (_, label, _) = pcs_child_labels(profile.specification().backend)?;
    for evaluation in [false, true] {
        task.evaluation = evaluation;
        let tail = ntt_batch_seed_tail(profile, task.parameters(pp), &task)?;
        rest = rest.strip_prefix(tail.as_slice())?;
        if rest.is_empty() {
            return Some(task);
        }
        // Earlier completion bytes determine framing only. Their presence is
        // not evidence that the preceding PCS opening was accepted.
        if message(&mut rest, 3, b"classical child seed")?.len() != 64
            || message(&mut rest, 7, label)?.len() != 64
        {
            return None;
        }
    }
    None
}
fn ntt_brakedown_batch_row_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
) -> Option<(NttBatchTask<F>, usize, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.specification().backend != Backend::Brakedown || profile.version() != 5 {
        return None;
    }
    let (mut task, mut rest) =
        ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let role = &profile.specification().roles[0];
    let count = (1usize.checked_shl(u32::try_from(role.left_vars?).ok()?)?)
        .checked_mul(role.width)?
        .checked_mul(role.width)?;
    let mut tail = Vec::new();
    frame(&mut tail, 1, b"typed request kind", b"vector");
    frame(&mut tail, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(&mut tail, 4, b"mw batch random linear test", &descriptor);
    for evaluation in [false, true] {
        task.evaluation = evaluation;
        let (context, root) = task.source();
        if message(&mut rest, 1, b"mw batched row-code v1")?
            != encoded(&(context, root, &task.queries, task.values()))
        {
            return None;
        }
        rest = rest.strip_prefix(tail.as_slice())?;
        // Only a fully framed earlier column output permits advancing to
        // the evaluation source. Earlier response truth is a separate obligation.
        if evaluation {
            return Some((task, count, rest));
        }
        let completed = (|| {
            let mut next = rest;
            if message(&mut next, 5, b"mw batch random linear test")?.len() != 80 {
                return None;
            }
            let left = role.left_vars?;
            let mut representatives: Vec<usize> = Vec::new();
            for (i, query) in task.queries.iter().enumerate() {
                if query.len() < left {
                    return None;
                }
                if !representatives
                    .iter()
                    .any(|&j| task.queries[j][..left] == query[..left])
                {
                    representatives.push(i);
                }
            }
            let (columns, _, cells) = brakedown_column_tail(profile)?;
            let mut body = message(&mut next, 1, b"mw batch linear responses")?;
            vector::<F>(&mut body, cells)?;
            rectangular::<F>(&mut body, representatives.len(), cells)?;
            if !body.is_empty() {
                return None;
            }
            next = next.strip_prefix(columns.as_slice())?;
            if message(&mut next, 3, b"mw atomic column block v5")?.len()
                != role.queries.checked_mul(8)?
            {
                return None;
            }
            Some(next)
        })();
        match completed {
            Some(next) if !next.is_empty() => rest = next,
            _ => return Some((task, count, rest)),
        }
    }
    None
}

fn ntt_brakedown_batch_row_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<(NttBatchTask<F>, usize)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, count, rest) =
        ntt_brakedown_batch_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    rest.is_empty().then_some((task, count))
}
struct NttBrakedownColumns<F> {
    batch: NttBatchTask<F>,
    random: Vec<F>,
    test: Vec<F>,
    evaluations: Vec<Vec<F>>,
    representatives: Vec<usize>,
    domain: usize,
}
fn ntt_brakedown_batch_column_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<NttBrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (batch, count, mut rest) =
        ntt_brakedown_batch_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw batch random linear test")?,
        count,
        before,
    )?;
    let left = profile.specification().roles[0].left_vars?;
    if batch.queries.iter().any(|query| query.len() < left) {
        return None;
    }
    let mut representatives: Vec<usize> = Vec::new();
    for (i, query) in batch.queries.iter().enumerate() {
        if !representatives
            .iter()
            .any(|&j| batch.queries[j][..left] == query[..left])
        {
            representatives.push(i);
        }
    }
    let (tail, domain, cells) = brakedown_column_tail(profile)?;
    let mut body = message(&mut rest, 1, b"mw batch linear responses")?;
    let test = vector::<F>(&mut body, cells)?;
    let evaluations = rectangular::<F>(&mut body, representatives.len(), cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(NttBrakedownColumns {
        batch,
        random,
        test,
        evaluations,
        representatives,
        domain,
    })
}

fn ntt_completed_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
) -> Option<&'a [u8]>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (batch, rest) = ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let digits = setup
        .config
        .decomposition::<F>()
        .ok()?
        .num_digits::<F>()
        .ok()?;
    if batch.ntt.row.component.checked_add(1)? != digits.checked_mul(2)?.checked_add(1)? {
        return None;
    }
    ntt_completed_openings::<F, P>(profile, pp, batch, rest)
}
struct DecompositionLinear<F> {
    sources: Vec<(Digest512, Commitment<Digest512>)>,
    relations: Vec<crate::packed_linear::Relation<F>>,
    query: Vec<algebra::matrix_weighted::MatrixPair<F>>,
}
fn decomposition_linear_bindings<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    coefficients: &[Commitment<Digest512>],
    inputs: &[Commitment<Digest512>],
    borrows: Vec<Commitment<Digest512>>,
) -> Option<(DecompositionLinear<F>, Vec<u8>)>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    decomposition_linear_bindings_at::<F, EF, P>(pp, setup, coefficients, inputs, borrows, 0)
}
fn decomposition_linear_bindings_at<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    coefficients: &[Commitment<Digest512>],
    inputs: &[Commitment<Digest512>],
    borrows: Vec<Commitment<Digest512>>,
    half: usize,
) -> Option<(DecompositionLinear<F>, Vec<u8>)>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let cfg = setup.config.decomposition::<F>().ok()?;
    let d = cfg.num_digits::<F>().ok()?;
    let width = pp.inputs.width();
    let vars = pp.inputs.num_vars();
    let scalar_vars = vars.checked_add(width.checked_ilog2()? as usize)?;
    let capacity = 1usize.checked_shl(u32::try_from(scalar_vars).ok()?)?;
    if half >= 2
        || inputs.len() != 2
        || coefficients.len() != 2 * d + 1
        || borrows.len() != d + 1
        || vars == 0
        || !width.is_power_of_two()
        || EF::D == 0
        || width < EF::D
        || cfg.logical_len() > capacity
        || pp.helper.num_vars() != scalar_vars
        || (pp.helper.width() != width && pp.helper.width() != EF::D)
        || pp.borrows.width() != width
        || pp.borrows.num_vars() != vars
        || pp.coefficients.width() != width
        || pp.coefficients.num_vars() != vars
    {
        return None;
    }
    let mut sources = vec![(pp.inputs.context().ok()?, inputs[half].clone())];
    sources.extend(
        coefficients[half * d..(half + 1) * d]
            .iter()
            .map(|root| Some((pp.coefficients.context().ok()?, root.clone())))
            .collect::<Option<Vec<_>>>()?,
    );
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"packed canonical shared radix decomposition v1",
        &encoded(&()),
    );
    frame(
        &mut out,
        1,
        b"packed canonical backend radix decomposition v1",
        &encoded(&(
            &cfg,
            F::MODULUS_VALUE.to_string(),
            EF::D,
            pp.borrows.context().ok()?,
            pp.helper.context().ok()?,
            &sources,
        )),
    );
    frame(
        &mut out,
        1,
        b"packed canonical decomposition borrow roots",
        &encoded(&borrows),
    );
    sources.extend(
        borrows
            .into_iter()
            .map(|root| Some((pp.borrows.context().ok()?, root)))
            .collect::<Option<Vec<_>>>()?,
    );
    let mut power = F::one();
    let radix = F::from(cfg.radix().ok()?);
    let mut reconstruction = vec![(-F::one(), 0)];
    for i in 0..d {
        reconstruction.push((power, i + 1));
        power *= radix;
    }
    let mut relations = vec![
        crate::packed_linear::Relation {
            terms: reconstruction,
        },
        crate::packed_linear::Relation {
            terms: vec![(F::one(), d + 1)],
        },
        crate::packed_linear::Relation {
            terms: vec![(F::one(), 2 * d + 1)],
        },
    ];
    for relation in &mut relations {
        let coefficients = pp
            .inputs
            .normalize_values(relation.terms.iter().map(|(a, _)| *a).collect());
        if coefficients.len() != relation.terms.len() {
            return None;
        }
        for ((a, _), coefficient) in relation.terms.iter_mut().zip(coefficients) {
            *a = coefficient;
        }
    }
    frame(
        &mut out,
        1,
        P::LINEAR_DOMAIN,
        &encoded(&(&sources, &relations)),
    );
    Some((
        DecompositionLinear {
            sources,
            relations,
            query: Vec::new(),
        },
        out,
    ))
}
fn decomposition_linear_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    round: usize,
) -> Option<(DecompositionLinear<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let rest = ntt_completed_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    let header = initial_header::<F>(profile)?;
    let mut outer = input.strip_prefix(header.as_slice())?;
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let (co, _, inputs, _, _) = recover::<F, EF, P>(pp, setup, statement, primary)?;
    decomposition_linear_body::<F, EF, P>(pp, setup, &co, &inputs, rest, before, round, 0)
}
fn decomposition_linear_body<'a, F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    co: &[Commitment<Digest512>],
    inputs: &[Commitment<Digest512>],
    rest: &'a [u8],
    before: &Producers,
    round: usize,
    half: usize,
) -> Option<(DecompositionLinear<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let mut body = rest;
    if message(
        &mut body,
        1,
        b"packed canonical shared radix decomposition v1",
    )? != encoded(&())
    {
        return None;
    }
    // The first binding has a trusted exact length; borrow roots alone are
    // prover supplied, and their count is checked before allocation.
    message(
        &mut body,
        1,
        b"packed canonical backend radix decomposition v1",
    )?;
    let mut roots = message(&mut body, 1, b"packed canonical decomposition borrow roots")?;
    let d = setup
        .config
        .decomposition::<F>()
        .ok()?
        .num_digits::<F>()
        .ok()?;
    let borrows = vector::<Commitment<Digest512>>(&mut roots, d + 1)?;
    if !roots.is_empty() || round >= pp.inputs.num_vars() {
        return None;
    }
    let (mut task, binding) =
        decomposition_linear_bindings_at::<F, EF, P>(pp, setup, co, inputs, borrows, half)?;
    let mut remaining = rest.strip_prefix(binding.as_slice())?;
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend((pp.inputs.width() as u64).to_le_bytes());
    for index in 0..=round {
        if message(&mut remaining, 1, b"typed request kind")? != b"vector"
            || message(&mut remaining, 1, b"field challenge kind")? != b"prime vector"
            || message(&mut remaining, 4, b"packed linear independent challenges")? != descriptor
        {
            return None;
        }
        if index == round {
            return Some((task, remaining));
        }
        let coins = replay_receipt::<F>(
            message(&mut remaining, 5, b"packed linear independent challenges")?,
            pp.inputs.width(),
            before,
        )?;
        task.query
            .push(sumcheck::packed::challenge_pair(&coins).ok()?);
    }
    None
}
fn second_decomposition_linear_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(DecompositionLinear<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rest) = decomposition_lookup_source_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, true,
    )?;
    let header = initial_header::<F>(profile)?;
    let mut outer = input.strip_prefix(header.as_slice())?;
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let (co, _, inputs, _, _) = recover::<F, EF, P>(pp, setup, statement, primary)?;
    decomposition_linear_body::<F, EF, P>(pp, setup, &co, &inputs, rest, before, round, 1)
}
fn decomposition_linear_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    round: usize,
) -> Option<DecompositionLinear<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = decomposition_linear_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, round,
    )?;
    rest.is_empty().then_some(task)
}
fn vector_length(input: &mut &[u8], expected: usize) -> Option<usize> {
    let (length, used): (usize, usize) =
        bincode::serde::decode_from_slice(input, bincode::config::standard()).ok()?;
    if length != expected || encoded(&length) != input.get(..used)? {
        return None;
    }
    *input = input.get(used..)?;
    Some(length)
}
fn decomposition_source_parameters<'a, P>(
    pp: &Parameters<'a, P>,
    digits: usize,
    index: usize,
) -> &'a P {
    if index == 0 {
        pp.inputs
    } else if index <= digits {
        pp.coefficients
    } else {
        pp.borrows
    }
}
fn decomposition_opening_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    completed: bool,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let last = pp.inputs.num_vars().checked_sub(1)?;
    let (linear, rest) = decomposition_linear_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, last,
    )?;
    decomposition_opening_body::<F, P>(
        profile,
        pp,
        setup,
        linear,
        rest,
        before,
        completed,
        OpeningFamily::Decomposition,
    )
}
fn decomposition_opening_body<'a, F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    mut linear: DecompositionLinear<F>,
    mut rest: &'a [u8],
    before: &Producers,
    completed: bool,
    family: OpeningFamily,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let coins = replay_receipt::<F>(
        message(&mut rest, 5, b"packed linear independent challenges")?,
        pp.inputs.width(),
        before,
    )?;
    linear
        .query
        .push(sumcheck::packed::challenge_pair(&coins).ok()?);
    let digits = setup
        .config
        .decomposition::<F>()
        .ok()?
        .num_digits::<F>()
        .ok()?;
    let relations = linear.relations;
    let mut opening = FirstOpening {
        family,
        selected: 0,
        sources: linear.sources,
        query: linear.query,
        values: Vec::new(),
    };
    for index in 0..opening.sources.len() {
        opening.selected = index;
        let parameters = decomposition_source_parameters(pp, digits, index);
        let (query, _) = parameters
            .normalize_claim(opening.query.clone(), vec![F::zero(); pp.inputs.width()])
            .ok()?;
        let source = &opening.sources[index];
        let mut body;
        if profile.specification().backend == Backend::Brakedown {
            if message(&mut rest, 1, b"mw brakedown row-code v2")? != encoded(&source.0) {
                return None;
            }
            body = message(&mut rest, 1, b"mw commitment and query")?;
            body = body.strip_prefix(encoded(&(&source.1, &query)).as_slice())?;
        } else {
            let (binding, _, _) = pcs_child_labels(profile.specification().backend)?;
            body = message(&mut rest, 1, binding)?;
            body =
                body.strip_prefix(encoded(&(source.0, &source.1, vec![query.clone()])).as_slice())?;
            // Exactly one ordered matrix claim per linear source.
            let count = vector_length(&mut body, 1)?;
            if count != 1 {
                return None;
            }
        }
        let value = vector::<F>(&mut body, pp.inputs.width())?;
        parameters.validate_values(&value).ok()?;
        if !body.is_empty() {
            return None;
        }
        let (normalized_query, normalized_value) =
            parameters.normalize_claim(query, value.clone()).ok()?;
        if encoded(&normalized_value) != encoded(&value) {
            return None;
        }
        opening.query = normalized_query;
        opening.values.push(value);
        if profile.specification().backend == Backend::Brakedown {
            let (tail, _) = brakedown_first_tail(profile, &opening)?;
            // Metadata has already been checked; only its exact request tail remains.
            let mut metadata = tail.as_slice();
            message(&mut metadata, 1, b"mw brakedown row-code v2")?;
            message(&mut metadata, 1, b"mw commitment and query")?;
            rest = rest.strip_prefix(metadata)?;
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if completed {
                rest = brakedown_completed_body::<F>(profile, rest)?;
                continue;
            }
            match brakedown_completed_body::<F>(profile, rest) {
                Some(next) if !next.is_empty() && index + 1 < opening.sources.len() => rest = next,
                _ => return Some((opening, rest)),
            }
        } else {
            let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
            if message(&mut rest, 6, label)? != context
                || message(&mut rest, 2, b"classical child seed")? != 64u64.to_le_bytes()
            {
                return None;
            }
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            // Fixed earlier completion bytes establish ordering, not acceptance.
            if message(&mut rest, 3, b"classical child seed")?.len() != 64
                || message(&mut rest, 7, label)?.len() != 64
            {
                return None;
            }
        }
    }
    if !completed {
        return None;
    }
    for relation in &relations {
        for lane in 0..pp.inputs.width() {
            let residual = relation
                .terms
                .iter()
                .try_fold(F::zero(), |sum, (a, index)| {
                    Some(sum + *a * *opening.values.get(*index)?.get(lane)?)
                })?;
            if residual != F::zero() {
                return None;
            }
        }
    }
    Some((opening, rest))
}
fn second_decomposition_opening_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    completed: bool,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (linear, rest) = second_decomposition_linear_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        pp.inputs.num_vars().checked_sub(1)?,
    )?;
    decomposition_opening_body::<F, P>(
        profile,
        pp,
        setup,
        linear,
        rest,
        before,
        completed,
        OpeningFamily::SecondDecomposition,
    )
}
fn decomposition_opening_query_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if half == 0 {
        return decomposition_opening_query::<F, EF, P>(
            profile, pp, setup, statement, input, before,
        );
    }
    if half != 1 {
        return None;
    }
    let (opening, rest) = second_decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, false,
    )?;
    rest.is_empty().then_some(opening)
}

fn decomposition_opening_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) = decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, false,
    )?;
    rest.is_empty().then_some(opening)
}
fn decomposition_brakedown_column_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<BrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.specification().backend != Backend::Brakedown || profile.version() != 5 {
        return None;
    }
    let (opening, rest) = decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, false,
    )?;
    decomposition_columns_body::<F>(profile, opening, rest, before)
}
fn decomposition_columns_body<F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    opening: FirstOpening<F>,
    mut rest: &[u8],
    before: &Producers,
) -> Option<BrakedownColumns<F>> {
    let (_, count) = brakedown_first_tail(profile, &opening)?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw random linear test")?,
        count,
        before,
    )?;
    let mut body = message(&mut rest, 1, b"mw linear responses")?;
    let (tail, domain, cells) = brakedown_column_tail(profile)?;
    let test = vector::<F>(&mut body, cells)?;
    let evaluation = vector::<F>(&mut body, cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(BrakedownColumns {
        opening,
        random,
        test,
        evaluation,
        domain,
    })
}
fn decomposition_column_query_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<BrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if half == 0 {
        return decomposition_brakedown_column_query::<F, EF, P>(
            profile, pp, setup, statement, input, before,
        );
    }
    if half != 1 || profile.specification().backend != Backend::Brakedown || profile.version() != 5
    {
        return None;
    }
    let (opening, rest) = second_decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, false,
    )?;
    decomposition_columns_body::<F>(profile, opening, rest, before)
}

struct DecompositionLookup<F: algebra::Field> {
    sources: Vec<(Digest512, Commitment<Digest512>)>,
    requests: Vec<crate::packed_extension_lookup::deferred::Request<F>>,
    multiplicities: Vec<Vec<F>>,
}
fn decomposition_lookup_bindings<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    linear: &FirstOpening<F>,
) -> Option<(DecompositionLookup<F>, Vec<u8>)>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let cfg = setup.config.decomposition::<F>().ok()?;
    let d = cfg.num_digits::<F>().ok()?;
    if !matches!(
        linear.family,
        OpeningFamily::Decomposition | OpeningFamily::SecondDecomposition
    ) || linear.sources.len() != 2 * d + 2
    {
        return None;
    }
    let sources = linear.sources.get(1..)?.to_vec();
    let requests = (0..d)
        .map(|limb| {
            Some(crate::packed_extension_lookup::deferred::Request {
                config: crate::packed_tuple_lookup::Config::new(
                    cfg.logical_len(),
                    cfg.comparison_table::<F>(limb)
                        .ok()?
                        .into_iter()
                        .map(|row| pp.coefficients.normalize_values(row))
                        .collect(),
                    cfg.repetitions(),
                )
                .ok()?,
                source_slots: vec![limb, d + limb, d + limb + 1],
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"canonical shared-query extension lookups v1",
        &encoded(&requests),
    );
    for request in &requests {
        let local = request
            .source_slots
            .iter()
            .map(|&index| sources.get(index).cloned())
            .collect::<Option<Vec<_>>>()?;
        frame(
            &mut out,
            1,
            b"packed canonical backend extension tuple lookup v1",
            &encoded(&(&request.config, EF::D, pp.helper.context().ok()?, local)),
        );
    }
    frame(&mut out, 1, P::REGISTRY_DOMAIN, &encoded(&sources));
    Some((
        DecompositionLookup {
            sources,
            requests,
            multiplicities: Vec::new(),
        },
        out,
    ))
}
fn decomposition_lookup_seed_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
) -> Option<(DecompositionLookup<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (linear, rest) = decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, true,
    )?;
    decomposition_lookup_seed_body::<F, EF, P>(pp, setup, &linear, rest)
}
fn decomposition_lookup_seed_body<'a, F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    linear: &FirstOpening<F>,
    rest: &'a [u8],
) -> Option<(DecompositionLookup<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (mut lookup, binding) = decomposition_lookup_bindings::<F, EF, P>(pp, setup, linear)?;
    let mut rest = rest.strip_prefix(binding.as_slice())?;
    let mut body = message(&mut rest, 1, b"shared lookup grouped multiplicities")?;
    vector_length(&mut body, lookup.requests.len())?;
    for request in &lookup.requests {
        let values = vector::<F>(&mut body, request.config.table().len())?;
        pp.coefficients.validate_values(&values).ok()?;
        lookup.multiplicities.push(values);
    }
    if !body.is_empty() {
        return None;
    }
    let flat: Vec<_> = lookup.multiplicities.iter().flatten().copied().collect();
    if message(&mut rest, 1, b"extension lookup multiplicities")? != encoded(&flat)
        || message(&mut rest, 6, b"classical extension lookup child v1")?
            != b"packed extension tuple lookup"
        || message(&mut rest, 2, b"classical child seed")? != 64u64.to_le_bytes()
    {
        return None;
    }
    Some((lookup, rest))
}
fn second_decomposition_lookup_seed_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DecompositionLookup<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (linear, rest) = second_decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, true,
    )?;
    decomposition_lookup_seed_body::<F, EF, P>(pp, setup, &linear, rest)
}

fn decomposition_lookup_seed_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
) -> Option<DecompositionLookup<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (lookup, rest) =
        decomposition_lookup_seed_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    rest.is_empty().then_some(lookup)
}
fn decomposition_lookup_parent_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(LookupTerminal<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rest) =
        decomposition_lookup_seed_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)?;
    lookup_parent_finish::<F, EF, P>(profile, pp, setup, statement, input, before, views, rest)
}
fn lookup_parent_finish<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    mut rest: &'a [u8],
) -> Option<(LookupTerminal<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let seed_input = input.get(..input.len().checked_sub(rest.len())?)?;
    let seed: [u8; 64] = message(&mut rest, 3, b"classical child seed")?
        .try_into()
        .ok()?;
    if shake64(seed_input) != seed || before.get(&seed)?.as_slice() != seed_input {
        return None;
    }
    let finish: [u8; 64] = message(&mut rest, 7, b"classical extension lookup child v1")?
        .try_into()
        .ok()?;
    let child_input = before.get(&finish)?;
    if shake64(child_input) != finish {
        return None;
    }
    let child_before = views.get(child_input.as_slice())?;
    let child = typed_child_prefix::<F, EF>(profile, child_input, child_before)?;
    if child.parent_input != seed_input {
        return None;
    }
    let terminal = decomposition_lookup_terminal_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child_input,
        child_before,
        views,
    )?;
    Some((terminal, rest))
}
fn second_decomposition_lookup_parent_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(LookupTerminal<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rest) = second_decomposition_lookup_seed_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    lookup_parent_finish::<F, EF, P>(profile, pp, setup, statement, input, before, views, rest)
}

fn decomposition_lookup_parent_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<(LookupTerminal<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    match half {
        0 => decomposition_lookup_parent_prefix::<F, EF, P>(
            profile, pp, setup, statement, input, before, views,
        ),
        1 => second_decomposition_lookup_parent_prefix::<F, EF, P>(
            profile, pp, setup, statement, input, before, views,
        ),
        _ => None,
    }
}
struct AccumulatorTask<F> {
    shape: crate::packed_accumulator::Shape,
    initial: Vec<F>,
    final_acc: Vec<F>,
    sources: Vec<(Digest512, Commitment<Digest512>)>,
    base: Vec<algebra::matrix_weighted::MatrixPair<F>>,
}
fn accumulator_parameters<'a, P>(pp: &Parameters<'a, P>, slot: usize) -> Option<&'a P> {
    match slot {
        0..=3 => pp.accumulators.get(slot).copied(),
        4 => Some(pp.coefficients),
        5..=6 => Some(pp.inputs),
        _ => None,
    }
}
fn accumulator_binding<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
) -> Option<(AccumulatorTask<F>, Vec<u8>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let header = initial_header::<F>(profile)?;
    let mut outer = input.strip_prefix(header.as_slice())?;
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let (co, _, inputs, accumulators, endpoint) =
        recover::<F, EF, P>(pp, setup, statement, primary)?;
    let cfg = &setup.config;
    let shape = crate::packed_accumulator::Shape::new(cfg.n, cfg.lwe).ok()?;
    let width = pp.accumulators[0].width();
    if !width.is_power_of_two() || width > cfg.n {
        return None;
    }
    let variables = (cfg.n / width).ilog2() as usize + shape.padded_rounds().ilog2() as usize + 1;
    let role = profile.specification().roles.first()?;
    if role.width != width || role.num_vars != variables {
        return None;
    }
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    if u128::try_from(width).ok()?.checked_mul(2)? >= p {
        return None;
    }
    let (_, initial) = public_inputs(cfg, &statement.borrowed()).ok()?;
    let initial = pp.accumulators[0].normalize_values(initial);
    let final_acc = pp.accumulators[0].normalize_values(endpoint);
    let mut roots = accumulators;
    roots.push(co.last()?.clone());
    roots.extend(inputs);
    let sources = roots
        .into_iter()
        .enumerate()
        .map(|(slot, root)| {
            let parameters = accumulator_parameters(pp, slot)?;
            if parameters.width() != width || parameters.num_vars() != variables {
                return None;
            }
            Some((parameters.context().ok()?, root))
        })
        .collect::<Option<Vec<_>>>()?;
    if sources.len() != 7 || initial.len() != 2 * cfg.n || final_acc.len() != initial.len() {
        return None;
    }
    let mut binding = Vec::new();
    frame(
        &mut binding,
        1,
        P::ACCUMULATOR_DOMAIN,
        &encoded(&(&shape, &initial, &final_acc, &sources)),
    );
    Some((
        AccumulatorTask {
            shape,
            initial,
            final_acc,
            sources,
            base: Vec::new(),
        },
        binding,
    ))
}
fn accumulator_lane_tail<F: NTTField>(width: usize) -> Option<Vec<u8>> {
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(width).ok()?.to_le_bytes());
    let mut tail = Vec::new();
    frame(&mut tail, 1, b"typed request kind", b"vector");
    frame(&mut tail, 1, b"field challenge kind", b"prime vector");
    frame(
        &mut tail,
        4,
        b"accumulator independent lane challenges",
        &descriptor,
    );
    Some(tail)
}
fn accumulator_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(AccumulatorTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rest) = decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, true, 1,
    )?;
    let (mut task, binding) =
        accumulator_binding::<F, EF, P>(profile, pp, setup, statement, input)?;
    let width = pp.accumulators[0].width();
    if round >= pp.accumulators[0].num_vars() {
        return None;
    }
    let mut rest = rest.strip_prefix(binding.as_slice())?;
    let tail = accumulator_lane_tail::<F>(width)?;
    for current in 0..=round {
        rest = rest.strip_prefix(tail.as_slice())?;
        if current == round {
            return Some((task, rest));
        }
        let coins = replay_receipt::<F>(
            message(&mut rest, 5, b"accumulator independent lane challenges")?,
            width,
            before,
        )?;
        task.base
            .push(sumcheck::packed::challenge_pair(&coins).ok()?);
    }
    None
}
fn accumulator_selector<F: NTTField>(
    width: usize,
    bit: usize,
    matrix: algebra::matrix_weighted::Matrix<F>,
) -> Option<algebra::matrix_weighted::MatrixPair<F>> {
    use algebra::matrix_weighted::{Matrix, MatrixPair};
    let zero = Matrix::new(width, vec![F::zero(); width.checked_mul(width)?]).ok()?;
    match bit {
        0 => Some(MatrixPair {
            zero: matrix,
            one: zero,
        }),
        1 => Some(MatrixPair { zero, one: matrix }),
        _ => None,
    }
}
fn accumulator_query_maps<F: NTTField>(
    task: &AccumulatorTask<F>,
    width: usize,
) -> Option<Vec<Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>>> {
    use algebra::matrix_weighted::{Matrix, MatrixPair};
    if !width.is_power_of_two() || width > task.shape.polynomial_size() {
        return None;
    }
    let coefficient = (task.shape.polynomial_size() / width).ilog2() as usize;
    let row_bits = task.shape.padded_rounds().ilog2() as usize;
    let base = &task.base;
    if base.len() != coefficient + row_bits + 1 {
        return None;
    }
    let identity = Matrix::identity(width).ok()?;
    let mut queries = vec![vec![base.to_vec()]; 7];
    let select = |row: usize| -> Option<Vec<MatrixPair<F>>> {
        let mut query = base.to_vec();
        for bit in 0..row_bits {
            query[coefficient + bit] =
                accumulator_selector(width, (row >> bit) & 1, identity.clone())?;
        }
        Some(query)
    };
    queries[0].push(select(0)?);
    if row_bits == 0 {
        queries[0].push(base.to_vec());
    } else {
        let mut lower = identity.clone();
        for bit in 0..row_bits {
            let mut query = base.to_vec();
            for low in 0..bit {
                query[coefficient + low] = accumulator_selector(width, 0, identity.clone())?;
            }
            query[coefficient + bit] =
                accumulator_selector(width, 1, base[coefficient + bit].zero.mul(&lower).ok()?)?;
            queries[0].push(query);
            lower = base[coefficient + bit].one.mul(&lower).ok()?;
        }
        let mut wrap = base.to_vec();
        wrap[coefficient] = accumulator_selector(width, 0, lower)?;
        for bit in 1..row_bits {
            wrap[coefficient + bit] = accumulator_selector(width, 0, identity.clone())?;
        }
        queries[0].push(wrap);
    }
    queries[3].push(select(task.shape.rounds().checked_sub(1)?)?);
    let half = base.last()?;
    let sum = Matrix::new(
        width,
        half.zero
            .values()
            .iter()
            .zip(half.one.values())
            .map(|(&a, &b)| a + b)
            .collect(),
    )
    .ok()?;
    for bit in 0..2 {
        let mut query = base.to_vec();
        *query.last_mut()? = accumulator_selector(width, bit, sum.clone())?;
        queries[2].push(query);
    }
    let counts = task.shape.opening_counts(width).ok()?;
    if queries.iter().zip(counts).any(|(q, n)| q.len() != n) {
        return None;
    }
    Some(queries)
}
fn accumulator_endpoint_projections<F: NTTField>(
    task: &AccumulatorTask<F>,
    width: usize,
) -> Option<(Vec<F>, Vec<F>, Vec<F>, Vec<F>)> {
    use algebra::matrix_weighted::{Matrix, PackedTable};
    let n = task.shape.polynomial_size();
    if !width.is_power_of_two()
        || width > n
        || task.initial.len() != 2 * n
        || task.final_acc.len() != 2 * n
    {
        return None;
    }
    let coefficient = (n / width).ilog2() as usize;
    let row_bits = task.shape.padded_rounds().ilog2() as usize;
    if task.base.len() != coefficient + row_bits + 1 {
        return None;
    }
    for pair in &task.base {
        pair.validate(width).ok()?;
    }
    let project = |endpoint: &[F]| -> Option<Vec<Vec<F>>> {
        endpoint
            .chunks_exact(n)
            .map(|half| {
                PackedTable::new(coefficient, width, half.to_vec())
                    .ok()?
                    .evaluate(&task.base[..coefficient])
                    .ok()
            })
            .collect()
    };
    let initial = project(&task.initial)?;
    let final_acc = project(&task.final_acc)?;
    let weight = |row: usize| -> Option<Matrix<F>> {
        let mut result = Matrix::identity(width).ok()?;
        for bit in 0..row_bits {
            let pair = &task.base[coefficient + bit];
            result = if row >> bit & 1 == 0 {
                pair.zero.mul(&result).ok()?
            } else {
                pair.one.mul(&result).ok()?
            };
        }
        Some(result)
    };
    let mix = |halves: &[Vec<F>], matrix: &Matrix<F>| -> Option<Vec<F>> {
        let mut left = vec![F::zero(); width];
        let mut right = left.clone();
        matrix.add_mul(halves.first()?, &mut left);
        matrix.add_mul(halves.get(1)?, &mut right);
        let mut result = vec![F::zero(); width];
        let half = task.base.last()?;
        half.zero.add_mul(&left, &mut result);
        half.one.add_mul(&right, &mut result);
        Some(result)
    };
    let identity = Matrix::identity(width).ok()?;
    Some((
        mix(&initial, &identity)?,
        mix(&final_acc, &identity)?,
        mix(
            &initial,
            &weight(task.shape.padded_rounds().checked_sub(1)?)?,
        )?,
        mix(&final_acc, &weight(task.shape.rounds().checked_sub(1)?)?)?,
    ))
}
fn accumulator_values_valid<F, P>(
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    values: &[Vec<Vec<F>>],
) -> bool
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let width = pp.accumulators[0].width();
    let Ok(counts) = task.shape.opening_counts(width) else {
        return false;
    };
    if values.len() != 7
        || values
            .iter()
            .zip(counts)
            .any(|(rows, count)| rows.len() != count || rows.iter().any(|row| row.len() != width))
    {
        return false;
    }
    for (slot, rows) in values.iter().enumerate() {
        let Some(parameters) = accumulator_parameters(pp, slot) else {
            return false;
        };
        if rows
            .iter()
            .any(|row| parameters.validate_values(row).is_err())
        {
            return false;
        }
    }
    let Some((initial, final_acc, correction_initial, correction_final)) =
        accumulator_endpoint_projections(task, width)
    else {
        return false;
    };
    for lane in 0..width {
        if values[2][0][lane] != values[1][0][lane] - values[0][0][lane]
            || values[3][0][lane] != values[0][0][lane] + values[4][0][lane]
            || values[2][1][lane] != values[5][0][lane]
            || values[2][2][lane] != values[6][0][lane]
            || values[0][1][lane] != initial[lane]
            || values[3][1][lane] != final_acc[lane]
        {
            return false;
        }
        let shifted = values[0][2..]
            .iter()
            .fold(F::zero(), |sum, row| sum + row[lane]);
        if shifted - values[3][0][lane] != correction_initial[lane] - correction_final[lane] {
            return false;
        }
    }
    true
}
fn exercise_accumulator_arithmetic<F, P>(
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
) -> Vec<Vec<Vec<F>>>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let width = pp.accumulators[0].width();
    let counts = task.shape.opening_counts(width).unwrap();
    let mut values: Vec<_> = counts
        .into_iter()
        .map(|n| vec![vec![F::zero(); width]; n])
        .collect();
    let (initial, final_acc, correction_initial, correction_final) =
        accumulator_endpoint_projections(task, width).unwrap();
    for lane in 0..width {
        values[0][0][lane] = F::from(lane + 2);
        values[1][0][lane] = F::from(lane + 11);
        values[4][0][lane] = F::from(lane + 5);
        values[3][0][lane] = values[0][0][lane] + values[4][0][lane];
        values[2][0][lane] = values[1][0][lane] - values[0][0][lane];
        values[5][0][lane] = F::from(lane + 17);
        values[6][0][lane] = F::from(lane + 19);
        values[2][1][lane] = values[5][0][lane];
        values[2][2][lane] = values[6][0][lane];
        values[0][1][lane] = initial[lane];
        values[3][1][lane] = final_acc[lane];
        values[0][2][lane] = values[3][0][lane] + correction_initial[lane] - correction_final[lane];
    }
    for (slot, rows) in values.iter_mut().enumerate() {
        for row in rows {
            *row = accumulator_parameters(pp, slot)
                .unwrap()
                .normalize_values(std::mem::take(row));
        }
    }
    let sources: Vec<_> = task
        .sources
        .iter()
        .enumerate()
        .map(|(slot, (_, root))| CanonicalVerifierOracle {
            parameters: accumulator_parameters(pp, slot).unwrap(),
            commitment: root,
        })
        .collect();
    let check = |values: &[Vec<Vec<F>>]| {
        let independent = accumulator_values_valid::<F, P>(pp, task, values);
        let production = crate::packed_accumulator::audit::terminal_valid::<F, Sha512, P>(
            &task.shape,
            &task.initial,
            &task.final_acc,
            &task.base,
            &sources,
            values,
        );
        assert_eq!(independent, production);
        independent
    };
    assert!(check(&values));
    for slot in 0..values.len() {
        for query in 0..values[slot].len() {
            let mut bad = values.clone();
            bad[slot][query][0] += F::one();
            bad[slot][query] = accumulator_parameters(pp, slot)
                .unwrap()
                .normalize_values(std::mem::take(&mut bad[slot][query]));
            assert!(!check(&bad));
        }
    }
    let mut bad = values.clone();
    bad.pop();
    assert!(!check(&bad));
    let mut bad = values.clone();
    bad[0].pop();
    assert!(!check(&bad));
    let mut bad = values.clone();
    bad[0][0].pop();
    assert!(!check(&bad));
    let mut bad = values.clone();
    bad[0].push(vec![F::zero(); width]);
    assert!(!check(&bad));
    values
}

fn accumulator_queries_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(
    AccumulatorTask<F>,
    Vec<Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>>,
    &'a [u8],
)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (mut task, mut rest) = accumulator_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        pp.accumulators[0].num_vars().checked_sub(1)?,
    )?;
    let width = pp.accumulators[0].width();
    let coins = replay_receipt::<F>(
        message(&mut rest, 5, b"accumulator independent lane challenges")?,
        width,
        before,
    )?;
    task.base
        .push(sumcheck::packed::challenge_pair(&coins).ok()?);
    let queries = accumulator_query_maps(&task, width)?;
    Some((task, queries, rest))
}

struct AccumulatorOpening<F> {
    task: AccumulatorTask<F>,
    queries: Vec<Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>>,
    values: Vec<Vec<Vec<F>>>,
    selected: usize,
}
// The assignment must come from the caller's frozen authenticated-word map.
// This compiler checks task geometry and evaluates words; it does not create
// or authenticate assignments from a matching digest alone.
fn accumulator_assigned_values<F, P>(
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    mut assignment: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<PackedTable<F>>,
) -> Option<Vec<Vec<Vec<F>>>>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    if task.sources.len() != 7 {
        return None;
    }
    let queries = accumulator_query_maps(task, pp.accumulators[0].width())?;
    let mut assignments = std::collections::HashMap::<Vec<u8>, PackedTable<F>>::new();
    task.sources
        .iter()
        .zip(queries)
        .enumerate()
        .map(|(slot, (source, queries))| {
            let parameters = accumulator_parameters(pp, slot)?;
            if source.0 != parameters.context().ok()? {
                return None;
            }
            let identity = encoded(source);
            if !assignments.contains_key(&identity) {
                assignments.insert(identity.clone(), assignment(source)?);
            }
            let table = assignments.get(&identity)?;
            table.validate().ok()?;
            if table.num_vars() != parameters.num_vars() || table.width() != parameters.width() {
                return None;
            }
            queries
                .iter()
                .map(|query| {
                    let values = parameters.normalize_values(table.evaluate(query).ok()?);
                    parameters.validate_values(&values).ok()?;
                    Some(values)
                })
                .collect()
        })
        .collect()
}

type FrozenWordView = std::collections::HashMap<Digest512, Vec<u8>>;
fn accumulator_brakedown_frozen_values<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    mut view: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<std::sync::Arc<FrozenWordView>>,
) -> Option<(Vec<bool>, Vec<Vec<Vec<F>>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use pcs::utils::code::{BlockReedSolomonCode, RowCode};
    if profile.specification().backend != Backend::Brakedown {
        return None;
    }
    let role = &profile.specification().roles[0];
    let left = role.left_vars?;
    let right = 1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(left)?).ok()?)?;
    let code =
        BlockReedSolomonCode::<F>::new(right, role.block_width?, profile.specification().blowup)
            .ok()?;
    let expected = pcs::matrix_weighted::Parameters::new_encoded::<F>(
        role.num_vars,
        role.width,
        left,
        role.queries,
        code,
    )
    .ok()?;
    let expected_context = expected.context_digest::<F, Sha512>().ok()?;
    let code = expected.code();
    if task.sources.len() != 7 {
        return None;
    }
    accumulator_query_maps(task, role.width)?;
    // Reject every context/geometry mismatch before requesting any word view.
    for (slot, source) in task.sources.iter().enumerate() {
        let parameters = accumulator_parameters(pp, slot)?;
        if parameters.num_vars() != role.num_vars
            || parameters.width() != role.width
            || parameters.context().ok()? != expected_context
            || source.0 != expected_context
        {
            return None;
        }
    }
    let cells = (1usize.checked_shl(u32::try_from(left).ok()?)?)
        .checked_mul(role.width)?
        .checked_mul(code.block_width())?;
    let mut promises = Vec::new();
    let mut assignments = std::collections::HashMap::new();
    let mut nearness = std::collections::HashMap::<Vec<u8>, bool>::new();
    for source in &task.sources {
        let identity = encoded(source);
        // Preserve one view/assignment per exact context-root alias. A later
        // callback must not replace its decoded word or nearness promise.
        if let Some(&promised) = nearness.get(&identity) {
            promises.push(promised);
            continue;
        }
        let frozen = view(source)?;
        let columns = classical_assignment::frozen_brakedown_columns::<F>(
            &frozen,
            source.1.root,
            code.codeword_blocks().ilog2() as usize,
            cells,
        )?;
        let (promised, table) = classical_assignment::brakedown_assignment(
            &columns,
            role.num_vars,
            role.width,
            left,
            code,
        );
        promises.push(promised);
        nearness.insert(identity.clone(), promised);
        assignments.insert(identity, table);
    }
    let values = accumulator_assigned_values(pp, task, |source| {
        assignments.get(&encoded(source)).cloned()
    })?;
    Some((promises, values))
}

fn direct_source_points<F: NTTField, EF: AbstractExtensionField<F>>(
    domain: usize,
) -> Option<Vec<EF>> {
    if domain < 2 || !domain.is_power_of_two() {
        return None;
    }
    let bits = domain.ilog2();
    let mut base = F::get_ntt_root(bits.max(5)).ok()?;
    for _ in bits..bits.max(5) {
        base *= base;
    }
    let shift = EF::from_base(base);
    let power = |mut value: EF, mut exponent: usize| {
        let mut result = EF::one();
        while exponent > 0 {
            if exponent & 1 != 0 {
                result *= value;
            }
            value *= value;
            exponent >>= 1;
        }
        result
    };
    Some(
        (0..domain)
            .map(|index| shift * power(shift * shift, index.reverse_bits() >> (usize::BITS - bits)))
            .collect(),
    )
}
fn accumulator_polyfrim_frozen_values<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    mut view: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<std::sync::Arc<FrozenWordView>>,
) -> Option<(Vec<bool>, Vec<Vec<Vec<F>>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let expected_context = match profile.specification().backend {
        Backend::Polyfrim => {
            profile.polyfrim_parameters::<F, EF>().ok()?.roles()[0].context_digest::<Sha512>()
        }
        Backend::PolyfrimDictionary => profile
            .polyfrim_dictionary_parameters::<F, EF>()
            .ok()?
            .roles()[0]
            .context_digest::<Sha512>(),
        _ => return None,
    };
    let role = &profile.specification().roles[0];
    if task.sources.len() != 7 {
        return None;
    }
    accumulator_query_maps(task, role.width)?;
    for (slot, source) in task.sources.iter().enumerate() {
        let parameters = accumulator_parameters(pp, slot)?;
        if parameters.num_vars() != role.num_vars
            || parameters.width() != role.width
            || parameters.context().ok()? != expected_context
            || source.0 != expected_context
        {
            return None;
        }
    }
    let (core, domain) = direct_core::<F, EF>(profile)?;
    let points = direct_source_points::<F, EF>(domain)?;
    let message = 1usize.checked_shl(u32::try_from(role.num_vars).ok()?)?;
    let radius = domain.checked_sub(message)? / 4;
    let mut promises = Vec::new();
    let mut assignments = std::collections::HashMap::new();
    let mut nearness = std::collections::HashMap::<Vec<u8>, bool>::new();
    for source in &task.sources {
        let identity = encoded(source);
        // Preserve one view/assignment per exact context-root alias. A later
        // callback must not replace its decoded word or nearness promise.
        if let Some(&promised) = nearness.get(&identity) {
            promises.push(promised);
            continue;
        }
        let frozen = view(source)?;
        let symbols = classical_assignment::frozen_polyfrim_symbols(
            &frozen,
            source.1.root,
            &core,
            domain,
            role.width,
        )?;
        let (promised, table) = classical_assignment::polyfrim_assignment::<F, EF>(
            &points,
            &symbols,
            role.num_vars,
            role.width,
            radius,
        );
        promises.push(promised);
        nearness.insert(identity.clone(), promised);
        assignments.insert(identity, table);
    }
    let values = accumulator_assigned_values(pp, task, |source| {
        assignments.get(&encoded(source)).cloned()
    })?;
    Some((promises, values))
}

fn accumulator_fragment_frozen_values<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    mut view: impl FnMut(&(Digest512, Commitment<Digest512>)) -> Option<std::sync::Arc<FrozenWordView>>,
) -> Option<(Vec<bool>, Vec<Vec<Vec<F>>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let expected_context = match profile.specification().backend {
        Backend::FragmentedPipfri => {
            let bundle = profile.fragmented_parameters::<F, EF>().ok()?;
            <_ as CanonicalPcs<F, Sha512>>::context(&bundle.roles()[0]).ok()?
        }
        Backend::FragmentedPipfriVirtual => {
            let bundle = profile.fragmented_virtual_parameters::<F, EF>().ok()?;
            <_ as CanonicalPcs<F, Sha512>>::context(&bundle.roles()[0]).ok()?
        }
        _ => return None,
    };
    let role = &profile.specification().roles[0];
    if task.sources.len() != 7 {
        return None;
    }
    accumulator_query_maps(task, role.width)?;
    for (slot, source) in task.sources.iter().enumerate() {
        let parameters = accumulator_parameters(pp, slot)?;
        if parameters.num_vars() != role.num_vars
            || parameters.width() != role.width
            || parameters.context().ok()? != expected_context
            || source.0 != expected_context
        {
            return None;
        }
    }
    let (_, retained, fragments, scalar_context, _) = scalar_geometry::<F, EF>(profile)?;
    let length = 1usize.checked_shl(u32::try_from(retained).ok()?)?;
    let domain = length.checked_mul(profile.specification().blowup)?;
    let points = direct_source_points::<F, EF>(domain)?;
    let radius = domain.checked_sub(length)? / 4;
    let mut promises = Vec::new();
    let mut assignments = std::collections::HashMap::new();
    let mut nearness = std::collections::HashMap::<Vec<u8>, bool>::new();
    for source in &task.sources {
        let identity = encoded(source);
        if let Some(&promised) = nearness.get(&identity) {
            promises.push(promised);
            continue;
        }
        let frozen = view(source)?;
        let symbols = classical_assignment::frozen_fragment_symbols::<EF>(
            &frozen,
            source.1.root,
            scalar_context,
            domain,
            fragments,
        )?;
        let (promised, table) = classical_assignment::fragment_assignment::<F, EF>(
            &points,
            &symbols,
            length,
            role.num_vars,
            role.width,
            radius,
        );
        promises.push(promised);
        nearness.insert(identity.clone(), promised);
        assignments.insert(identity, table);
    }
    let values = accumulator_assigned_values(pp, task, |source| {
        assignments.get(&encoded(source)).cloned()
    })?;
    Some((promises, values))
}

fn exercise_accumulator_decoder_preflight<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    for mutation in 0..5 {
        let mut spec = profile.specification().clone();
        match mutation {
            0 => spec.roles[0].queries += 1,
            1 => spec.blowup = 4,
            2 => spec.roles[0].num_vars += 1,
            3 => {
                for role in &mut spec.roles {
                    role.width *= 2;
                }
            }
            _ => match spec.backend {
                Backend::Polyfrim => spec.backend = Backend::PolyfrimDictionary,
                Backend::PolyfrimDictionary => spec.backend = Backend::Polyfrim,
                Backend::FragmentedPipfri => spec.backend = Backend::FragmentedPipfriVirtual,
                Backend::FragmentedPipfriVirtual => spec.backend = Backend::FragmentedPipfri,
                _ => unreachable!(),
            },
        }
        let wrong = if profile.version() == 4 {
            ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
        } else {
            ClassicalProfile::new_atomic_columns::<F, EF>(spec)
        }
        .unwrap();
        let mut callbacks = 0;
        let mut view = |_: &(Digest512, Commitment<Digest512>)| {
            callbacks += 1;
            None
        };
        let result = match profile.specification().backend {
            Backend::Polyfrim | Backend::PolyfrimDictionary => {
                accumulator_polyfrim_frozen_values::<F, EF, P>(&wrong, pp, task, &mut view)
            }
            _ => accumulator_fragment_frozen_values::<F, EF, P>(&wrong, pp, task, &mut view),
        };
        assert!(result.is_none());
        assert_eq!(callbacks, 0);
    }
}

fn accumulator_row_request_tail<F: NTTField>(
    profile: &ClassicalProfile,
) -> Option<(Vec<u8>, usize)> {
    if profile.specification().backend != Backend::Brakedown {
        return None;
    }
    let role = &profile.specification().roles[0];
    let count = (1usize.checked_shl(u32::try_from(role.left_vars?).ok()?)?)
        .checked_mul(role.width)?
        .checked_mul(role.width)?;
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    let mut tail = Vec::new();
    frame(&mut tail, 1, b"typed request kind", b"vector");
    frame(&mut tail, 1, b"field challenge kind", b"prime vector");
    frame(&mut tail, 4, b"mw batch random linear test", &descriptor);
    Some((tail, count))
}
fn accumulator_representatives<F: NTTField>(
    profile: &ClassicalProfile,
    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
) -> Option<Vec<usize>> {
    let left = profile.specification().roles[0].left_vars?;
    let mut representatives = Vec::new();
    for (index, query) in queries.iter().enumerate() {
        if query.len() < left {
            return None;
        }
        if !representatives
            .iter()
            .any(|&prior: &usize| queries[prior][..left] == query[..left])
        {
            representatives.push(index);
        }
    }
    (!representatives.is_empty()).then_some(representatives)
}
fn accumulator_brakedown_completed<'a, F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
    mut rest: &'a [u8],
) -> Option<&'a [u8]> {
    if message(&mut rest, 5, b"mw batch random linear test")?.len() != 80 {
        return None;
    }
    let (tail, _, cells) = brakedown_column_tail(profile)?;
    let representatives = accumulator_representatives(profile, queries)?;
    let mut body = message(&mut rest, 1, b"mw batch linear responses")?;
    vector::<F>(&mut body, cells)?;
    rectangular::<F>(&mut body, representatives.len(), cells)?;
    if !body.is_empty() {
        return None;
    }
    rest = rest.strip_prefix(tail.as_slice())?;
    if message(&mut rest, 3, b"mw atomic column block v5")?.len()
        != 8usize.checked_mul(profile.specification().roles[0].queries)?
    {
        return None;
    }
    Some(rest)
}
fn accumulator_opening_tail<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
    values: &[Vec<F>],
    slot: usize,
) -> Option<Vec<u8>>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let parameters = accumulator_parameters(pp, slot)?;
    let mut queries = queries.to_vec();
    let mut values = values.to_vec();
    if matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        for (query, value) in queries.iter_mut().zip(&mut values) {
            (*query, *value) = parameters
                .normalize_claim(query.clone(), value.clone())
                .ok()?;
        }
    }
    let source = task.sources.get(slot)?;
    let mut out = Vec::new();
    if profile.specification().backend == Backend::Brakedown {
        frame(
            &mut out,
            1,
            b"mw batched row-code v1",
            &encoded(&(source.0, &source.1, &queries, &values)),
        );
        out.extend(accumulator_row_request_tail::<F>(profile)?.0);
    } else {
        let (binding, label, context) = pcs_child_labels(profile.specification().backend)?;
        frame(
            &mut out,
            1,
            binding,
            &encoded(&(source.0, &source.1, &queries, &values)),
        );
        frame(&mut out, 6, label, context);
        frame(&mut out, 2, b"classical child seed", &64u64.to_le_bytes());
    }
    Some(out)
}
fn accumulator_opening_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    completed: bool,
) -> Option<(AccumulatorOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, mut queries, mut rest) = accumulator_queries_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let width = pp.accumulators[0].width();
    let direct = matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    );
    if direct {
        for (slot, group) in queries.iter_mut().enumerate() {
            let parameters = accumulator_parameters(pp, slot)?;
            for query in group {
                *query = parameters
                    .normalize_claim(query.clone(), vec![F::zero(); width])
                    .ok()?
                    .0;
            }
        }
    }
    let mut opening = AccumulatorOpening {
        task,
        queries,
        values: Vec::new(),
        selected: 0,
    };
    for slot in 0..7 {
        opening.selected = slot;
        let parameters = accumulator_parameters(pp, slot)?;
        let source = &opening.task.sources[slot];
        let label = if profile.specification().backend == Backend::Brakedown {
            b"mw batched row-code v1".as_slice()
        } else {
            pcs_child_labels(profile.specification().backend)?.0
        };
        let mut body = message(&mut rest, 1, label)?;
        body =
            body.strip_prefix(encoded(&(source.0, &source.1, &opening.queries[slot])).as_slice())?;
        let values = rectangular::<F>(&mut body, opening.queries[slot].len(), width)?;
        if !body.is_empty() {
            return None;
        }
        for (query, value) in opening.queries[slot].iter().zip(&values) {
            parameters.validate_values(value).ok()?;
            if direct {
                let (q, v) = parameters
                    .normalize_claim(query.clone(), value.clone())
                    .ok()?;
                if encoded(&q) != encoded(query) || encoded(&v) != encoded(value) {
                    return None;
                }
            }
        }
        opening.values.push(values);
        if profile.specification().backend == Backend::Brakedown {
            rest = rest.strip_prefix(accumulator_row_request_tail::<F>(profile)?.0.as_slice())?;
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if completed {
                rest = accumulator_brakedown_completed::<F>(profile, &opening.queries[slot], rest)?;
            } else {
                match accumulator_brakedown_completed::<F>(profile, &opening.queries[slot], rest) {
                    Some(next) if !next.is_empty() && slot < 6 => rest = next,
                    _ => return Some((opening, rest)),
                }
            }
        } else {
            let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
            if message(&mut rest, 6, label)? != context
                || message(&mut rest, 2, b"classical child seed")? != 64u64.to_le_bytes()
            {
                return None;
            }
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if message(&mut rest, 3, b"classical child seed")?.len() != 64
                || message(&mut rest, 7, label)?.len() != 64
            {
                return None;
            }
        }
    }
    (completed && accumulator_values_valid::<F, P>(pp, &opening.task, &opening.values))
        .then_some((opening, rest))
}
struct AccumulatorColumns<F> {
    opening: AccumulatorOpening<F>,
    random: Vec<F>,
    test: Vec<F>,
    evaluations: Vec<Vec<F>>,
    representatives: Vec<usize>,
    domain: usize,
}
fn accumulator_column_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<AccumulatorColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, mut rest) = accumulator_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, false,
    )?;
    let (_, count) = accumulator_row_request_tail::<F>(profile)?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw batch random linear test")?,
        count,
        before,
    )?;
    let representatives = accumulator_representatives(profile, &opening.queries[opening.selected])?;
    let (tail, domain, cells) = brakedown_column_tail(profile)?;
    let mut body = message(&mut rest, 1, b"mw batch linear responses")?;
    let test = vector::<F>(&mut body, cells)?;
    let evaluations = rectangular::<F>(&mut body, representatives.len(), cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(AccumulatorColumns {
        opening,
        random,
        test,
        evaluations,
        representatives,
        domain,
    })
}
fn accumulator_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    let (opening, rest) = accumulator_opening_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        views.get(child.parent_input)?,
        views,
        false,
    )?;
    let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
    if !rest.is_empty() || child.label != label || child.context != context {
        return None;
    }
    Some((opening, child.rest))
}

fn accumulator_direct_consistency_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    member: usize,
) -> Option<AccumulatorOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if !matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        return None;
    }
    let (opening, rest) =
        accumulator_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let slot = opening.selected;
    let (_, _, _, rest) = direct_batch_consistency_prefix::<F, EF, P>(
        profile,
        accumulator_parameters(pp, slot)?,
        opening.task.sources.get(slot)?.1.root,
        opening.queries.get(slot)?,
        opening.values.get(slot)?,
        rest,
        member,
    )?;
    rest.is_empty().then_some(opening)
}

struct AccumulatorDirectTask<F, E> {
    opening: AccumulatorOpening<F>,
    core: pcs::packed_polyfrim::authenticated::Parameters<E>,
    roots: Vec<Vec<Digest512>>,
    domain: usize,
}
fn accumulator_direct_projection_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorDirectTask<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if !matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        return None;
    }
    let (opening, rest) =
        accumulator_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let slot = opening.selected;
    let queries = opening.queries.get(slot)?;
    let claims = queries.len();
    let (core, roots, domain, rest) = direct_batch_consistency_prefix::<F, EF, P>(
        profile,
        accumulator_parameters(pp, slot)?,
        opening.task.sources.get(slot)?.1.root,
        queries,
        opening.values.get(slot)?,
        rest,
        claims.checked_sub(1)?,
    )?;
    let rest = direct_batch_projection_tail::<F, EF>(profile, &core, &roots, rest)?;
    Some((
        AccumulatorDirectTask {
            opening,
            core,
            roots,
            domain,
        },
        rest,
    ))
}
fn accumulator_direct_projection_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<AccumulatorDirectTask<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = accumulator_direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    rest.is_empty().then_some(task)
}
struct AccumulatorDirectRolling<F, E> {
    direct: AccumulatorDirectTask<F, E>,
    data: DirectRollingData<E>,
}
fn accumulator_direct_rolling_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(AccumulatorDirectRolling<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (direct, rest) = accumulator_direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let (data, rest) = direct_rolling_data_prefix::<F, EF>(
        profile,
        0,
        &direct.core,
        &direct.roots,
        rest,
        before,
        round,
    )?;
    Some((AccumulatorDirectRolling { direct, data }, rest))
}
fn accumulator_direct_rolling_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<AccumulatorDirectRolling<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = accumulator_direct_rolling_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn accumulator_direct_rolling_indices<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorDirectRolling<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let role = &profile.specification().roles[0];
    let (mut task, mut rest) = accumulator_direct_rolling_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        role.num_vars.checked_sub(1)?,
    )?;
    task.data.alphas.push(
        replay_extension::<F, EF>(
            message(&mut rest, 5, b"rolling FRI fold challenge")?,
            1,
            before,
        )?[0],
    );
    let body = message(&mut rest, 1, b"rolling FRI terminal")?;
    let (terminal, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if used != body.len() || encoded(&terminal) != body {
        return None;
    }
    if message(&mut rest, 1, b"index domain")? != (task.direct.domain as u64).to_le_bytes()
        || message(&mut rest, 2, b"rolling FRI unbiased domain index")?
            != u64::try_from(role.queries.checked_mul(8)?)
                .ok()?
                .to_le_bytes()
        || !rest.is_empty()
    {
        return None;
    }
    Some((task, terminal))
}

fn accumulator_fragment_projection_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) =
        accumulator_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let count = opening
        .queries
        .get(opening.selected)?
        .len()
        .checked_mul(profile.specification().roles[0].width)?;
    let tail = ntt_fragment_projection_tail::<F, EF>(profile, count)?.0;
    Some((opening, rest.strip_prefix(tail.as_slice())?))
}
struct AccumulatorFragmentRound<F, E> {
    opening: AccumulatorOpening<F>,
    rho: Vec<E>,
    point: Vec<E>,
    expected: E,
    evaluations: Vec<E>,
}
fn accumulator_fragment_round_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(AccumulatorFragmentRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) = accumulator_fragment_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let (rho, point, expected, evaluations, rest) = fragment_batch_round_prefix::<F, EF>(
        profile,
        opening.values.get(opening.selected)?,
        profile.specification().roles[0].width,
        rest,
        before,
        round,
    )?;
    Some((
        AccumulatorFragmentRound {
            opening,
            rho,
            point,
            expected,
            evaluations,
        },
        rest,
    ))
}
fn accumulator_fragment_round_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<AccumulatorFragmentRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = accumulator_fragment_round_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}

struct AccumulatorScalarGamma<F, E> {
    bridge: AccumulatorFragmentRound<F, E>,
    point: Vec<E>,
    bridge_expected: E,
    value: E,
    fragments: Vec<E>,
}
fn accumulator_scalar_gamma_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorScalarGamma<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let n = role_vars_for_bridge(profile);
    let (bridge, mut rest) = accumulator_fragment_round_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        n.checked_sub(1)?,
    )?;
    let coin = replay_extension::<F, EF>(
        message(&mut rest, 5, b"random point in each round")?,
        1,
        before,
    )?[0];
    let bridge_expected = quadratic(&bridge.evaluations, coin);
    let mut point = bridge.point.clone();
    point.push(coin);
    let (value, fragments, rest) = fragment_scalar_gamma_tail::<F, EF>(
        profile,
        &bridge.opening.task.sources.get(bridge.opening.selected)?.1,
        &point,
        rest,
    )?;
    Some((
        AccumulatorScalarGamma {
            bridge,
            point,
            bridge_expected,
            value,
            fragments,
        },
        rest,
    ))
}
// Evaluate the public matrix kernel by forward matrix/column products. The
// production verifier instead multiplies challenge rows in reverse order.
fn fragment_terminal_kernel<F: NTTField, EF: AbstractExtensionField<F>>(
    width: usize,
    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
    rho: &[EF],
    point: &[EF],
) -> Option<EF> {
    if !width.is_power_of_two()
        || queries.is_empty()
        || rho.len() != queries.len().checked_mul(width)?
    {
        return None;
    }
    let bits = width.ilog2() as usize;
    let variables = point.len().checked_sub(bits)?;
    if queries.iter().any(|q| q.len() != variables) {
        return None;
    }
    let lane: Vec<_> = (0..width)
        .map(|j| {
            point[..bits]
                .iter()
                .enumerate()
                .fold(EF::one(), |w, (bit, &x)| {
                    w * if j >> bit & 1 == 0 { EF::one() - x } else { x }
                })
        })
        .collect();
    let mut result = EF::zero();
    for (query, challenges) in queries.iter().zip(rho.chunks_exact(width)) {
        let mut column = lane.clone();
        for (index, pair) in query.iter().enumerate() {
            if pair.zero.values().len() != width.checked_mul(width)?
                || pair.one.values().len() != width.checked_mul(width)?
            {
                return None;
            }
            let x = point[bits + index];
            column = (0..width)
                .map(|row| {
                    (0..width).fold(EF::zero(), |sum, col| {
                        let at = row * width + col;
                        let entry = (EF::one() - x) * EF::from_base(pair.zero.values()[at])
                            + x * EF::from_base(pair.one.values()[at]);
                        sum + entry * column[col]
                    })
                })
                .collect();
        }
        result += challenges
            .iter()
            .zip(column)
            .fold(EF::zero(), |sum, (&r, c)| sum + r * c);
    }
    Some(result)
}
fn accumulator_bridge_terminal_valid<F: NTTField, EF: AbstractExtensionField<F>>(
    task: &AccumulatorScalarGamma<F, EF>,
    width: usize,
) -> bool {
    let Some(queries) = task
        .bridge
        .opening
        .queries
        .get(task.bridge.opening.selected)
    else {
        return false;
    };
    fragment_terminal_kernel(width, queries, &task.bridge.rho, &task.point)
        .is_some_and(|kernel| task.bridge_expected == task.value * kernel)
}

fn accumulator_scalar_gamma_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<AccumulatorScalarGamma<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = accumulator_scalar_gamma_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    rest.is_empty().then_some(task)
}

struct AccumulatorRollingRound<F, E> {
    scalar: AccumulatorScalarGamma<F, E>,
    data: RollingData<E>,
}
fn accumulator_rolling_alpha_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(AccumulatorRollingRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (scalar, rest) = accumulator_scalar_gamma_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let (data, rest) = rolling_data_prefix::<F, EF>(
        profile,
        0,
        &scalar
            .bridge
            .opening
            .task
            .sources
            .get(scalar.bridge.opening.selected)?
            .1,
        &scalar.point,
        rest,
        before,
        round,
    )?;
    Some((AccumulatorRollingRound { scalar, data }, rest))
}
fn accumulator_rolling_alpha_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<AccumulatorRollingRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = accumulator_rolling_alpha_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn accumulator_rolling_index_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorRollingRound<F, EF>, EF, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rounds, _, _, _) = scalar_geometry::<F, EF>(profile)?;
    let (mut task, mut rest) = accumulator_rolling_alpha_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        rounds.checked_sub(1)?,
    )?;
    task.data.alphas.push(
        replay_extension::<F, EF>(
            message(&mut rest, 5, b"rolling FRI fold challenge")?,
            1,
            before,
        )?[0],
    );
    let body = message(&mut rest, 1, b"rolling FRI terminal")?;
    let (terminal, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if used != body.len() || encoded(&terminal) != body {
        return None;
    }
    let tail = rolling_index_tail(profile)?.0;
    Some((task, terminal, rest.strip_prefix(tail.as_slice())?))
}
fn accumulator_rolling_index_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorRollingRound<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, terminal, rest) = accumulator_rolling_index_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    rest.is_empty().then_some((task, terminal))
}
fn accumulator_consistency_index_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(AccumulatorRollingRound<F, EF>, Vec<usize>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, _, mut rest) = accumulator_rolling_index_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let bytes = message(&mut rest, 3, b"rolling FRI unbiased domain index")?;
    let count = profile.specification().roles[0].queries.checked_mul(8)?;
    if bytes.len() != count || rest != consistency_index_tail(profile)? {
        return None;
    }
    let domain = rolling_index_tail(profile)?.1;
    let indices = bytes
        .chunks_exact(8)
        .map(|chunk| (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize)
        .collect();
    Some((task, indices))
}

fn lookup_helper_opening<F: NTTField, EF, P: CanonicalPcs<F, Sha512>>(
    pp: &Parameters<'_, P>,
    terminal: &LookupTerminal<F, EF>,
) -> Option<FirstOpening<F>> {
    if terminal.helper_query.post_matrix.is_some()
        || terminal.batch.equality.helper_context != pp.helper.context().ok()?
    {
        return None;
    }
    Some(FirstOpening {
        family: OpeningFamily::LookupHelper,
        selected: 0,
        sources: terminal
            .batch
            .equality
            .roots
            .iter()
            .map(|root| (terminal.batch.equality.helper_context, root.clone()))
            .collect(),
        query: terminal.helper_query.query.clone(),
        values: terminal.helper_claims.clone(),
    })
}

fn decomposition_lookup_helper_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    completed: bool,
    half: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (terminal, mut rest) = decomposition_lookup_parent_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, half,
    )?;
    let mut opening = lookup_helper_opening(pp, &terminal)?;
    if half == 1 {
        opening.family = OpeningFamily::SecondLookupHelper;
    }
    let role = profile.specification().roles.get(opening.role())?;
    if role.width != pp.helper.width()
        || role.num_vars != pp.helper.num_vars()
        || opening.query.len() != pp.helper.num_vars()
        || opening.values.len() != opening.sources.len()
    {
        return None;
    }
    for index in 0..opening.sources.len() {
        opening.selected = index;
        if profile.specification().backend == Backend::Brakedown {
            let (tail, _) = brakedown_first_tail(profile, &opening)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if completed {
                rest = brakedown_completed_body_for_role::<F>(profile, rest, 1)?;
                continue;
            }
            match brakedown_completed_body_for_role::<F>(profile, rest, 1) {
                Some(next) if !next.is_empty() && index + 1 < opening.sources.len() => rest = next,
                _ => return Some((opening, rest)),
            }
        } else {
            let (tail, label, _) = factor_seed_tail(profile, pp.helper, &opening, index)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if message(&mut rest, 3, b"classical child seed")?.len() != 64
                || message(&mut rest, 7, label)?.len() != 64
            {
                return None;
            }
        }
    }
    completed.then_some((opening, rest))
}

// Original-source obligations follow every helper opening. Aliases are defined
// by the complete parameter context and root, in original registry order.
struct LookupSourceClaim<F> {
    slot: usize,
    query: Vec<algebra::matrix_weighted::MatrixPair<F>>,
    value: Vec<F>,
}
fn lookup_source_bindings<F, EF, P>(
    pp: &Parameters<'_, P>,
    terminal: &LookupTerminal<F, EF>,
) -> Option<(Vec<LookupSourceClaim<F>>, Vec<u8>)>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    lookup_source_registry_bindings::<F, P>(
        pp,
        &terminal.batch.equality.lookup.sources,
        &terminal.batch.equality.lookup.requests,
        &terminal.source_query.query,
        &terminal.source_values,
    )
}
fn lookup_source_registry_bindings<F, P>(
    pp: &Parameters<'_, P>,
    sources: &[(Digest512, Commitment<Digest512>)],
    requests: &[crate::packed_extension_lookup::deferred::Request<F>],
    query: &[algebra::matrix_weighted::MatrixPair<F>],
    values: &[Vec<F>],
) -> Option<(Vec<LookupSourceClaim<F>>, Vec<u8>)>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let count = sources.len();
    let digits = count.checked_sub(1)? / 2;
    if digits == 0 || count != 2 * digits + 1 || values.len() != count {
        return None;
    }
    let mut used = vec![false; count];
    for request in requests {
        for &slot in &request.source_slots {
            *used.get_mut(slot)? = true;
        }
    }
    let mut claims: Vec<LookupSourceClaim<F>> = Vec::new();
    let mut binding = Vec::new();
    for (slot, &(context, ref root)) in sources.iter().enumerate() {
        let parameters = if slot < digits {
            pp.coefficients
        } else {
            pp.borrows
        };
        if parameters.context().ok()? != context {
            return None;
        }
        parameters.validate_values(&values[slot]).ok()?;
        if !used[slot] {
            if values[slot].iter().any(|&v| v != F::zero()) {
                return None;
            }
            continue;
        }
        if let Some(prior) = claims.iter().find(|claim| {
            sources[claim.slot].0 == context && sources[claim.slot].1.root == root.root
        }) {
            if values[prior.slot] != values[slot] {
                return None;
            }
            continue;
        }
        let (query, value) = parameters
            .normalize_claim(query.to_vec(), values[slot].clone())
            .ok()?;
        frame(
            &mut binding,
            1,
            P::CLAIM_DOMAIN,
            &encoded(&(claims.len(), slot, &query, &value)),
        );
        claims.push(LookupSourceClaim { slot, query, value });
    }
    (!claims.is_empty()).then_some((claims, binding))
}

fn decomposition_lookup_source_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<(Vec<LookupSourceClaim<F>>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, mut rest) = decomposition_lookup_helper_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, true, half,
    )?;
    let (terminal, _) = decomposition_lookup_parent_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, half,
    )?;
    let (claims, binding) = lookup_source_bindings::<F, EF, P>(pp, &terminal)?;
    rest = rest.strip_prefix(binding.as_slice())?;
    if message(&mut rest, 1, P::SEAL_DOMAIN)? != encoded(&(claims.len(), claims.len())) {
        return None;
    }
    Some((claims, rest))
}

fn lookup_source_opening<F: NTTField, EF>(
    terminal: &LookupTerminal<F, EF>,
    claim: &LookupSourceClaim<F>,
) -> Option<FirstOpening<F>> {
    let sources = &terminal.batch.equality.lookup.sources;
    let digits = sources.len().checked_sub(1)? / 2;
    Some(FirstOpening {
        family: OpeningFamily::LookupSource {
            slot: claim.slot,
            digits,
        },
        selected: 0,
        sources: vec![sources.get(claim.slot)?.clone()],
        query: claim.query.clone(),
        values: vec![claim.value.clone()],
    })
}
fn lookup_source_opening_at<F: NTTField, EF>(
    terminal: &LookupTerminal<F, EF>,
    claim: &LookupSourceClaim<F>,
    half: usize,
) -> Option<FirstOpening<F>> {
    if half > 1 {
        return None;
    }
    let mut opening = lookup_source_opening(terminal, claim)?;
    if half == 1 {
        let OpeningFamily::LookupSource { slot, digits } = opening.family else {
            return None;
        };
        opening.family = OpeningFamily::SecondLookupSource { slot, digits };
    }
    Some(opening)
}
fn lookup_source_batch_row_tail<F: NTTField + Serialize>(
    profile: &ClassicalProfile,
    opening: &FirstOpening<F>,
) -> Option<(Vec<u8>, usize)> {
    let (_, count) = brakedown_first_tail(profile, opening)?;
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"mw batched row-code v1",
        &encoded(&(
            opening.sources[0].0,
            &opening.sources[0].1,
            vec![&opening.query],
            &opening.values,
        )),
    );
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut request = p.to_le_bytes().to_vec();
    request.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(&mut out, 4, b"mw batch random linear test", &request);
    Some((out, count))
}
fn lookup_source_batch_completed<'a, F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    mut rest: &'a [u8],
) -> Option<&'a [u8]> {
    if message(&mut rest, 5, b"mw batch random linear test")?.len() != 80 {
        return None;
    }
    let (tail, _, cells) = brakedown_column_tail(profile)?;
    let mut body = message(&mut rest, 1, b"mw batch linear responses")?;
    vector::<F>(&mut body, cells)?;
    rectangular::<F>(&mut body, 1, cells)?;
    if !body.is_empty() {
        return None;
    }
    rest = rest.strip_prefix(tail.as_slice())?;
    if message(&mut rest, 3, b"mw atomic column block v5")?.len()
        != profile.specification().roles[0].queries.checked_mul(8)?
    {
        return None;
    }
    Some(rest)
}
fn decomposition_lookup_source_opening_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    completed: bool,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, completed, 0,
    )
}
fn decomposition_lookup_source_opening_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    completed: bool,
    half: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (claims, mut rest) = decomposition_lookup_source_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, half,
    )?;
    let (terminal, _) = decomposition_lookup_parent_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, half,
    )?;
    let mut last = None;
    for (index, claim) in claims.iter().enumerate() {
        let opening = lookup_source_opening_at(&terminal, claim, half)?;
        if profile.specification().backend == Backend::Brakedown {
            let (tail, _) = lookup_source_batch_row_tail(profile, &opening)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if completed {
                rest = lookup_source_batch_completed::<F>(profile, rest)?;
            } else {
                match lookup_source_batch_completed::<F>(profile, rest) {
                    Some(next) if !next.is_empty() && index + 1 < claims.len() => rest = next,
                    _ => return Some((opening, rest)),
                }
            }
        } else {
            let (tail, label, _) =
                factor_seed_tail(profile, opening.parameters(pp, 0)?, &opening, 0)?;
            rest = rest.strip_prefix(tail.as_slice())?;
            if rest.is_empty() {
                return (!completed).then_some((opening, rest));
            }
            if message(&mut rest, 3, b"classical child seed")?.len() != 64
                || message(&mut rest, 7, label)?.len() != 64
            {
                return None;
            }
        }
        last = Some(opening);
    }
    completed.then_some((last?, rest))
}

fn decomposition_lookup_source_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    decomposition_lookup_source_child_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 0,
    )
}
fn decomposition_lookup_source_child_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    let (opening, rest) = decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        views.get(child.parent_input)?,
        views,
        false,
        half,
    )?;
    let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
    if !rest.is_empty() || child.label != label || child.context != context {
        return None;
    }
    Some((opening, child.rest))
}

fn decomposition_lookup_source_column_query_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<BrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, mut rest) = decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, false, half,
    )?;
    let (_, count) = lookup_source_batch_row_tail(profile, &opening)?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw batch random linear test")?,
        count,
        before,
    )?;
    let (tail, domain, cells) = brakedown_column_tail(profile)?;
    let mut body = message(&mut rest, 1, b"mw batch linear responses")?;
    let test = vector::<F>(&mut body, cells)?;
    let mut evaluations = rectangular::<F>(&mut body, 1, cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(BrakedownColumns {
        opening,
        random,
        test,
        evaluation: evaluations.pop()?,
        domain,
    })
}

fn decomposition_lookup_helper_query_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) = decomposition_lookup_helper_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, false, half,
    )?;
    rest.is_empty().then_some(opening)
}

fn decomposition_lookup_helper_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    decomposition_lookup_helper_child_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 0,
    )
}
fn decomposition_lookup_helper_child_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    let opening = decomposition_lookup_helper_query_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        views.get(child.parent_input)?,
        views,
        half,
    )?;
    let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
    if child.label != label || child.context != context {
        return None;
    }
    Some((opening, child.rest))
}

fn decomposition_lookup_helper_column_query_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<BrakedownColumns<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.specification().backend != Backend::Brakedown || profile.version() != 5 {
        return None;
    }
    let (opening, mut rest) = decomposition_lookup_helper_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, false, half,
    )?;
    let (_, count) = brakedown_first_tail(profile, &opening)?;
    let random = replay_receipt::<F>(
        message(&mut rest, 5, b"mw random linear test")?,
        count,
        before,
    )?;
    let (tail, domain, cells) = brakedown_column_tail_for_role(profile, opening.role())?;
    let mut body = message(&mut rest, 1, b"mw linear responses")?;
    let test = vector::<F>(&mut body, cells)?;
    let evaluation = vector::<F>(&mut body, cells)?;
    if !body.is_empty() || rest != tail {
        return None;
    }
    Some(BrakedownColumns {
        opening,
        random,
        test,
        evaluation,
        domain,
    })
}

fn lookup_scalar_tail<F: NTTField, EF: AbstractExtensionField<F>>(label: &'static [u8]) -> Vec<u8> {
    let mut tail = Vec::new();
    frame(&mut tail, 1, b"typed request kind", b"scalar");
    frame(&mut tail, 1, b"field challenge kind", b"extension vector");
    frame(&mut tail, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend((EF::D as u64).to_le_bytes());
    frame(&mut tail, 4, label, &descriptor);
    tail
}
fn lookup_hash_tail<F: NTTField, EF: AbstractExtensionField<F>>() -> Vec<u8> {
    lookup_scalar_tail::<F, EF>(b"extension tuple hash challenge")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LookupChallengePhase {
    Hash,
    Reciprocal,
}
struct LookupChallengeTask<E> {
    request: usize,
    repetition: usize,
    phase: LookupChallengePhase,
    hash: Option<E>,
    table: Vec<E>,
    rejected: usize,
    accepted: Vec<(usize, usize, E, E)>,
}
enum LookupChallengeBoundary<'a, E> {
    Pending(LookupChallengeTask<E>),
    Complete {
        accepted: Vec<(usize, usize, E, E)>,
        rest: &'a [u8],
    },
}
fn compressed_lookup_table<F: NTTField, EF: AbstractExtensionField<F>>(
    request: &crate::packed_extension_lookup::deferred::Request<F>,
    hash: EF,
) -> Vec<EF> {
    request
        .config
        .table()
        .iter()
        .map(|row| {
            let mut power = EF::one();
            let mut value = EF::zero();
            for &entry in row {
                value = value + power * entry;
                power *= hash;
            }
            value
        })
        .collect()
}
fn lookup_challenge_walk<'a, F: NTTField, EF: AbstractExtensionField<F>>(
    requests: &[crate::packed_extension_lookup::deferred::Request<F>],
    mut rest: &'a [u8],
    before: &Producers,
) -> Option<LookupChallengeBoundary<'a, EF>> {
    if requests.is_empty() {
        return None;
    }
    let hash_tail = lookup_hash_tail::<F, EF>();
    let reciprocal_tail = lookup_scalar_tail::<F, EF>(b"extension tuple reciprocal challenge");
    let mut accepted = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        if message(&mut rest, 1, b"shared lookup challenge request")? != encoded(&index) {
            return None;
        }
        for repetition in 0..request.config.repetitions() {
            if rest == hash_tail {
                return Some(LookupChallengeBoundary::Pending(LookupChallengeTask {
                    request: index,
                    repetition,
                    phase: LookupChallengePhase::Hash,
                    hash: None,
                    table: Vec::new(),
                    rejected: 0,
                    accepted,
                }));
            }
            rest = rest.strip_prefix(hash_tail.as_slice())?;
            let hash = replay_extension::<F, EF>(
                message(&mut rest, 5, b"extension tuple hash challenge")?,
                1,
                before,
            )?[0];
            let table = compressed_lookup_table(request, hash);
            let mut rejected = 0usize;
            loop {
                if rest == reciprocal_tail {
                    return Some(LookupChallengeBoundary::Pending(LookupChallengeTask {
                        request: index,
                        repetition,
                        phase: LookupChallengePhase::Reciprocal,
                        hash: Some(hash),
                        table,
                        rejected,
                        accepted,
                    }));
                }
                rest = rest.strip_prefix(reciprocal_tail.as_slice())?;
                let r = replay_extension::<F, EF>(
                    message(&mut rest, 5, b"extension tuple reciprocal challenge")?,
                    1,
                    before,
                )?[0];
                if r != EF::zero() && table.iter().all(|&value| r + value != EF::zero()) {
                    accepted.push((index, repetition, hash, r));
                    break;
                }
                // Each iteration consumes a complete request and receipt from
                // finite input. There is no arbitrary retry/query cutoff.
                rejected = rejected.checked_add(1)?;
            }
        }
    }
    Some(LookupChallengeBoundary::Complete { accepted, rest })
}
fn decomposition_lookup_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DecompositionLookup<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    if child.label != b"classical extension lookup child v1"
        || child.context != b"packed extension tuple lookup"
    {
        return None;
    }
    let lookup = decomposition_lookup_seed_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        views.get(child.parent_input)?,
    )?;
    Some((lookup, child.rest))
}
fn second_decomposition_lookup_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DecompositionLookup<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    if child.label != b"classical extension lookup child v1"
        || child.context != b"packed extension tuple lookup"
    {
        return None;
    }
    let (lookup, rest) = second_decomposition_lookup_seed_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        views.get(child.parent_input)?,
        views,
    )?;
    if !rest.is_empty() {
        return None;
    }
    Some((lookup, child.rest))
}
fn second_decomposition_lookup_challenge_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DecompositionLookup<F>, LookupChallengeTask<EF>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (lookup, rest) = second_decomposition_lookup_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    match lookup_challenge_walk::<F, EF>(&lookup.requests, rest, before)? {
        LookupChallengeBoundary::Pending(task) => Some((lookup, task)),
        LookupChallengeBoundary::Complete { .. } => None,
    }
}
fn decomposition_lookup_algebra_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DecompositionLookup<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    decomposition_lookup_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )
    .or_else(|| {
        second_decomposition_lookup_child_prefix::<F, EF, P>(
            profile, pp, setup, statement, input, before, views,
        )
    })
}
fn decomposition_lookup_challenge_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DecompositionLookup<F>, LookupChallengeTask<EF>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (lookup, rest) = decomposition_lookup_algebra_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    match lookup_challenge_walk::<F, EF>(&lookup.requests, rest, before)? {
        LookupChallengeBoundary::Pending(task) => Some((lookup, task)),
        LookupChallengeBoundary::Complete { .. } => None,
    }
}
fn lookup_vector_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    label: &'static [u8],
    count: usize,
) -> Option<Vec<u8>> {
    let mut tail = Vec::new();
    frame(&mut tail, 1, b"typed request kind", b"vector");
    frame(&mut tail, 1, b"field challenge kind", b"extension vector");
    frame(&mut tail, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count.checked_mul(EF::D)?).ok()?.to_le_bytes());
    frame(&mut tail, 4, label, &descriptor);
    Some(tail)
}
struct LookupEqualityTask<F: algebra::Field, E> {
    lookup: DecompositionLookup<F>,
    accepted: Vec<(usize, usize, E, E)>,
    roots: Vec<Commitment<Digest512>>,
    points: Vec<Vec<E>>,
    variables: usize,
    helper_context: Digest512,
}
fn decomposition_lookup_equality_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    index: usize,
) -> Option<(LookupEqualityTask<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (lookup, rest) = decomposition_lookup_algebra_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let LookupChallengeBoundary::Complete { accepted, mut rest } =
        lookup_challenge_walk::<F, EF>(&lookup.requests, rest, before)?
    else {
        return None;
    };
    if index >= accepted.len() {
        return None;
    }
    let width = pp.coefficients.width();
    let variables = pp
        .coefficients
        .num_vars()
        .checked_add(width.checked_ilog2()? as usize)?;
    if variables == 0
        || pp.helper.num_vars() != variables
        || (pp.helper.width() != width && pp.helper.width() != EF::D)
    {
        return None;
    }
    let mut body = message(&mut rest, 1, b"shared lookup helper roots")?;
    let roots = vector::<Commitment<Digest512>>(&mut body, accepted.len())?;
    if !body.is_empty() {
        return None;
    }
    let tail = lookup_vector_tail::<F, EF>(b"shared lookup equality point", variables)?;
    let mut points = Vec::new();
    for current in 0..=index {
        rest = rest.strip_prefix(tail.as_slice())?;
        if current == index {
            return Some((
                LookupEqualityTask {
                    lookup,
                    accepted,
                    roots,
                    points,
                    variables,
                    helper_context: pp.helper.context().ok()?,
                },
                rest,
            ));
        }
        points.push(replay_extension::<F, EF>(
            message(&mut rest, 5, b"shared lookup equality point")?,
            variables,
            before,
        )?);
    }
    None
}
fn decomposition_lookup_equality_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    index: usize,
) -> Option<LookupEqualityTask<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = decomposition_lookup_equality_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, index,
    )?;
    rest.is_empty().then_some(task)
}
thread_local! {
    // Pure public algebra only: never cache histories, producer availability,
    // source compilation or acceptance. Eviction changes work, not eligibility.
    static LOOKUP_EQUATION_CACHE: std::cell::RefCell<std::collections::HashMap<
        (std::any::TypeId, Vec<u8>), Box<dyn std::any::Any>
    >> = std::cell::RefCell::new(std::collections::HashMap::new());
}
fn lookup_equations<F: NTTField + Serialize, EF: AbstractExtensionField<F> + Serialize>(
    task: &LookupEqualityTask<F, EF>,
) -> Option<(Vec<algebra::PolynomialInfo>, Vec<EF>)> {
    let key = (
        std::any::TypeId::of::<(F, EF)>(),
        encoded(&(
            task.variables,
            &task.lookup.requests,
            &task.lookup.multiplicities,
            &task.accepted,
        )),
    );
    if let Some(result) = LOOKUP_EQUATION_CACHE.with(|cache| {
        cache
            .borrow()
            .get(&key)?
            .downcast_ref::<(Vec<algebra::PolynomialInfo>, Vec<EF>)>()
            .cloned()
    }) {
        return Some(result);
    }
    let result = lookup_equations_uncached(task)?;
    LOOKUP_EQUATION_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= 64 {
            cache.clear();
        }
        cache.insert(key, Box::new(result.clone()));
    });
    Some(result)
}
fn exercise_lookup_equation_cache<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let request = crate::packed_extension_lookup::deferred::Request {
        config: crate::packed_tuple_lookup::Config::new(
            4,
            vec![
                vec![F::one(), F::from(2usize)],
                vec![F::from(3usize), F::from(4usize)],
            ],
            1,
        )
        .unwrap(),
        source_slots: vec![0, 1],
    };
    let mut task = LookupEqualityTask {
        lookup: DecompositionLookup {
            sources: Vec::new(),
            requests: vec![request],
            multiplicities: vec![vec![F::from(3usize), F::one()]],
        },
        accepted: vec![(
            0,
            0,
            EF::from_base(F::from(3usize)),
            EF::from_base(F::from(5usize)),
        )],
        roots: Vec::new(),
        points: Vec::new(),
        variables: 2,
        helper_context: Digest512::default(),
    };
    let compare = |task: &LookupEqualityTask<F, EF>| {
        let expected = lookup_equations_uncached(task).unwrap();
        assert_eq!(
            encoded(&lookup_equations(task).unwrap()),
            encoded(&expected)
        );
        assert_eq!(
            encoded(&lookup_equations(task).unwrap()),
            encoded(&expected)
        );
    };
    compare(&task);
    task.lookup.multiplicities[0][0] += F::one();
    compare(&task);
    task.accepted[0].2 = EF::from_base(F::from(9usize));
    compare(&task);
    task.accepted[0].3 = EF::from_base(F::from(8usize));
    compare(&task);
    task.lookup.requests[0].config = crate::packed_tuple_lookup::Config::new(
        3,
        vec![
            vec![F::from(2usize), F::from(3usize)],
            vec![F::from(4usize), F::from(5usize)],
        ],
        1,
    )
    .unwrap();
    compare(&task);
    task.variables = 3;
    compare(&task);
    for index in 0..70 {
        task.accepted[0].3 = EF::from_base(F::from(index + 100));
        compare(&task);
    }
}
#[test]
fn lookup_equation_cache_preserves_all_fields_and_inputs() {
    exercise_lookup_equation_cache::<algebra::BabyBear, algebra::BabyBearExetension>();
    exercise_lookup_equation_cache::<algebra::BabyBear, algebra::BabyBearExtension5>();
    exercise_lookup_equation_cache::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_lookup_equation_cache::<algebra::BabyBear, algebra::BabyBearExtension8>();
    exercise_lookup_equation_cache::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    exercise_lookup_equation_cache::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    exercise_lookup_equation_cache::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
    exercise_lookup_equation_cache::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

fn lookup_equations_uncached<F: NTTField, EF: AbstractExtensionField<F>>(
    task: &LookupEqualityTask<F, EF>,
) -> Option<(Vec<algebra::PolynomialInfo>, Vec<EF>)> {
    let capacity = 1usize.checked_shl(u32::try_from(task.variables).ok()?)?;
    let mut infos = Vec::new();
    let mut claims = Vec::new();
    for &(request, _, hash, reciprocal) in &task.accepted {
        let request_config = task.lookup.requests.get(request)?;
        let table = compressed_lookup_table(request_config, hash);
        let multiplicities = task.lookup.multiplicities.get(request)?;
        if table.len() != multiplicities.len() {
            return None;
        }
        let mut sum = EF::zero();
        for (&value, &multiplicity) in table.iter().zip(multiplicities) {
            let denominator = reciprocal + value;
            if denominator == EF::zero() {
                return None;
            }
            sum = sum + (EF::one() / denominator) * multiplicity;
        }
        infos.push(algebra::PolynomialInfo {
            num_variables: task.variables,
            max_multiplicands: 1,
        });
        claims.push(sum);
        infos.push(algebra::PolynomialInfo {
            num_variables: task.variables,
            max_multiplicands: if request_config.config.logical_len() == capacity {
                3
            } else {
                4
            },
        });
        claims.push(EF::zero());
    }
    Some((infos, claims))
}
fn interpolate_extension<F: NTTField, EF: AbstractExtensionField<F>>(
    values: &[EF],
    point: EF,
) -> EF {
    values
        .iter()
        .enumerate()
        .fold(EF::zero(), |sum, (i, &value)| {
            let at = EF::from_base(F::from(i));
            let basis = (0..values.len())
                .filter(|&j| j != i)
                .fold(EF::one(), |product, j| {
                    let node = EF::from_base(F::from(j));
                    product * (point - node) / (at - node)
                });
            sum + value * basis
        })
}
struct LookupBatchRound<F: algebra::Field, E> {
    equality: LookupEqualityTask<F, E>,
    infos: Vec<algebra::PolynomialInfo>,
    claims: Vec<E>,
    point: Vec<E>,
    expected: Vec<E>,
    evaluations: Vec<Vec<E>>,
}
fn decomposition_lookup_batch_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(LookupBatchRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (lookup, rest) = decomposition_lookup_algebra_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let LookupChallengeBoundary::Complete { accepted, .. } =
        lookup_challenge_walk::<F, EF>(&lookup.requests, rest, before)?
    else {
        return None;
    };
    let last = accepted.len().checked_sub(1)?;
    let (mut equality, mut rest) = decomposition_lookup_equality_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, last,
    )?;
    if round >= equality.variables {
        return None;
    }
    equality.points.push(replay_extension::<F, EF>(
        message(&mut rest, 5, b"shared lookup equality point")?,
        equality.variables,
        before,
    )?);
    let (infos, claims) = lookup_equations(&equality)?;
    if message(&mut rest, 1, b"independent scalar sumcheck batch v1")?
        != encoded(&(&infos, &claims))
    {
        return None;
    }
    let tail = lookup_scalar_tail::<F, EF>(b"scalar batch common challenge");
    let mut expected = claims.clone();
    let mut point = Vec::new();
    for current in 0..=round {
        let mut body = message(&mut rest, 1, b"scalar batch round messages")?;
        body = body.strip_prefix(encoded(&current).as_slice())?;
        vector_length(&mut body, infos.len())?;
        let evaluations = infos
            .iter()
            .map(|info| vector::<EF>(&mut body, info.max_multiplicands.checked_add(1)?))
            .collect::<Option<Vec<_>>>()?;
        if !body.is_empty()
            || evaluations
                .iter()
                .zip(&expected)
                .any(|(values, &claim)| values[0] + values[1] != claim)
        {
            return None;
        }
        rest = rest.strip_prefix(tail.as_slice())?;
        if current == round {
            return Some((
                LookupBatchRound {
                    equality,
                    infos,
                    claims,
                    point,
                    expected,
                    evaluations,
                },
                rest,
            ));
        }
        let coin = replay_extension::<F, EF>(
            message(&mut rest, 5, b"scalar batch common challenge")?,
            1,
            before,
        )?[0];
        expected = evaluations
            .iter()
            .map(|values| interpolate_extension::<F, EF>(values, coin))
            .collect();
        point.push(coin);
    }
    None
}
fn decomposition_lookup_batch_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<LookupBatchRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = decomposition_lookup_batch_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn lookup_equality<E: algebra::Field>(left: &[E], right: &[E]) -> E {
    left.iter().zip(right).fold(E::one(), |product, (&a, &b)| {
        product * (a * b + (E::one() - a) * (E::one() - b))
    })
}
fn lookup_mask<E: algebra::Field>(point: &[E], length: usize) -> Option<E> {
    let capacity = 1usize.checked_shl(u32::try_from(point.len()).ok()?)?;
    if length > capacity {
        return None;
    }
    if length == capacity {
        return Some(E::one());
    }
    let mut same = E::one();
    let mut result = E::zero();
    for index in (0..point.len()).rev() {
        if length >> index & 1 == 1 {
            result += same * (E::one() - point[index]);
            same *= point[index];
        } else {
            same *= E::one() - point[index];
        }
    }
    Some(result)
}
struct LookupTerminal<F: algebra::Field, E> {
    batch: LookupBatchRound<F, E>,
    source_values: Vec<Vec<F>>,
    helper_values: Vec<E>,
    source_query: crate::packed_extension::Query<F>,
    helper_query: crate::packed_extension::Query<F>,
    helper_claims: Vec<Vec<F>>,
}
fn decomposition_lookup_terminal_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<LookupTerminal<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let last = pp.helper.num_vars().checked_sub(1)?;
    let (mut batch, mut rest) = decomposition_lookup_batch_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, last,
    )?;
    let coin = replay_extension::<F, EF>(
        message(&mut rest, 5, b"scalar batch common challenge")?,
        1,
        before,
    )?[0];
    batch.expected = batch
        .evaluations
        .iter()
        .map(|values| interpolate_extension::<F, EF>(values, coin))
        .collect();
    batch.point.push(coin);
    let mut body = message(&mut rest, 1, b"shared lookup terminal values")?;
    let width = pp.coefficients.width();
    let source_values = rectangular::<F>(&mut body, batch.equality.lookup.sources.len(), width)?;
    let helper_values = vector::<EF>(&mut body, batch.equality.accepted.len())?;
    if !body.is_empty() || helper_values.iter().any(|value| !value.is_canonical()) {
        return None;
    }
    let digits = setup
        .config
        .decomposition::<F>()
        .ok()?
        .num_digits::<F>()
        .ok()?;
    for (index, values) in source_values.iter().enumerate() {
        let parameters = if index < digits {
            pp.coefficients
        } else {
            pp.borrows
        };
        parameters.validate_values(values).ok()?;
    }
    let source_query = crate::packed_extension::scalar_query::<F, EF>(
        pp.coefficients.num_vars(),
        width,
        &batch.point,
    )
    .ok()?;
    for (index, &(request_index, _, hash, reciprocal)) in batch.equality.accepted.iter().enumerate()
    {
        let h = helper_values[index];
        if batch.expected[2 * index] != h {
            return None;
        }
        let request = batch.equality.lookup.requests.get(request_index)?;
        let mut g = EF::zero();
        let mut power = EF::one();
        for &slot in &request.source_slots {
            let value = source_query.apply(source_values.get(slot)?, width).ok()?;
            g += power * crate::packed_extension::element::<F, EF>(width, &value).ok()?;
            power *= hash;
        }
        let mask = lookup_mask(&batch.point, request.config.logical_len())?;
        let residual = lookup_equality(&batch.equality.points[index], &batch.point)
            * (reciprocal * h + mask * g * h - mask);
        if residual != batch.expected[2 * index + 1] {
            return None;
        }
    }
    let helper_query =
        crate::packed_extension::coefficients_query::<F, EF>(pp.helper.width(), &batch.point)
            .ok()?;
    let helper_claims = helper_values
        .iter()
        .map(|&value| {
            Some(pp.helper.normalize_values(
                crate::packed_extension::vector::<F, EF>(pp.helper.width(), value).ok()?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let mut tail = Vec::new();
    frame(
        &mut tail,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    if rest != tail {
        return None;
    }
    Some(LookupTerminal {
        batch,
        source_values,
        helper_values,
        source_query,
        helper_query,
        helper_claims,
    })
}

fn decomposition_lookup_hash_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<DecompositionLookup<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (lookup, task) = decomposition_lookup_challenge_query::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    (task.request == 0 && task.repetition == 0 && task.phase == LookupChallengePhase::Hash)
        .then_some(lookup)
}

fn decomposition_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    let parent_before = views.get(child.parent_input)?;
    let opening = decomposition_opening_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        parent_before,
    )?;
    let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
    if child.label != label || child.context != context {
        return None;
    }
    Some((opening, child.rest))
}

fn decomposition_child_prefix_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    half: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if half == 0 {
        return decomposition_child_prefix::<F, EF, P>(
            profile, pp, setup, statement, input, before, views,
        );
    }
    if half != 1 {
        return None;
    }
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    let opening = decomposition_opening_query_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        views.get(child.parent_input)?,
        views,
        1,
    )?;
    let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
    if child.label != label || child.context != context {
        return None;
    }
    Some((opening, child.rest))
}
fn shake64(input: &[u8]) -> [u8; 64] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut state = sha3::Shake256::default();
    Update::update(&mut state, input);
    let mut out = [0; 64];
    state.finalize_xof().read(&mut out);
    out
}
fn raw_basis<F: NTTField, EF: AbstractExtensionField<F>>() -> Vec<u8> {
    let mut basis = (EF::D as u64).to_le_bytes().to_vec();
    for i in 0..EF::D {
        for j in 0..EF::D {
            let product = EF::monomial(i) * EF::monomial(j);
            for k in 0..EF::D {
                let value = product
                    .as_base_slice()
                    .get(k)
                    .copied()
                    .unwrap_or_else(F::zero)
                    .canonicalized();
                basis.extend(
                    value
                        .value()
                        .to_string()
                        .parse::<u128>()
                        .unwrap()
                        .to_le_bytes(),
                );
            }
        }
    }
    basis
}
fn raw_child<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
    label: &[u8],
    context: &[u8],
    seed: &[u8; 64],
) -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, 0, b"protocol", b"HasteBoots framed SHAKE256 v1");
    frame(
        &mut out,
        0,
        b"application",
        b"HasteBoots framed SHAKE256 child v1",
    );
    frame(&mut out, 0, b"trusted profile", &profile.id().0);
    frame(&mut out, 1, b"child label", label);
    frame(&mut out, 1, b"child context", context);
    frame(&mut out, 1, b"parent seed", seed);
    let basis = raw_basis::<F, EF>();
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &basis);
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let mut request = p.to_le_bytes().to_vec();
    request.extend(0u64.to_le_bytes());
    frame(&mut out, 4, b"typed extension identity", &request);
    frame(&mut out, 5, b"typed extension identity", &receipt(&[]).0);
    out
}

type FirstViews = std::collections::HashMap<Vec<u8>, Producers>;
fn fragment_first_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
) -> Option<Vec<u8>> {
    fragment_first_tail_for_role::<F, EF>(profile, 0)
}
fn fragment_first_tail_for_role<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<Vec<u8>> {
    let label: &[u8] = match profile.specification().backend {
        Backend::FragmentedPipfri => b"fragmented lane projections",
        Backend::FragmentedPipfriVirtual => b"virtual bridge lane projections v2",
        _ => return None,
    };
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let count = profile
        .specification()
        .roles
        .get(role_index)?
        .width
        .checked_mul(EF::D)?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(&mut out, 4, label, &descriptor);
    Some(out)
}
struct TypedChild<'a, 'b> {
    label: &'a [u8],
    context: &'a [u8],
    parent_input: &'b [u8],
    rest: &'a [u8],
}
fn typed_child_prefix<'a, 'b, F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
    input: &'a [u8],
    before: &'b Producers,
) -> Option<TypedChild<'a, 'b>> {
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
        b"HasteBoots framed SHAKE256 child v1",
    );
    frame(&mut header, 0, b"trusted profile", &profile.id().0);
    let mut rest = input.strip_prefix(header.as_slice())?;
    let label = message(&mut rest, 1, b"child label")?;
    let context = message(&mut rest, 1, b"child context")?;
    let seed: [u8; 64] = message(&mut rest, 1, b"parent seed")?.try_into().ok()?;
    let parent_input = before.get(&seed)?;
    if shake64(parent_input) != seed {
        return None;
    }
    // A prior XOF answer is insufficient: this producer must be a framed
    // parent fork for this exact child. Its intervening algebra/PCS body is
    // still checked by the caller's parent-prefix interpreter.
    let mut parent_header = parent_input.as_slice();
    if message(&mut parent_header, 0, b"protocol")? != b"HasteBoots framed SHAKE256 v1" {
        return None;
    }
    let application = message(&mut parent_header, 0, b"application")?;
    if ![
        b"HasteBoots typed classical prime v1".as_slice(),
        b"HasteBoots typed classical extension v1".as_slice(),
        b"HasteBoots framed SHAKE256 child v1".as_slice(),
    ].contains(&application)
        || message(&mut parent_header, 0, b"trusted profile")? != profile.id().0
    {
        return None;
    }
    let mut fork_tail = Vec::new();
    frame(&mut fork_tail, 6, label, context);
    frame(&mut fork_tail, 2, b"classical child seed", &64u64.to_le_bytes());
    if !parent_input.ends_with(&fork_tail) {
        return None;
    }
    replay_receipt::<F>(&receipt(&[]).0, 0, before)?;
    let raw = raw_child::<F, EF>(profile, label, context, &seed);
    Some(TypedChild {
        label,
        context,
        parent_input,
        rest: input.strip_prefix(raw.as_slice())?,
    })
}
fn ntt_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttBatchTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, before)?;
    let parent_before = views.get(child.parent_input)?;
    let batch = ntt_batch_seed_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        parent_before,
    )?;
    let (_, label, context) = pcs_child_labels(profile.specification().backend)?;
    if child.label != label || child.context != context {
        return None;
    }
    Some((batch, child.rest))
}

fn ntt_fragment_projection_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
    count: usize,
) -> Option<(Vec<u8>, &'static [u8])> {
    let label: &[u8] = match profile.specification().backend {
        Backend::FragmentedPipfri => b"fragmented lane projections",
        Backend::FragmentedPipfriVirtual => b"virtual bridge lane projections v2",
        _ => return None,
    };
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count.checked_mul(EF::D)?).ok()?.to_le_bytes());
    frame(&mut out, 4, label, &descriptor);
    Some((out, label))
}
fn ntt_fragment_projection_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttBatchTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (batch, rest) =
        ntt_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let count = batch
        .queries
        .len()
        .checked_mul(batch.ntt.row.shape.width())?;
    let tail = ntt_fragment_projection_tail::<F, EF>(profile, count)?.0;
    Some((batch, rest.strip_prefix(tail.as_slice())?))
}
struct NttFragmentRound<F, E> {
    batch: NttBatchTask<F>,
    rho: Vec<E>,
    point: Vec<E>,
    expected: E,
    evaluations: Vec<E>,
}
fn ntt_fragment_round_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(NttFragmentRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (batch, rest) = ntt_fragment_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let (rho, point, expected, evaluations, rest) = fragment_batch_round_prefix::<F, EF>(
        profile,
        batch.values(),
        batch.ntt.row.shape.width(),
        rest,
        before,
        round,
    )?;
    Some((
        NttFragmentRound {
            batch,
            rho,
            point,
            expected,
            evaluations,
        },
        rest,
    ))
}

// Claim/lane-independent bridge grammar, after the caller binds its child
// origin and exact projection request. No committed-word acceptance here.
fn fragment_batch_round_prefix<'a, F, EF>(
    profile: &ClassicalProfile,
    values: &[Vec<F>],
    width: usize,
    mut rest: &'a [u8],
    before: &Producers,
    round: usize,
) -> Option<(Vec<EF>, Vec<EF>, EF, Vec<EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    if values.is_empty() || values.iter().any(|row| row.len() != width) {
        return None;
    }
    let count = values.len().checked_mul(width)?;
    let label = ntt_fragment_projection_tail::<F, EF>(profile, count)?.1;
    let rho = replay_extension::<F, EF>(message(&mut rest, 5, label)?, count, before)?;
    let mut expected = rho
        .iter()
        .zip(values.iter().flatten())
        .fold(EF::zero(), |sum, (&r, &v)| sum + r * EF::from_base(v));
    let n = role_vars_for_bridge(profile);
    if round >= n {
        return None;
    }
    let info = algebra::PolynomialInfo {
        num_variables: n,
        max_multiplicands: 2,
    };
    if message(&mut rest, 1, b"polynomial info")? != encoded(&info) {
        return None;
    }
    let tail = bridge_round_tail::<F, EF>();
    let mut point = Vec::new();
    for index in 0..=round {
        let mut body = message(&mut rest, 1, b"sumcheck msg")?;
        let evaluations = vector::<EF>(&mut body, 3)?;
        if !body.is_empty() || evaluations[0] + evaluations[1] != expected {
            return None;
        }
        rest = rest.strip_prefix(tail.as_slice())?;
        if index == round {
            return Some((rho, point, expected, evaluations, rest));
        }
        let coin = replay_extension::<F, EF>(
            message(&mut rest, 5, b"random point in each round")?,
            1,
            before,
        )?[0];
        expected = quadratic(&evaluations, coin);
        point.push(coin);
    }
    None
}

fn ntt_fragment_round_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<NttFragmentRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = ntt_fragment_round_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
struct NttScalarGamma<F, E> {
    bridge: NttFragmentRound<F, E>,
    point: Vec<E>,
    bridge_expected: E,
    value: E,
    fragments: Vec<E>,
}
fn ntt_scalar_gamma_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttScalarGamma<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let n = role_vars_for_bridge(profile);
    let (bridge, mut rest) = ntt_fragment_round_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        n.checked_sub(1)?,
    )?;
    let coin = replay_extension::<F, EF>(
        message(&mut rest, 5, b"random point in each round")?,
        1,
        before,
    )?[0];
    let bridge_expected = quadratic(&bridge.evaluations, coin);
    let mut point = bridge.point.clone();
    point.push(coin);
    let (value, fragments, rest) =
        fragment_scalar_gamma_tail::<F, EF>(profile, &bridge.batch.source().1, &point, rest)?;
    Some((
        NttScalarGamma {
            bridge,
            point,
            bridge_expected,
            value,
            fragments,
        },
        rest,
    ))
}

// Bind scalar PCS mode, trusted source and full bridge point before gamma.
fn fragment_scalar_gamma_tail<'a, F, EF>(
    profile: &ClassicalProfile,
    root: &Commitment<Digest512>,
    point: &[EF],
    mut rest: &'a [u8],
) -> Option<(EF, Vec<EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (n, r, count, context, _) = scalar_geometry::<F, EF>(profile)?;
    if point.len() != n {
        return None;
    }
    let virtual_source = profile.specification().backend == Backend::FragmentedPipfriVirtual;
    if virtual_source {
        if message(&mut rest, 1, b"unmasked virtual PipFRI PCS v2")? != encoded(&n) {
            return None;
        }
    } else if message(&mut rest, 1, b"ordinary PipFRI PCS adapter v1")?
        != encoded(&(n, b"base table".as_slice()))
    {
        return None;
    }
    let mut body = message(
        &mut rest,
        1,
        if virtual_source {
            b"unmasked scalar PipFRI virtual v2"
        } else {
            b"HasteBoots ordinary PipFRI v1"
        },
    )?;
    let prefix = if virtual_source {
        encoded(&(2u32, context, root, &point))
    } else {
        encoded(&(context, root, &point))
    };
    body = body.strip_prefix(prefix.as_slice())?;
    let (value, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if body.get(..used)? != encoded(&value) {
        return None;
    }
    body = body.get(used..)?;
    let fragments = vector::<EF>(&mut body, count)?;
    if !body.is_empty() {
        return None;
    }
    let tail = gamma_tail::<F, EF>(profile)?.0;
    rest = rest.strip_prefix(tail.as_slice())?;
    let mut aggregate = fragments.clone();
    for &coordinate in &point[r..] {
        aggregate = aggregate
            .chunks_exact(2)
            .map(|pair| (EF::one() - coordinate) * pair[0] + coordinate * pair[1])
            .collect();
    }
    if aggregate.as_slice() != [value] {
        return None;
    }
    Some((value, fragments, rest))
}

fn ntt_scalar_gamma_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<NttScalarGamma<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        ntt_scalar_gamma_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    rest.is_empty().then_some(task)
}

fn primary_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    child_before: &Producers,
    first_views: &FirstViews,
    expected_index: Option<usize>,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let child = typed_child_prefix::<F, EF>(profile, input, child_before)?;
    let parent_before = first_views.get(child.parent_input)?;
    let opening = factor_seed_any::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child.parent_input,
        parent_before,
    )?;
    let index = opening.selected;
    if expected_index.is_some_and(|expected| expected != index) {
        return None;
    }
    let parameters = if index % 2 == 1 {
        pp.key
    } else {
        pp.evaluations
    };
    let (_, expected_label, expected_context) =
        factor_seed_tail::<F, P>(profile, parameters, &opening, index)?;
    if child.label != expected_label || child.context != expected_context {
        return None;
    }
    Some((opening, child.rest))
}

fn matrix_child_at<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    index: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if let Some(task) = primary_child_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        Some(index),
    ) {
        return Some(task);
    }
    if let Some((opening, rest)) =
        decomposition_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)
    {
        return (opening.selected == index && opening.family == OpeningFamily::Decomposition)
            .then_some((opening, rest));
    }
    if let Some((opening, rest)) = decomposition_lookup_helper_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    ) {
        return (opening.selected == index && opening.family == OpeningFamily::LookupHelper)
            .then_some((opening, rest));
    }
    if let Some((opening, rest)) = decomposition_child_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 1,
    ) {
        return (opening.selected == index && opening.family == OpeningFamily::SecondDecomposition)
            .then_some((opening, rest));
    }
    if let Some((opening, rest)) = decomposition_lookup_helper_child_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 1,
    ) {
        return (opening.selected == index && opening.family == OpeningFamily::SecondLookupHelper)
            .then_some((opening, rest));
    }
    if let Some((opening, rest)) = decomposition_lookup_source_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    ) {
        return (index == 0 && matches!(opening.family, OpeningFamily::LookupSource { .. }))
            .then_some((opening, rest));
    }
    let (opening, rest) = decomposition_lookup_source_child_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 1,
    )?;
    (index == 0 && matches!(opening.family, OpeningFamily::SecondLookupSource { .. }))
        .then_some((opening, rest))
}

fn matrix_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    primary_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views, None)
        .or_else(|| {
            decomposition_child_prefix::<F, EF, P>(
                profile, pp, setup, statement, input, before, views,
            )
        })
        .or_else(|| {
            decomposition_lookup_helper_child_prefix::<F, EF, P>(
                profile, pp, setup, statement, input, before, views,
            )
        })
        .or_else(|| {
            decomposition_child_prefix_at::<F, EF, P>(
                profile, pp, setup, statement, input, before, views, 1,
            )
        })
        .or_else(|| {
            decomposition_lookup_source_child_prefix::<F, EF, P>(
                profile, pp, setup, statement, input, before, views,
            )
        })
        .or_else(|| {
            decomposition_lookup_helper_child_prefix_at::<F, EF, P>(
                profile, pp, setup, statement, input, before, views, 1,
            )
        })
        .or_else(|| {
            decomposition_lookup_source_child_prefix_at::<F, EF, P>(
                profile, pp, setup, statement, input, before, views, 1,
            )
        })
}

fn factor_child_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    index: usize,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    primary_child_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        Some(index),
    )
}

fn fragment_first_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(FirstOpening<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) =
        matrix_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let tail = fragment_first_tail_for_role::<F, EF>(profile, opening.role())?;
    Some((opening, rest.strip_prefix(tail.as_slice())?))
}

// The first direct/dictionary consistency task is fixed by the parent's
// opening and the complete public ladder, before its atomic index block.
struct DirectTask<F, E> {
    opening: FirstOpening<F>,
    roots: Vec<Digest512>,
    domain: usize,
    core: pcs::packed_polyfrim::authenticated::Parameters<E>,
}
fn direct_core<F: NTTField, EF: AbstractExtensionField<F> + Serialize>(
    profile: &ClassicalProfile,
) -> Option<(pcs::packed_polyfrim::authenticated::Parameters<EF>, usize)> {
    direct_core_for_role::<F, EF>(profile, 0)
}
fn direct_core_for_role<F: NTTField, EF: AbstractExtensionField<F> + Serialize>(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<(pcs::packed_polyfrim::authenticated::Parameters<EF>, usize)> {
    let role = profile.specification().roles.get(role_index)?;
    let rounds = role.num_vars;
    let message_size = 1usize.checked_shl(u32::try_from(rounds).ok()?)?;
    let domain = message_size.checked_mul(profile.specification().blowup)?;
    let bits = domain.ilog2();
    let mut root = F::get_ntt_root(bits.max(5)).ok()?;
    for _ in bits..bits.max(5) {
        root *= root;
    }
    let core = pcs::packed_polyfrim::authenticated::Parameters::new(
        message_size,
        role.width,
        profile.specification().blowup,
        role.queries,
        EF::from_base(root),
    )
    .ok()?;
    Some((core, domain))
}

fn direct_first_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    factor: usize,
) -> Option<(DirectTask<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if !matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        return None;
    }
    let (opening, mut rest) =
        matrix_child_at::<F, EF, P>(profile, pp, setup, statement, input, before, views, factor)?;
    let role = &profile.specification().roles[opening.role()];
    // Classical primary factors share role-zero geometry. Zero-variable
    // dummy coordinates require their own explicit (I,0) normalization audit.
    if role.num_vars == 0 {
        return None;
    }
    let rounds = role.num_vars;
    let (core, domain) = direct_core_for_role::<F, EF>(profile, opening.role())?;
    let parameters = opening.parameters(pp, factor)?;
    let (query, value) = parameters
        .normalize_claim(opening.query.clone(), opening.values[factor].clone())
        .ok()?;
    let lifted: Vec<_> = query
        .iter()
        .map(|pair| {
            Some(algebra::matrix_weighted::MatrixPair {
                zero: algebra::matrix_weighted::Matrix::new(
                    role.width,
                    pair.zero
                        .values()
                        .iter()
                        .copied()
                        .map(EF::from_base)
                        .collect(),
                )
                .ok()?,
                one: algebra::matrix_weighted::Matrix::new(
                    role.width,
                    pair.one
                        .values()
                        .iter()
                        .copied()
                        .map(EF::from_base)
                        .collect(),
                )
                .ok()?,
            })
        })
        .collect::<Option<_>>()?;
    let claims = vec![value.into_iter().map(EF::from_base).collect::<Vec<_>>()];
    let queries = vec![lifted];
    let source = opening.sources[factor].1.root;
    let body = message(&mut rest, 1, b"packed PolyFRIM joint query proximity v1")?;
    let prefix = encoded(&(&core, source, 1usize, &queries, &claims));
    let mut body = body.strip_prefix(prefix.as_slice())?;
    body = body.strip_prefix(encoded(&1usize).as_slice())?;
    let roots = vector::<Digest512>(&mut body, rounds)?;
    if !body.is_empty() || roots.first() != Some(&source) {
        return None;
    }
    if message(&mut rest, 1, b"packed PolyFRIM joint consistency member v1")? != encoded(&0usize) {
        return None;
    }
    if message(&mut rest, 1, b"packed PolyFRIM consistency v2")?
        != encoded(&(&core, source, &roots[1..], &queries[0], &claims[0]))
    {
        return None;
    }
    if message(&mut rest, 1, b"index domain")? != u64::try_from(domain).ok()?.to_le_bytes() {
        return None;
    }
    if message(&mut rest, 2, b"packed PolyFRIM domain index v2")?
        != u64::try_from(role.queries.checked_mul(8)?)
            .ok()?
            .to_le_bytes()
    {
        return None;
    }
    Some((
        DirectTask {
            opening,
            roots,
            domain,
            core,
        },
        rest,
    ))
}

fn direct_first_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(FirstOpening<F>, Vec<Digest512>, usize)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        direct_first_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views, 0)?;
    rest.is_empty()
        .then_some((task.opening, task.roots, task.domain))
}

fn direct_projection_count_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
    claims: usize,
) -> Option<Vec<u8>> {
    direct_projection_role_tail::<F, EF>(profile, claims, 0)
}
fn direct_projection_role_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
    claims: usize,
    role_index: usize,
) -> Option<Vec<u8>> {
    if !matches!(profile.version(), 4 | 5) {
        return None;
    }
    let role = profile.specification().roles.get(role_index)?;
    let count = role
        .num_vars
        .checked_mul(claims)?
        .checked_mul(role.width)?
        .checked_mul(EF::D)?;
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(
        &mut out,
        4,
        b"packed PolyFRIM atomic joint lane weights v3",
        &descriptor,
    );
    Some(out)
}

fn direct_projection_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
) -> Option<Vec<u8>> {
    direct_projection_count_tail::<F, EF>(profile, 1)
}

fn direct_projection_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    factor: usize,
) -> Option<(DirectTask<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, mut rest) = direct_first_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, factor,
    )?;
    let bytes = message(&mut rest, 3, b"packed PolyFRIM domain index v2")?;
    let count = profile.specification().roles[task.opening.role()]
        .queries
        .checked_mul(8)?;
    if bytes.len() != count {
        return None;
    }
    // The inline previous output is a fixed part of this candidate input.
    // Its provenance is a prior-phase obligation; the projection task depends
    // on the ladder, not those sampled indices. Do not query an unknown oracle
    // input while interpreting this candidate's current task.
    if message(&mut rest, 1, b"packed PolyFRIM joint projections v1")?
        != encoded(&(&task.core, vec![task.roots.clone()]))
    {
        return None;
    }
    let tail = direct_projection_role_tail::<F, EF>(profile, 1, task.opening.role())?;
    Some((task, rest.strip_prefix(tail.as_slice())?))
}

fn direct_projection_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<DirectTask<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 0,
    )?;
    rest.is_empty().then_some(task)
}

struct DirectRolling<F, E> {
    direct: DirectTask<F, E>,
    weights: Vec<E>,
    originals: Vec<RollingRoot>,
    derived: Vec<RollingRoot>,
    alphas: Vec<E>,
}
struct NttDirectTask<F, E> {
    batch: NttBatchTask<F>,
    core: pcs::packed_polyfrim::authenticated::Parameters<E>,
    roots: Vec<Vec<Digest512>>,
    domain: usize,
}
fn ntt_direct_consistency_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    member: usize,
) -> Option<(NttDirectTask<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    if !matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        return None;
    }
    let (batch, rest) =
        ntt_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let (core, roots, domain, rest) = direct_batch_consistency_prefix::<F, EF, P>(
        profile,
        batch.parameters(pp),
        batch.source().1.root,
        &batch.queries,
        batch.values(),
        rest,
        member,
    )?;
    Some((
        NttDirectTask {
            batch,
            core,
            roots,
            domain,
        },
        rest,
    ))
}

// Shared role-zero batch grammar. Callers must first recover a typed child
// from its own frozen parent view and supply the trusted source parameters.
fn direct_batch_consistency_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    source: Digest512,
    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
    values: &[Vec<F>],
    mut rest: &'a [u8],
    member: usize,
) -> Option<(
    pcs::packed_polyfrim::authenticated::Parameters<EF>,
    Vec<Vec<Digest512>>,
    usize,
    &'a [u8],
)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let claims = queries.len();
    if values.len() != claims {
        return None;
    }
    if member >= claims {
        return None;
    }
    let role = &profile.specification().roles[0];
    if role.num_vars == 0 {
        return None;
    }
    let (core, domain) = direct_core::<F, EF>(profile)?;
    let mut lifted_queries = Vec::with_capacity(claims);
    let mut lifted_values = Vec::with_capacity(claims);
    for (query, value) in queries.iter().zip(values) {
        let (query, value) = parameters
            .normalize_claim(query.clone(), value.clone())
            .ok()?;
        let lifted = query
            .iter()
            .map(|pair| {
                Some(algebra::matrix_weighted::MatrixPair {
                    zero: algebra::matrix_weighted::Matrix::new(
                        role.width,
                        pair.zero
                            .values()
                            .iter()
                            .copied()
                            .map(EF::from_base)
                            .collect(),
                    )
                    .ok()?,
                    one: algebra::matrix_weighted::Matrix::new(
                        role.width,
                        pair.one
                            .values()
                            .iter()
                            .copied()
                            .map(EF::from_base)
                            .collect(),
                    )
                    .ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        lifted_queries.push(lifted);
        lifted_values.push(value.into_iter().map(EF::from_base).collect::<Vec<_>>());
    }
    let queries = lifted_queries;
    let values = lifted_values;
    let mut body = message(&mut rest, 1, b"packed PolyFRIM joint query proximity v1")?;
    body = body.strip_prefix(encoded(&(&core, source, claims, &queries, &values)).as_slice())?;
    body = body.strip_prefix(encoded(&claims).as_slice())?;
    let roots: Vec<_> = (0..claims)
        .map(|_| vector::<Digest512>(&mut body, role.num_vars))
        .collect::<Option<_>>()?;
    if !body.is_empty() || roots.iter().any(|row| row.first() != Some(&source)) {
        return None;
    }
    let request = u64::try_from(role.queries.checked_mul(8)?)
        .ok()?
        .to_le_bytes();
    for index in 0..=member {
        if message(&mut rest, 1, b"packed PolyFRIM joint consistency member v1")? != encoded(&index)
        {
            return None;
        }
        if message(&mut rest, 1, b"packed PolyFRIM consistency v2")?
            != encoded(&(
                &core,
                source,
                &roots[index][1..],
                &queries[index],
                &values[index],
            ))
        {
            return None;
        }
        if message(&mut rest, 1, b"index domain")? != (domain as u64).to_le_bytes() {
            return None;
        }
        if message(&mut rest, 2, b"packed PolyFRIM domain index v2")? != request {
            return None;
        }
        if index == member {
            return Some((core, roots, domain, rest));
        }
        if message(&mut rest, 3, b"packed PolyFRIM domain index v2")?.len()
            != role.queries.checked_mul(8)?
        {
            return None;
        }
    }
    None
}
fn ntt_direct_consistency_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    member: usize,
) -> Option<NttDirectTask<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = ntt_direct_consistency_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, member,
    )?;
    rest.is_empty().then_some(task)
}

fn ntt_direct_projection_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttDirectTask<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let claims = profile.specification().roles[0].width;
    let (task, rest) = ntt_direct_consistency_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        claims.checked_sub(1)?,
    )?;
    if task.batch.queries.len() != claims {
        return None;
    }
    let rest = direct_batch_projection_tail::<F, EF>(profile, &task.core, &task.roots, rest)?;
    Some((task, rest))
}

fn direct_batch_projection_tail<'a, F, EF>(
    profile: &ClassicalProfile,
    core: &pcs::packed_polyfrim::authenticated::Parameters<EF>,
    roots: &[Vec<Digest512>],
    mut rest: &'a [u8],
) -> Option<&'a [u8]>
where
    F: NTTField,
    EF: AbstractExtensionField<F> + Serialize,
{
    if message(&mut rest, 3, b"packed PolyFRIM domain index v2")?.len()
        != profile.specification().roles[0].queries.checked_mul(8)?
    {
        return None;
    }
    if message(&mut rest, 1, b"packed PolyFRIM joint projections v1")? != encoded(&(core, roots)) {
        return None;
    }
    let tail = direct_projection_count_tail::<F, EF>(profile, roots.len())?;
    rest.strip_prefix(tail.as_slice())
}

fn ntt_direct_projection_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<NttDirectTask<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = ntt_direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    rest.is_empty().then_some(task)
}

fn direct_fri<F: NTTField, EF: AbstractExtensionField<F> + Serialize>(
    profile: &ClassicalProfile,
) -> Option<pcs::rolling_fri::Parameters<EF>> {
    direct_fri_for_role::<F, EF>(profile, 0)
}
fn direct_fri_for_role<F: NTTField, EF: AbstractExtensionField<F> + Serialize>(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<pcs::rolling_fri::Parameters<EF>> {
    let role = profile.specification().roles.get(role_index)?;
    let size = 1usize.checked_shl(u32::try_from(role.num_vars).ok()?)?;
    let domain = size.checked_mul(profile.specification().blowup)?;
    let bits = domain.ilog2();
    let mut root = F::get_ntt_root(bits.max(5)).ok()?;
    for _ in bits..bits.max(5) {
        root *= root;
    }
    pcs::rolling_fri::Parameters::new(
        size,
        profile.specification().blowup,
        role.queries,
        EF::from_base(root),
    )
    .ok()
}
struct DirectRollingData<E> {
    weights: Vec<E>,
    originals: Vec<RollingRoot>,
    derived: Vec<RollingRoot>,
    alphas: Vec<E>,
}
fn direct_rolling_data_prefix<'a, F, EF>(
    profile: &ClassicalProfile,
    role_index: usize,
    core: &pcs::packed_polyfrim::authenticated::Parameters<EF>,
    roots: &[Vec<Digest512>],
    mut rest: &'a [u8],
    before: &Producers,
    round: usize,
) -> Option<(DirectRollingData<EF>, &'a [u8])>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let role = profile.specification().roles.get(role_index)?;
    if round >= role.num_vars || roots.is_empty() {
        return None;
    }
    let count = role
        .num_vars
        .checked_mul(roots.len())?
        .checked_mul(role.width)?;
    let weights = replay_extension::<F, EF>(
        message(
            &mut rest,
            5,
            b"packed PolyFRIM atomic joint lane weights v3",
        )?,
        count,
        before,
    )?;
    let originals: Vec<_> = weights
        .chunks_exact(roots.len().checked_mul(role.width)?)
        .enumerate()
        .map(|(layer, row)| {
            let rows: Vec<_> = row.chunks_exact(role.width).map(<[EF]>::to_vec).collect();
            RollingRoot {
                root: Digest512(
                    Sha512::digest(encoded(&(
                        b"packed PolyFRIM joint virtual layer v1".as_slice(),
                        core,
                        layer,
                        &roots,
                        &rows,
                    )))
                    .into(),
                ),
            }
        })
        .collect();
    let fri = direct_fri_for_role::<F, EF>(profile, role_index)?;
    let context = Digest512(
        Sha512::digest(encoded(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            EF::MODULUS_VALUE.to_string(),
            &fri,
        )))
        .into(),
    );
    if message(&mut rest, 1, b"HasteBoots rolling batch FRI virtual all v2")?
        != encoded(&(context, &originals))
    {
        return None;
    }
    let mut derived = Vec::new();
    let mut alphas = Vec::new();
    let tail = rolling_alpha_tail::<F, EF>();
    for index in 0..=round {
        rest = rest.strip_prefix(tail.as_slice())?;
        if index == round {
            return Some((
                DirectRollingData {
                    weights,
                    originals,
                    derived,
                    alphas,
                },
                rest,
            ));
        }
        alphas.push(
            replay_extension::<F, EF>(
                message(&mut rest, 5, b"rolling FRI fold challenge")?,
                1,
                before,
            )?[0],
        );
        let mut body = message(&mut rest, 1, b"rolling FRI derived root")?;
        body = body.strip_prefix(encoded(&(index + 1)).as_slice())?;
        let (root, used): (RollingRoot, usize) =
            bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
        if used != body.len() || encoded(&root) != body {
            return None;
        }
        derived.push(root);
    }
    None
}
fn direct_rolling_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    factor: usize,
    round: usize,
) -> Option<(DirectRolling<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (direct, rest) = direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, factor,
    )?;
    let (data, rest) = direct_rolling_data_prefix::<F, EF>(
        profile,
        direct.opening.role(),
        &direct.core,
        &[direct.roots.clone()],
        rest,
        before,
        round,
    )?;
    Some((
        DirectRolling {
            direct,
            weights: data.weights,
            originals: data.originals,
            derived: data.derived,
            alphas: data.alphas,
        },
        rest,
    ))
}

fn direct_rolling_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<DirectRolling<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = direct_rolling_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, 0, round,
    )?;
    rest.is_empty().then_some(task)
}
fn direct_rolling_indices_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    factor: usize,
) -> Option<(DirectRolling<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, _) =
        matrix_child_at::<F, EF, P>(profile, pp, setup, statement, input, before, views, factor)?;
    let role = &profile.specification().roles[opening.role()];
    let (mut task, mut rest) = direct_rolling_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        factor,
        role.num_vars.checked_sub(1)?,
    )?;
    task.alphas.push(
        replay_extension::<F, EF>(
            message(&mut rest, 5, b"rolling FRI fold challenge")?,
            1,
            before,
        )?[0],
    );
    let body = message(&mut rest, 1, b"rolling FRI terminal")?;
    let (terminal, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if used != body.len() || encoded(&terminal) != body {
        return None;
    }
    if message(&mut rest, 1, b"index domain")? != (task.direct.domain as u64).to_le_bytes() {
        return None;
    }
    if message(&mut rest, 2, b"rolling FRI unbiased domain index")?
        != u64::try_from(role.queries.checked_mul(8)?)
            .ok()?
            .to_le_bytes()
        || !rest.is_empty()
    {
        return None;
    }
    Some((task, terminal))
}

struct NttDirectRolling<F, E> {
    direct: NttDirectTask<F, E>,
    data: DirectRollingData<E>,
}
fn ntt_direct_rolling_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(NttDirectRolling<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (direct, rest) = ntt_direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let (data, rest) = direct_rolling_data_prefix::<F, EF>(
        profile,
        0,
        &direct.core,
        &direct.roots,
        rest,
        before,
        round,
    )?;
    Some((NttDirectRolling { direct, data }, rest))
}
fn ntt_direct_rolling_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<NttDirectRolling<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = ntt_direct_rolling_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn ntt_direct_rolling_indices<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttDirectRolling<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let role = &profile.specification().roles[0];
    let (mut task, mut rest) = ntt_direct_rolling_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        role.num_vars.checked_sub(1)?,
    )?;
    task.data.alphas.push(
        replay_extension::<F, EF>(
            message(&mut rest, 5, b"rolling FRI fold challenge")?,
            1,
            before,
        )?[0],
    );
    let body = message(&mut rest, 1, b"rolling FRI terminal")?;
    let (terminal, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if used != body.len() || encoded(&terminal) != body {
        return None;
    }
    if message(&mut rest, 1, b"index domain")? != (task.direct.domain as u64).to_le_bytes() {
        return None;
    }
    if message(&mut rest, 2, b"rolling FRI unbiased domain index")?
        != u64::try_from(role.queries.checked_mul(8)?)
            .ok()?
            .to_le_bytes()
        || !rest.is_empty()
    {
        return None;
    }
    Some((task, terminal))
}

fn direct_rolling_indices<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(DirectRolling<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    direct_rolling_indices_at::<F, EF, P>(profile, pp, setup, statement, input, before, views, 0)
}

fn fragment_first_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<FirstOpening<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, rest) =
        fragment_first_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    rest.is_empty().then_some(opening)
}
fn replay_extension<F: NTTField, EF: AbstractExtensionField<F>>(
    receipt: &[u8],
    count: usize,
    before: &Producers,
) -> Option<Vec<EF>> {
    let values = replay_receipt::<F>(receipt, count.checked_mul(EF::D)?, before)?;
    Some(
        values
            .chunks_exact(EF::D)
            .map(|coefficients| EF::from_base_fn(|i| coefficients[i]))
            .collect(),
    )
}
fn quadratic<E: algebra::Field>(values: &[E], point: E) -> E {
    let one = E::one();
    let two = one + one;
    values[0] * (point - one) * (point - two) / two - values[1] * point * (point - two)
        + values[2] * point * (point - one) / two
}
fn role_vars_for_bridge(profile: &ClassicalProfile) -> usize {
    role_vars_for_bridge_at(profile, 0)
}
fn role_vars_for_bridge_at(profile: &ClassicalProfile, role_index: usize) -> usize {
    let role = &profile.specification().roles[role_index];
    role.num_vars + role.width.ilog2() as usize
}
fn bridge_round_tail<F: NTTField, EF: AbstractExtensionField<F>>() -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"scalar");
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let mut request = p.to_le_bytes().to_vec();
    request.extend((EF::D as u64).to_le_bytes());
    frame(&mut out, 4, b"random point in each round", &request);
    out
}
struct FragmentRound<F, E> {
    opening: FirstOpening<F>,
    rho: Vec<E>,
    point: Vec<E>,
    expected: E,
    evaluations: Vec<E>,
}
fn fragment_round_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(FragmentRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, mut rest) =
        fragment_first_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let role = &profile.specification().roles[opening.role()];
    if !role.width.is_power_of_two() {
        return None;
    }
    let n = role.num_vars.checked_add(role.width.ilog2() as usize)?;
    if round >= n {
        return None;
    }
    let label = if profile.specification().backend == Backend::FragmentedPipfri {
        b"fragmented lane projections".as_slice()
    } else {
        b"virtual bridge lane projections v2"
    };
    let rho = replay_extension::<F, EF>(message(&mut rest, 5, label)?, role.width, before)?;
    let mut expected = rho
        .iter()
        .zip(&opening.values[opening.selected])
        .fold(EF::zero(), |v, (&r, &value)| v + r * EF::from_base(value));
    let info = algebra::PolynomialInfo {
        num_variables: n,
        max_multiplicands: 2,
    };
    if message(&mut rest, 1, b"polynomial info")? != encoded(&info) {
        return None;
    }
    let tail = bridge_round_tail::<F, EF>();
    let mut point = Vec::new();
    for index in 0..=round {
        let mut body = message(&mut rest, 1, b"sumcheck msg")?;
        let evaluations = vector::<EF>(&mut body, 3)?;
        // Production defers these checks until the final round. A failed
        // prefix has no accepting continuation and can be excluded here.
        if !body.is_empty() || evaluations[0] + evaluations[1] != expected {
            return None;
        }
        rest = rest.strip_prefix(tail.as_slice())?;
        if index == round {
            return Some((
                FragmentRound {
                    opening,
                    rho,
                    point,
                    expected,
                    evaluations,
                },
                rest,
            ));
        }
        let coin = replay_extension::<F, EF>(
            message(&mut rest, 5, b"random point in each round")?,
            1,
            before,
        )?[0];
        expected = quadratic(&evaluations, coin);
        point.push(coin);
    }
    None
}

fn fragment_round_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<FragmentRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = fragment_round_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn scalar_geometry<F: NTTField + Serialize, EF: AbstractExtensionField<F> + Serialize>(
    profile: &ClassicalProfile,
) -> Option<(usize, usize, usize, Digest512, Digest512)> {
    scalar_geometry_for_role::<F, EF>(profile, 0)
}
fn scalar_geometry_for_role<F: NTTField + Serialize, EF: AbstractExtensionField<F> + Serialize>(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<(usize, usize, usize, Digest512, Digest512)> {
    let n = role_vars_for_bridge_at(profile, role_index);
    let physical = n.max(1);
    let r = physical.min(profile.specification().fragment_vars?);
    let length = 1usize.checked_shl(u32::try_from(r).ok()?)?;
    let total = 1usize.checked_shl(u32::try_from(physical).ok()?)?;
    let b = profile.specification().blowup;
    let q = profile.specification().roles.get(role_index)?.queries;
    let encoded_len = length.checked_mul(b)?;
    let log = encoded_len.ilog2();
    let mut root = F::generate_ntt_table(log.max(5)).ok()?.root();
    for _ in log..log.max(5) {
        root *= root;
    }
    let root = EF::from_base(root);
    let fri = pcs::rolling_fri::Parameters::new(length, b, q, root).ok()?;
    let parameters = pcs::pipfri::Parameters::new(
        length,
        total / length,
        b,
        q,
        root,
        pcs::pipfri::Basis::BooleanEvaluations,
    )
    .ok()?;
    let fri_context = Digest512(
        Sha512::digest(encoded(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            EF::MODULUS_VALUE.to_string(),
            &fri,
        )))
        .into(),
    );
    let context = Digest512(
        Sha512::digest(encoded(&(
            b"HasteBoots scalar PipFRI parameters v1".as_slice(),
            fri_context,
            &parameters,
        )))
        .into(),
    );
    Some((n, r, total / length, context, fri_context))
}
fn gamma_tail<F: NTTField, EF: AbstractExtensionField<F>>(
    profile: &ClassicalProfile,
) -> Option<(Vec<u8>, &'static [u8])> {
    let label: &[u8] = match profile.specification().backend {
        Backend::FragmentedPipfri => b"PipFRI fragment batch",
        Backend::FragmentedPipfriVirtual => b"virtual PipFRI fragment batch v2",
        _ => return None,
    };
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"scalar");
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut request = p.to_le_bytes().to_vec();
    request.extend((EF::D as u64).to_le_bytes());
    frame(&mut out, 4, label, &request);
    Some((out, label))
}
struct ScalarGamma<F, E> {
    opening: FirstOpening<F>,
    point: Vec<E>,
    bridge_expected: E,
    value: E,
    fragments: Vec<E>,
}
fn scalar_gamma_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(ScalarGamma<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, _) =
        matrix_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let (n, r, count, context, _) = scalar_geometry_for_role::<F, EF>(profile, opening.role())?;
    let (mut task, mut rest) = fragment_round_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        n.checked_sub(1)?,
    )?;
    let coin = replay_extension::<F, EF>(
        message(&mut rest, 5, b"random point in each round")?,
        1,
        before,
    )?[0];
    let expected = quadratic(&task.evaluations, coin);
    task.point.push(coin);
    let virtual_source = profile.specification().backend == Backend::FragmentedPipfriVirtual;
    if virtual_source {
        if message(&mut rest, 1, b"unmasked virtual PipFRI PCS v2")? != encoded(&n) {
            return None;
        }
    } else if message(&mut rest, 1, b"ordinary PipFRI PCS adapter v1")?
        != encoded(&(n, b"base table".as_slice()))
    {
        return None;
    }
    let root = &task.opening.sources[task.opening.selected].1;
    let mut body = message(
        &mut rest,
        1,
        if virtual_source {
            b"unmasked scalar PipFRI virtual v2"
        } else {
            b"HasteBoots ordinary PipFRI v1"
        },
    )?;
    let prefix = if virtual_source {
        encoded(&(2u32, context, root, &task.point))
    } else {
        encoded(&(context, root, &task.point))
    };
    body = body.strip_prefix(prefix.as_slice())?;
    let (value, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if body.get(..used)? != encoded(&value) {
        return None;
    }
    body = body.get(used..)?;
    let fragments = vector::<EF>(&mut body, count)?;
    if !body.is_empty() {
        return None;
    }
    let tail = gamma_tail::<F, EF>(profile)?.0;
    rest = rest.strip_prefix(tail.as_slice())?;
    let mut aggregate = fragments.clone();
    for &point in &task.point[r..] {
        aggregate = aggregate
            .chunks_exact(2)
            .map(|v| (EF::one() - point) * v[0] + point * v[1])
            .collect();
    }
    if aggregate.as_slice() != [value] {
        return None;
    }
    Some((
        ScalarGamma {
            opening: task.opening,
            point: task.point,
            bridge_expected: expected,
            value,
            fragments,
        },
        rest,
    ))
}

fn scalar_gamma_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<ScalarGamma<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        scalar_gamma_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    rest.is_empty().then_some(task)
}
fn rolling_alpha_tail<F: NTTField, EF: AbstractExtensionField<F>>() -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, 1, b"typed request kind", b"scalar");
    frame(&mut out, 1, b"field challenge kind", b"extension vector");
    frame(&mut out, 1, b"extension basis", &raw_basis::<F, EF>());
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let mut request = p.to_le_bytes().to_vec();
    request.extend((EF::D as u64).to_le_bytes());
    frame(&mut out, 4, b"rolling FRI fold challenge", &request);
    out
}
type RollingRoot = pcs::rolling_fri::Commitment<Digest512>;
struct RollingRound<F, E> {
    scalar: ScalarGamma<F, E>,
    gamma: E,
    originals: Vec<RollingRoot>,
    derived: Vec<RollingRoot>,
    alphas: Vec<E>,
}
struct RollingData<E> {
    gamma: E,
    originals: Vec<RollingRoot>,
    derived: Vec<RollingRoot>,
    alphas: Vec<E>,
}
fn rolling_data_prefix<'a, F, EF>(
    profile: &ClassicalProfile,
    role_index: usize,
    root: &Commitment<Digest512>,
    point: &[EF],
    mut rest: &'a [u8],
    before: &Producers,
    round: usize,
) -> Option<(RollingData<EF>, &'a [u8])>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (_, r, _, context, fri_context) = scalar_geometry_for_role::<F, EF>(profile, role_index)?;
    if round >= r {
        return None;
    }
    let gamma_label = gamma_tail::<F, EF>(profile)?.1;
    let gamma = replay_extension::<F, EF>(message(&mut rest, 5, gamma_label)?, 1, before)?[0];
    let virtual_source = profile.specification().backend == Backend::FragmentedPipfriVirtual;
    let label = if virtual_source {
        b"unmasked virtual PipFRI public roots v2".as_slice()
    } else {
        b"PipFRI public fold roots"
    };
    let mut body = message(&mut rest, 1, label)?;
    let ladder = vector::<RollingRoot>(&mut body, r - usize::from(virtual_source))?;
    if !body.is_empty() {
        return None;
    }
    let mut originals = Vec::with_capacity(r);
    if virtual_source {
        let id = Digest512(
            Sha512::digest(encoded(&(
                b"unmasked PipFRI virtual initial v2".as_slice(),
                context,
                root,
                point,
                gamma,
            )))
            .into(),
        );
        originals.push(RollingRoot { root: id });
    }
    originals.extend(ladder);
    let label = if virtual_source {
        b"HasteBoots rolling batch FRI virtual initial v1".as_slice()
    } else {
        b"HasteBoots rolling batch FRI v1"
    };
    if message(&mut rest, 1, label)? != encoded(&(fri_context, &originals)) {
        return None;
    }
    let mut derived = Vec::new();
    let mut alphas = Vec::new();
    let tail = rolling_alpha_tail::<F, EF>();
    for index in 0..=round {
        rest = rest.strip_prefix(tail.as_slice())?;
        if index == round {
            return Some((
                RollingData {
                    gamma,
                    originals,
                    derived,
                    alphas,
                },
                rest,
            ));
        }
        alphas.push(
            replay_extension::<F, EF>(
                message(&mut rest, 5, b"rolling FRI fold challenge")?,
                1,
                before,
            )?[0],
        );
        let mut body = message(&mut rest, 1, b"rolling FRI derived root")?;
        body = body.strip_prefix(encoded(&(index + 1)).as_slice())?;
        let (root, used): (RollingRoot, usize) =
            bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
        if used != body.len() || encoded(&root) != body {
            return None;
        }
        derived.push(root);
    }
    None
}
fn rolling_alpha_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(RollingRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (scalar, rest) =
        scalar_gamma_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let (data, rest) = rolling_data_prefix::<F, EF>(
        profile,
        scalar.opening.role(),
        &scalar.opening.sources[scalar.opening.selected].1,
        &scalar.point,
        rest,
        before,
        round,
    )?;
    Some((
        RollingRound {
            scalar,
            gamma: data.gamma,
            originals: data.originals,
            derived: data.derived,
            alphas: data.alphas,
        },
        rest,
    ))
}

fn rolling_alpha_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<RollingRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = rolling_alpha_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn rolling_index_tail(profile: &ClassicalProfile) -> Option<(Vec<u8>, usize)> {
    rolling_index_tail_for_role(profile, 0)
}
fn rolling_index_tail_for_role(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<(Vec<u8>, usize)> {
    let role = &profile.specification().roles[role_index];
    let r = role_vars_for_bridge_at(profile, role_index)
        .max(1)
        .min(profile.specification().fragment_vars?);
    let domain = (1usize.checked_shl(u32::try_from(r).ok()?)?)
        .checked_mul(profile.specification().blowup)?;
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"index domain",
        &u64::try_from(domain).ok()?.to_le_bytes(),
    );
    frame(
        &mut out,
        2,
        b"rolling FRI unbiased domain index",
        &u64::try_from(role.queries.checked_mul(8)?)
            .ok()?
            .to_le_bytes(),
    );
    Some((out, domain))
}
fn rolling_index_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(RollingRound<F, EF>, EF, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (opening, _) =
        matrix_child_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let (_, r, _, _, _) = scalar_geometry_for_role::<F, EF>(profile, opening.role())?;
    let (mut task, mut rest) = rolling_alpha_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        r.checked_sub(1)?,
    )?;
    task.alphas.push(
        replay_extension::<F, EF>(
            message(&mut rest, 5, b"rolling FRI fold challenge")?,
            1,
            before,
        )?[0],
    );
    let body = message(&mut rest, 1, b"rolling FRI terminal")?;
    let (terminal, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if used != body.len() || encoded(&terminal) != body {
        return None;
    }
    let tail = rolling_index_tail_for_role(profile, task.scalar.opening.role())?.0;
    rest = rest.strip_prefix(tail.as_slice())?;
    Some((task, terminal, rest))
}

struct NttRollingRound<F, E> {
    scalar: NttScalarGamma<F, E>,
    data: RollingData<E>,
}
fn ntt_rolling_alpha_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<(NttRollingRound<F, EF>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (scalar, rest) =
        ntt_scalar_gamma_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let (data, rest) = rolling_data_prefix::<F, EF>(
        profile,
        0,
        &scalar.bridge.batch.source().1,
        &scalar.point,
        rest,
        before,
        round,
    )?;
    Some((NttRollingRound { scalar, data }, rest))
}
fn ntt_rolling_alpha_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<NttRollingRound<F, EF>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) = ntt_rolling_alpha_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, round,
    )?;
    rest.is_empty().then_some(task)
}
fn ntt_rolling_index_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttRollingRound<F, EF>, EF, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rounds, _, _, _) = scalar_geometry::<F, EF>(profile)?;
    let (mut task, mut rest) = ntt_rolling_alpha_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        rounds.checked_sub(1)?,
    )?;
    task.data.alphas.push(
        replay_extension::<F, EF>(
            message(&mut rest, 5, b"rolling FRI fold challenge")?,
            1,
            before,
        )?[0],
    );
    let body = message(&mut rest, 1, b"rolling FRI terminal")?;
    let (terminal, used): (EF, usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if used != body.len() || encoded(&terminal) != body {
        return None;
    }
    let tail = rolling_index_tail(profile)?.0;
    Some((task, terminal, rest.strip_prefix(tail.as_slice())?))
}
fn ntt_rolling_index_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttRollingRound<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, terminal, rest) =
        ntt_rolling_index_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    rest.is_empty().then_some((task, terminal))
}
fn ntt_consistency_index_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttRollingRound<F, EF>, Vec<usize>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, _, mut rest) =
        ntt_rolling_index_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let bytes = message(&mut rest, 3, b"rolling FRI unbiased domain index")?;
    let count = profile.specification().roles[0].queries.checked_mul(8)?;
    if bytes.len() != count || rest != consistency_index_tail(profile)? {
        return None;
    }
    let domain = rolling_index_tail(profile)?.1;
    let indices = bytes
        .chunks_exact(8)
        .map(|chunk| (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize)
        .collect();
    Some((task, indices))
}

fn rolling_index_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(RollingRound<F, EF>, EF)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, terminal, rest) =
        rolling_index_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    rest.is_empty().then_some((task, terminal))
}
fn consistency_index_tail(profile: &ClassicalProfile) -> Option<Vec<u8>> {
    consistency_index_tail_for_role(profile, 0)
}
fn consistency_index_tail_for_role(
    profile: &ClassicalProfile,
    role_index: usize,
) -> Option<Vec<u8>> {
    if profile.specification().backend != Backend::FragmentedPipfri {
        return None;
    }
    let (_, domain) = rolling_index_tail_for_role(profile, role_index)?;
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        b"index domain",
        &u64::try_from(domain).ok()?.to_le_bytes(),
    );
    frame(
        &mut out,
        2,
        b"PipFRI consistency domain index",
        &u64::try_from(
            profile
                .specification()
                .roles
                .get(role_index)?
                .queries
                .checked_mul(8)?,
        )
        .ok()?
        .to_le_bytes(),
    );
    Some(out)
}
fn consistency_index_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(RollingRound<F, EF>, Vec<usize>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, _, mut rest) =
        rolling_index_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    let bytes = message(&mut rest, 3, b"rolling FRI unbiased domain index")?;
    let draws = profile.specification().roles[task.scalar.opening.role()].queries;
    if bytes.len() != draws.checked_mul(8)?
        || rest != consistency_index_tail_for_role(profile, task.scalar.opening.role())?
    {
        return None;
    }
    let domain = rolling_index_tail_for_role(profile, task.scalar.opening.role())?.1;
    let indices = bytes
        .chunks_exact(8)
        .map(|chunk| (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize)
        .collect();
    Some((task, indices))
}

fn receipt(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut producer = RECEIPT_DOMAIN.to_vec();
    producer.extend(raw);
    let mut state = sha3::Shake256::default();
    Update::update(&mut state, &producer);
    let mut fingerprint = [0u8; 64];
    state.finalize_xof().read(&mut fingerprint);
    let mut receipt = (raw.len() as u128).to_le_bytes().to_vec();
    receipt.extend(fingerprint);
    (receipt, producer)
}

fn first_product<F, EF, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    outer: &[u8],
) -> Option<InitialProduct<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, evaluations, _, _, _) = recover::<F, EF, P>(pp, setup, statement, outer)?;
    let digits = setup
        .config
        .decomposition::<F>()
        .ok()?
        .num_digits::<F>()
        .ok()?;
    let evaluation_context = <P as CanonicalPcs<F, Sha512>>::context(pp.evaluations).ok()?;
    let key_context = <P as CanonicalPcs<F, Sha512>>::context(pp.key).ok()?;
    let mut sources = Vec::with_capacity(4 * digits + 1);
    for (evaluation, key) in evaluations.iter().zip(setup.br.roots()) {
        sources.push((evaluation_context, evaluation.clone()));
        sources.push((key_context, key.clone()));
    }
    sources.push((evaluation_context, evaluations.get(2 * digits)?.clone()));
    if sources.len() != 4 * digits + 1 {
        return None;
    }
    Some(InitialProduct {
        shape: shape(
            pp.evaluations.num_vars(),
            pp.evaluations.width(),
            2 * digits,
        ),
        sources,
    })
}

fn exercise_ntt_direct_projection<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    parent_input: &[u8],
    parent_before: &Producers,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let batch = ntt_batch_seed_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        parent_input,
        parent_before,
    )
    .unwrap();
    let seed = shake64(parent_input);
    let (_, label, context) = pcs_child_labels(profile.specification().backend).unwrap();
    let mut input = raw_child::<F, EF>(profile, label, context, &seed);
    let mut crypto = helper::classical_transcript::ClassicalTranscript::new(
        b"HasteBoots framed SHAKE256 child v1",
        &profile.id().0,
    );
    crypto.append_bytes(b"child label", label);
    crypto.append_bytes(b"child context", context);
    crypto.append_bytes(b"parent seed", &seed);
    assert!(
        crypto
            .challenge_extension::<F, EF>(b"typed extension identity", 0)
            .unwrap()
            .is_empty()
    );
    let mut views = FirstViews::new();
    views.insert(parent_input.to_vec(), parent_before.clone());
    let mut before = parent_before.clone();
    before.insert(seed, parent_input.to_vec());
    let (empty, producer) = receipt(&[]);
    before.insert(empty[16..].try_into().unwrap(), producer);
    let role = &profile.specification().roles[0];
    let claims = batch.queries.len();
    let rounds = role.num_vars;
    let (core, domain) = direct_core::<F, EF>(profile).unwrap();
    let mut queries = Vec::new();
    let mut values = Vec::new();
    for (query, value) in batch.queries.iter().zip(batch.values()) {
        let (query, value) = batch
            .parameters(pp)
            .normalize_claim(query.clone(), value.clone())
            .ok()
            .unwrap();
        queries.push(
            query
                .iter()
                .map(|pair| algebra::matrix_weighted::MatrixPair {
                    zero: algebra::matrix_weighted::Matrix::new(
                        role.width,
                        pair.zero
                            .values()
                            .iter()
                            .copied()
                            .map(EF::from_base)
                            .collect(),
                    )
                    .unwrap(),
                    one: algebra::matrix_weighted::Matrix::new(
                        role.width,
                        pair.one
                            .values()
                            .iter()
                            .copied()
                            .map(EF::from_base)
                            .collect(),
                    )
                    .unwrap(),
                })
                .collect::<Vec<_>>(),
        );
        values.push(value.into_iter().map(EF::from_base).collect::<Vec<_>>());
    }
    let source = batch.source().1.root;
    let roots: Vec<_> = (0..claims)
        .map(|member| {
            let mut row = vec![Digest512([u8::try_from(member + 37).unwrap(); 64]); rounds];
            row[0] = source;
            row
        })
        .collect();
    let binding = (&core, source, claims, &queries, &values, &roots);
    frame(
        &mut input,
        1,
        b"packed PolyFRIM joint query proximity v1",
        &encoded(&binding),
    );
    crypto
        .append_message(b"packed PolyFRIM joint query proximity v1", &binding)
        .unwrap();
    for member in 0..claims {
        frame(
            &mut input,
            1,
            b"packed PolyFRIM joint consistency member v1",
            &encoded(&member),
        );
        crypto
            .append_message(b"packed PolyFRIM joint consistency member v1", &member)
            .unwrap();
        let binding = (
            &core,
            source,
            &roots[member][1..],
            &queries[member],
            &values[member],
        );
        frame(
            &mut input,
            1,
            b"packed PolyFRIM consistency v2",
            &encoded(&binding),
        );
        crypto
            .append_message(b"packed PolyFRIM consistency v2", &binding)
            .unwrap();
        frame(
            &mut input,
            1,
            b"index domain",
            &(domain as u64).to_le_bytes(),
        );
        frame(
            &mut input,
            2,
            b"packed PolyFRIM domain index v2",
            &((8 * role.queries) as u64).to_le_bytes(),
        );
        let task = ntt_direct_consistency_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views, member,
        )
        .unwrap();
        assert_eq!(task.roots, roots);
        assert_eq!(task.domain, domain);
        assert_eq!(encoded(&task.batch.queries), encoded(&batch.queries));
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            ntt_direct_consistency_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, &views, member
            )
            .is_none()
        );
        assert!(
            ntt_direct_consistency_query::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, claims
            )
            .is_none()
        );
        if member > 0 {
            assert!(
                ntt_direct_consistency_query::<F, EF, P>(
                    profile, pp, setup, statement, &input, &before, &views, 0
                )
                .is_none()
            );
        }
        let mut xof = sha3::Shake256::default();
        Update::update(&mut xof, &input);
        let mut bytes = vec![0; 8 * role.queries];
        xof.finalize_xof().read(&mut bytes);
        let indices: Vec<_> = bytes
            .chunks_exact(8)
            .map(|chunk| {
                (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
            })
            .collect();
        assert_eq!(
            crypto
                .challenge_indices(b"packed PolyFRIM domain index v2", domain, role.queries)
                .unwrap(),
            indices
        );
        frame(&mut input, 3, b"packed PolyFRIM domain index v2", &bytes);
    }
    let binding = (&core, &roots);
    frame(
        &mut input,
        1,
        b"packed PolyFRIM joint projections v1",
        &encoded(&binding),
    );
    crypto
        .append_message(b"packed PolyFRIM joint projections v1", &binding)
        .unwrap();
    input.extend(direct_projection_count_tail::<F, EF>(profile, claims).unwrap());
    let task = ntt_direct_projection_query::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views,
    )
    .unwrap();
    assert_eq!(task.roots, roots);
    let mut wrong = input.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        ntt_direct_projection_query::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &before, &views
        )
        .is_none()
    );
    let mut missing = before.clone();
    missing.remove(&seed);
    assert!(
        ntt_direct_projection_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &missing, &views
        )
        .is_none()
    );
    let count = rounds * claims * role.width;
    let (coefficients, raw) = raw_prime_phase::<F>(&input, count * EF::D);
    let weights: Vec<_> = coefficients
        .chunks_exact(EF::D)
        .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
        .collect();
    crypto.append_bytes(b"typed request kind", b"vector");
    assert_eq!(
        crypto
            .challenge_extension::<F, EF>(b"packed PolyFRIM atomic joint lane weights v3", count)
            .unwrap(),
        weights
    );

    let (projection_receipt, producer) = receipt(&raw);
    let mut previous: [u8; 64] = projection_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(
        &mut input,
        5,
        b"packed PolyFRIM atomic joint lane weights v3",
        &projection_receipt,
    );
    let originals: Vec<_> = weights
        .chunks_exact(claims * role.width)
        .enumerate()
        .map(|(layer, row)| {
            let rows: Vec<_> = row.chunks_exact(role.width).map(<[EF]>::to_vec).collect();
            RollingRoot {
                root: Digest512(
                    Sha512::digest(encoded(&(
                        b"packed PolyFRIM joint virtual layer v1".as_slice(),
                        &core,
                        layer,
                        &roots,
                        &rows,
                    )))
                    .into(),
                ),
            }
        })
        .collect();
    let fri = direct_fri::<F, EF>(profile).unwrap();
    let fri_context = Digest512(
        Sha512::digest(encoded(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            EF::MODULUS_VALUE.to_string(),
            &fri,
        )))
        .into(),
    );
    frame(
        &mut input,
        1,
        b"HasteBoots rolling batch FRI virtual all v2",
        &encoded(&(fri_context, &originals)),
    );
    crypto
        .append_message(
            b"HasteBoots rolling batch FRI virtual all v2",
            &(fri_context, &originals),
        )
        .unwrap();
    let mut alphas = Vec::new();
    let mut derived = Vec::new();
    let mut wrong_layer = None;
    for round in 0..rounds {
        input.extend(rolling_alpha_tail::<F, EF>());
        let task = ntt_direct_rolling_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views, round,
        )
        .unwrap();
        assert_eq!(task.data.weights, weights);
        assert_eq!(task.data.alphas, alphas);
        assert_eq!(encoded(&task.data.originals), encoded(&originals));
        assert_eq!(encoded(&task.data.derived), encoded(&derived));
        assert_eq!(encoded(&task.direct.batch.queries), encoded(&batch.queries));
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            ntt_direct_rolling_query::<F, EF, P>(
                profile, pp, setup, statement, &input, &missing, &views, round
            )
            .is_none()
        );
        if let Some(at) = wrong_layer {
            let mut wrong = input.clone();
            wrong[at] ^= 1;
            assert!(
                ntt_direct_rolling_query::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, round
                )
                .is_none()
            );
        }
        let (coefficients, raw) = raw_prime_phase::<F>(&input, EF::D);
        let alpha = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        crypto.append_bytes(b"typed request kind", b"scalar");
        assert_eq!(
            crypto
                .challenge_extension::<F, EF>(b"rolling FRI fold challenge", 1)
                .unwrap(),
            vec![alpha]
        );
        alphas.push(alpha);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(&mut input, 5, b"rolling FRI fold challenge", &phase_receipt);
        if round + 1 < rounds {
            let root = RollingRoot {
                root: Digest512([u8::try_from(round + 71).unwrap(); 64]),
            };
            let start = input.len();
            let label = b"rolling FRI derived root";
            frame(&mut input, 1, label, &encoded(&(round + 1, &root)));
            wrong_layer = Some(start + 1 + 8 + label.len() + 8);
            crypto.append_message(label, &(round + 1, &root)).unwrap();
            derived.push(root);
        }
    }
    let terminal = EF::from_base(F::from(17usize));
    frame(&mut input, 1, b"rolling FRI terminal", &encoded(&terminal));
    crypto
        .append_message(b"rolling FRI terminal", &terminal)
        .unwrap();
    frame(
        &mut input,
        1,
        b"index domain",
        &(domain as u64).to_le_bytes(),
    );
    frame(
        &mut input,
        2,
        b"rolling FRI unbiased domain index",
        &((8 * role.queries) as u64).to_le_bytes(),
    );
    let (task, value) = ntt_direct_rolling_indices::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views,
    )
    .unwrap();
    assert_eq!(value, terminal);
    assert_eq!(task.data.alphas, alphas);
    let mut missing = before.clone();
    missing.remove(&previous);
    assert!(
        ntt_direct_rolling_indices::<F, EF, P>(
            profile, pp, setup, statement, &input, &missing, &views
        )
        .is_none()
    );
    let mut trailing = input.clone();
    trailing.push(0);
    assert!(
        ntt_direct_rolling_indices::<F, EF, P>(
            profile, pp, setup, statement, &trailing, &before, &views
        )
        .is_none()
    );
    let mut xof = sha3::Shake256::default();
    Update::update(&mut xof, &input);
    let mut bytes = vec![0; 8 * role.queries];
    xof.finalize_xof().read(&mut bytes);
    let indices: Vec<_> = bytes
        .chunks_exact(8)
        .map(|chunk| (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize)
        .collect();
    assert_eq!(
        crypto
            .challenge_indices(b"rolling FRI unbiased domain index", domain, role.queries)
            .unwrap(),
        indices
    );
    frame(&mut input, 3, b"rolling FRI unbiased domain index", &bytes);
    frame(
        &mut input,
        2,
        b"NTT direct complete rolling replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    crypto.challenge_bytes(b"NTT direct complete rolling replay", &mut output);
    assert_eq!(shake64(&input), output);
}

fn exercise_ntt_fragment_bridge<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    parent_input: &[u8],
    before: &Producers,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let batch =
        ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, parent_input, before)
            .unwrap();
    let count = batch.queries.len() * batch.ntt.row.shape.width();
    let seed = shake64(parent_input);
    let (_, child_label, context) = pcs_child_labels(profile.specification().backend).unwrap();
    let mut input = raw_child::<F, EF>(profile, child_label, context, &seed);
    let mut crypto = helper::classical_transcript::ClassicalTranscript::new(
        b"HasteBoots framed SHAKE256 child v1",
        &profile.id().0,
    );
    crypto.append_bytes(b"child label", child_label);
    crypto.append_bytes(b"child context", context);
    crypto.append_bytes(b"parent seed", &seed);
    assert!(
        crypto
            .challenge_extension::<F, EF>(b"typed extension identity", 0)
            .unwrap()
            .is_empty()
    );
    let mut views = FirstViews::new();
    views.insert(parent_input.to_vec(), before.clone());
    let mut before = before.clone();
    before.insert(seed, parent_input.to_vec());
    let (empty, producer) = receipt(&[]);
    before.insert(empty[16..].try_into().unwrap(), producer);
    // Parent seed interpretation retains its own view from before the
    // seed output and child identity producer were added above.
    let (tail, label) = ntt_fragment_projection_tail::<F, EF>(profile, count).unwrap();
    input.extend(tail);
    let (task, rest) = ntt_fragment_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&task.queries), encoded(&batch.queries));
    let mut wrong = input.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        ntt_fragment_projection_prefix::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &before, &views
        )
        .is_none()
    );
    let (coefficients, raw) = raw_prime_phase::<F>(&input, count * EF::D);
    let rho: Vec<_> = coefficients
        .chunks_exact(EF::D)
        .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
        .collect();
    crypto.append_bytes(b"typed request kind", b"vector");
    assert_eq!(
        crypto.challenge_extension::<F, EF>(label, count).unwrap(),
        rho
    );
    let claim = rho
        .iter()
        .zip(batch.values().iter().flatten())
        .fold(EF::zero(), |sum, (&r, &v)| sum + r * EF::from_base(v));
    if batch.values().iter().flatten().any(|&v| v != F::zero()) {
        assert_ne!(claim, EF::zero());
    }
    let (phase_receipt, producer) = receipt(&raw);
    let mut previous: [u8; 64] = phase_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(&mut input, 5, label, &phase_receipt);
    let n = role_vars_for_bridge(profile);
    let info = algebra::PolynomialInfo {
        num_variables: n,
        max_multiplicands: 2,
    };
    frame(&mut input, 1, b"polynomial info", &encoded(&info));
    crypto.append_message(b"polynomial info", &info).unwrap();
    let mut point = Vec::new();
    let mut expected = claim;
    for round in 0..n {
        let values = vec![EF::zero(), expected, expected + expected];
        let msg = sumcheck::prover::ProverMsg::from_evaluations(values.clone());
        frame(&mut input, 1, b"sumcheck msg", &encoded(&msg));
        crypto.append_message(b"sumcheck msg", &msg).unwrap();
        input.extend(bridge_round_tail::<F, EF>());
        let task = ntt_fragment_round_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views, round,
        )
        .unwrap();
        assert_eq!(task.rho, rho);
        assert_eq!(task.expected, expected);
        assert_eq!(task.point, point);
        assert_eq!(task.evaluations, values);
        assert_eq!(encoded(&task.batch.queries), encoded(&batch.queries));
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            ntt_fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, &input, &missing, &views, round
            )
            .is_none()
        );
        let mut trailing = input.clone();
        trailing.push(0);
        assert!(
            ntt_fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, &trailing, &before, &views, round
            )
            .is_none()
        );
        let (coefficients, raw) = raw_prime_phase::<F>(&input, EF::D);
        let coin = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        crypto.append_bytes(b"typed request kind", b"scalar");
        assert_eq!(
            crypto
                .challenge_extension::<F, EF>(b"random point in each round", 1)
                .unwrap(),
            vec![coin]
        );
        expected *= coin;
        point.push(coin);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(&mut input, 5, b"random point in each round", &phase_receipt);
    }

    let (variables, retained, fragments, scalar_context, fri_context) =
        scalar_geometry::<F, EF>(profile).unwrap();
    assert_eq!(variables, point.len());
    let u: Vec<_> = (0..fragments)
        .map(|i| EF::from_base(F::from(i + 3)))
        .collect();
    // Independent Boolean-basis evaluation, rather than the parser's pair folds.
    let value = u
        .iter()
        .enumerate()
        .fold(EF::zero(), |sum, (index, &entry)| {
            let weight = point[retained..].iter().enumerate().fold(
                EF::one(),
                |weight, (bit, &coordinate)| {
                    weight
                        * if index & (1usize << bit) == 0 {
                            EF::one() - coordinate
                        } else {
                            coordinate
                        }
                },
            );
            sum + weight * entry
        });
    let root = &batch.source().1;
    let virtual_source = profile.specification().backend == Backend::FragmentedPipfriVirtual;
    let (mode_label, mode): (&[u8], Vec<u8>) = if virtual_source {
        (b"unmasked virtual PipFRI PCS v2", encoded(&variables))
    } else {
        (
            b"ordinary PipFRI PCS adapter v1",
            encoded(&(variables, b"base table".as_slice())),
        )
    };
    let binding_label: &[u8] = if virtual_source {
        b"unmasked scalar PipFRI virtual v2"
    } else {
        b"HasteBoots ordinary PipFRI v1"
    };
    let scalar_binding = |claims: &[EF]| {
        if virtual_source {
            encoded(&(2u32, scalar_context, root, &point, value, claims))
        } else {
            encoded(&(scalar_context, root, &point, value, claims))
        }
    };
    let completed_bridge = input.clone();
    frame(&mut input, 1, mode_label, &mode);
    crypto.append_bytes(mode_label, &mode);
    let binding = scalar_binding(&u);
    frame(&mut input, 1, binding_label, &binding);
    crypto.append_bytes(binding_label, &binding);
    let (tail, gamma_label) = gamma_tail::<F, EF>(profile).unwrap();
    input.extend(&tail);
    let task =
        ntt_scalar_gamma_query::<F, EF, P>(profile, pp, setup, statement, &input, &before, &views)
            .unwrap();
    assert_eq!(task.point, point);
    assert_eq!(task.bridge_expected, expected);
    assert_eq!(task.value, value);
    assert_eq!(task.fragments, u);
    assert_eq!(encoded(&task.bridge.batch.queries), encoded(&batch.queries));
    let mut missing = before.clone();
    missing.remove(&previous);
    assert!(
        ntt_scalar_gamma_query::<F, EF, P>(profile, pp, setup, statement, &input, &missing, &views)
            .is_none()
    );
    let mut trailing = input.clone();
    trailing.push(0);
    assert!(
        ntt_scalar_gamma_query::<F, EF, P>(
            profile, pp, setup, statement, &trailing, &before, &views
        )
        .is_none()
    );
    let wrong_u: Vec<_> = u.iter().map(|&entry| entry + EF::one()).collect();
    let mut wrong = completed_bridge.clone();
    frame(&mut wrong, 1, mode_label, &mode);
    frame(&mut wrong, 1, binding_label, &scalar_binding(&wrong_u));
    wrong.extend(&tail);
    assert!(
        ntt_scalar_gamma_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before, &views)
            .is_none()
    );
    let prefix = if virtual_source {
        encoded(&(2u32, scalar_context, root, &point, value))
    } else {
        encoded(&(scalar_context, root, &point, value))
    };
    let mut oversized = prefix;
    oversized.extend(encoded(&usize::MAX));
    let mut wrong = completed_bridge;
    frame(&mut wrong, 1, mode_label, &mode);
    frame(&mut wrong, 1, binding_label, &oversized);
    wrong.extend(&tail);
    assert!(
        ntt_scalar_gamma_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before, &views)
            .is_none()
    );
    let (coefficients, raw) = raw_prime_phase::<F>(&input, EF::D);
    let gamma = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
    crypto.append_bytes(b"typed request kind", b"scalar");
    assert_eq!(
        crypto.challenge_extension::<F, EF>(gamma_label, 1).unwrap(),
        vec![gamma]
    );

    let (gamma_receipt, producer) = receipt(&raw);
    previous = gamma_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(&mut input, 5, gamma_label, &gamma_receipt);
    let ladder: Vec<_> = (0..retained - usize::from(virtual_source))
        .map(|i| RollingRoot {
            root: Digest512([u8::try_from(i + 37).unwrap(); 64]),
        })
        .collect();
    let mut originals = Vec::new();
    if virtual_source {
        originals.push(RollingRoot {
            root: Digest512(
                Sha512::digest(encoded(&(
                    b"unmasked PipFRI virtual initial v2".as_slice(),
                    scalar_context,
                    root,
                    &point,
                    gamma,
                )))
                .into(),
            ),
        });
    }
    originals.extend(ladder.clone());
    let public_label = if virtual_source {
        b"unmasked virtual PipFRI public roots v2".as_slice()
    } else {
        b"PipFRI public fold roots"
    };
    frame(&mut input, 1, public_label, &encoded(&ladder));
    crypto.append_message(public_label, &ladder).unwrap();
    let rolling_label = if virtual_source {
        b"HasteBoots rolling batch FRI virtual initial v1".as_slice()
    } else {
        b"HasteBoots rolling batch FRI v1"
    };
    frame(
        &mut input,
        1,
        rolling_label,
        &encoded(&(fri_context, &originals)),
    );
    crypto
        .append_message(rolling_label, &(fri_context, &originals))
        .unwrap();
    let mut alphas = Vec::new();
    let mut derived = Vec::new();
    let mut wrong_layer = None;
    for round in 0..retained {
        input.extend(rolling_alpha_tail::<F, EF>());
        let task = ntt_rolling_alpha_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views, round,
        )
        .unwrap();
        assert_eq!(task.data.gamma, gamma);
        assert_eq!(task.data.alphas, alphas);
        assert_eq!(encoded(&task.data.originals), encoded(&originals));
        assert_eq!(encoded(&task.data.derived), encoded(&derived));
        assert_eq!(task.scalar.point, point);
        assert_eq!(task.scalar.value, value);
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            ntt_rolling_alpha_query::<F, EF, P>(
                profile, pp, setup, statement, &input, &missing, &views, round
            )
            .is_none()
        );
        if let Some(at) = wrong_layer {
            let mut wrong = input.clone();
            wrong[at] ^= 1;
            assert!(
                ntt_rolling_alpha_query::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, round
                )
                .is_none()
            );
        }
        let (coefficients, raw) = raw_prime_phase::<F>(&input, EF::D);
        let alpha = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        crypto.append_bytes(b"typed request kind", b"scalar");
        assert_eq!(
            crypto
                .challenge_extension::<F, EF>(b"rolling FRI fold challenge", 1)
                .unwrap(),
            vec![alpha]
        );
        alphas.push(alpha);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(&mut input, 5, b"rolling FRI fold challenge", &phase_receipt);
        if round + 1 < retained {
            let root = RollingRoot {
                root: Digest512([u8::try_from(round + 61).unwrap(); 64]),
            };
            let start = input.len();
            let label = b"rolling FRI derived root";
            frame(&mut input, 1, label, &encoded(&(round + 1, &root)));
            wrong_layer = Some(start + 1 + 8 + label.len() + 8);
            crypto.append_message(label, &(round + 1, &root)).unwrap();
            derived.push(root);
        }
    }
    let terminal = EF::from_base(F::from(11usize));
    frame(&mut input, 1, b"rolling FRI terminal", &encoded(&terminal));
    crypto
        .append_message(b"rolling FRI terminal", &terminal)
        .unwrap();
    let (tail, domain) = rolling_index_tail(profile).unwrap();
    input.extend(tail);
    let (task, checked_terminal) =
        ntt_rolling_index_query::<F, EF, P>(profile, pp, setup, statement, &input, &before, &views)
            .unwrap();
    assert_eq!(checked_terminal, terminal);
    assert_eq!(task.data.alphas, alphas);
    let mut trailing = input.clone();
    trailing.push(0);
    assert!(
        ntt_rolling_index_query::<F, EF, P>(
            profile, pp, setup, statement, &trailing, &before, &views
        )
        .is_none()
    );
    let mut missing = before.clone();
    missing.remove(&previous);
    assert!(
        ntt_rolling_index_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &missing, &views
        )
        .is_none()
    );
    let draws = profile.specification().roles[0].queries;
    let sample = |input: &[u8]| {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut xof = sha3::Shake256::default();
        Update::update(&mut xof, input);
        let mut bytes = vec![0; 8 * draws];
        xof.finalize_xof().read(&mut bytes);
        let indices: Vec<_> = bytes
            .chunks_exact(8)
            .map(|chunk| {
                (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
            })
            .collect();
        (bytes, indices)
    };
    let (bytes, indices) = sample(&input);
    assert_eq!(
        crypto
            .challenge_indices(b"rolling FRI unbiased domain index", domain, draws)
            .unwrap(),
        indices
    );
    frame(&mut input, 3, b"rolling FRI unbiased domain index", &bytes);
    if !virtual_source {
        input.extend(consistency_index_tail(profile).unwrap());
        let (task, previous_indices) = ntt_consistency_index_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views,
        )
        .unwrap();
        assert_eq!(task.data.alphas, alphas);
        assert_eq!(previous_indices, indices);
        let (bytes, indices) = sample(&input);
        assert_eq!(
            crypto
                .challenge_indices(b"PipFRI consistency domain index", domain, draws)
                .unwrap(),
            indices
        );
        frame(&mut input, 3, b"PipFRI consistency domain index", &bytes);
    }
    frame(
        &mut input,
        2,
        b"NTT scalar rolling replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    crypto.challenge_bytes(b"NTT scalar rolling replay", &mut output);
    assert_eq!(shake64(&input), output);
}

// Complete synthetic earlier components to exercise the trusted outer ordering.
// This is a sampling/source-origin fixture, not an accepted NTT certificate.
fn exercise_decomposition_openings<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: Vec<u8>,
    before: Producers,
    linear: &DecompositionLinear<F>,
    query: &[algebra::matrix_weighted::MatrixPair<F>],
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    exercise_decomposition_openings_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        linear,
        query,
        FirstViews::new(),
        0,
    );
}
fn exercise_decomposition_openings_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
    linear: &DecompositionLinear<F>,
    query: &[algebra::matrix_weighted::MatrixPair<F>],
    base_views: FirstViews,
    half: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    assert!(half < 2);
    let family = if half == 0 {
        OpeningFamily::Decomposition
    } else {
        OpeningFamily::SecondDecomposition
    };
    let d = setup
        .config
        .decomposition::<F>()
        .unwrap()
        .num_digits::<F>()
        .unwrap();
    let mut opening = FirstOpening {
        family: family,
        selected: 0,
        sources: linear.sources.clone(),
        query: query.to_vec(),
        values: vec![vec![F::zero(); pp.inputs.width()]; linear.sources.len()],
    };
    let radix = F::from(setup.config.decomposition::<F>().unwrap().radix().unwrap());
    let mut power = F::one();
    let mut reconstructed = F::zero();
    for digit in 0..d {
        let value = F::from(digit + 1);
        opening.values[digit + 1].fill(value);
        reconstructed += power * value;
        power *= radix;
    }
    opening.values[0] = pp
        .inputs
        .normalize_values(vec![reconstructed; pp.inputs.width()]);
    for borrow in 1..d {
        opening.values[d + 1 + borrow].fill(F::from(borrow + 1));
    }
    // Nonzero source/digit/interior-borrow claims preserve reconstruction
    // and both zero borrow endpoints; they are not authenticated certificates.
    for relation in &linear.relations {
        for lane in 0..pp.inputs.width() {
            assert_eq!(
                relation
                    .terms
                    .iter()
                    .fold(F::zero(), |sum, (a, i)| sum + *a * opening.values[*i][lane]),
                F::zero()
            );
        }
    }
    for index in 0..opening.sources.len() {
        opening.selected = index;
        let parameters = decomposition_source_parameters(pp, d, index);
        let start = input.len();
        if profile.specification().backend == Backend::Brakedown {
            let (tail, count) = brakedown_first_tail(profile, &opening).unwrap();
            input.extend(tail);
            let selected = decomposition_opening_query_at::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &input,
                &before,
                &base_views,
                half,
            )
            .unwrap();
            assert_eq!(selected.selected, index);
            assert_eq!(encoded(&selected.sources), encoded(&opening.sources));
            let mut wrong_opening = FirstOpening {
                family: family,
                selected: index,
                sources: opening.sources.clone(),
                query: opening.query.clone(),
                values: opening.values.clone(),
            };
            wrong_opening.sources[index].1.root.0[0] ^= 1;
            let mut wrong = input[..start].to_vec();
            wrong.extend(brakedown_first_tail(profile, &wrong_opening).unwrap().0);
            assert!(
                decomposition_opening_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &wrong,
                    &before,
                    &base_views,
                    half
                )
                .is_none()
            );
            let (coins, raw) = raw_prime_phase::<F>(&input, count);
            let (phase_receipt, producer) = receipt(&raw);
            let fingerprint = phase_receipt[16..].try_into().unwrap();
            before.insert(fingerprint, producer);
            frame(&mut input, 5, b"mw random linear test", &phase_receipt);
            let responses_start = input.len();
            let (columns, domain, cells) = brakedown_column_tail(profile).unwrap();
            let test = vec![F::from(index + 1); cells];
            let evaluation = vec![F::from(index + 2); cells];
            frame(
                &mut input,
                1,
                b"mw linear responses",
                &encoded(&(&test, &evaluation)),
            );
            input.extend(&columns);
            let checked = decomposition_column_query_at::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &input,
                &before,
                &base_views,
                half,
            )
            .unwrap();
            assert_eq!(checked.opening.family, family);
            assert_eq!(checked.opening.selected, index);
            assert_eq!(
                encoded(&checked.opening.sources[index]),
                encoded(&opening.sources[index])
            );
            assert_eq!(
                checked.random,
                coins
                    .into_iter()
                    .map(|v| F::from(usize::try_from(v).unwrap()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(checked.test, test);
            assert_eq!(checked.evaluation, evaluation);
            assert_eq!(checked.domain, domain);
            let mut missing = before.clone();
            missing.remove(&fingerprint);
            assert!(
                decomposition_column_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &input,
                    &missing,
                    &base_views,
                    half
                )
                .is_none()
            );
            let mut wrong = input.clone();
            wrong.push(0);
            assert!(
                decomposition_column_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &wrong,
                    &before,
                    &base_views,
                    half
                )
                .is_none()
            );
            let mut wrong = input.clone();
            *wrong.last_mut().unwrap() ^= 1;
            assert!(
                decomposition_column_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &wrong,
                    &before,
                    &base_views,
                    half
                )
                .is_none()
            );
            let mut wrong = input[..responses_start].to_vec();
            frame(&mut wrong, 1, b"mw linear responses", &encoded(&usize::MAX));
            wrong.extend(&columns);
            assert!(
                decomposition_column_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &wrong,
                    &before,
                    &base_views,
                    half
                )
                .is_none()
            );
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut xof = sha3::Shake256::default();
            Update::update(&mut xof, input.as_slice());
            let mut bytes = vec![0; 8 * profile.specification().roles[0].queries];
            xof.finalize_xof().read(&mut bytes);
            frame(&mut input, 3, b"mw atomic column block v5", &bytes);
        } else {
            let (tail, label, context) =
                factor_seed_tail(profile, parameters, &opening, index).unwrap();
            input.extend(tail);
            let selected = decomposition_opening_query_at::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &input,
                &before,
                &base_views,
                half,
            )
            .unwrap();
            assert_eq!(selected.selected, index);
            assert_eq!(encoded(&selected.sources), encoded(&opening.sources));
            assert_eq!(
                encoded(&selected.query),
                encoded(
                    &parameters
                        .normalize_claim(query.to_vec(), opening.values[index].clone())
                        .ok()
                        .unwrap()
                        .0
                )
            );
            let mut wrong = opening.sources[index].1.clone();
            wrong.root.0[0] ^= 1;
            let mut wrong_opening = FirstOpening {
                family: family,
                selected: index,
                sources: opening.sources.clone(),
                query: query.to_vec(),
                values: opening.values.clone(),
            };
            wrong_opening.sources[index].1 = wrong;
            let mut bad = input[..start].to_vec();
            bad.extend(
                factor_seed_tail(profile, parameters, &wrong_opening, index)
                    .unwrap()
                    .0,
            );
            assert!(
                decomposition_opening_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &bad,
                    &before,
                    &base_views,
                    half
                )
                .is_none()
            );
            let seed = shake64(&input);
            let mut child_before = before.clone();
            child_before.insert(seed, input.clone());
            let (empty, producer) = receipt(&[]);
            child_before.insert(empty[16..].try_into().unwrap(), producer);
            let child = raw_child::<F, EF>(profile, label, context, &seed);
            let mut views = base_views.clone();
            views.insert(input.clone(), before.clone());
            let (inherited, rest) = decomposition_child_prefix_at::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child,
                &child_before,
                &views,
                half,
            )
            .unwrap();
            assert!(rest.is_empty());
            assert_eq!(inherited.selected, index);
            assert_eq!(
                encoded(&inherited.sources[index]),
                encoded(&opening.sources[index])
            );
            assert_eq!(inherited.family, family);
            if matches!(
                profile.specification().backend,
                Backend::Polyfrim | Backend::PolyfrimDictionary
            ) {
                let mut child_input = child.clone();
                let mut replay = ExtensionReplay::<F, EF>::child(profile, label, context, &seed);
                exercise_direct_factor::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &selected,
                    index,
                    &mut child_input,
                    &mut replay,
                    &child_before,
                    &views,
                );
                frame(
                    &mut child_input,
                    2,
                    b"decomposition direct sampling replay",
                    &64u64.to_le_bytes(),
                );
                let mut output = [0; 64];
                replay.get_challenge_bytes(b"decomposition direct sampling replay", &mut output);
                assert_eq!(shake64(&child_input), output);
            }
            if matches!(
                profile.specification().backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            ) {
                let mut child_input = child.clone();
                let mut replay = ExtensionReplay::<F, EF>::child(profile, label, context, &seed);
                exercise_fragment_factor::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &selected,
                    index,
                    &mut child_input,
                    &mut replay,
                    &child_before,
                    &views,
                );
                frame(
                    &mut child_input,
                    2,
                    b"decomposition fragmented sampling replay",
                    &64u64.to_le_bytes(),
                );
                let mut output = [0; 64];
                replay
                    .get_challenge_bytes(b"decomposition fragmented sampling replay", &mut output);
                assert_eq!(shake64(&child_input), output);
            }
            let mut missing = child_before.clone();
            missing.remove(&seed);
            assert!(
                decomposition_child_prefix_at::<F, EF, P>(
                    profile, pp, setup, statement, &child, &missing, &views, half
                )
                .is_none()
            );
            assert!(
                primary_child_prefix::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &child,
                    &child_before,
                    &views,
                    None
                )
                .is_none()
            );
            let mut bad = input.clone();
            bad.push(0);
            assert!(
                decomposition_opening_query_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &bad,
                    &before,
                    &base_views,
                    half
                )
                .is_none()
            );
            frame(&mut input, 3, b"classical child seed", &seed);
            frame(&mut input, 7, label, &[0; 64]);
        }
    }
    if half == 0 {
        exercise_decomposition_lookup_entry::<F, EF, P>(
            profile, pp, setup, statement, input, before, &opening,
        );
    } else {
        let (completed, rest) = second_decomposition_opening_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &input,
            &before,
            &base_views,
            true,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_eq!(completed.family, OpeningFamily::SecondDecomposition);
        assert_eq!(encoded(&completed.sources), encoded(&opening.sources));
        assert_eq!(encoded(&completed.values), encoded(&opening.values));
        exercise_second_lookup_compression::<F, EF, P>(
            profile, pp, setup, statement, input, before, base_views, &completed,
        );
    }
}

fn lookup_test_evaluate<F: NTTField, EF: AbstractExtensionField<F>>(
    claim: EF,
    degree: usize,
    coefficient: usize,
    point: EF,
) -> EF {
    let mut value = claim * point;
    if degree > 1 {
        let mut power = EF::one();
        for _ in 0..degree - 1 {
            power *= point;
        }
        value += EF::from_base(F::from(coefficient)) * power * (point - EF::one());
    }
    value
}
fn lookup_test_round<F: NTTField, EF: AbstractExtensionField<F>>(
    claim: EF,
    degree: usize,
    coefficient: usize,
) -> Vec<EF> {
    (0..=degree)
        .map(|index| {
            lookup_test_evaluate::<F, EF>(claim, degree, coefficient, EF::from_base(F::from(index)))
        })
        .collect()
}
fn exercise_lookup_batch_conformance<
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
>(
    profile: &ClassicalProfile,
    infos: &[algebra::PolynomialInfo],
    claims: &[EF],
) {
    let mut sampler = Transcript::<EF>::new_classical_extension::<F>(&profile.id().0);
    sampler.append_message(b"independent scalar sumcheck batch v1", &(infos, claims));
    let mut expected = claims.to_vec();
    let mut point = Vec::new();
    let mut instances: Vec<sumcheck::Proof<EF>> = vec![Vec::new(); infos.len()];
    for round in 0..infos[0].num_variables {
        let messages: Vec<_> = infos
            .iter()
            .zip(&expected)
            .enumerate()
            .map(|(index, (info, &claim))| {
                sumcheck::prover::ProverMsg::from_evaluations(lookup_test_round::<F, EF>(
                    claim,
                    info.max_multiplicands,
                    index + round + 2,
                ))
            })
            .collect();
        sampler.append_message(b"scalar batch round messages", &(round, &messages));
        let coin = sampler.get_challenge(b"scalar batch common challenge");
        for (index, ((instance, message), info)) in
            instances.iter_mut().zip(messages).zip(infos).enumerate()
        {
            instance.push(message);
            expected[index] = lookup_test_evaluate::<F, EF>(
                expected[index],
                info.max_multiplicands,
                index + round + 2,
                coin,
            );
        }
        point.push(coin);
    }
    let mut verifier = Transcript::<EF>::new_classical_extension::<F>(&profile.id().0);
    let subclaims = sumcheck::batch::verify(
        &mut verifier,
        infos,
        claims,
        &sumcheck::batch::Proof { instances },
    )
    .unwrap();
    for (subclaim, &value) in subclaims.iter().zip(&expected) {
        assert_eq!(subclaim.point, point);
        assert_eq!(subclaim.expected_evaluations, value);
    }
    let mut a = [0; 64];
    let mut b = [0; 64];
    sampler.get_challenge_bytes(b"lookup batch isolated conformance", &mut a);
    verifier.get_challenge_bytes(b"lookup batch isolated conformance", &mut b);
    assert_eq!(a, b);
}

fn exercise_lookup_helper_openings<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: Vec<u8>,
    before: Producers,
    views: FirstViews,
    terminal: &LookupTerminal<F, EF>,
    lookup_finish: [u8; 64],
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    exercise_lookup_helper_openings_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        terminal,
        lookup_finish,
        0,
    );
}
fn exercise_lookup_helper_openings_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
    mut views: FirstViews,
    terminal: &LookupTerminal<F, EF>,
    lookup_finish: [u8; 64],
    half: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    assert!(half < 2);
    let mut opening = lookup_helper_opening(pp, terminal).unwrap();
    if half == 1 {
        opening.family = OpeningFamily::SecondLookupHelper;
    }
    assert_eq!(opening.role(), 1);
    assert_ne!(pp.helper.num_vars(), pp.coefficients.num_vars());
    for index in 0..opening.sources.len() {
        opening.selected = index;
        let start = input.len();
        if profile.specification().backend == Backend::Brakedown {
            let (tail, count) = brakedown_first_tail(profile, &opening).unwrap();
            input.extend(tail);
            let selected = decomposition_lookup_helper_query_at::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, half,
            )
            .unwrap();
            assert_eq!(selected.family, opening.family);
            assert_eq!(selected.selected, index);
            assert_eq!(
                encoded(&selected.values[index]),
                encoded(&opening.values[index])
            );
            let mut wrong = input[..start].to_vec();
            wrong.extend(brakedown_row_tail_for_role(profile, &opening, 0).unwrap().0);
            assert!(
                decomposition_lookup_helper_query_at::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, half
                )
                .is_none()
            );
            let (coins, raw) = raw_prime_phase::<F>(&input, count);
            let (phase_receipt, producer) = receipt(&raw);
            let fingerprint = phase_receipt[16..].try_into().unwrap();
            before.insert(fingerprint, producer);
            frame(&mut input, 5, b"mw random linear test", &phase_receipt);
            let responses_start = input.len();
            let (tail, domain, cells) = brakedown_column_tail_for_role(profile, 1).unwrap();
            let test = vec![F::from(index + 5); cells];
            let evaluation = vec![F::from(index + 6); cells];
            frame(
                &mut input,
                1,
                b"mw linear responses",
                &encoded(&(&test, &evaluation)),
            );
            input.extend(&tail);
            let checked = decomposition_lookup_helper_column_query_at::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, half,
            )
            .unwrap();
            assert_eq!(checked.opening.selected, index);
            assert_eq!(checked.domain, domain);
            assert_eq!(checked.test, test);
            assert_eq!(checked.evaluation, evaluation);
            assert_eq!(
                checked.random,
                coins
                    .into_iter()
                    .map(|value| F::from(usize::try_from(value).unwrap()))
                    .collect::<Vec<_>>()
            );
            let mut missing = before.clone();
            missing.remove(&fingerprint);
            assert!(
                decomposition_lookup_helper_column_query_at::<F, EF, P>(
                    profile, pp, setup, statement, &input, &missing, &views, half
                )
                .is_none()
            );
            let (_, _, wrong_cells) = brakedown_column_tail(profile).unwrap();
            assert_ne!(cells, wrong_cells);
            let mut wrong = input[..responses_start].to_vec();
            frame(
                &mut wrong,
                1,
                b"mw linear responses",
                &encoded(&(vec![F::zero(); wrong_cells], vec![F::zero(); wrong_cells])),
            );
            wrong.extend(&tail);
            assert!(
                decomposition_lookup_helper_column_query_at::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, half
                )
                .is_none()
            );
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut xof = sha3::Shake256::default();
            Update::update(&mut xof, input.as_slice());
            let mut bytes = vec![0; 8 * profile.specification().roles[1].queries];
            xof.finalize_xof().read(&mut bytes);
            frame(&mut input, 3, b"mw atomic column block v5", &bytes);
        } else {
            let (tail, label, context) =
                factor_seed_tail(profile, pp.helper, &opening, index).unwrap();
            input.extend(tail);
            let selected = decomposition_lookup_helper_query_at::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, half,
            )
            .unwrap();
            assert_eq!(selected.family, opening.family);
            assert_eq!(selected.selected, index);
            assert_eq!(selected.role(), 1);
            let seed = shake64(&input);
            let mut child_before = before.clone();
            child_before.insert(seed, input.clone());
            let (empty, producer) = receipt(&[]);
            child_before.insert(empty[16..].try_into().unwrap(), producer);
            views.insert(input.clone(), before.clone());
            let child = raw_child::<F, EF>(profile, label, context, &seed);
            let (inherited, rest) = decomposition_lookup_helper_child_prefix_at::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child,
                &child_before,
                &views,
                half,
            )
            .unwrap();
            assert!(rest.is_empty());
            if half == 1 {
                assert!(
                    decomposition_lookup_helper_child_prefix::<F, EF, P>(
                        profile,
                        pp,
                        setup,
                        statement,
                        &child,
                        &child_before,
                        &views,
                    )
                    .is_none()
                );
            }
            assert_eq!(inherited.family, opening.family);
            assert_eq!(inherited.selected, index);
            assert_eq!(
                encoded(&inherited.sources[index]),
                encoded(&opening.sources[index])
            );
            assert_eq!(
                inherited.parameters(pp, index).unwrap().context().ok(),
                pp.helper.context().ok()
            );
            if matches!(
                profile.specification().backend,
                Backend::Polyfrim | Backend::PolyfrimDictionary
            ) {
                let mut child_input = child.clone();
                let mut replay = ExtensionReplay::<F, EF>::child(profile, label, context, &seed);
                exercise_direct_factor::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &inherited,
                    index,
                    &mut child_input,
                    &mut replay,
                    &child_before,
                    &views,
                );
                frame(
                    &mut child_input,
                    2,
                    b"lookup helper direct sampling replay",
                    &64u64.to_le_bytes(),
                );
                let mut output = [0; 64];
                replay.get_challenge_bytes(b"lookup helper direct sampling replay", &mut output);
                assert_eq!(shake64(&child_input), output);
            }
            if matches!(
                profile.specification().backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            ) {
                let mut child_input = child.clone();
                let mut replay = ExtensionReplay::<F, EF>::child(profile, label, context, &seed);
                exercise_fragment_factor::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &inherited,
                    index,
                    &mut child_input,
                    &mut replay,
                    &child_before,
                    &views,
                );
                frame(
                    &mut child_input,
                    2,
                    b"lookup helper fragment sampling replay",
                    &64u64.to_le_bytes(),
                );
                let mut output = [0; 64];
                replay.get_challenge_bytes(b"lookup helper fragment sampling replay", &mut output);
                assert_eq!(shake64(&child_input), output);
            }
            assert!(
                decomposition_child_prefix::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &child,
                    &child_before,
                    &views
                )
                .is_none()
            );
            let mut late = views.clone();
            late.get_mut(input.as_slice())
                .unwrap()
                .remove(&lookup_finish);
            assert!(child_before.contains_key(&lookup_finish));
            assert!(
                decomposition_lookup_helper_child_prefix_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &child,
                    &child_before,
                    &late,
                    half
                )
                .is_none()
            );
            let mut missing = child_before.clone();
            missing.remove(&seed);
            assert!(
                decomposition_lookup_helper_child_prefix_at::<F, EF, P>(
                    profile, pp, setup, statement, &child, &missing, &views, half
                )
                .is_none()
            );
            before.insert(seed, input.clone());
            frame(&mut input, 3, b"classical child seed", &seed);
            frame(&mut input, 7, label, &[0; 64]);
        }
    }
    let (completed, rest) = decomposition_lookup_helper_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views, true, half,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(completed.selected + 1, opening.sources.len());
    let (claims, binding) = lookup_source_bindings::<F, EF, P>(pp, terminal).unwrap();
    let lookup = &terminal.batch.equality.lookup;
    let digits = (lookup.sources.len() - 1) / 2;
    assert!(digits > 1);
    let mut aliased = lookup.sources.clone();
    aliased[1] = aliased[0].clone();
    let mut alias_values = terminal.source_values.clone();
    alias_values[1] = alias_values[0].clone();
    let (alias_claims, alias_binding) = lookup_source_registry_bindings::<F, P>(
        pp,
        &aliased,
        &lookup.requests,
        &terminal.source_query.query,
        &alias_values,
    )
    .unwrap();
    assert_eq!(alias_claims.len() + 1, claims.len());
    assert!(alias_claims.iter().all(|claim| claim.slot != 1));
    let alias_sources: Vec<_> = aliased
        .iter()
        .enumerate()
        .map(|(slot, (_, root))| CanonicalVerifierOracle {
            parameters: if slot < digits {
                pp.coefficients
            } else {
                pp.borrows
            },
            commitment: root,
        })
        .collect();
    let mut alias_production = profile.parent_transcript::<F>().unwrap();
    let observed = crate::packed_extension_lookup::canonical::shared::audit::source_obligations::<
        F,
        Sha512,
        P,
    >(
        &mut alias_production,
        &alias_sources,
        &lookup.requests,
        &terminal.source_query.query,
        &alias_values,
    )
    .unwrap();
    assert_eq!(observed, (alias_claims.len(), alias_claims.len()));
    let mut isolated_alias = initial_header::<F>(profile).unwrap();
    frame(
        &mut isolated_alias,
        1,
        P::REGISTRY_DOMAIN,
        &encoded(&aliased),
    );
    isolated_alias.extend(alias_binding);
    frame(
        &mut isolated_alias,
        2,
        b"lookup source alias replay",
        &64u64.to_le_bytes(),
    );
    let mut alias_output = [0; 64];
    alias_production.get_challenge_bytes(b"lookup source alias replay", &mut alias_output);
    assert_eq!(shake64(&isolated_alias), alias_output);
    alias_values[1][0] += F::one();
    assert!(
        lookup_source_registry_bindings::<F, P>(
            pp,
            &aliased,
            &lookup.requests,
            &terminal.source_query.query,
            &alias_values,
        )
        .is_none()
    );
    let mut rejected = profile.parent_transcript::<F>().unwrap();
    assert!(crate::packed_extension_lookup::canonical::shared::audit::source_obligations::<F, Sha512, P>(
        &mut rejected, &alias_sources, &lookup.requests,
        &terminal.source_query.query, &alias_values,
    ).is_err());
    let mut wrong_context = lookup.sources.clone();
    wrong_context[0].0.0[0] ^= 1;
    assert!(
        lookup_source_registry_bindings::<F, P>(
            pp,
            &wrong_context,
            &lookup.requests,
            &terminal.source_query.query,
            &terminal.source_values,
        )
        .is_none()
    );
    let sources: Vec<_> = lookup
        .sources
        .iter()
        .enumerate()
        .map(|(slot, (_, root))| CanonicalVerifierOracle {
            parameters: if slot < digits {
                pp.coefficients
            } else {
                pp.borrows
            },
            commitment: root,
        })
        .collect();
    let mut production = profile.parent_transcript::<F>().unwrap();
    let observed = crate::packed_extension_lookup::canonical::shared::audit::source_obligations::<
        F,
        Sha512,
        P,
    >(
        &mut production,
        &sources,
        &lookup.requests,
        &terminal.source_query.query,
        &terminal.source_values,
    )
    .unwrap();
    assert_eq!(observed, (claims.len(), claims.len()));
    let mut isolated = initial_header::<F>(profile).unwrap();
    frame(
        &mut isolated,
        1,
        P::REGISTRY_DOMAIN,
        &encoded(&lookup.sources),
    );
    isolated.extend(&binding);
    frame(
        &mut isolated,
        2,
        b"lookup source obligations replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    production.get_challenge_bytes(b"lookup source obligations replay", &mut output);
    assert_eq!(shake64(&isolated), output);
    let claims_start = input.len();
    input.extend(&binding);
    frame(
        &mut input,
        1,
        P::SEAL_DOMAIN,
        &encoded(&(claims.len(), claims.len())),
    );
    let (recovered, rest) = decomposition_lookup_source_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views, half,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(recovered.len(), claims.len());
    for (expected, actual) in claims.iter().zip(&recovered) {
        assert_eq!(expected.slot, actual.slot);
        assert_eq!(encoded(&expected.query), encoded(&actual.query));
        assert_eq!(encoded(&expected.value), encoded(&actual.value));
    }
    let mut wrong = input.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        decomposition_lookup_source_prefix_at::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &before, &views, half
        )
        .is_none()
    );
    let mut wrong = input[..claims_start].to_vec();
    wrong.extend(&binding);
    wrong.extend(&binding);
    frame(
        &mut wrong,
        1,
        P::SEAL_DOMAIN,
        &encoded(&(claims.len(), claims.len())),
    );
    assert!(
        decomposition_lookup_source_prefix_at::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &before, &views, half
        )
        .is_none()
    );
    assert!(
        decomposition_lookup_helper_query_at::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views, half
        )
        .is_none()
    );
    exercise_lookup_source_openings_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views,
        terminal,
        &claims,
        lookup_finish,
        half,
    );
}

fn exercise_lookup_source_openings_at<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
    mut views: FirstViews,
    terminal: &LookupTerminal<F, EF>,
    claims: &[LookupSourceClaim<F>],
    lookup_finish: [u8; 64],
    half: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    assert!(half < 2);
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    for claim in claims {
        let opening = lookup_source_opening_at(terminal, claim, half).unwrap();
        let start = input.len();
        if profile.specification().backend == Backend::Brakedown {
            let (tail, count) = lookup_source_batch_row_tail(profile, &opening).unwrap();
            input.extend(tail);
            let (selected, rest) = decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, false, half,
            )
            .unwrap();
            assert!(rest.is_empty());
            assert_eq!(selected.family, opening.family);
            let mut wrong = input[..start].to_vec();
            wrong.extend(brakedown_first_tail(profile, &opening).unwrap().0);
            assert!(
                decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, false, half
                )
                .is_none()
            );
            let (coins, raw) = raw_prime_phase::<F>(&input, count);
            let (phase_receipt, producer) = receipt(&raw);
            let fingerprint = phase_receipt[16..].try_into().unwrap();
            before.insert(fingerprint, producer);
            frame(
                &mut input,
                5,
                b"mw batch random linear test",
                &phase_receipt,
            );
            let response_start = input.len();
            let (tail, domain, cells) = brakedown_column_tail(profile).unwrap();
            let test = vec![F::from(claim.slot + 5); cells];
            let evaluation = vec![F::from(claim.slot + 6); cells];
            frame(
                &mut input,
                1,
                b"mw batch linear responses",
                &encoded(&(&test, vec![&evaluation])),
            );
            input.extend(&tail);
            let checked = decomposition_lookup_source_column_query_at::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, half,
            )
            .unwrap();
            assert_eq!(checked.opening.family, opening.family);
            assert_eq!(checked.domain, domain);
            assert_eq!(checked.test, test);
            assert_eq!(checked.evaluation, evaluation);
            assert_eq!(
                checked.random,
                coins
                    .into_iter()
                    .map(|v| F::from(usize::try_from(v).unwrap()))
                    .collect::<Vec<_>>()
            );
            let mut missing = before.clone();
            missing.remove(&fingerprint);
            assert!(
                decomposition_lookup_source_column_query_at::<F, EF, P>(
                    profile, pp, setup, statement, &input, &missing, &views, half
                )
                .is_none()
            );
            let mut wrong = input[..response_start].to_vec();
            frame(
                &mut wrong,
                1,
                b"mw batch linear responses",
                &encoded(&(&test, &evaluation)),
            );
            wrong.extend(&tail);
            assert!(
                decomposition_lookup_source_column_query_at::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, half
                )
                .is_none()
            );
            let mut state = sha3::Shake256::default();
            Update::update(&mut state, &input);
            let mut bytes = vec![0; 8 * profile.specification().roles[0].queries];
            state.finalize_xof().read(&mut bytes);
            frame(&mut input, 3, b"mw atomic column block v5", &bytes);
        } else {
            let parameters = opening.parameters(pp, 0).unwrap();
            let (tail, label, context) =
                factor_seed_tail(profile, parameters, &opening, 0).unwrap();
            input.extend(tail);
            let (selected, rest) = decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views, false, half,
            )
            .unwrap();
            assert!(rest.is_empty());
            assert_eq!(selected.family, opening.family);
            let seed = shake64(&input);
            let mut child_before = before.clone();
            child_before.insert(seed, input.clone());
            let (empty, producer) = receipt(&[]);
            child_before.insert(empty[16..].try_into().unwrap(), producer);
            views.insert(input.clone(), before.clone());
            let child = raw_child::<F, EF>(profile, label, context, &seed);
            let (selected, rest) = decomposition_lookup_source_child_prefix_at::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child,
                &child_before,
                &views,
                half,
            )
            .unwrap();
            assert!(rest.is_empty());
            assert_eq!(selected.family, opening.family);
            if half == 1 {
                assert!(
                    decomposition_lookup_source_child_prefix::<F, EF, P>(
                        profile,
                        pp,
                        setup,
                        statement,
                        &child,
                        &child_before,
                        &views,
                    )
                    .is_none()
                );
            }
            assert_eq!(encoded(&selected.sources), encoded(&opening.sources));
            assert_eq!(encoded(&selected.query), encoded(&opening.query));
            assert_eq!(encoded(&selected.values), encoded(&opening.values));
            let mut child_input = child.clone();
            let mut replay = ExtensionReplay::<F, EF>::child(profile, label, context, &seed);
            if matches!(
                profile.specification().backend,
                Backend::Polyfrim | Backend::PolyfrimDictionary
            ) {
                exercise_direct_factor::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &selected,
                    0,
                    &mut child_input,
                    &mut replay,
                    &child_before,
                    &views,
                );
            } else {
                exercise_fragment_factor::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &selected,
                    0,
                    &mut child_input,
                    &mut replay,
                    &child_before,
                    &views,
                );
            }
            frame(
                &mut child_input,
                2,
                b"lookup source PCS sampling replay",
                &64u64.to_le_bytes(),
            );
            let mut output = [0; 64];
            replay.get_challenge_bytes(b"lookup source PCS sampling replay", &mut output);
            assert_eq!(shake64(&child_input), output);
            let mut missing = child_before.clone();
            missing.remove(&seed);
            assert!(
                decomposition_lookup_source_child_prefix_at::<F, EF, P>(
                    profile, pp, setup, statement, &child, &missing, &views, half
                )
                .is_none()
            );
            let mut late = views.clone();
            late.get_mut(input.as_slice())
                .unwrap()
                .remove(&lookup_finish);
            assert!(child_before.contains_key(&lookup_finish));
            assert!(
                decomposition_lookup_source_child_prefix_at::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &child,
                    &child_before,
                    &late,
                    half
                )
                .is_none()
            );
            let mut changed = lookup_source_opening_at(terminal, claim, half).unwrap();
            changed.sources[0].1.root.0[0] ^= 1;
            let mut wrong = input[..start].to_vec();
            wrong.extend(
                factor_seed_tail(profile, parameters, &changed, 0)
                    .unwrap()
                    .0,
            );
            assert!(
                decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views, false, half
                )
                .is_none()
            );
            before.insert(seed, input.clone());
            frame(&mut input, 3, b"classical child seed", &seed);
            frame(&mut input, 7, label, &[0; 64]);
        }
    }
    let (last, rest) = decomposition_lookup_source_opening_prefix_at::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views, true, half,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        last.family,
        lookup_source_opening_at(terminal, claims.last().unwrap(), half)
            .unwrap()
            .family
    );
    if half == 0 {
        exercise_second_decomposition_entry::<F, EF, P>(
            profile, pp, setup, statement, input, before, &views,
        );
    } else {
        exercise_accumulator_entry::<F, EF, P>(
            profile, pp, setup, statement, input, before, &views,
        );
    }
}

fn exercise_accumulator_entry<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
    views: &FirstViews,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (expected, binding) =
        accumulator_binding::<F, EF, P>(profile, pp, setup, statement, &input).unwrap();
    let start = input.len();
    input.extend(&binding);
    let width = pp.accumulators[0].width();
    let mut base = Vec::new();
    let mut previous = None;
    for round in 0..pp.accumulators[0].num_vars() {
        let tail = accumulator_lane_tail::<F>(width).unwrap();
        input.extend(&tail);
        let (task, rest) = accumulator_prefix::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, views, round,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_eq!(encoded(&task.sources), encoded(&expected.sources));
        assert_eq!(encoded(&task.initial), encoded(&expected.initial));
        assert_eq!(encoded(&task.final_acc), encoded(&expected.final_acc));
        assert_eq!(encoded(&task.base), encoded(&base));
        if round == 0 {
            for endpoint in [false, true] {
                let (mut changed, _) =
                    accumulator_binding::<F, EF, P>(profile, pp, setup, statement, &input).unwrap();
                if endpoint {
                    changed.final_acc[0] += F::one();
                } else {
                    changed.sources.swap(5, 6);
                }
                let mut wrong = input[..start].to_vec();
                frame(
                    &mut wrong,
                    1,
                    P::ACCUMULATOR_DOMAIN,
                    &encoded(&(
                        &changed.shape,
                        &changed.initial,
                        &changed.final_acc,
                        &changed.sources,
                    )),
                );
                wrong.extend(&tail);
                assert!(
                    accumulator_prefix::<F, EF, P>(
                        profile, pp, setup, statement, &wrong, &before, views, round,
                    )
                    .is_none()
                );
            }
        }
        if let Some(previous) = previous {
            let mut missing = before.clone();
            missing.remove(&previous);
            assert!(
                accumulator_prefix::<F, EF, P>(
                    profile, pp, setup, statement, &input, &missing, views, round,
                )
                .is_none()
            );
        }
        let mut wrong = input.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(
            accumulator_prefix::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, views, round,
            )
            .is_none()
        );
        let (coins, raw) = raw_prime_phase::<F>(&input, width);
        base.push(
            sumcheck::packed::challenge_pair(
                &coins
                    .into_iter()
                    .map(|v| F::from(usize::try_from(v).unwrap()))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        let (phase_receipt, producer) = receipt(&raw);
        let fingerprint = phase_receipt[16..].try_into().unwrap();
        before.insert(fingerprint, producer);
        previous = Some(fingerprint);
        frame(
            &mut input,
            5,
            b"accumulator independent lane challenges",
            &phase_receipt,
        );
    }
    let (task, queries, rest) = accumulator_queries_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&task.base), encoded(&base));
    assert_eq!(
        queries.iter().map(Vec::len).collect::<Vec<_>>(),
        task.shape.opening_counts(width).unwrap().to_vec()
    );
    exercise_accumulator_isolated::<F, P>(profile, pp, &task, &binding);
    exercise_accumulator_openings::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        views.clone(),
        &task,
        &queries,
    );
}

fn exercise_accumulator_openings<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
    mut views: FirstViews,
    task: &AccumulatorTask<F>,
    queries: &[Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>],
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let values = exercise_accumulator_arithmetic::<F, P>(pp, task);
    let mut last_start = 0;
    let mut last_tail_len = 0;
    for slot in 0..7 {
        let start = input.len();
        let tail = accumulator_opening_tail(profile, pp, task, &queries[slot], &values[slot], slot)
            .unwrap();
        last_start = start;
        last_tail_len = tail.len();
        input.extend(&tail);
        let (selected, rest) = accumulator_opening_prefix::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, &views, false,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_eq!(selected.selected, slot);
        assert_eq!(
            encoded(&selected.task.sources[slot]),
            encoded(&task.sources[slot])
        );
        assert_eq!(encoded(&selected.values[slot]), encoded(&values[slot]));
        let mut changed = AccumulatorTask {
            shape: task.shape.clone(),
            initial: task.initial.clone(),
            final_acc: task.final_acc.clone(),
            sources: task.sources.clone(),
            base: task.base.clone(),
        };
        changed.sources[slot].1.root.0[0] ^= 1;
        let mut wrong = input[..start].to_vec();
        wrong.extend(
            accumulator_opening_tail(profile, pp, &changed, &queries[slot], &values[slot], slot)
                .unwrap(),
        );
        assert!(
            accumulator_opening_prefix::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, &views, false
            )
            .is_none()
        );
        if profile.specification().backend == Backend::Brakedown {
            let (_, count) = accumulator_row_request_tail::<F>(profile).unwrap();
            let (coins, raw) = raw_prime_phase::<F>(&input, count);
            let (phase_receipt, producer) = receipt(&raw);
            let fingerprint = phase_receipt[16..].try_into().unwrap();
            before.insert(fingerprint, producer);
            frame(
                &mut input,
                5,
                b"mw batch random linear test",
                &phase_receipt,
            );
            let response_start = input.len();
            let (tail, domain, cells) = brakedown_column_tail(profile).unwrap();
            let representatives = accumulator_representatives(profile, &queries[slot]).unwrap();
            let test = vec![F::from(slot + 5); cells];
            let evaluations: Vec<_> = (0..representatives.len())
                .map(|index| vec![F::from(slot + index + 7); cells])
                .collect();
            frame(
                &mut input,
                1,
                b"mw batch linear responses",
                &encoded(&(&test, &evaluations)),
            );
            input.extend(&tail);
            let compiled = accumulator_column_query::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, &views,
            )
            .unwrap();
            assert_eq!(compiled.opening.selected, slot);
            assert_eq!(compiled.domain, domain);
            assert_eq!(compiled.representatives, representatives);
            assert_eq!(compiled.test, test);
            assert_eq!(compiled.evaluations, evaluations);
            assert_eq!(
                compiled.random,
                coins
                    .into_iter()
                    .map(|x| F::from(usize::try_from(x).unwrap()))
                    .collect::<Vec<_>>()
            );
            let mut missing = before.clone();
            missing.remove(&fingerprint);
            assert!(
                accumulator_column_query::<F, EF, P>(
                    profile, pp, setup, statement, &input, &missing, &views
                )
                .is_none()
            );
            let mut wrong = input[..response_start].to_vec();
            frame(
                &mut wrong,
                1,
                b"mw batch linear responses",
                &encoded(&(
                    &test,
                    vec![vec![F::zero(); cells]; representatives.len() + 1],
                )),
            );
            wrong.extend(&tail);
            assert!(
                accumulator_column_query::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, &views
                )
                .is_none()
            );
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut state = sha3::Shake256::default();
            Update::update(&mut state, &input);
            let mut bytes = vec![0; 8 * profile.specification().roles[0].queries];
            state.finalize_xof().read(&mut bytes);
            frame(&mut input, 3, b"mw atomic column block v5", &bytes);
        } else {
            let (_, label, context) = pcs_child_labels(profile.specification().backend).unwrap();
            let seed = shake64(&input);
            let mut known = before.clone();
            known.insert(seed, input.clone());
            let (empty, producer) = receipt(&[]);
            known.insert(empty[16..].try_into().unwrap(), producer);
            views.insert(input.clone(), before.clone());
            let child = raw_child::<F, EF>(profile, label, context, &seed);
            let (compiled, rest) = accumulator_child_prefix::<F, EF, P>(
                profile, pp, setup, statement, &child, &known, &views,
            )
            .unwrap();
            assert!(rest.is_empty());
            assert_eq!(compiled.selected, slot);
            assert_eq!(
                encoded(&compiled.queries[slot]),
                encoded(&selected.queries[slot])
            );
            assert_eq!(encoded(&compiled.values[slot]), encoded(&values[slot]));
            if matches!(
                profile.specification().backend,
                Backend::Polyfrim | Backend::PolyfrimDictionary
            ) {
                exercise_accumulator_direct_consistency::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    child.clone(),
                    &known,
                    &views,
                    &compiled,
                );
            } else {
                exercise_accumulator_fragment_bridge::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    child.clone(),
                    &known,
                    &views,
                    &compiled,
                );
            }
            let mut missing = known.clone();
            missing.remove(&seed);
            assert!(
                accumulator_child_prefix::<F, EF, P>(
                    profile, pp, setup, statement, &child, &missing, &views
                )
                .is_none()
            );
            let mut missing_view = views.clone();
            missing_view.remove(input.as_slice());
            assert!(
                accumulator_child_prefix::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &child,
                    &known,
                    &missing_view
                )
                .is_none()
            );
            before.insert(seed, input.clone());
            frame(&mut input, 3, b"classical child seed", &seed);
            frame(&mut input, 7, label, &[0; 64]);
        }
    }
    let (complete, rest) = accumulator_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views, true,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(complete.selected, 6);
    assert_eq!(encoded(&complete.values), encoded(&values));
    monomial_entry_audit::exercise_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views,
    );
    // All earlier completions remain conditional obligations. Replacing a
    // bounded final claim must fail the collected arithmetic predicate too.
    let mut bad_values = values[6].clone();
    bad_values[0][0] += F::one();
    bad_values[0] = accumulator_parameters(pp, 6)
        .unwrap()
        .normalize_values(std::mem::take(&mut bad_values[0]));
    let mut wrong = input[..last_start].to_vec();
    wrong.extend(accumulator_opening_tail(profile, pp, task, &queries[6], &bad_values, 6).unwrap());
    wrong.extend(&input[last_start + last_tail_len..]);
    assert!(
        accumulator_opening_prefix::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &before, &views, true
        )
        .is_none()
    );
}

fn exercise_accumulator_direct_consistency<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut child: Vec<u8>,
    before: &Producers,
    views: &FirstViews,
    opening: &AccumulatorOpening<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let slot = opening.selected;
    let role = &profile.specification().roles[0];
    let (core, domain) = direct_core::<F, EF>(profile).unwrap();
    let claims = opening.queries[slot].len();
    let mut queries = Vec::new();
    let mut values = Vec::new();
    for (query, value) in opening.queries[slot].iter().zip(&opening.values[slot]) {
        let (query, value) = accumulator_parameters(pp, slot)
            .unwrap()
            .normalize_claim(query.clone(), value.clone())
            .ok()
            .unwrap();
        queries.push(
            query
                .iter()
                .map(|pair| algebra::matrix_weighted::MatrixPair {
                    zero: algebra::matrix_weighted::Matrix::new(
                        role.width,
                        pair.zero
                            .values()
                            .iter()
                            .copied()
                            .map(EF::from_base)
                            .collect(),
                    )
                    .unwrap(),
                    one: algebra::matrix_weighted::Matrix::new(
                        role.width,
                        pair.one
                            .values()
                            .iter()
                            .copied()
                            .map(EF::from_base)
                            .collect(),
                    )
                    .unwrap(),
                })
                .collect::<Vec<_>>(),
        );
        values.push(value.into_iter().map(EF::from_base).collect::<Vec<_>>());
    }
    let source = opening.task.sources[slot].1.root;
    let roots: Vec<_> = (0..claims)
        .map(|index| {
            let mut roots = vec![Digest512([u8::try_from(index + 1).unwrap(); 64]); role.num_vars];
            roots[0] = source;
            roots
        })
        .collect();
    frame(
        &mut child,
        1,
        b"packed PolyFRIM joint query proximity v1",
        &encoded(&(&core, source, claims, &queries, &values, &roots)),
    );
    for member in 0..claims {
        frame(
            &mut child,
            1,
            b"packed PolyFRIM joint consistency member v1",
            &encoded(&member),
        );
        let start = child.len();
        let binding = (
            &core,
            source,
            &roots[member][1..],
            &queries[member],
            &values[member],
        );
        frame(
            &mut child,
            1,
            b"packed PolyFRIM consistency v2",
            &encoded(&binding),
        );
        frame(
            &mut child,
            1,
            b"index domain",
            &(domain as u64).to_le_bytes(),
        );
        let request = u64::try_from(role.queries * 8).unwrap().to_le_bytes();
        frame(&mut child, 2, b"packed PolyFRIM domain index v2", &request);
        let selected = accumulator_direct_consistency_query::<F, EF, P>(
            profile, pp, setup, statement, &child, before, views, member,
        )
        .unwrap();
        assert_eq!(selected.selected, slot);
        assert_eq!(
            encoded(&selected.values[slot]),
            encoded(&opening.values[slot])
        );
        let mut wrong = child[..start].to_vec();
        let mut changed = values[member].clone();
        changed[0] += EF::one();
        frame(
            &mut wrong,
            1,
            b"packed PolyFRIM consistency v2",
            &encoded(&(
                &core,
                source,
                &roots[member][1..],
                &queries[member],
                &changed,
            )),
        );
        frame(
            &mut wrong,
            1,
            b"index domain",
            &(domain as u64).to_le_bytes(),
        );
        frame(&mut wrong, 2, b"packed PolyFRIM domain index v2", &request);
        assert!(
            accumulator_direct_consistency_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, before, views, member
            )
            .is_none()
        );
        assert!(
            accumulator_direct_consistency_query::<F, EF, P>(
                profile, pp, setup, statement, &child, before, views, claims
            )
            .is_none()
        );
        // Earlier sampler outputs are framing obligations here, not Merkle authentication.
        frame(
            &mut child,
            3,
            b"packed PolyFRIM domain index v2",
            &vec![0; role.queries * 8],
        );
    }
    // The selected group can have 1, 2, 3, or row_bits+3 claims; projection
    // count follows that group, never the packing width.
    frame(
        &mut child,
        1,
        b"packed PolyFRIM joint projections v1",
        &encoded(&(&core, &roots)),
    );
    child.extend(direct_projection_count_tail::<F, EF>(profile, claims).unwrap());
    let selected = accumulator_direct_projection_query::<F, EF, P>(
        profile, pp, setup, statement, &child, before, views,
    )
    .unwrap();
    assert_eq!(selected.opening.selected, slot);
    assert_eq!(selected.roots, roots);
    let mut wrong = child.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        accumulator_direct_projection_query::<F, EF, P>(
            profile, pp, setup, statement, &wrong, before, views
        )
        .is_none()
    );
    let rounds = role.num_vars;
    let count = rounds * claims * role.width;
    let (coefficients, raw) = raw_prime_phase::<F>(&child, count * EF::D);
    let weights: Vec<_> = coefficients
        .chunks_exact(EF::D)
        .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
        .collect();
    let mut known = before.clone();
    let (phase_receipt, producer) = receipt(&raw);
    let mut previous: [u8; 64] = phase_receipt[16..].try_into().unwrap();
    known.insert(previous, producer);
    frame(
        &mut child,
        5,
        b"packed PolyFRIM atomic joint lane weights v3",
        &phase_receipt,
    );
    let originals: Vec<_> = weights
        .chunks_exact(claims * role.width)
        .enumerate()
        .map(|(layer, row)| {
            let rows: Vec<_> = row.chunks_exact(role.width).map(<[EF]>::to_vec).collect();
            RollingRoot {
                root: Digest512(
                    Sha512::digest(encoded(&(
                        b"packed PolyFRIM joint virtual layer v1".as_slice(),
                        &core,
                        layer,
                        &roots,
                        &rows,
                    )))
                    .into(),
                ),
            }
        })
        .collect();
    let fri = direct_fri::<F, EF>(profile).unwrap();
    let context = Digest512(
        Sha512::digest(encoded(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            EF::MODULUS_VALUE.to_string(),
            &fri,
        )))
        .into(),
    );
    frame(
        &mut child,
        1,
        b"HasteBoots rolling batch FRI virtual all v2",
        &encoded(&(context, &originals)),
    );
    let mut alphas = Vec::new();
    let mut derived = Vec::new();
    for round in 0..rounds {
        child.extend(rolling_alpha_tail::<F, EF>());
        let compiled = accumulator_direct_rolling_query::<F, EF, P>(
            profile, pp, setup, statement, &child, &known, views, round,
        )
        .unwrap();
        assert_eq!(compiled.direct.opening.selected, slot);
        assert_eq!(compiled.data.weights, weights);
        assert_eq!(compiled.data.alphas, alphas);
        assert_eq!(encoded(&compiled.data.originals), encoded(&originals));
        assert_eq!(encoded(&compiled.data.derived), encoded(&derived));
        let mut missing = known.clone();
        missing.remove(&previous);
        assert!(
            accumulator_direct_rolling_query::<F, EF, P>(
                profile, pp, setup, statement, &child, &missing, views, round
            )
            .is_none()
        );
        let mut wrong = child.clone();
        wrong.push(0);
        assert!(
            accumulator_direct_rolling_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &known, views, round
            )
            .is_none()
        );
        let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
        alphas.push(EF::from_base_fn(|i| {
            F::from(usize::try_from(coefficients[i]).unwrap())
        }));
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        known.insert(previous, producer);
        frame(&mut child, 5, b"rolling FRI fold challenge", &phase_receipt);
        if round + 1 < rounds {
            let root = RollingRoot {
                root: Digest512([u8::try_from(round + 71).unwrap(); 64]),
            };
            frame(
                &mut child,
                1,
                b"rolling FRI derived root",
                &encoded(&(round + 1, &root)),
            );
            derived.push(root);
        }
    }
    let terminal = EF::from_base(F::from(17usize));
    frame(&mut child, 1, b"rolling FRI terminal", &encoded(&terminal));
    frame(
        &mut child,
        1,
        b"index domain",
        &(domain as u64).to_le_bytes(),
    );
    frame(
        &mut child,
        2,
        b"rolling FRI unbiased domain index",
        &u64::try_from(role.queries * 8).unwrap().to_le_bytes(),
    );
    let (compiled, value) = accumulator_direct_rolling_indices::<F, EF, P>(
        profile, pp, setup, statement, &child, &known, views,
    )
    .unwrap();
    assert_eq!(value, terminal);
    assert_eq!(compiled.data.alphas, alphas);
    let mut missing = known.clone();
    missing.remove(&previous);
    assert!(
        accumulator_direct_rolling_indices::<F, EF, P>(
            profile, pp, setup, statement, &child, &missing, views
        )
        .is_none()
    );
    let mut wrong = child.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        accumulator_direct_rolling_indices::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &known, views
        )
        .is_none()
    );
}

fn exercise_accumulator_fragment_bridge<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut child: Vec<u8>,
    before: &Producers,
    views: &FirstViews,
    opening: &AccumulatorOpening<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let slot = opening.selected;
    let count = opening.queries[slot].len() * profile.specification().roles[0].width;
    let (tail, label) = ntt_fragment_projection_tail::<F, EF>(profile, count).unwrap();
    child.extend(tail);
    let (compiled, rest) = accumulator_fragment_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, &child, before, views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(compiled.selected, slot);
    let mut wrong = child.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        accumulator_fragment_projection_prefix::<F, EF, P>(
            profile, pp, setup, statement, &wrong, before, views
        )
        .is_none()
    );
    let (coefficients, raw) = raw_prime_phase::<F>(&child, count * EF::D);
    let rho: Vec<_> = coefficients
        .chunks_exact(EF::D)
        .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
        .collect();
    let mut expected = rho
        .iter()
        .zip(opening.values[slot].iter().flatten())
        .fold(EF::zero(), |sum, (&r, &v)| sum + r * EF::from_base(v));
    let mut known = before.clone();
    let (phase_receipt, producer) = receipt(&raw);
    let mut previous: [u8; 64] = phase_receipt[16..].try_into().unwrap();
    known.insert(previous, producer);
    frame(&mut child, 5, label, &phase_receipt);
    let n = role_vars_for_bridge(profile);
    let info = algebra::PolynomialInfo {
        num_variables: n,
        max_multiplicands: 2,
    };
    frame(&mut child, 1, b"polynomial info", &encoded(&info));
    let mut point = Vec::new();
    for round in 0..n {
        let start = child.len();
        let evaluations = vec![EF::zero(), expected, expected + expected];
        let msg = sumcheck::prover::ProverMsg::from_evaluations(evaluations.clone());
        frame(&mut child, 1, b"sumcheck msg", &encoded(&msg));
        child.extend(bridge_round_tail::<F, EF>());
        let compiled = accumulator_fragment_round_query::<F, EF, P>(
            profile, pp, setup, statement, &child, &known, views, round,
        )
        .unwrap();
        assert_eq!(compiled.opening.selected, slot);
        assert_eq!(compiled.rho, rho);
        assert_eq!(compiled.point, point);
        assert_eq!(compiled.expected, expected);
        assert_eq!(compiled.evaluations, evaluations);
        let mut missing = known.clone();
        missing.remove(&previous);
        assert!(
            accumulator_fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, &child, &missing, views, round
            )
            .is_none()
        );
        let mut wrong = child[..start].to_vec();
        let mut changed = evaluations.clone();
        changed[0] += EF::one();
        frame(
            &mut wrong,
            1,
            b"sumcheck msg",
            &encoded(&sumcheck::prover::ProverMsg::from_evaluations(changed)),
        );
        wrong.extend(bridge_round_tail::<F, EF>());
        assert!(
            accumulator_fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &known, views, round
            )
            .is_none()
        );
        let mut trailing = child.clone();
        trailing.push(0);
        assert!(
            accumulator_fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, &trailing, &known, views, round
            )
            .is_none()
        );
        assert!(
            accumulator_fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, &child, &known, views, n
            )
            .is_none()
        );
        let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
        let coin = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        expected = quadratic(&evaluations, coin);
        point.push(coin);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        known.insert(previous, producer);
        frame(&mut child, 5, b"random point in each round", &phase_receipt);
    }
    let (_, retained, fragments, context, _) = scalar_geometry::<F, EF>(profile).unwrap();
    let entries: Vec<_> = (0..fragments)
        .map(|i| EF::from_base(F::from(i + 3)))
        .collect();
    // Boolean-basis reference, independent of the parser's adjacent-pair folds.
    let value = entries
        .iter()
        .enumerate()
        .fold(EF::zero(), |sum, (index, &entry)| {
            let weight = point[retained..]
                .iter()
                .enumerate()
                .fold(EF::one(), |w, (bit, &x)| {
                    w * if index & (1usize << bit) == 0 {
                        EF::one() - x
                    } else {
                        x
                    }
                });
            sum + weight * entry
        });
    let virtual_source = profile.specification().backend == Backend::FragmentedPipfriVirtual;
    let root = &opening.task.sources[slot].1;
    let (mode_label, mode, binding_label) = if virtual_source {
        (
            b"unmasked virtual PipFRI PCS v2".as_slice(),
            encoded(&n),
            b"unmasked scalar PipFRI virtual v2".as_slice(),
        )
    } else {
        (
            b"ordinary PipFRI PCS adapter v1".as_slice(),
            encoded(&(n, b"base table".as_slice())),
            b"HasteBoots ordinary PipFRI v1".as_slice(),
        )
    };
    let binding = |root: &Commitment<Digest512>, entries: &[EF]| {
        if virtual_source {
            encoded(&(2u32, context, root, &point, value, entries))
        } else {
            encoded(&(context, root, &point, value, entries))
        }
    };
    let start = child.len();
    frame(&mut child, 1, mode_label, &mode);
    frame(&mut child, 1, binding_label, &binding(root, &entries));
    let tail = gamma_tail::<F, EF>(profile).unwrap().0;
    child.extend(&tail);
    let compiled = accumulator_scalar_gamma_query::<F, EF, P>(
        profile, pp, setup, statement, &child, &known, views,
    )
    .unwrap();
    assert_eq!(compiled.bridge.opening.selected, slot);
    assert_eq!(compiled.point, point);
    assert_eq!(compiled.bridge_expected, expected);
    assert_eq!(compiled.value, value);
    assert_eq!(compiled.fragments, entries);
    // The gamma request precedes scalar PCS acceptance. Check the eventual
    // necessary terminal equation separately, including a scalar claim whose
    // fragments are internally consistent but whose bridge equation is false.
    let kernel = fragment_terminal_kernel(
        profile.specification().roles[0].width,
        &opening.queries[slot],
        &rho,
        &point,
    )
    .unwrap();
    if kernel != EF::zero() {
        let mut terminal = compiled;
        terminal.value = terminal.bridge_expected / kernel;
        terminal.fragments.fill(terminal.value);
        assert!(accumulator_bridge_terminal_valid(
            &terminal,
            profile.specification().roles[0].width
        ));
        terminal.value += EF::one();
        terminal.fragments.fill(terminal.value);
        assert!(!accumulator_bridge_terminal_valid(
            &terminal,
            profile.specification().roles[0].width
        ));
    } else {
        assert_eq!(
            accumulator_bridge_terminal_valid(&compiled, profile.specification().roles[0].width),
            expected == EF::zero()
        );
    }
    let mut missing = known.clone();
    missing.remove(&previous);
    assert!(
        accumulator_scalar_gamma_query::<F, EF, P>(
            profile, pp, setup, statement, &child, &missing, views
        )
        .is_none()
    );
    let mut wrong_root = root.clone();
    wrong_root.root.0[0] ^= 1;
    let changed: Vec<_> = entries.iter().map(|&v| v + EF::one()).collect();
    for payload in [binding(&wrong_root, &entries), binding(root, &changed)] {
        let mut wrong = child[..start].to_vec();
        frame(&mut wrong, 1, mode_label, &mode);
        frame(&mut wrong, 1, binding_label, &payload);
        wrong.extend(&tail);
        assert!(
            accumulator_scalar_gamma_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &known, views
            )
            .is_none()
        );
    }
    let mut oversized = if virtual_source {
        encoded(&(2u32, context, root, &point, value))
    } else {
        encoded(&(context, root, &point, value))
    };
    oversized.extend(encoded(&usize::MAX));
    let mut wrong = child[..start].to_vec();
    frame(&mut wrong, 1, mode_label, &mode);
    frame(&mut wrong, 1, binding_label, &oversized);
    wrong.extend(&tail);
    assert!(
        accumulator_scalar_gamma_query::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &known, views
        )
        .is_none()
    );
    let mut trailing = child.clone();
    trailing.push(0);
    assert!(
        accumulator_scalar_gamma_query::<F, EF, P>(
            profile, pp, setup, statement, &trailing, &known, views
        )
        .is_none()
    );
    let (_, gamma_label) = gamma_tail::<F, EF>(profile).unwrap();
    let (_, _, _, _, fri_context) = scalar_geometry::<F, EF>(profile).unwrap();
    let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
    let gamma = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
    let (gamma_receipt, producer) = receipt(&raw);
    previous = gamma_receipt[16..].try_into().unwrap();
    known.insert(previous, producer);
    frame(&mut child, 5, gamma_label, &gamma_receipt);
    let ladder: Vec<_> = (0..retained - usize::from(virtual_source))
        .map(|i| RollingRoot {
            root: Digest512([u8::try_from(i + 37).unwrap(); 64]),
        })
        .collect();
    let mut originals = Vec::new();
    if virtual_source {
        originals.push(RollingRoot {
            root: Digest512(
                Sha512::digest(encoded(&(
                    b"unmasked PipFRI virtual initial v2".as_slice(),
                    context,
                    root,
                    &point,
                    gamma,
                )))
                .into(),
            ),
        });
    }
    originals.extend(ladder.clone());
    let public_label = if virtual_source {
        b"unmasked virtual PipFRI public roots v2".as_slice()
    } else {
        b"PipFRI public fold roots"
    };
    frame(&mut child, 1, public_label, &encoded(&ladder));
    let rolling_label = if virtual_source {
        b"HasteBoots rolling batch FRI virtual initial v1".as_slice()
    } else {
        b"HasteBoots rolling batch FRI v1"
    };
    frame(
        &mut child,
        1,
        rolling_label,
        &encoded(&(fri_context, &originals)),
    );
    let mut alphas = Vec::new();
    let mut derived = Vec::new();
    let mut wrong_layer = None;
    for round in 0..retained {
        child.extend(rolling_alpha_tail::<F, EF>());
        let compiled = accumulator_rolling_alpha_query::<F, EF, P>(
            profile, pp, setup, statement, &child, &known, views, round,
        )
        .unwrap();
        assert_eq!(compiled.scalar.bridge.opening.selected, slot);
        assert_eq!(compiled.data.gamma, gamma);
        assert_eq!(compiled.data.alphas, alphas);
        assert_eq!(encoded(&compiled.data.originals), encoded(&originals));
        assert_eq!(encoded(&compiled.data.derived), encoded(&derived));
        let mut missing = known.clone();
        missing.remove(&previous);
        assert!(
            accumulator_rolling_alpha_query::<F, EF, P>(
                profile, pp, setup, statement, &child, &missing, views, round
            )
            .is_none()
        );
        if let Some(at) = wrong_layer {
            let mut wrong = child.clone();
            wrong[at] ^= 1;
            assert!(
                accumulator_rolling_alpha_query::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &known, views, round
                )
                .is_none()
            );
        }
        let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
        let alpha = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        alphas.push(alpha);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        known.insert(previous, producer);
        frame(&mut child, 5, b"rolling FRI fold challenge", &phase_receipt);
        if round + 1 < retained {
            let root = RollingRoot {
                root: Digest512([u8::try_from(round + 71).unwrap(); 64]),
            };
            let start = child.len();
            let label = b"rolling FRI derived root";
            frame(&mut child, 1, label, &encoded(&(round + 1, &root)));
            wrong_layer = Some(start + 1 + 8 + label.len() + 8);
            derived.push(root);
        }
    }
    let terminal = EF::from_base(F::from(17usize));
    frame(&mut child, 1, b"rolling FRI terminal", &encoded(&terminal));
    let (tail, domain) = rolling_index_tail(profile).unwrap();
    child.extend(tail);
    let (compiled, value) = accumulator_rolling_index_query::<F, EF, P>(
        profile, pp, setup, statement, &child, &known, views,
    )
    .unwrap();
    assert_eq!(value, terminal);
    assert_eq!(compiled.data.alphas, alphas);
    let mut missing = known.clone();
    missing.remove(&previous);
    assert!(
        accumulator_rolling_index_query::<F, EF, P>(
            profile, pp, setup, statement, &child, &missing, views
        )
        .is_none()
    );
    let mut wrong = child.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        accumulator_rolling_index_query::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &known, views
        )
        .is_none()
    );
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut state = sha3::Shake256::default();
    Update::update(&mut state, &child);
    let mut bytes = vec![0; profile.specification().roles[0].queries * 8];
    state.finalize_xof().read(&mut bytes);
    let indices: Vec<_> = bytes
        .chunks_exact(8)
        .map(|chunk| (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize)
        .collect();
    frame(&mut child, 3, b"rolling FRI unbiased domain index", &bytes);
    child.extend(consistency_index_tail(profile).unwrap());
    let (compiled, replayed) = accumulator_consistency_index_query::<F, EF, P>(
        profile, pp, setup, statement, &child, &known, views,
    )
    .unwrap();
    assert_eq!(compiled.scalar.bridge.opening.selected, slot);
    assert_eq!(replayed, indices);
    let mut trailing = child.clone();
    trailing.push(0);
    assert!(
        accumulator_consistency_index_query::<F, EF, P>(
            profile, pp, setup, statement, &trailing, &known, views
        )
        .is_none()
    );
}

fn exercise_accumulator_assigned_words<F, P>(pp: &Parameters<'_, P>, task: &AccumulatorTask<F>)
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let n = task.shape.polynomial_size();
    let rounds = task.shape.rounds();
    let rows = task.shape.padded_rounds();
    let width = pp.accumulators[0].width();
    let len = 2 * n * rows;
    let mut words = vec![vec![F::zero(); len]; 7];
    for half in 0..2 {
        for coefficient in 0..n {
            let at = half * n + coefficient;
            let delta = (task.final_acc[at] - task.initial[at]) / F::from(rounds);
            for row in 0..rounds {
                let index = (half * rows + row) * n + coefficient;
                let input = task.initial[at] + F::from(row) * delta;
                words[0][index] = input;
                words[1][index] = input;
                words[3][index] = input + delta;
                words[4][index] = delta;
            }
        }
    }
    let tables: Vec<_> = words
        .into_iter()
        .enumerate()
        .map(|(slot, values)| {
            PackedTable::new(
                accumulator_parameters(pp, slot).unwrap().num_vars(),
                width,
                values,
            )
            .unwrap()
        })
        .collect();
    let mut assignments = std::collections::HashMap::new();
    for (source, table) in task.sources.iter().zip(&tables) {
        let identity = encoded(source);
        if let Some(previous) = assignments.get(&identity) {
            assert_eq!(encoded(previous), encoded(table), "one source alias requires one assigned word");
        } else {
            assignments.insert(identity, table.clone());
        }
    }
    let unique = task.sources.iter().map(encoded).collect::<std::collections::HashSet<_>>();
    assert_eq!(assignments.len(), unique.len());
    let values = accumulator_assigned_values(pp, task, |source| {
        assignments.get(&encoded(source)).cloned()
    })
    .unwrap();
    assert_eq!(values.len(), 7);
    assert!(accumulator_values_valid(pp, task, &values));
    assert!(crate::packed_accumulator::audit::terminal_valid::<
        F,
        Sha512,
        P,
    >(
        &task.shape,
        &task.initial,
        &task.final_acc,
        &task.base,
        &task
            .sources
            .iter()
            .enumerate()
            .map(|(slot, (_, commitment))| CanonicalVerifierOracle {
                parameters: accumulator_parameters(pp, slot).unwrap(),
                commitment,
            })
            .collect::<Vec<_>>(),
        &values
    ));
    assert!(accumulator_assigned_values(pp, task, |_| None).is_none());
    assert!(
        accumulator_assigned_values(pp, task, |_| PackedTable::new(
            0,
            width,
            vec![F::zero(); width]
        )
        .ok())
        .is_none()
    );
    let mut altered = assignments.clone();
    let mut changed = tables[0].values().to_vec();
    changed[0] += F::one();
    altered.insert(
        encoded(&task.sources[0]),
        PackedTable::new(tables[0].num_vars(), width, changed).unwrap(),
    );
    let changed =
        accumulator_assigned_values(pp, task, |source| altered.get(&encoded(source)).cloned())
            .unwrap();
    assert!(!accumulator_values_valid(pp, task, &changed));
    for slot in 0..7 {
        let mut absent = assignments.clone();
        absent.remove(&encoded(&task.sources[slot]));
        assert!(
            accumulator_assigned_values(pp, task, |source| absent.get(&encoded(source)).cloned())
                .is_none()
        );
    }
}

fn exercise_accumulator_assigned_geometry<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    // Assigned-word arithmetic needs its own synthetic source identities.
    // The real prefix can alias other slots (for example a zero monomial
    // product and external input); arbitrary interpolated words are not
    // valid assignments to those real roots. Actual frozen source words
    // are checked by the complete PBS event audit instead.
    let aliases = [0, 1, 2, 3, 4, 2, 2];
    let sources = task.sources.iter().enumerate().map(|(slot, (context, _))| {
        (context.clone(), Commitment { root: Digest512([aliases[slot] + 11; 64]) })
    }).collect::<Vec<_>>();
    let shape = task.shape.clone();
    let initial = vec![F::zero(); 2 * shape.polynomial_size()];
    let final_acc = vec![F::from(shape.rounds()); initial.len()];
    let public = sources.iter().enumerate().map(|(slot, (_, commitment))| {
        CanonicalVerifierOracle {
            parameters: accumulator_parameters(pp, slot).unwrap(),
            commitment,
        }
    }).collect::<Vec<_>>();
    let mut transcript = profile.parent_transcript::<F>().unwrap();
    let (base, _) = crate::packed_accumulator::audit::binding_queries::<F, Sha512, P>(
        &mut transcript, &shape, &initial, &final_acc, &public,
    ).unwrap();
    let synthetic_task = AccumulatorTask { shape, initial, final_acc, sources, base };
    exercise_accumulator_assigned_words(pp, &synthetic_task);
}

fn exercise_accumulator_isolated<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    binding: &[u8],
) where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let width = pp.accumulators[0].width();
    // Isolated actual production binding and query-map generation. This does
    // not assert accepted accumulator values or earlier PCS authentication.
    let sources: Vec<_> = task
        .sources
        .iter()
        .enumerate()
        .map(|(slot, (_, root))| CanonicalVerifierOracle {
            parameters: accumulator_parameters(pp, slot).unwrap(),
            commitment: root,
        })
        .collect();
    let mut production = profile.parent_transcript::<F>().unwrap();
    let (production_base, production_queries) =
        crate::packed_accumulator::audit::binding_queries::<F, Sha512, P>(
            &mut production,
            &task.shape,
            &task.initial,
            &task.final_acc,
            &sources,
        )
        .unwrap();
    let mut isolated = initial_header::<F>(profile).unwrap();
    isolated.extend(binding);
    let mut isolated_task = AccumulatorTask {
        shape: task.shape.clone(),
        initial: task.initial.clone(),
        final_acc: task.final_acc.clone(),
        sources: task.sources.clone(),
        base: Vec::new(),
    };
    for _ in 0..pp.accumulators[0].num_vars() {
        isolated.extend(accumulator_lane_tail::<F>(width).unwrap());
        let (coins, raw) = raw_prime_phase::<F>(&isolated, width);
        isolated_task.base.push(
            sumcheck::packed::challenge_pair(
                &coins
                    .into_iter()
                    .map(|v| F::from(usize::try_from(v).unwrap()))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        frame(
            &mut isolated,
            5,
            b"accumulator independent lane challenges",
            &receipt(&raw).0,
        );
    }
    assert_eq!(encoded(&production_base), encoded(&isolated_task.base));
    assert_eq!(
        encoded(&production_queries),
        encoded(&accumulator_query_maps(&isolated_task, width).unwrap())
    );
    exercise_accumulator_arithmetic::<F, P>(pp, &isolated_task);
    if task.shape.polynomial_size() == 32 {
        exercise_accumulator_assigned_geometry(profile, pp, task);
    }
    frame(
        &mut isolated,
        2,
        b"accumulator source and query maps replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    production.get_challenge_bytes(b"accumulator source and query maps replay", &mut output);
    assert_eq!(shake64(&isolated), output);
}

fn exercise_second_decomposition_entry<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
    views: &FirstViews,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let header = initial_header::<F>(profile).unwrap();
    let mut outer = input.strip_prefix(header.as_slice()).unwrap();
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )
    .unwrap();
    let (co, _, inputs, _, _) = recover::<F, EF, P>(pp, setup, statement, primary).unwrap();
    let digits = setup
        .config
        .decomposition::<F>()
        .unwrap()
        .num_digits::<F>()
        .unwrap();
    let borrows: Vec<_> = (0..=digits)
        .map(|i| {
            let mut root = Digest512::default();
            root.0[0] = u8::try_from(192 + i).unwrap();
            Commitment { root }
        })
        .collect();
    let (expected, binding) =
        decomposition_linear_bindings_at::<F, EF, P>(pp, setup, &co, &inputs, borrows.clone(), 1)
            .unwrap();
    assert_eq!(expected.sources[0].1.root, inputs[1].root);
    assert_eq!(expected.sources[1].1.root, co[digits].root);
    let start = input.len();
    input.extend(&binding);
    let mut query = Vec::new();
    let mut previous = None;
    for round in 0..pp.inputs.num_vars() {
        let mut tail = Vec::new();
        frame(&mut tail, 1, b"typed request kind", b"vector");
        frame(&mut tail, 1, b"field challenge kind", b"prime vector");
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((pp.inputs.width() as u64).to_le_bytes());
        frame(
            &mut tail,
            4,
            b"packed linear independent challenges",
            &descriptor,
        );
        input.extend(&tail);
        let (task, rest) = second_decomposition_linear_prefix::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, views, round,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_eq!(encoded(&task.sources), encoded(&expected.sources));
        assert_eq!(encoded(&task.relations), encoded(&expected.relations));
        assert_eq!(encoded(&task.query), encoded(&query));
        if round == 0 {
            let (_, first_binding) =
                decomposition_linear_bindings::<F, EF, P>(pp, setup, &co, &inputs, borrows.clone())
                    .unwrap();
            assert_ne!(first_binding, binding);
            let mut wrong = input[..start].to_vec();
            wrong.extend(first_binding);
            wrong.extend(&tail);
            assert!(
                second_decomposition_linear_prefix::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, views, round,
                )
                .is_none()
            );
            let mut wrong = input[..start].to_vec();
            wrong.extend(&binding);
            wrong.extend(&binding);
            wrong.extend(&tail);
            assert!(
                second_decomposition_linear_prefix::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, views, round,
                )
                .is_none()
            );
        }
        if let Some(previous) = previous {
            let mut missing = before.clone();
            missing.remove(&previous);
            assert!(
                second_decomposition_linear_prefix::<F, EF, P>(
                    profile, pp, setup, statement, &input, &missing, views, round,
                )
                .is_none()
            );
        }
        let (coins, raw) = raw_prime_phase::<F>(&input, pp.inputs.width());
        query.push(
            sumcheck::packed::challenge_pair(
                &coins
                    .into_iter()
                    .map(|v| F::from(usize::try_from(v).unwrap()))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        let (phase_receipt, producer) = receipt(&raw);
        let fingerprint = phase_receipt[16..].try_into().unwrap();
        before.insert(fingerprint, producer);
        previous = Some(fingerprint);
        frame(
            &mut input,
            5,
            b"packed linear independent challenges",
            &phase_receipt,
        );
    }
    exercise_decomposition_openings_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        before,
        &expected,
        &query,
        views.clone(),
        1,
    );
    exercise_decomposition_linear_conformance::<F, EF, P>(
        profile, pp, setup, &co, &inputs, borrows, binding, 1,
    );
}

fn exercise_decomposition_linear_conformance<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    co: &[Commitment<Digest512>],
    inputs: &[Commitment<Digest512>],
    borrows: Vec<Commitment<Digest512>>,
    binding: Vec<u8>,
    half: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let cfg = setup.config.decomposition::<F>().unwrap();
    let d = cfg.num_digits::<F>().unwrap();
    let header = initial_header::<F>(profile).unwrap();
    // Isolated production stage confirms all binding/round framing. The full
    // outer prefix above has synthetic earlier completions, not acceptance.
    let mut production = profile.parent_transcript::<F>().unwrap();
    let sources: Vec<_> = std::iter::once((pp.inputs, &inputs[half]))
        .chain(
            co[half * d..(half + 1) * d]
                .iter()
                .map(|root| (pp.coefficients, root)),
        )
        .map(|(parameters, commitment)| CanonicalVerifierOracle {
            parameters,
            commitment,
        })
        .collect();
    let proof = crate::packed_decomposition::canonical::shared::Proof::<
        F,
        EF,
        Digest512,
        P::SingleProof,
        P::BatchProof,
    > {
        borrow_commitments: borrows,
        linear: crate::packed_linear::CanonicalProof {
            values: Vec::new(),
            openings: Vec::new(),
        },
        comparisons: crate::packed_extension_lookup::canonical::shared::Proof {
            multiplicities: Vec::new(),
            helper_roots: Vec::new(),
            algebra: sumcheck::batch::Proof {
                instances: Vec::new(),
            },
            source_values: Vec::new(),
            helper_values: Vec::new(),
            source_opening: crate::packed_opening_batch::CanonicalProof {
                openings: Vec::new(),
            },
            helper_openings: Vec::new(),
        },
    };
    assert!(
        crate::packed_decomposition::canonical::shared::verify::<F, EF, Sha512, P>(
            &mut production,
            &cfg,
            &sources[0],
            pp.borrows,
            pp.helper,
            &sources[1..],
            &proof
        )
        .is_err()
    );
    let mut isolated = header;
    isolated.extend(binding);
    for _ in 0..pp.inputs.num_vars() {
        frame(&mut isolated, 1, b"typed request kind", b"vector");
        frame(&mut isolated, 1, b"field challenge kind", b"prime vector");
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((pp.inputs.width() as u64).to_le_bytes());
        frame(
            &mut isolated,
            4,
            b"packed linear independent challenges",
            &descriptor,
        );
        let (_, raw) = raw_prime_phase::<F>(&isolated, pp.inputs.width());
        let (phase_receipt, _) = receipt(&raw);
        frame(
            &mut isolated,
            5,
            b"packed linear independent challenges",
            &phase_receipt,
        );
    }
    frame(
        &mut isolated,
        2,
        b"decomposition linear prefix replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    production.get_challenge_bytes(b"decomposition linear prefix replay", &mut output);
    assert_eq!(shake64(&isolated), output);
}

fn exercise_lookup_algebra<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut full: Vec<u8>,
    mut full_before: Producers,
    views: &FirstViews,
    lookup: &DecompositionLookup<F>,
    multiplicities: &[Vec<F>],
    accepted: &[(usize, usize, EF, EF)],
    crypto: &mut ExtensionReplay<F, EF>,
) -> (Vec<u8>, Producers, LookupTerminal<F, EF>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let roots: Vec<_> = (0..accepted.len())
        .map(|index| Commitment {
            root: Digest512([u8::try_from(index + 145).unwrap(); 64]),
        })
        .collect();
    let roots_start = full.len();
    frame(
        &mut full,
        1,
        b"shared lookup helper roots",
        &encoded(&roots),
    );
    crypto.append_message(b"shared lookup helper roots", &roots);
    let roots_end = full.len();
    let variables = pp.helper.num_vars();
    let mut points = Vec::new();
    let mut previous = None;
    for index in 0..accepted.len() {
        full.extend(
            lookup_vector_tail::<F, EF>(b"shared lookup equality point", variables).unwrap(),
        );
        let task = decomposition_lookup_equality_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &full,
            &full_before,
            &views,
            index,
        )
        .unwrap();
        assert_eq!(encoded(&task.roots), encoded(&roots));
        assert_eq!(task.points, points);
        assert_eq!(task.accepted, accepted);
        assert_eq!(task.helper_context, pp.helper.context().ok().unwrap());
        let mut huge = full[..roots_start].to_vec();
        frame(
            &mut huge,
            1,
            b"shared lookup helper roots",
            &encoded(&usize::MAX),
        );
        huge.extend_from_slice(&full[roots_end..]);
        assert!(
            decomposition_lookup_equality_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &huge,
                &full_before,
                &views,
                index
            )
            .is_none()
        );
        if let Some(fingerprint) = previous {
            let mut missing = full_before.clone();
            missing.remove(&fingerprint);
            assert!(
                decomposition_lookup_equality_query::<F, EF, P>(
                    profile, pp, setup, statement, &full, &missing, &views, index
                )
                .is_none()
            );
        }
        let (coefficients, raw) = raw_prime_phase::<F>(&full, variables * EF::D);
        let point: Vec<_> = coefficients
            .chunks_exact(EF::D)
            .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
            .collect();
        assert_eq!(
            crypto.get_vec_challenge(b"shared lookup equality point", variables),
            point
        );
        points.push(point);
        let (phase_receipt, producer) = receipt(&raw);
        let fingerprint = phase_receipt[16..].try_into().unwrap();
        previous = Some(fingerprint);
        full_before.insert(fingerprint, producer);
        frame(
            &mut full,
            5,
            b"shared lookup equality point",
            &phase_receipt,
        );
    }
    let equality = LookupEqualityTask {
        lookup: DecompositionLookup {
            sources: lookup.sources.clone(),
            requests: lookup.requests.clone(),
            multiplicities: multiplicities.to_vec(),
        },
        accepted: accepted.to_vec(),
        roots: roots.clone(),
        points: points.clone(),
        variables,
        helper_context: pp.helper.context().ok().unwrap(),
    };
    let (infos, claims) = lookup_equations(&equality).unwrap();
    let (production_infos, production_claims) =
        crate::packed_extension_lookup::canonical::shared::audit::compression_claims::<F, EF>(
            &lookup.requests,
            &multiplicities,
            &accepted,
            variables,
        );
    assert_eq!(encoded(&infos), encoded(&production_infos));
    assert_eq!(encoded(&claims), encoded(&production_claims));
    exercise_lookup_batch_conformance::<F, EF>(profile, &infos, &claims);
    frame(
        &mut full,
        1,
        b"independent scalar sumcheck batch v1",
        &encoded(&(&infos, &claims)),
    );
    crypto.append_message(b"independent scalar sumcheck batch v1", &(&infos, &claims));
    let mut expected = claims.clone();
    let mut point = Vec::new();
    for round in 0..variables {
        let evaluations: Vec<_> = infos
            .iter()
            .zip(&expected)
            .enumerate()
            .map(|(index, (info, &claim))| {
                lookup_test_round::<F, EF>(claim, info.max_multiplicands, index + round + 2)
            })
            .collect();
        let messages: Vec<_> = evaluations
            .iter()
            .cloned()
            .map(sumcheck::prover::ProverMsg::from_evaluations)
            .collect();
        let start = full.len();
        frame(
            &mut full,
            1,
            b"scalar batch round messages",
            &encoded(&(round, &messages)),
        );
        crypto.append_message(b"scalar batch round messages", &(round, &messages));
        full.extend(lookup_scalar_tail::<F, EF>(
            b"scalar batch common challenge",
        ));
        let task = decomposition_lookup_batch_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &full,
            &full_before,
            &views,
            round,
        )
        .unwrap();
        assert_eq!(task.point, point);
        assert_eq!(task.expected, expected);
        assert_eq!(task.evaluations, evaluations);
        assert_eq!(task.equality.points, points);
        assert_eq!(encoded(&task.infos), encoded(&infos));
        assert_eq!(task.claims, claims);
        let mut bad = evaluations.clone();
        bad[0][0] += EF::one();
        let bad_messages: Vec<_> = bad
            .into_iter()
            .map(sumcheck::prover::ProverMsg::from_evaluations)
            .collect();
        let mut wrong = full[..start].to_vec();
        frame(
            &mut wrong,
            1,
            b"scalar batch round messages",
            &encoded(&(round, &bad_messages)),
        );
        wrong.extend(lookup_scalar_tail::<F, EF>(
            b"scalar batch common challenge",
        ));
        assert!(
            decomposition_lookup_batch_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &wrong,
                &full_before,
                &views,
                round
            )
            .is_none()
        );
        if let Some(fingerprint) = previous {
            let mut missing = full_before.clone();
            missing.remove(&fingerprint);
            assert!(
                decomposition_lookup_batch_query::<F, EF, P>(
                    profile, pp, setup, statement, &full, &missing, &views, round
                )
                .is_none()
            );
        }
        let (coefficients, raw) = raw_prime_phase::<F>(&full, EF::D);
        let coin = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        assert_eq!(crypto.get_challenge(b"scalar batch common challenge"), coin);
        for (index, (info, value)) in infos.iter().zip(&mut expected).enumerate() {
            *value = lookup_test_evaluate::<F, EF>(
                *value,
                info.max_multiplicands,
                index + round + 2,
                coin,
            );
        }
        point.push(coin);
        let (phase_receipt, producer) = receipt(&raw);
        let fingerprint = phase_receipt[16..].try_into().unwrap();
        previous = Some(fingerprint);
        full_before.insert(fingerprint, producer);
        frame(
            &mut full,
            5,
            b"scalar batch common challenge",
            &phase_receipt,
        );
    }
    let width = pp.coefficients.width();
    let mut source_values = vec![vec![F::zero(); width]; lookup.sources.len()];
    let helper_values: Vec<_> = expected
        .iter()
        .step_by(2)
        .map(|value| value.canonicalized())
        .collect();
    for (index, &(request_index, repetition, _, reciprocal)) in accepted.iter().enumerate() {
        assert_eq!(repetition, 0);
        let h = helper_values[index];
        let equality = lookup_equality(&points[index], &point);
        assert_ne!(h, EF::zero());
        assert_ne!(equality, EF::zero());
        assert_eq!(
            lookup.requests[request_index].config.logical_len(),
            1usize << variables
        );
        let g = (expected[2 * index + 1] / equality + EF::one() - reciprocal * h) / h;
        let digit_slot = lookup.requests[request_index].source_slots[0];
        source_values[digit_slot] = pp
            .coefficients
            .normalize_values(crate::packed_extension::vector::<F, EF>(width, g).unwrap());
    }
    let terminal_start = full.len();
    frame(
        &mut full,
        1,
        b"shared lookup terminal values",
        &encoded(&(&source_values, &helper_values)),
    );
    crypto.append_message(
        b"shared lookup terminal values",
        &(&source_values, &helper_values),
    );
    frame(
        &mut full,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    let terminal = decomposition_lookup_terminal_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &full,
        &full_before,
        &views,
    )
    .unwrap();
    assert_eq!(terminal.batch.point, point);
    assert_eq!(terminal.batch.expected, expected);
    assert_eq!(terminal.source_values, source_values);
    assert_eq!(terminal.helper_values, helper_values);
    assert_eq!(
        terminal.source_query.query.len(),
        pp.coefficients.num_vars()
    );
    assert_eq!(terminal.helper_query.query.len(), pp.helper.num_vars());
    for (&value, claim) in helper_values.iter().zip(&terminal.helper_claims) {
        assert_eq!(
            *claim,
            pp.helper.normalize_values(
                crate::packed_extension::vector::<F, EF>(pp.helper.width(), value).unwrap()
            )
        );
    }
    assert!(
        crate::packed_extension_lookup::canonical::shared::audit::terminal_valid::<F, EF>(
            &lookup.requests,
            &accepted,
            &points,
            &point,
            &source_values,
            &helper_values,
            &expected,
            pp.coefficients.num_vars(),
            width
        )
    );
    let mut bad_sources = source_values.clone();
    bad_sources[0][0] += F::one();
    assert!(
        !crate::packed_extension_lookup::canonical::shared::audit::terminal_valid::<F, EF>(
            &lookup.requests,
            &accepted,
            &points,
            &point,
            &bad_sources,
            &helper_values,
            &expected,
            pp.coefficients.num_vars(),
            width
        )
    );
    let mut wrong = full[..terminal_start].to_vec();
    frame(
        &mut wrong,
        1,
        b"shared lookup terminal values",
        &encoded(&(&bad_sources, &helper_values)),
    );
    frame(
        &mut wrong,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    assert!(
        decomposition_lookup_terminal_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &wrong,
            &full_before,
            &views
        )
        .is_none()
    );
    let mut bad_helpers = helper_values.clone();
    bad_helpers[0] += EF::one();
    let mut wrong = full[..terminal_start].to_vec();
    frame(
        &mut wrong,
        1,
        b"shared lookup terminal values",
        &encoded(&(&source_values, &bad_helpers)),
    );
    frame(
        &mut wrong,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    assert!(
        decomposition_lookup_terminal_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &wrong,
            &full_before,
            &views
        )
        .is_none()
    );
    let mut wrong = full[..terminal_start].to_vec();
    frame(
        &mut wrong,
        1,
        b"shared lookup terminal values",
        &encoded(&usize::MAX),
    );
    frame(
        &mut wrong,
        2,
        b"classical child finish",
        &64u64.to_le_bytes(),
    );
    assert!(
        decomposition_lookup_terminal_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &wrong,
            &full_before,
            &views
        )
        .is_none()
    );
    (full, full_before, terminal)
}

fn exercise_second_lookup_compression<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    before: Producers,
    mut views: FirstViews,
    linear: &FirstOpening<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    assert_eq!(linear.family, OpeningFamily::SecondDecomposition);
    let (lookup, binding) = decomposition_lookup_bindings::<F, EF, P>(pp, setup, linear).unwrap();
    assert_eq!(
        encoded(&lookup.sources),
        encoded(&linear.sources[1..].to_vec())
    );
    let start = input.len();
    input.extend(&binding);
    let grouped_start = input.len();
    let multiplicities: Vec<_> = lookup
        .requests
        .iter()
        .map(|request| {
            let mut values = vec![F::zero(); request.config.table().len()];
            values[0] = F::from(setup.config.decomposition::<F>().unwrap().logical_len());
            values
        })
        .collect();
    frame(
        &mut input,
        1,
        b"shared lookup grouped multiplicities",
        &encoded(&multiplicities),
    );
    let flat: Vec<_> = multiplicities.iter().flatten().copied().collect();
    frame(
        &mut input,
        1,
        b"extension lookup multiplicities",
        &encoded(&flat),
    );
    frame(
        &mut input,
        6,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
    );
    frame(&mut input, 2, b"classical child seed", &64u64.to_le_bytes());
    let (recovered, rest) = second_decomposition_lookup_seed_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, &views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&recovered.sources), encoded(&lookup.sources));
    assert_eq!(recovered.multiplicities, multiplicities);
    let mut changed = FirstOpening {
        family: linear.family,
        selected: linear.selected,
        sources: linear.sources.clone(),
        query: linear.query.clone(),
        values: linear.values.clone(),
    };
    changed.sources[1].1.root.0[0] ^= 1;
    let (_, wrong_binding) =
        decomposition_lookup_bindings::<F, EF, P>(pp, setup, &changed).unwrap();
    let mut wrong = input[..start].to_vec();
    wrong.extend(wrong_binding);
    wrong.extend(&input[grouped_start..]);
    assert!(
        second_decomposition_lookup_seed_prefix::<F, EF, P>(
            profile, pp, setup, statement, &wrong, &before, &views,
        )
        .is_none()
    );
    let mut huge = input[..grouped_start].to_vec();
    frame(
        &mut huge,
        1,
        b"shared lookup grouped multiplicities",
        &encoded(&usize::MAX),
    );
    assert!(
        second_decomposition_lookup_seed_prefix::<F, EF, P>(
            profile, pp, setup, statement, &huge, &before, &views,
        )
        .is_none()
    );
    let seed = shake64(&input);
    views.insert(input.clone(), before.clone());
    let mut known = before.clone();
    known.insert(seed, input.clone());
    let (empty, producer) = receipt(&[]);
    known.insert(empty[16..].try_into().unwrap(), producer);
    let mut child = raw_child::<F, EF>(
        profile,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
        &seed,
    );
    let (checked, rest) = second_decomposition_lookup_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, &child, &known, &views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&checked.sources), encoded(&lookup.sources));
    assert!(
        decomposition_lookup_child_prefix::<F, EF, P>(
            profile, pp, setup, statement, &child, &known, &views,
        )
        .is_none()
    );
    let mut missing = known.clone();
    missing.remove(&seed);
    assert!(
        second_decomposition_lookup_child_prefix::<F, EF, P>(
            profile, pp, setup, statement, &child, &missing, &views,
        )
        .is_none()
    );
    let (_, mut first_rest) = decomposition_lookup_seed_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before,
    )
    .unwrap();
    message(&mut first_rest, 3, b"classical child seed").unwrap();
    let ancestor_finish: [u8; 64] =
        message(&mut first_rest, 7, b"classical extension lookup child v1")
            .unwrap()
            .try_into()
            .unwrap();
    let mut late = views.clone();
    late.get_mut(input.as_slice())
        .unwrap()
        .remove(&ancestor_finish);
    assert!(known.contains_key(&ancestor_finish));
    assert!(
        second_decomposition_lookup_child_prefix::<F, EF, P>(
            profile, pp, setup, statement, &child, &known, &late,
        )
        .is_none()
    );
    let mut crypto = ExtensionReplay::<F, EF>::child(
        profile,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
        &seed,
    );
    let mut accepted = Vec::new();
    for (index, request) in lookup.requests.iter().enumerate() {
        frame(
            &mut child,
            1,
            b"shared lookup challenge request",
            &encoded(&index),
        );
        crypto.append_message(b"shared lookup challenge request", &index);
        for repetition in 0..request.config.repetitions() {
            child.extend(lookup_hash_tail::<F, EF>());
            let (_, task) = second_decomposition_lookup_challenge_query::<F, EF, P>(
                profile, pp, setup, statement, &child, &known, &views,
            )
            .unwrap();
            assert_eq!(
                (task.request, task.repetition, task.phase),
                (index, repetition, LookupChallengePhase::Hash)
            );
            assert_eq!(task.accepted, accepted);
            let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
            let hash = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
            assert_eq!(
                crypto.get_challenge(b"extension tuple hash challenge"),
                hash
            );
            let (phase_receipt, producer) = receipt(&raw);
            known.insert(phase_receipt[16..].try_into().unwrap(), producer);
            frame(
                &mut child,
                5,
                b"extension tuple hash challenge",
                &phase_receipt,
            );
            let table = compressed_lookup_table(request, hash);
            let mut rejected = 0usize;
            loop {
                child.extend(lookup_scalar_tail::<F, EF>(
                    b"extension tuple reciprocal challenge",
                ));
                let (_, task) = second_decomposition_lookup_challenge_query::<F, EF, P>(
                    profile, pp, setup, statement, &child, &known, &views,
                )
                .unwrap();
                assert_eq!(
                    (task.request, task.repetition, task.phase),
                    (index, repetition, LookupChallengePhase::Reciprocal)
                );
                assert_eq!(task.hash, Some(hash));
                assert_eq!(encoded(&task.table), encoded(&table));
                assert_eq!(task.rejected, rejected);
                let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
                let reciprocal =
                    EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
                assert_eq!(
                    crypto.get_challenge(b"extension tuple reciprocal challenge"),
                    reciprocal
                );
                let (phase_receipt, producer) = receipt(&raw);
                known.insert(phase_receipt[16..].try_into().unwrap(), producer);
                frame(
                    &mut child,
                    5,
                    b"extension tuple reciprocal challenge",
                    &phase_receipt,
                );
                if reciprocal != EF::zero() && !table.contains(&-reciprocal) {
                    accepted.push((index, repetition, hash, reciprocal));
                    break;
                }
                rejected = rejected.checked_add(1).unwrap();
            }
        }
    }
    let (_, rest) = second_decomposition_lookup_child_prefix::<F, EF, P>(
        profile, pp, setup, statement, &child, &known, &views,
    )
    .unwrap();
    match lookup_challenge_walk::<F, EF>(&lookup.requests, rest, &known).unwrap() {
        LookupChallengeBoundary::Complete {
            accepted: actual,
            rest,
        } => {
            assert_eq!(actual, accepted);
            assert!(rest.is_empty());
        }
        _ => panic!("second lookup compression did not complete"),
    }
    let (mut child, known, terminal) = exercise_lookup_algebra::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        child,
        known,
        &views,
        &lookup,
        &multiplicities,
        &accepted,
        &mut crypto,
    );
    assert_eq!(
        encoded(&terminal.batch.equality.lookup.sources),
        encoded(&lookup.sources)
    );
    let finish = shake64(&child);
    let mut output = [0; 64];
    crypto.get_challenge_bytes(b"classical child finish", &mut output);
    assert_eq!(finish, output);
    let mut parent = input.clone();
    frame(&mut parent, 3, b"classical child seed", &seed);
    frame(
        &mut parent,
        7,
        b"classical extension lookup child v1",
        &finish,
    );
    let mut parent_before = known.clone();
    parent_before.insert(finish, child.clone());
    views.insert(child.clone(), known.clone());
    let (returned, rest) = second_decomposition_lookup_parent_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &parent,
        &parent_before,
        &views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(returned.batch.point, terminal.batch.point);
    assert_eq!(returned.source_values, terminal.source_values);
    assert_eq!(returned.helper_values, terminal.helper_values);
    let mut missing = parent_before.clone();
    missing.remove(&finish);
    assert!(
        second_decomposition_lookup_parent_prefix::<F, EF, P>(
            profile, pp, setup, statement, &parent, &missing, &views,
        )
        .is_none()
    );
    let mut missing_view = views.clone();
    missing_view.remove(child.as_slice());
    assert!(
        second_decomposition_lookup_parent_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &parent,
            &parent_before,
            &missing_view,
        )
        .is_none()
    );
    let mut wrong = parent.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        second_decomposition_lookup_parent_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &wrong,
            &parent_before,
            &views,
        )
        .is_none()
    );
    exercise_lookup_helper_openings_at::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        parent,
        parent_before,
        views.clone(),
        &returned,
        finish,
        1,
    );
    frame(&mut child, 3, b"classical child finish", &finish);
    frame(
        &mut child,
        2,
        b"second lookup algebra replay",
        &64u64.to_le_bytes(),
    );
    crypto.get_challenge_bytes(b"second lookup algebra replay", &mut output);
    assert_eq!(shake64(&child), output);
}

fn exercise_decomposition_lookup_entry<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    before: Producers,
    linear: &FirstOpening<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (complete, rest) = decomposition_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, &input, &before, true,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&complete.sources), encoded(&linear.sources));
    assert!(
        decomposition_opening_query::<F, EF, P>(profile, pp, setup, statement, &input, &before)
            .is_none()
    );
    let (lookup, binding) =
        decomposition_lookup_bindings::<F, EF, P>(pp, setup, &complete).unwrap();
    assert_eq!(
        encoded(&lookup.sources),
        encoded(&linear.sources[1..].to_vec())
    );
    input.extend(&binding);
    let multiplicities: Vec<_> = lookup
        .requests
        .iter()
        .enumerate()
        .map(|(i, request)| {
            let mut values = vec![F::zero(); request.config.table().len()];
            values[i] = F::from(setup.config.decomposition::<F>().unwrap().logical_len());
            values
        })
        .collect();
    let grouped_start = input.len();
    frame(
        &mut input,
        1,
        b"shared lookup grouped multiplicities",
        &encoded(&multiplicities),
    );
    let flat: Vec<_> = multiplicities.iter().flatten().copied().collect();
    frame(
        &mut input,
        1,
        b"extension lookup multiplicities",
        &encoded(&flat),
    );
    frame(
        &mut input,
        6,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
    );
    frame(&mut input, 2, b"classical child seed", &64u64.to_le_bytes());
    let recovered =
        decomposition_lookup_seed_query::<F, EF, P>(profile, pp, setup, statement, &input, &before)
            .unwrap();
    assert_eq!(encoded(&recovered.requests), encoded(&lookup.requests));
    assert_eq!(recovered.multiplicities, multiplicities);
    let mut huge = input[..grouped_start].to_vec();
    frame(
        &mut huge,
        1,
        b"shared lookup grouped multiplicities",
        &encoded(&usize::MAX),
    );
    assert!(
        decomposition_lookup_seed_query::<F, EF, P>(profile, pp, setup, statement, &huge, &before)
            .is_none()
    );
    let seed = shake64(&input);
    let mut child_before = before.clone();
    child_before.insert(seed, input.clone());
    let (empty, producer) = receipt(&[]);
    child_before.insert(empty[16..].try_into().unwrap(), producer);
    let mut views = FirstViews::new();
    views.insert(input.clone(), before.clone());
    let mut child = raw_child::<F, EF>(
        profile,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
        &seed,
    );
    frame(
        &mut child,
        1,
        b"shared lookup challenge request",
        &encoded(&0usize),
    );
    child.extend(lookup_hash_tail::<F, EF>());
    let checked = decomposition_lookup_hash_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &child,
        &child_before,
        &views,
    )
    .unwrap();
    assert_eq!(checked.sources.len(), linear.sources.len() - 1);
    let mut missing = child_before.clone();
    missing.remove(&seed);
    assert!(
        decomposition_lookup_hash_query::<F, EF, P>(
            profile, pp, setup, statement, &child, &missing, &views
        )
        .is_none()
    );
    let mut wrong = child.clone();
    wrong.push(0);
    assert!(
        decomposition_lookup_hash_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &wrong,
            &child_before,
            &views
        )
        .is_none()
    );
    let mut replay = ExtensionReplay::<F, EF>::child(
        profile,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
        &seed,
    );
    replay.append_message(b"shared lookup challenge request", &0usize);
    let (coefficients, raw) = raw_prime_phase::<F>(&child, EF::D);
    let y = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
    assert_eq!(replay.get_challenge(b"extension tuple hash challenge"), y);
    frame(
        &mut child,
        5,
        b"extension tuple hash challenge",
        &receipt(&raw).0,
    );
    frame(
        &mut child,
        2,
        b"decomposition lookup hash replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    replay.get_challenge_bytes(b"decomposition lookup hash replay", &mut output);
    assert_eq!(shake64(&child), output);
    let mut full = raw_child::<F, EF>(
        profile,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
        &seed,
    );
    let body_start = full.len();
    let mut full_before = child_before.clone();
    let mut accepted = Vec::new();
    let mut crypto = ExtensionReplay::<F, EF>::child(
        profile,
        b"classical extension lookup child v1",
        b"packed extension tuple lookup",
        &seed,
    );
    for (index, request) in lookup.requests.iter().enumerate() {
        frame(
            &mut full,
            1,
            b"shared lookup challenge request",
            &encoded(&index),
        );
        crypto.append_message(b"shared lookup challenge request", &index);
        for repetition in 0..request.config.repetitions() {
            full.extend(lookup_hash_tail::<F, EF>());
            let (_, task) = decomposition_lookup_challenge_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &full,
                &full_before,
                &views,
            )
            .unwrap();
            assert_eq!(
                (task.request, task.repetition, task.phase),
                (index, repetition, LookupChallengePhase::Hash)
            );
            assert_eq!(task.accepted, accepted);
            let (coefficients, raw) = raw_prime_phase::<F>(&full, EF::D);
            let hash = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
            assert_eq!(
                crypto.get_challenge(b"extension tuple hash challenge"),
                hash
            );
            let (hash_receipt, producer) = receipt(&raw);
            let hash_fingerprint = hash_receipt[16..].try_into().unwrap();
            full_before.insert(hash_fingerprint, producer);
            frame(
                &mut full,
                5,
                b"extension tuple hash challenge",
                &hash_receipt,
            );
            let table = compressed_lookup_table(request, hash);
            let mut rejected = 0;
            loop {
                full.extend(lookup_scalar_tail::<F, EF>(
                    b"extension tuple reciprocal challenge",
                ));
                let (_, task) = decomposition_lookup_challenge_query::<F, EF, P>(
                    profile,
                    pp,
                    setup,
                    statement,
                    &full,
                    &full_before,
                    &views,
                )
                .unwrap();
                assert_eq!(
                    (task.request, task.repetition, task.phase),
                    (index, repetition, LookupChallengePhase::Reciprocal)
                );
                assert_eq!(task.hash, Some(hash));
                assert_eq!(task.table, table);
                assert_eq!(task.rejected, rejected);
                assert_eq!(task.accepted, accepted);
                let mut missing = full_before.clone();
                missing.remove(&hash_fingerprint);
                assert!(
                    decomposition_lookup_challenge_query::<F, EF, P>(
                        profile, pp, setup, statement, &full, &missing, &views
                    )
                    .is_none()
                );
                let (coefficients, raw) = raw_prime_phase::<F>(&full, EF::D);
                let r = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
                assert_eq!(
                    crypto.get_challenge(b"extension tuple reciprocal challenge"),
                    r
                );
                let (phase_receipt, producer) = receipt(&raw);
                full_before.insert(phase_receipt[16..].try_into().unwrap(), producer);
                frame(
                    &mut full,
                    5,
                    b"extension tuple reciprocal challenge",
                    &phase_receipt,
                );
                if r != EF::zero() && table.iter().all(|&value| r + value != EF::zero()) {
                    accepted.push((index, repetition, hash, r));
                    break;
                }
                rejected += 1;
            }
        }
    }
    match lookup_challenge_walk::<F, EF>(&lookup.requests, &full[body_start..], &full_before)
        .unwrap()
    {
        LookupChallengeBoundary::Complete {
            accepted: checked,
            rest,
        } => {
            assert_eq!(checked, accepted);
            assert!(rest.is_empty());
        }
        _ => panic!("all lookup compression phases must be complete"),
    }
    let (mut full, full_before, terminal) = exercise_lookup_algebra::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        full,
        full_before,
        &views,
        &lookup,
        &multiplicities,
        &accepted,
        &mut crypto,
    );
    let helper_values = terminal.helper_values.clone();
    let point = terminal.batch.point.clone();
    let finish_input = full.clone();
    let finish = shake64(&finish_input);
    let mut actual_finish = [0; 64];
    crypto.get_challenge_bytes(b"classical child finish", &mut actual_finish);
    assert_eq!(finish, actual_finish);
    let mut parent = input.clone();
    frame(&mut parent, 3, b"classical child seed", &seed);
    frame(
        &mut parent,
        7,
        b"classical extension lookup child v1",
        &finish,
    );
    let mut parent_before = full_before.clone();
    parent_before.insert(finish, finish_input.clone());
    let mut finish_views = views.clone();
    finish_views.insert(finish_input.clone(), full_before.clone());
    let (returned, rest) = decomposition_lookup_parent_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &parent,
        &parent_before,
        &finish_views,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(returned.helper_values, helper_values);
    assert_eq!(returned.batch.point, point);
    exercise_lookup_helper_openings::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        parent.clone(),
        parent_before.clone(),
        finish_views.clone(),
        &returned,
        finish,
    );
    let mut missing = parent_before.clone();
    missing.remove(&finish);
    assert!(
        decomposition_lookup_parent_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &parent,
            &missing,
            &finish_views
        )
        .is_none()
    );
    let mut missing = finish_views.clone();
    missing.remove(&finish_input);
    assert!(
        decomposition_lookup_parent_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &parent,
            &parent_before,
            &missing
        )
        .is_none()
    );
    let mut wrong = parent.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        decomposition_lookup_parent_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &wrong,
            &parent_before,
            &finish_views
        )
        .is_none()
    );
    frame(&mut full, 3, b"classical child finish", &finish);
    frame(
        &mut full,
        2,
        b"all lookup compression challenges replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    crypto.get_challenge_bytes(b"all lookup compression challenges replay", &mut output);
    assert_eq!(shake64(&full), output);
    // Isolated actual preflight/registry binding rejects the absent helper
    // packets before the child seed; it confirms only this metadata boundary.
    let mut production = profile.parent_transcript::<F>().unwrap();
    let d = setup
        .config
        .decomposition::<F>()
        .unwrap()
        .num_digits::<F>()
        .unwrap();
    let sources: Vec<_> = lookup
        .sources
        .iter()
        .enumerate()
        .map(|(i, (_, commitment))| CanonicalVerifierOracle {
            parameters: if i < d { pp.coefficients } else { pp.borrows },
            commitment,
        })
        .collect();
    let proof = crate::packed_extension_lookup::canonical::shared::Proof::<
        F,
        EF,
        Digest512,
        P::SingleProof,
        P::BatchProof,
    > {
        multiplicities: Vec::new(),
        helper_roots: Vec::new(),
        algebra: sumcheck::batch::Proof {
            instances: Vec::new(),
        },
        source_values: Vec::new(),
        helper_values: Vec::new(),
        source_opening: crate::packed_opening_batch::CanonicalProof {
            openings: Vec::new(),
        },
        helper_openings: Vec::new(),
    };
    assert!(
        crate::packed_extension_lookup::canonical::shared::verify::<F, EF, Sha512, P>(
            &mut production,
            pp.helper,
            &sources,
            &lookup.requests,
            &proof
        )
        .is_err()
    );
    let mut isolated = initial_header::<F>(profile).unwrap();
    isolated.extend(binding);
    frame(
        &mut isolated,
        2,
        b"lookup preflight registry replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    production.get_challenge_bytes(b"lookup preflight registry replay", &mut output);
    assert_eq!(shake64(&isolated), output);
}

fn exercise_decomposition_linear<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let header = initial_header::<F>(profile).unwrap();
    let mut outer = input.strip_prefix(header.as_slice()).unwrap();
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )
    .unwrap();
    let (co, _, inputs, _, _) = recover::<F, EF, P>(pp, setup, statement, primary).unwrap();
    let cfg = setup.config.decomposition::<F>().unwrap();
    let d = cfg.num_digits::<F>().unwrap();
    let borrows: Vec<_> = (0..=d)
        .map(|i| {
            let mut root = Digest512::default();
            root.0[0] = 128 + i as u8;
            Commitment { root }
        })
        .collect();
    let (expected, binding) =
        decomposition_linear_bindings::<F, EF, P>(pp, setup, &co, &inputs, borrows.clone())
            .unwrap();
    assert_eq!(expected.sources.len(), 2 * d + 2);
    assert_eq!(expected.relations.len(), 3);
    let start = input.len();
    input.extend(&binding);
    let mut query = Vec::new();
    let mut previous = None;
    for round in 0..pp.inputs.num_vars() {
        frame(&mut input, 1, b"typed request kind", b"vector");
        frame(&mut input, 1, b"field challenge kind", b"prime vector");
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((pp.inputs.width() as u64).to_le_bytes());
        frame(
            &mut input,
            4,
            b"packed linear independent challenges",
            &descriptor,
        );
        let task = decomposition_linear_query::<F, EF, P>(
            profile, pp, setup, statement, &input, &before, round,
        )
        .unwrap();
        assert_eq!(encoded(&task.sources), encoded(&expected.sources));
        assert_eq!(encoded(&task.query), encoded(&query));
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            decomposition_linear_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, round
            )
            .is_none()
        );
        if let Some(previous) = previous {
            let mut missing = before.clone();
            missing.remove(&previous);
            assert!(
                decomposition_linear_query::<F, EF, P>(
                    profile, pp, setup, statement, &input, &missing, round
                )
                .is_none()
            );
        }
        let (coins, raw) = raw_prime_phase::<F>(&input, pp.inputs.width());
        query.push(
            sumcheck::packed::challenge_pair(
                &coins
                    .into_iter()
                    .map(|v| F::from(usize::try_from(v).unwrap()))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        let (phase_receipt, producer) = receipt(&raw);
        let fingerprint = phase_receipt[16..].try_into().unwrap();
        before.insert(fingerprint, producer);
        previous = Some(fingerprint);
        frame(
            &mut input,
            5,
            b"packed linear independent challenges",
            &phase_receipt,
        );
    }
    exercise_decomposition_openings::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input.clone(),
        before.clone(),
        &expected,
        &query,
    );
    exercise_decomposition_linear_conformance::<F, EF, P>(
        profile, pp, setup, &co, &inputs, borrows, binding, 0,
    );
    assert!(input.len() > start);
}

fn exercise_ntt_components<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    mut input: Vec<u8>,
    mut before: Producers,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let header = initial_header::<F>(profile).unwrap();
    let mut outer = input.strip_prefix(header.as_slice()).unwrap();
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )
    .unwrap();
    let (co, ev, _, _, _) = recover::<F, EF, P>(pp, setup, statement, primary).unwrap();
    assert!(co.len() > 1);
    let shape = ntt::Shape::new_canonical::<F, Sha512, P>(pp.coefficients, setup.config.n).unwrap();
    let contexts = (
        pp.coefficients.context().ok().unwrap(),
        pp.evaluations.context().ok().unwrap(),
    );
    let root = F::get_ntt_table(shape.polynomial_size().ilog2())
        .unwrap()
        .root();
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    for component in 1..co.len() {
        let start = input.len();
        let binding = encoded(&(
            F::MODULUS_VALUE.to_string(),
            &shape,
            root,
            contexts,
            &co[component],
            &ev[component],
        ));
        frame(&mut input, 1, P::NTT_DOMAIN, &binding);
        let binding_end = input.len();
        frame(&mut input, 1, b"typed request kind", b"vector");
        frame(&mut input, 1, b"field challenge kind", b"prime vector");
        let count = shape.width() * shape.row_variables();
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((count as u64).to_le_bytes());
        frame(
            &mut input,
            4,
            b"packed NTT atomic row points v2",
            &descriptor,
        );
        let row = ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &input, &before)
            .unwrap();
        assert_eq!(row.component, component);
        assert_eq!(
            encoded(&row.coefficients),
            encoded(&(contexts.0, &co[component]))
        );
        assert_eq!(
            encoded(&row.evaluations),
            encoded(&(contexts.1, &ev[component]))
        );
        assert_ne!(co[component].root, co[0].root);
        assert_ne!(ev[component].root, ev[0].root);
        let mut wrong = input[..start].to_vec();
        frame(
            &mut wrong,
            1,
            P::NTT_DOMAIN,
            &encoded(&(
                F::MODULUS_VALUE.to_string(),
                &shape,
                root,
                contexts,
                &co[0],
                &ev[component],
            )),
        );
        wrong.extend_from_slice(&input[binding_end..]);
        assert!(
            ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before)
                .is_none()
        );
        let mut wrong = input[..start].to_vec();
        frame(
            &mut wrong,
            1,
            P::NTT_DOMAIN,
            &encoded(&(
                F::MODULUS_VALUE.to_string(),
                &shape,
                root,
                contexts,
                &co[component],
                &ev[0],
            )),
        );
        wrong.extend_from_slice(&input[binding_end..]);
        assert!(
            ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before)
                .is_none()
        );
        let mut wrong = input.clone();
        wrong[start] ^= 1;
        assert!(
            ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before)
                .is_none()
        );
        let (_, raw) = raw_prime_phase::<F>(&input, count);
        let (row_receipt, producer) = receipt(&raw);
        before.insert(row_receipt[16..].try_into().unwrap(), producer);
        frame(
            &mut input,
            5,
            b"packed NTT atomic row points v2",
            &row_receipt,
        );
        let zero = vec![vec![F::zero(); shape.polynomial_size()]; shape.width()];
        frame(
            &mut input,
            1,
            b"packed NTT folded polynomials",
            &encoded(&(&zero, &zero)),
        );
        for round in 0..shape.coefficient_variables() {
            input.extend(ntt_compression_tail::<F>(shape.width()));
            let task = ntt_compression_query::<F, EF, P>(
                profile, pp, setup, statement, &input, &before, round,
            )
            .unwrap();
            assert_eq!(task.row.component, component);
            let (_, raw) = raw_prime_phase::<F>(&input, shape.width());
            let (phase_receipt, producer) = receipt(&raw);
            before.insert(phase_receipt[16..].try_into().unwrap(), producer);
            frame(
                &mut input,
                5,
                b"packed NTT coefficient compression",
                &phase_receipt,
            );
        }
        let (mut batch, rest) =
            ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, &input, &before).unwrap();
        assert!(rest.is_empty());
        assert_eq!(batch.ntt.row.component, component);
        for evaluation in [false, true] {
            batch.evaluation = evaluation;
            if profile.specification().backend != Backend::Brakedown {
                input.extend(ntt_batch_seed_tail(profile, batch.parameters(pp), &batch).unwrap());
                let selected = ntt_batch_seed_query::<F, EF, P>(
                    profile, pp, setup, statement, &input, &before,
                )
                .unwrap();
                assert_eq!(selected.ntt.row.component, component);
                assert_eq!(selected.evaluation, evaluation);
                assert_eq!(encoded(selected.source()), encoded(batch.source()));
                let seed = shake64(&input);
                let (_, label, _) = pcs_child_labels(profile.specification().backend).unwrap();
                frame(&mut input, 3, b"classical child seed", &seed);
                frame(&mut input, 7, label, &[0; 64]);
            } else {
                let (context, root) = batch.source();
                frame(
                    &mut input,
                    1,
                    b"mw batched row-code v1",
                    &encoded(&(context, root, &batch.queries, batch.values())),
                );
                let role = &profile.specification().roles[0];
                let left = role.left_vars.unwrap();
                let count = (1usize << left) * role.width * role.width;
                frame(&mut input, 1, b"typed request kind", b"vector");
                frame(&mut input, 1, b"field challenge kind", b"prime vector");
                let mut descriptor = p.to_le_bytes().to_vec();
                descriptor.extend((count as u64).to_le_bytes());
                frame(&mut input, 4, b"mw batch random linear test", &descriptor);
                let (selected, _) = ntt_brakedown_batch_row_query::<F, EF, P>(
                    profile, pp, setup, statement, &input, &before,
                )
                .unwrap();
                assert_eq!(selected.ntt.row.component, component);
                assert_eq!(selected.evaluation, evaluation);
                let (_, raw) = raw_prime_phase::<F>(&input, count);
                let (phase_receipt, producer) = receipt(&raw);
                before.insert(phase_receipt[16..].try_into().unwrap(), producer);
                frame(
                    &mut input,
                    5,
                    b"mw batch random linear test",
                    &phase_receipt,
                );
                let mut representatives: Vec<usize> = Vec::new();
                for (i, query) in batch.queries.iter().enumerate() {
                    if !representatives
                        .iter()
                        .any(|&j| batch.queries[j][..left] == query[..left])
                    {
                        representatives.push(i);
                    }
                }
                let (tail, _, cells) = brakedown_column_tail(profile).unwrap();
                frame(
                    &mut input,
                    1,
                    b"mw batch linear responses",
                    &encoded(&(
                        vec![F::zero(); cells],
                        vec![vec![F::zero(); cells]; representatives.len()],
                    )),
                );
                input.extend(tail);
                let selected = ntt_brakedown_batch_column_query::<F, EF, P>(
                    profile, pp, setup, statement, &input, &before,
                )
                .unwrap();
                assert_eq!(selected.batch.ntt.row.component, component);
                assert_eq!(selected.batch.evaluation, evaluation);
                frame(
                    &mut input,
                    3,
                    b"mw atomic column block v5",
                    &vec![0; 8 * role.queries],
                );
            }
        }
    }
    assert!(
        ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &input, &before).is_none()
    );
    assert!(
        ntt_completed_prefix::<F, EF, P>(profile, pp, setup, statement, &input, &before)
            .unwrap()
            .is_empty()
    );
    exercise_decomposition_linear::<F, EF, P>(profile, pp, setup, statement, input, before);
}

fn exercise_first_ntt<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &mut Vec<u8>,
    transcript: &mut Transcript<F>,
    before: &Producers,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use rand::{SeedableRng, rngs::StdRng};
    assert!(
        primary_completed_prefix::<F, EF, P>(profile, pp, setup, statement, input, before)
            .unwrap()
            .is_empty()
    );
    let header = initial_header::<F>(profile).unwrap();
    let mut outer = input.strip_prefix(header.as_slice()).unwrap();
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )
    .unwrap();
    let (co, ev, _, _, _) = recover::<F, EF, P>(pp, setup, statement, primary).unwrap();
    let shape = ntt::Shape::new_canonical::<F, Sha512, P>(pp.coefficients, setup.config.n).unwrap();
    let contexts = (
        pp.coefficients.context().ok().unwrap(),
        pp.evaluations.context().ok().unwrap(),
    );
    let root = F::get_ntt_table(shape.polynomial_size().ilog2())
        .unwrap()
        .root();
    let binding = encoded(&(
        F::MODULUS_VALUE.to_string(),
        &shape,
        root,
        contexts,
        &co[0],
        &ev[0],
    ));
    let binding_start = input.len();
    frame(input, 1, P::NTT_DOMAIN, &binding);
    frame(input, 1, b"typed request kind", b"vector");
    frame(input, 1, b"field challenge kind", b"prime vector");
    let count = shape.width() * shape.row_variables();
    assert!(count > 0);
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend((count as u64).to_le_bytes());
    frame(input, 4, b"packed NTT atomic row points v2", &descriptor);
    let task =
        ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, input, before).unwrap();
    assert_eq!(encoded(&task.coefficients), encoded(&(contexts.0, &co[0])));
    assert_eq!(encoded(&task.evaluations), encoded(&(contexts.1, &ev[0])));
    assert_eq!(encoded(&task.shape), encoded(&shape));
    let mut wrong = input.clone();
    wrong.push(0);
    assert!(
        ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, before).is_none()
    );
    let mut wrong = input.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, before).is_none()
    );
    let at = binding
        .windows(64)
        .position(|window| window == ev[0].root.0)
        .unwrap();
    let mut wrong = input.clone();
    wrong[binding_start + 1 + 8 + P::NTT_DOMAIN.len() + 8 + at] ^= 1;
    assert!(
        ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, before).is_none()
    );
    assert!(
        ntt_first_row_query::<F, EF, P>(profile, pp, setup, statement, input, &Producers::new())
            .is_none()
    );
    // Correctly shaped packets for a different zero-source root reach the
    // first PCS sampling boundary after all NTT compression phases.
    let width = pp.coefficients.width();
    let vars = pp.coefficients.num_vars();
    let zero = PackedTable::new(vars, width, vec![F::zero(); width << vars]).unwrap();
    let (dummy_root, state) = pp
        .coefficients
        .commit(&zero, &mut StdRng::seed_from_u64(906))
        .ok()
        .unwrap();
    assert_ne!(dummy_root.root, co[0].root);
    let folded_coefficients = vec![vec![F::zero(); shape.polynomial_size()]; width];
    let folded_evaluations = folded_coefficients.clone();
    let co_oracle = crate::packed_oracle::CanonicalVerifierOracle {
        parameters: pp.coefficients,
        commitment: &co[0],
    };
    let ev_oracle = crate::packed_oracle::CanonicalVerifierOracle {
        parameters: pp.evaluations,
        commitment: &ev[0],
    };

    let (row_coins, row_raw) = raw_prime_phase::<F>(input, count);
    let points: Vec<Vec<F>> = row_coins
        .chunks_exact(shape.row_variables())
        .map(|row| {
            row.iter()
                .map(|&v| F::from(usize::try_from(v).unwrap()))
                .collect()
        })
        .collect();
    let mut before = before.clone();
    let (row_receipt, producer) = receipt(&row_raw);
    let mut previous: [u8; 64] = row_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(input, 5, b"packed NTT atomic row points v2", &row_receipt);
    let folded_start = input.len();
    frame(
        input,
        1,
        b"packed NTT folded polynomials",
        &encoded(&(&folded_coefficients, &folded_evaluations)),
    );
    let folded_end = input.len();
    let tail = ntt_compression_tail::<F>(width);
    let mut compression = Vec::new();
    for round in 0..shape.coefficient_variables() {
        input.extend(&tail);
        let task =
            ntt_compression_query::<F, EF, P>(profile, pp, setup, statement, input, &before, round)
                .unwrap();
        assert_eq!(task.points, points);
        assert_eq!(task.coefficients, folded_coefficients);
        assert_eq!(task.evaluations, folded_evaluations);
        assert_eq!(encoded(&task.compression), encoded(&compression));
        assert_eq!(
            encoded(&task.row.coefficients),
            encoded(&(contexts.0, &co[0]))
        );
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            ntt_compression_query::<F, EF, P>(
                profile, pp, setup, statement, input, &missing, round
            )
            .is_none()
        );
        let mut trailing = input.clone();
        trailing.push(0);
        assert!(
            ntt_compression_query::<F, EF, P>(
                profile, pp, setup, statement, &trailing, &before, round
            )
            .is_none()
        );
        if round == 0 {
            let mut nonzero: Vec<Vec<F>> = (0..width)
                .map(|row| {
                    (0..shape.polynomial_size())
                        .map(|i| F::from(i + row + 1))
                        .collect()
                })
                .collect();
            let mut transformed = nonzero.clone();
            let table = F::get_ntt_table(shape.polynomial_size().ilog2()).unwrap();
            for row in &mut transformed {
                table.transform_slice(row);
            }
            let mut candidate = input[..folded_start].to_vec();
            frame(
                &mut candidate,
                1,
                b"packed NTT folded polynomials",
                &encoded(&(&nonzero, &transformed)),
            );
            candidate.extend(&tail);
            let valid = ntt_compression_query::<F, EF, P>(
                profile, pp, setup, statement, &candidate, &before, 0,
            )
            .unwrap();
            assert_eq!(valid.coefficients, nonzero);
            assert_eq!(valid.evaluations, transformed);
            nonzero[0][0] += F::one();
            let mut bad = input[..folded_start].to_vec();
            frame(
                &mut bad,
                1,
                b"packed NTT folded polynomials",
                &encoded(&(&nonzero, &transformed)),
            );
            bad.extend(&tail);
            assert!(
                ntt_compression_query::<F, EF, P>(profile, pp, setup, statement, &bad, &before, 0)
                    .is_none()
            );
            let mut huge = encoded(&width);
            huge.extend(encoded(&usize::MAX));
            let mut bad = input[..folded_start].to_vec();
            frame(&mut bad, 1, b"packed NTT folded polynomials", &huge);
            bad.extend(&tail);
            assert!(
                ntt_compression_query::<F, EF, P>(profile, pp, setup, statement, &bad, &before, 0)
                    .is_none()
            );
        }
        let (coins, raw) = raw_prime_phase::<F>(input, width);
        let values: Vec<F> = coins
            .into_iter()
            .map(|v| F::from(usize::try_from(v).unwrap()))
            .collect();
        compression.push(sumcheck::packed::challenge_pair(&values).unwrap());
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(
            input,
            5,
            b"packed NTT coefficient compression",
            &phase_receipt,
        );
    }
    let source_queries: Vec<_> = points
        .iter()
        .map(|point| {
            let mut query = compression.clone();
            for &r in point {
                let diagonal = |value| {
                    let mut matrix = vec![F::zero(); width * width];
                    for i in 0..width {
                        matrix[i * width + i] = value;
                    }
                    algebra::matrix_weighted::Matrix::new(width, matrix).unwrap()
                };
                query.push(algebra::matrix_weighted::MatrixPair {
                    zero: diagonal(F::one() - r),
                    one: diagonal(r),
                });
            }
            query
        })
        .collect();
    assert!(width > 1);
    assert_ne!(encoded(&source_queries[0]), encoded(&source_queries[1]));
    let co_values: Vec<_> = folded_coefficients
        .iter()
        .map(|row| {
            PackedTable::new(shape.coefficient_variables(), width, row.clone())
                .unwrap()
                .evaluate(&compression)
                .unwrap()
        })
        .collect();

    let ev_values: Vec<_> = folded_evaluations
        .iter()
        .map(|row| {
            PackedTable::new(shape.coefficient_variables(), width, row.clone())
                .unwrap()
                .evaluate(&compression)
                .unwrap()
        })
        .collect();
    let (batch, rest) =
        ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, input, &before).unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&batch.queries), encoded(&source_queries));
    assert_eq!(batch.coefficient_values, co_values);
    assert_eq!(batch.evaluation_values, ev_values);
    let opening_start = input.len();
    let make_packet = || {
        pp.coefficients
            .open_many(
                &mut profile.parent_transcript::<F>().unwrap(),
                &dummy_root,
                &state,
                &source_queries,
                &co_values,
            )
            .ok()
            .unwrap()
    };
    let packet = ntt::CanonicalProof {
        coefficients: folded_coefficients,
        evaluations: folded_evaluations,
        coefficient_opening: make_packet(),
        evaluation_opening: make_packet(),
    };
    let error =
        ntt::verify_canonical::<F, Sha512, P>(transcript, &shape, &co_oracle, &ev_oracle, &packet)
            .unwrap_err();
    // Exact post-error replay below proves that the first PCS query was
    // reached; backend error text can depend on its sampled indices.
    assert!(!error.0.is_empty());
    if profile.specification().backend == Backend::Brakedown {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let batch_start = input.len();
        frame(
            input,
            1,
            b"mw batched row-code v1",
            &encoded(&(contexts.0, &co[0], &source_queries, &co_values)),
        );
        let role = &profile.specification().roles[0];
        let count = (1usize << role.left_vars.unwrap()) * width * width;
        let mut tail = Vec::new();
        frame(&mut tail, 1, b"typed request kind", b"vector");
        frame(&mut tail, 1, b"field challenge kind", b"prime vector");
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((count as u64).to_le_bytes());
        frame(&mut tail, 4, b"mw batch random linear test", &descriptor);
        input.extend(&tail);
        let (checked, checked_count) = ntt_brakedown_batch_row_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before,
        )
        .unwrap();
        assert_eq!(checked_count, count);
        assert_eq!(encoded(&checked.queries), encoded(&source_queries));
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            ntt_brakedown_batch_row_query::<F, EF, P>(
                profile, pp, setup, statement, input, &missing
            )
            .is_none()
        );
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            ntt_brakedown_batch_row_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before
            )
            .is_none()
        );
        let (row_values, raw) = raw_prime_phase::<F>(input, count);
        let (batch_row_receipt, producer) = receipt(&raw);
        let batch_row_fingerprint: [u8; 64] = batch_row_receipt[16..].try_into().unwrap();
        before.insert(batch_row_fingerprint, producer);
        frame(input, 5, b"mw batch random linear test", &batch_row_receipt);
        let bytes = encoded(&packet.coefficient_opening);
        let (opening, used): (pcs::matrix_weighted::BatchOpening<F, Digest512>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let response_start = input.len();
        frame(
            input,
            1,
            b"mw batch linear responses",
            &encoded(&(&opening.test, &opening.evaluations)),
        );
        let response_end = input.len();
        let (column_tail, column_domain, _) = brakedown_column_tail(profile).unwrap();
        input.extend(&column_tail);
        let columns = ntt_brakedown_batch_column_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before,
        )
        .unwrap();
        assert_eq!(columns.domain, column_domain);
        assert_eq!(
            columns.random,
            row_values
                .iter()
                .map(|&v| F::from(usize::try_from(v).unwrap()))
                .collect::<Vec<_>>()
        );
        assert_eq!(columns.test, opening.test);
        assert_eq!(columns.evaluations, opening.evaluations);
        assert_eq!(columns.representatives.len(), opening.evaluations.len());
        assert_eq!(encoded(&columns.batch.queries), encoded(&source_queries));
        let mut missing = before.clone();
        missing.remove(&batch_row_fingerprint);
        assert!(
            ntt_brakedown_batch_column_query::<F, EF, P>(
                profile, pp, setup, statement, input, &missing
            )
            .is_none()
        );
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            ntt_brakedown_batch_column_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before
            )
            .is_none()
        );
        let mut wrong = input[..response_start].to_vec();
        let mut huge = encoded(&opening.test);
        huge.extend(encoded(&usize::MAX));
        frame(&mut wrong, 1, b"mw batch linear responses", &huge);
        wrong.extend_from_slice(&input[response_end..]);
        assert!(
            ntt_brakedown_batch_column_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before
            )
            .is_none()
        );
        // Proposed row coins share all left query coordinates but differ
        // on the right. Group count must follow the left prefix, not the
        // complete query. This is a synthetic frozen-producer fixture.
        let left = role.left_vars.unwrap();
        let coefficient_vars = shape.coefficient_variables();
        assert!(left >= coefficient_vars && left < vars);
        let field_bytes = ((128 - (p - 1).leading_zeros()) as usize).div_ceil(8);
        let mut controlled_raw = Vec::new();
        for repetition in 0..width {
            for coordinate in 0..shape.row_variables() {
                let value = if coordinate + 1 == shape.row_variables() {
                    repetition + 1
                } else {
                    0
                };
                controlled_raw.extend_from_slice(&(value as u128).to_le_bytes()[..field_bytes]);
            }
        }
        let (controlled_receipt, producer) = receipt(&controlled_raw);
        let mut controlled_before = before.clone();
        controlled_before.insert(controlled_receipt[16..].try_into().unwrap(), producer);
        let mut controlled = input[..batch_start].to_vec();
        let at = controlled
            .windows(row_receipt.len())
            .position(|window| window == row_receipt)
            .unwrap();
        controlled[at..at + row_receipt.len()].copy_from_slice(&controlled_receipt);
        let (controlled_task, rest) = ntt_batch_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &controlled,
            &controlled_before,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_ne!(
            encoded(&controlled_task.queries[0]),
            encoded(&controlled_task.queries[1])
        );
        assert_eq!(
            &controlled_task.queries[0][..left],
            &controlled_task.queries[1][..left]
        );
        frame(
            &mut controlled,
            1,
            b"mw batched row-code v1",
            &encoded(&(
                contexts.0,
                &co[0],
                &controlled_task.queries,
                &controlled_task.coefficient_values,
            )),
        );
        controlled.extend(&tail);
        frame(
            &mut controlled,
            5,
            b"mw batch random linear test",
            &batch_row_receipt,
        );
        let response_start = controlled.len();
        let evaluation = vec![opening.evaluations[0].clone()];
        frame(
            &mut controlled,
            1,
            b"mw batch linear responses",
            &encoded(&(&opening.test, &evaluation)),
        );
        controlled.extend(&column_tail);
        let grouped = ntt_brakedown_batch_column_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &controlled,
            &controlled_before,
        )
        .unwrap();
        assert_eq!(grouped.representatives, vec![0]);
        let mut wrong = controlled[..response_start].to_vec();
        frame(
            &mut wrong,
            1,
            b"mw batch linear responses",
            &encoded(&(&opening.test, vec![evaluation[0].clone(); 2])),
        );
        wrong.extend(&column_tail);
        assert!(
            ntt_brakedown_batch_column_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &wrong,
                &controlled_before
            )
            .is_none()
        );
        let mut xof = sha3::Shake256::default();
        Update::update(&mut xof, input.as_slice());
        let mut bytes = vec![0; 8 * role.queries];
        xof.finalize_xof().read(&mut bytes);
        frame(input, 3, b"mw atomic column block v5", &bytes);
        // The preceding coefficient response is synthetic; this establishes
        // continuation framing and source selection, not PCS acceptance.
        let mut evaluation_input = input.clone();
        frame(
            &mut evaluation_input,
            1,
            b"mw batched row-code v1",
            &encoded(&(contexts.1, &ev[0], &source_queries, &ev_values)),
        );
        evaluation_input.extend(&tail);
        let (selected, selected_count) = ntt_brakedown_batch_row_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &evaluation_input,
            &before,
        )
        .unwrap();
        assert!(selected.evaluation);
        assert_eq!(selected_count, count);
        assert_eq!(
            encoded(selected.source()),
            encoded(&batch.ntt.row.evaluations)
        );
        assert_eq!(selected.values(), &ev_values);
        let (random, raw) = raw_prime_phase::<F>(&evaluation_input, count);
        let (evaluation_receipt, producer) = receipt(&raw);
        let mut evaluation_before = before.clone();
        let fingerprint = evaluation_receipt[16..].try_into().unwrap();
        evaluation_before.insert(fingerprint, producer);
        frame(
            &mut evaluation_input,
            5,
            b"mw batch random linear test",
            &evaluation_receipt,
        );
        frame(
            &mut evaluation_input,
            1,
            b"mw batch linear responses",
            &encoded(&(&opening.test, &opening.evaluations)),
        );
        evaluation_input.extend(&column_tail);
        let selected = ntt_brakedown_batch_column_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &evaluation_input,
            &evaluation_before,
        )
        .unwrap();
        assert!(selected.batch.evaluation);
        assert_eq!(
            selected.random,
            random
                .into_iter()
                .map(|v| F::from(usize::try_from(v).unwrap()))
                .collect::<Vec<_>>()
        );
        let complete_before = evaluation_before.clone();
        let mut completed = evaluation_input.clone();
        frame(
            &mut completed,
            3,
            b"mw atomic column block v5",
            &vec![0; 8 * role.queries],
        );
        exercise_ntt_components::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            completed,
            complete_before.clone(),
        );
        evaluation_before.remove(&fingerprint);
        assert!(
            ntt_brakedown_batch_column_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &evaluation_input,
                &evaluation_before
            )
            .is_none()
        );
        evaluation_input.push(0);
        assert!(
            ntt_brakedown_batch_column_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &evaluation_input,
                &complete_before
            )
            .is_none()
        );
    } else {
        let tail = ntt_batch_seed_tail(profile, pp.coefficients, &batch).unwrap();
        input.extend(&tail);
        let checked =
            ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, input, &before)
                .unwrap();
        assert_eq!(encoded(&checked.queries), encoded(&source_queries));
        assert_eq!(checked.coefficient_values, co_values);
        assert_eq!(checked.evaluation_values, ev_values);
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, input, &missing)
                .is_none()
        );
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before)
                .is_none()
        );
        let mut wrong = input.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(
            ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before)
                .is_none()
        );
        let seed = shake64(input);
        let (_, label, context) = pcs_child_labels(profile.specification().backend).unwrap();
        let child_input = raw_child::<F, EF>(profile, label, context, &seed);
        let mut child_before = before.clone();
        child_before.insert(seed, input.clone());
        let (empty, producer) = receipt(&[]);
        let identity: [u8; 64] = empty[16..].try_into().unwrap();
        child_before.insert(identity, producer);
        let mut views = FirstViews::new();
        views.insert(input.clone(), before.clone());
        let (inherited, rest) = ntt_child_prefix::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &child_input,
            &child_before,
            &views,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_eq!(encoded(&inherited.queries), encoded(&source_queries));
        assert_eq!(inherited.coefficient_values, co_values);
        let mut missing = child_before.clone();
        missing.remove(&seed);
        assert!(
            ntt_child_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child_input,
                &missing,
                &views
            )
            .is_none()
        );
        let mut missing = child_before.clone();
        missing.remove(&identity);
        assert!(
            ntt_child_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child_input,
                &missing,
                &views
            )
            .is_none()
        );
        let mut late = views.clone();
        late.get_mut(input.as_slice()).unwrap().remove(&previous);
        assert!(child_before.contains_key(&previous));
        assert!(
            ntt_child_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child_input,
                &child_before,
                &late
            )
            .is_none()
        );
        let wrong = raw_child::<F, EF>(profile, b"wrong NTT child", context, &seed);
        assert!(
            ntt_child_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &wrong,
                &child_before,
                &views
            )
            .is_none()
        );
        assert!(
            primary_child_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &child_input,
                &child_before,
                &views,
                None
            )
            .is_none()
        );
        {
            let fragmented = matches!(
                profile.specification().backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            );
            if fragmented {
                exercise_ntt_fragment_bridge::<F, EF, P>(
                    profile, pp, setup, statement, input, &before,
                );
            } else {
                exercise_ntt_direct_projection::<F, EF, P>(
                    profile, pp, setup, statement, input, &before,
                );
            }
            let nonzero: Vec<Vec<F>> = (0..width)
                .map(|row| {
                    (0..shape.polynomial_size())
                        .map(|i| F::from(1 + row + i))
                        .collect()
                })
                .collect();
            let mut transformed = nonzero.clone();
            let table = F::get_ntt_table(shape.polynomial_size().ilog2()).unwrap();
            for row in &mut transformed {
                table.transform_slice(row);
            }
            let mut proposed = input[..folded_start].to_vec();
            frame(
                &mut proposed,
                1,
                b"packed NTT folded polynomials",
                &encoded(&(&nonzero, &transformed)),
            );
            proposed.extend_from_slice(&input[folded_end..opening_start]);
            let (nonzero_batch, rest) =
                ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, &proposed, &before)
                    .unwrap();
            assert!(rest.is_empty());
            assert!(
                nonzero_batch
                    .coefficient_values
                    .iter()
                    .flatten()
                    .any(|&v| v != F::zero())
            );
            proposed.extend(ntt_batch_seed_tail(profile, pp.coefficients, &nonzero_batch).unwrap());
            if fragmented {
                exercise_ntt_fragment_bridge::<F, EF, P>(
                    profile, pp, setup, statement, &proposed, &before,
                );
            } else {
                exercise_ntt_direct_projection::<F, EF, P>(
                    profile, pp, setup, statement, &proposed, &before,
                );
            }
        }
        // Synthetic completed coefficient opening: checks ordered source
        // selection and sampling, without claiming an accepted NTT proof.
        let mut evaluation_input = input.clone();
        frame(&mut evaluation_input, 3, b"classical child seed", &seed);
        frame(&mut evaluation_input, 7, label, &[0; 64]);
        let (mut evaluation_batch, _) =
            ntt_batch_prefix::<F, EF, P>(profile, pp, setup, statement, input, &before).unwrap();
        evaluation_batch.evaluation = true;
        evaluation_input
            .extend(ntt_batch_seed_tail(profile, pp.evaluations, &evaluation_batch).unwrap());
        let mut missing_finish = input.clone();
        frame(&mut missing_finish, 3, b"classical child seed", &seed);
        missing_finish
            .extend(ntt_batch_seed_tail(profile, pp.evaluations, &evaluation_batch).unwrap());
        assert!(
            ntt_batch_seed_query::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &missing_finish,
                &before
            )
            .is_none()
        );
        let mut short_finish = input.clone();
        frame(&mut short_finish, 3, b"classical child seed", &seed);
        frame(&mut short_finish, 7, label, &[0; 63]);
        short_finish
            .extend(ntt_batch_seed_tail(profile, pp.evaluations, &evaluation_batch).unwrap());
        assert!(
            ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, &short_finish, &before)
                .is_none()
        );
        let selected = ntt_batch_seed_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &evaluation_input,
            &before,
        )
        .unwrap();
        assert!(selected.evaluation);
        assert_eq!(
            encoded(selected.source()),
            encoded(&batch.ntt.row.evaluations)
        );
        assert_eq!(selected.values(), &ev_values);
        if matches!(
            profile.specification().backend,
            Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
        ) {
            exercise_ntt_fragment_bridge::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &evaluation_input,
                &before,
            );
        } else {
            exercise_ntt_direct_projection::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &evaluation_input,
                &before,
            );
        }
        let mut completed = evaluation_input.clone();
        let evaluation_seed = shake64(&completed);
        frame(&mut completed, 3, b"classical child seed", &evaluation_seed);
        frame(&mut completed, 7, label, &[0; 64]);
        exercise_ntt_components::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            completed,
            before.clone(),
        );
        let mut wrong = evaluation_input.clone();
        wrong.push(0);
        assert!(
            ntt_batch_seed_query::<F, EF, P>(profile, pp, setup, statement, &wrong, &before)
                .is_none()
        );
        frame(input, 3, b"classical child seed", &seed);
    }
}

fn exercise_brakedown_factors<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    opening: &FirstOpening<F>,
    input: &mut Vec<u8>,
    transcript: &mut Transcript<F>,
    primary_before: &Producers,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    assert_eq!(profile.version(), 5);
    let mut before = primary_before.clone();
    let (column_tail, domain, cells) = brakedown_column_tail(profile).unwrap();
    let draws = profile.specification().roles[0].queries;
    for factor in 0..opening.sources.len() {
        let selected = FirstOpening {
            family: OpeningFamily::Primary,
            selected: factor,
            sources: opening.sources.clone(),
            query: opening.query.clone(),
            values: opening.values.clone(),
        };
        let (row_tail, count) = brakedown_first_tail(profile, &selected).unwrap();
        let row_start = input.len();
        input.extend(&row_tail);
        let (task, recovered_count) = brakedown_factor_row_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before, factor,
        )
        .unwrap();
        let mut trailing = input.clone();
        trailing.push(0);
        assert!(
            brakedown_factor_row_query::<F, EF, P>(
                profile, pp, setup, statement, &trailing, &before, factor
            )
            .is_none()
        );
        assert_eq!(recovered_count, count);
        assert_eq!(task.selected, factor);
        assert_eq!(
            encoded(&task.sources[factor]),
            encoded(&opening.sources[factor])
        );
        assert!(
            brakedown_factor_row_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                input,
                &before,
                opening.sources.len()
            )
            .is_none()
        );
        let root_at = row_tail
            .windows(64)
            .position(|window| window == opening.sources[factor].1.root.0)
            .unwrap();
        let mut wrong = input.clone();
        wrong[row_start + root_at] ^= 1;
        assert!(
            brakedown_factor_row_prefix::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, factor
            )
            .is_none()
        );
        if factor > 0 {
            // Older sampled values do not select this factor's inherited task.
            let mut opaque = input.clone();
            opaque[row_start - 1] ^= 1;
            let (same, _, rest) = brakedown_factor_row_prefix::<F, EF, P>(
                profile,
                pp,
                setup,
                statement,
                &opaque,
                primary_before,
                factor,
            )
            .unwrap();
            assert!(rest.is_empty());
            assert_eq!(same.selected, factor);
            assert_eq!(
                encoded(&same.values[factor]),
                encoded(&opening.values[factor])
            );
            let mut short = input[..row_start - 1].to_vec();
            short.extend_from_slice(&input[row_start..]);
            assert!(
                brakedown_factor_row_prefix::<F, EF, P>(
                    profile, pp, setup, statement, &short, &before, factor
                )
                .is_none()
            );
        }
        transcript.append_message(b"mw brakedown row-code v2", &opening.sources[factor].0);
        transcript.append_message(
            b"mw commitment and query",
            &(
                &opening.sources[factor].1,
                &opening.query,
                &opening.values[factor],
            ),
        );
        let (coefficients, raw) = raw_prime_phase::<F>(input, count);
        let random: Vec<F> = coefficients
            .into_iter()
            .map(|v| F::from(usize::try_from(v).unwrap()))
            .collect();
        assert_eq!(
            transcript.get_vec_challenge(b"mw random linear test", count),
            random
        );
        let (phase_receipt, producer) = receipt(&raw);
        let fingerprint: [u8; 64] = phase_receipt[16..].try_into().unwrap();
        before.insert(fingerprint, producer);
        frame(input, 5, b"mw random linear test", &phase_receipt);
        let test: Vec<_> = (0..cells).map(|i| F::from(i + factor + 3)).collect();
        let evaluation: Vec<_> = (0..cells).map(|i| F::from(2 * i + factor + 5)).collect();
        let response_start = input.len();
        frame(
            input,
            1,
            b"mw linear responses",
            &encoded(&(&test, &evaluation)),
        );
        let response_end = input.len();
        transcript.append_message(b"mw linear responses", &(&test, &evaluation));
        input.extend(&column_tail);
        let task = brakedown_factor_column_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before, factor,
        )
        .unwrap();
        assert_eq!(task.opening.selected, factor);
        assert_eq!(task.random, random);
        assert_eq!(task.test, test);
        assert_eq!(task.evaluation, evaluation);
        assert_eq!(task.domain, domain);
        let mut missing = before.clone();
        missing.remove(&fingerprint);
        assert!(
            brakedown_factor_column_query::<F, EF, P>(
                profile, pp, setup, statement, input, &missing, factor
            )
            .is_none()
        );
        let mut wrong = input[..response_start].to_vec();
        frame(&mut wrong, 1, b"mw linear responses", &encoded(&usize::MAX));
        wrong.extend_from_slice(&input[response_end..]);
        assert!(
            brakedown_factor_column_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, factor
            )
            .is_none()
        );
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            brakedown_factor_column_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &before, factor
            )
            .is_none()
        );
        let mut xof = sha3::Shake256::default();
        Update::update(&mut xof, input.as_slice());
        let mut bytes = vec![0; 8 * draws];
        xof.finalize_xof().read(&mut bytes);
        let indices: Vec<_> = bytes
            .chunks_exact(8)
            .map(|chunk| {
                (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
            })
            .collect();
        assert_eq!(
            transcript
                .get_index_challenges(b"mw atomic column block v5", domain, draws)
                .unwrap(),
            indices
        );
        frame(input, 3, b"mw atomic column block v5", &bytes);
    }
    exercise_first_ntt::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        input,
        transcript,
        primary_before,
    );
    frame(
        input,
        2,
        b"all Brakedown factors replay",
        &64u64.to_le_bytes(),
    );
    let mut output = [0; 64];
    transcript.get_challenge_bytes(b"all Brakedown factors replay", &mut output);
    assert_eq!(shake64(input), output);
}

fn exercise_fragment_factor<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    opening: &FirstOpening<F>,
    factor: usize,
    input: &mut Vec<u8>,
    transcript: &mut impl ReplayTranscript<EF>,
    before: &Producers,
    views: &FirstViews,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let width = profile.specification().roles[opening.role()].width;
    let virtual_source = profile.specification().backend == Backend::FragmentedPipfriVirtual;
    let projection_start = input.len();
    input.extend(fragment_first_tail_for_role::<F, EF>(profile, opening.role()).unwrap());
    if opening.role() == 1 && width != profile.specification().roles[0].width {
        let mut wrong = input[..projection_start].to_vec();
        wrong.extend(fragment_first_tail::<F, EF>(profile).unwrap());
        assert!(
            fragment_first_query::<F, EF, P>(profile, pp, setup, statement, &wrong, before, views,)
                .is_none()
        );
    }
    let task =
        fragment_first_query::<F, EF, P>(profile, pp, setup, statement, input, before, views)
            .unwrap();
    assert_eq!(task.selected, factor);
    assert_eq!(
        encoded(&task.sources[factor]),
        encoded(&opening.sources[factor])
    );
    let label = if virtual_source {
        b"virtual bridge lane projections v2".as_slice()
    } else {
        b"fragmented lane projections"
    };
    let (coefficients, raw) = raw_prime_phase::<F>(input, width * EF::D);
    let rho: Vec<_> = coefficients
        .chunks_exact(EF::D)
        .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
        .collect();
    assert_eq!(transcript.get_vec_challenge(label, width), rho);
    let mut before = before.clone();
    let (phase_receipt, producer) = receipt(&raw);
    let mut previous: [u8; 64] = phase_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(input, 5, label, &phase_receipt);
    let (n, rounds, fragments, scalar_context, fri_context) =
        scalar_geometry_for_role::<F, EF>(profile, opening.role()).unwrap();
    let claim = rho
        .iter()
        .zip(&opening.values[factor])
        .fold(EF::zero(), |sum, (&r, &v)| sum + r * EF::from_base(v));
    let info = algebra::PolynomialInfo {
        num_variables: n,
        max_multiplicands: 2,
    };
    let info_start = input.len();
    frame(input, 1, b"polynomial info", &encoded(&info));
    let mut expected = claim;
    let mut point = Vec::new();
    let mut messages = Vec::new();
    for round in 0..n {
        let values = vec![EF::zero(), expected, expected + expected];
        let msg = sumcheck::prover::ProverMsg::from_evaluations(values);
        frame(input, 1, b"sumcheck msg", &encoded(&msg));
        input.extend(bridge_round_tail::<F, EF>());
        if opening.role() == 1 && round == 0 {
            let source_info = algebra::PolynomialInfo {
                num_variables: role_vars_for_bridge(profile),
                max_multiplicands: 2,
            };
            assert_ne!(source_info.num_variables, n);
            let mut wrong = input[..info_start].to_vec();
            frame(&mut wrong, 1, b"polynomial info", &encoded(&source_info));
            frame(&mut wrong, 1, b"sumcheck msg", &encoded(&msg));
            wrong.extend(bridge_round_tail::<F, EF>());
            assert!(
                fragment_round_query::<F, EF, P>(
                    profile, pp, setup, statement, &wrong, &before, views, round,
                )
                .is_none()
            );
        }
        let task = fragment_round_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before, views, round,
        )
        .unwrap();
        assert_eq!(task.opening.selected, factor);
        assert_eq!(task.rho, rho);
        assert_eq!(task.point, point);
        assert_eq!(task.expected, expected);
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            fragment_round_query::<F, EF, P>(
                profile, pp, setup, statement, input, &missing, views, round
            )
            .is_none()
        );
        let (coefficients, raw) = raw_prime_phase::<F>(input, EF::D);
        let coin = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        // The independently chosen round polynomial is expected*X.
        expected *= coin;
        point.push(coin);
        messages.push(msg);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(input, 5, b"random point in each round", &phase_receipt);
    }
    let (checked_point, checked_expected) = transcript.bridge_subclaim(&info, claim, &messages);
    assert_eq!(checked_point, point);
    assert_eq!(checked_expected, expected);
    // Synthetic scalar claims test task origin, not terminal-kernel acceptance.
    let value = EF::from_base(F::from(factor + 7));
    let u = vec![value; fragments];
    let root = &opening.sources[factor].1;
    if virtual_source {
        frame(input, 1, b"unmasked virtual PipFRI PCS v2", &encoded(&n));
        transcript.append_message(b"unmasked virtual PipFRI PCS v2", &n);
        let binding = (2u32, scalar_context, root, &point, value, &u);
        frame(
            input,
            1,
            b"unmasked scalar PipFRI virtual v2",
            &encoded(&binding),
        );
        transcript.append_message(b"unmasked scalar PipFRI virtual v2", &binding);
    } else {
        let mode = (n, b"base table".as_slice());
        frame(input, 1, b"ordinary PipFRI PCS adapter v1", &encoded(&mode));
        transcript.append_message(b"ordinary PipFRI PCS adapter v1", &mode);
        let binding = (scalar_context, root, &point, value, &u);
        frame(
            input,
            1,
            b"HasteBoots ordinary PipFRI v1",
            &encoded(&binding),
        );
        transcript.append_message(b"HasteBoots ordinary PipFRI v1", &binding);
    }
    let (tail, gamma_label) = gamma_tail::<F, EF>(profile).unwrap();
    input.extend(tail);
    let task = scalar_gamma_query::<F, EF, P>(profile, pp, setup, statement, input, &before, views)
        .unwrap();
    assert_eq!(task.opening.selected, factor);
    assert_eq!(task.point, point);
    assert_eq!(task.bridge_expected, expected);
    assert_eq!(task.value, value);
    let (coefficients, raw) = raw_prime_phase::<F>(input, EF::D);
    let gamma = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
    assert_eq!(transcript.get_challenge(gamma_label), gamma);
    let (phase_receipt, producer) = receipt(&raw);
    previous = phase_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(input, 5, gamma_label, &phase_receipt);
    let ladder: Vec<_> = (0..rounds - usize::from(virtual_source))
        .map(|i| RollingRoot {
            root: Digest512([u8::try_from(factor + i + 31).unwrap(); 64]),
        })
        .collect();
    let mut originals = Vec::new();
    if virtual_source {
        originals.push(RollingRoot {
            root: Digest512(
                Sha512::digest(encoded(&(
                    b"unmasked PipFRI virtual initial v2".as_slice(),
                    scalar_context,
                    root,
                    &point,
                    gamma,
                )))
                .into(),
            ),
        });
    }
    originals.extend(ladder.clone());
    let public_label = if virtual_source {
        b"unmasked virtual PipFRI public roots v2".as_slice()
    } else {
        b"PipFRI public fold roots"
    };
    frame(input, 1, public_label, &encoded(&ladder));
    transcript.append_message(public_label, &ladder);
    let rolling_label = if virtual_source {
        b"HasteBoots rolling batch FRI virtual initial v1".as_slice()
    } else {
        b"HasteBoots rolling batch FRI v1"
    };
    frame(
        input,
        1,
        rolling_label,
        &encoded(&(fri_context, &originals)),
    );
    transcript.append_message(rolling_label, &(fri_context, &originals));
    let mut alphas = Vec::new();
    for round in 0..rounds {
        input.extend(rolling_alpha_tail::<F, EF>());
        let task = rolling_alpha_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before, views, round,
        )
        .unwrap();
        assert_eq!(task.scalar.opening.selected, factor);
        assert_eq!(task.gamma, gamma);
        assert_eq!(task.alphas, alphas);
        assert_eq!(encoded(&task.originals), encoded(&originals));
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            rolling_alpha_query::<F, EF, P>(
                profile, pp, setup, statement, input, &missing, views, round
            )
            .is_none()
        );
        let (coefficients, raw) = raw_prime_phase::<F>(input, EF::D);
        let alpha = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        assert_eq!(
            transcript.get_challenge(b"rolling FRI fold challenge"),
            alpha
        );
        alphas.push(alpha);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(input, 5, b"rolling FRI fold challenge", &phase_receipt);
        if round + 1 < rounds {
            let derived = RollingRoot {
                root: Digest512([u8::try_from(factor + round + 61).unwrap(); 64]),
            };
            frame(
                input,
                1,
                b"rolling FRI derived root",
                &encoded(&(round + 1, &derived)),
            );
            transcript.append_message(b"rolling FRI derived root", &(round + 1, &derived));
        }
    }
    let terminal = EF::from_base(F::from(factor + 11));
    frame(input, 1, b"rolling FRI terminal", &encoded(&terminal));
    transcript.append_message(b"rolling FRI terminal", &terminal);
    let (tail, domain) = rolling_index_tail_for_role(profile, opening.role()).unwrap();
    input.extend(tail);
    let (task, checked_terminal) =
        rolling_index_query::<F, EF, P>(profile, pp, setup, statement, input, &before, views)
            .unwrap();
    assert_eq!(task.scalar.opening.selected, factor);
    assert_eq!(task.alphas, alphas);
    assert_eq!(checked_terminal, terminal);
    let sample = |input: &[u8]| {
        let mut xof = sha3::Shake256::default();
        Update::update(&mut xof, input);
        let mut bytes = vec![0; 8 * profile.specification().roles[opening.role()].queries];
        xof.finalize_xof().read(&mut bytes);
        let indices: Vec<_> = bytes
            .chunks_exact(8)
            .map(|chunk| {
                (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
            })
            .collect();
        (bytes, indices)
    };
    let draws = profile.specification().roles[opening.role()].queries;
    let (bytes, indices) = sample(input);
    assert_eq!(
        transcript
            .get_index_challenges(b"rolling FRI unbiased domain index", domain, draws)
            .unwrap(),
        indices
    );
    frame(input, 3, b"rolling FRI unbiased domain index", &bytes);
    if !virtual_source {
        input.extend(consistency_index_tail_for_role(profile, opening.role()).unwrap());
        let (task, prior) = consistency_index_query::<F, EF, P>(
            profile, pp, setup, statement, input, &before, views,
        )
        .unwrap();
        assert_eq!(task.scalar.opening.selected, factor);
        assert_eq!(prior, indices);
        let (bytes, indices) = sample(input);
        assert_eq!(
            transcript
                .get_index_challenges(b"PipFRI consistency domain index", domain, draws)
                .unwrap(),
            indices
        );
        frame(input, 3, b"PipFRI consistency domain index", &bytes);
    }
}

trait ReplayTranscript<E: algebra::Field + Serialize + DeserializeOwned>:
    helper::FiatShamirTranscript<E>
{
    fn get_index_challenges(
        &mut self,
        label: &'static [u8],
        domain: usize,
        count: usize,
    ) -> Result<Vec<usize>, &'static str>;
    fn bridge_subclaim(
        &mut self,
        info: &algebra::PolynomialInfo,
        claim: E,
        messages: &sumcheck::Proof<E>,
    ) -> (Vec<E>, E) {
        assert_eq!(info.max_multiplicands, 2);
        assert_eq!(messages.len(), info.num_variables);
        self.append_message(b"polynomial info", info);
        let mut expected = claim;
        let mut point = Vec::new();
        for message in messages {
            let bytes = encoded(message);
            let mut body = bytes.as_slice();
            let evaluations = vector::<E>(&mut body, 3).unwrap();
            assert!(body.is_empty());
            assert_eq!(evaluations[0] + evaluations[1], expected);
            self.append_message(b"sumcheck msg", message);
            let coin = self.get_challenge(b"random point in each round");
            expected = quadratic(&evaluations, coin);
            point.push(coin);
        }
        (point, expected)
    }
}
impl<E: algebra::Field + Serialize + DeserializeOwned> ReplayTranscript<E> for Transcript<E> {
    fn get_index_challenges(
        &mut self,
        label: &'static [u8],
        domain: usize,
        count: usize,
    ) -> Result<Vec<usize>, &'static str> {
        Transcript::get_index_challenges(self, label, domain, count)
    }
    fn bridge_subclaim(
        &mut self,
        info: &algebra::PolynomialInfo,
        claim: E,
        messages: &sumcheck::Proof<E>,
    ) -> (Vec<E>, E) {
        let subclaim = sumcheck::MLSumcheck::verify(self, info, claim, messages).unwrap();
        (subclaim.point, subclaim.expected_evaluations)
    }
}
struct ExtensionReplay<F, E> {
    inner: helper::classical_transcript::ClassicalTranscript,
    marker: std::marker::PhantomData<(F, E)>,
}
impl<F: NTTField, E: AbstractExtensionField<F>> ExtensionReplay<F, E> {
    fn child(profile: &ClassicalProfile, label: &[u8], context: &[u8], seed: &[u8; 64]) -> Self {
        let mut inner = helper::classical_transcript::ClassicalTranscript::new(
            b"HasteBoots framed SHAKE256 child v1",
            &profile.id().0,
        );
        inner.append_bytes(b"child label", label);
        inner.append_bytes(b"child context", context);
        inner.append_bytes(b"parent seed", seed);
        assert!(
            inner
                .challenge_extension::<F, E>(b"typed extension identity", 0)
                .unwrap()
                .is_empty()
        );
        Self {
            inner,
            marker: std::marker::PhantomData,
        }
    }
}
impl<F: NTTField, E: AbstractExtensionField<F> + Serialize> helper::FiatShamirTranscript<E>
    for ExtensionReplay<F, E>
{
    fn append_message<M: Serialize>(&mut self, label: &'static [u8], message: &M) {
        self.inner.append_message(label, message).unwrap();
    }
    fn get_challenge_bytes(&mut self, label: &'static [u8], bytes: &mut [u8]) {
        self.inner.challenge_bytes(label, bytes);
    }
    fn get_challenge(&mut self, label: &'static [u8]) -> E {
        self.inner.append_bytes(b"typed request kind", b"scalar");
        self.inner.challenge_extension::<F, E>(label, 1).unwrap()[0]
    }
    fn get_vec_challenge(&mut self, label: &'static [u8], count: usize) -> Vec<E> {
        self.inner.append_bytes(b"typed request kind", b"vector");
        self.inner
            .challenge_extension::<F, E>(label, count)
            .unwrap()
    }
}
impl<F: NTTField, E: AbstractExtensionField<F> + Serialize + DeserializeOwned> ReplayTranscript<E>
    for ExtensionReplay<F, E>
{
    fn get_index_challenges(
        &mut self,
        label: &'static [u8],
        domain: usize,
        count: usize,
    ) -> Result<Vec<usize>, &'static str> {
        self.inner.challenge_indices(label, domain, count)
    }
}

fn exercise_direct_factor<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    opening: &FirstOpening<F>,
    factor: usize,
    input: &mut Vec<u8>,
    transcript: &mut impl ReplayTranscript<EF>,
    before: &Producers,
    views: &FirstViews,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let role = &profile.specification().roles[opening.role()];
    let rounds = role.num_vars;
    let domain = (1usize << rounds) * profile.specification().blowup;
    let bits = domain.ilog2();
    let mut root = F::get_ntt_root(bits.max(5)).unwrap();
    for _ in bits..bits.max(5) {
        root *= root;
    }
    let core = pcs::packed_polyfrim::authenticated::Parameters::new(
        1usize << rounds,
        role.width,
        profile.specification().blowup,
        role.queries,
        EF::from_base(root),
    )
    .unwrap();
    let parameters = opening.parameters(pp, factor).unwrap();
    let (query, values) = parameters
        .normalize_claim(opening.query.clone(), opening.values[factor].clone())
        .ok()
        .unwrap();
    let queries = vec![
        query
            .iter()
            .map(|pair| algebra::matrix_weighted::MatrixPair {
                zero: algebra::matrix_weighted::Matrix::new(
                    role.width,
                    pair.zero
                        .values()
                        .iter()
                        .copied()
                        .map(EF::from_base)
                        .collect(),
                )
                .unwrap(),
                one: algebra::matrix_weighted::Matrix::new(
                    role.width,
                    pair.one
                        .values()
                        .iter()
                        .copied()
                        .map(EF::from_base)
                        .collect(),
                )
                .unwrap(),
            })
            .collect::<Vec<_>>(),
    ];
    let claims = vec![values.into_iter().map(EF::from_base).collect::<Vec<_>>()];
    let source = opening.sources[factor].1.root;
    let mut ladder = vec![Digest512([u8::try_from(factor + 17).unwrap(); 64]); rounds];
    ladder[0] = source;
    let roots = vec![ladder.clone()];
    let joint = (&core, source, 1usize, &queries, &claims, &roots);
    frame(
        input,
        1,
        b"packed PolyFRIM joint query proximity v1",
        &encoded(&joint),
    );
    transcript.append_message(b"packed PolyFRIM joint query proximity v1", &joint);
    frame(
        input,
        1,
        b"packed PolyFRIM joint consistency member v1",
        &encoded(&0usize),
    );
    transcript.append_message(b"packed PolyFRIM joint consistency member v1", &0usize);
    let binding = (&core, source, &ladder[1..], &queries[0], &claims[0]);
    frame(
        input,
        1,
        b"packed PolyFRIM consistency v2",
        &encoded(&binding),
    );
    transcript.append_message(b"packed PolyFRIM consistency v2", &binding);
    frame(input, 1, b"index domain", &(domain as u64).to_le_bytes());
    frame(
        input,
        2,
        b"packed PolyFRIM domain index v2",
        &((8 * role.queries) as u64).to_le_bytes(),
    );
    let (task, rest) = direct_first_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, factor,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(task.roots, ladder);
    assert_eq!(
        encoded(&task.opening.sources[factor]),
        encoded(&opening.sources[factor])
    );
    if factor > 0 {
        assert!(
            direct_first_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views, 0)
                .is_none()
        );
    }
    let sample = |input: &[u8]| {
        let mut xof = sha3::Shake256::default();
        Update::update(&mut xof, input);
        let mut bytes = vec![0; 8 * role.queries];
        xof.finalize_xof().read(&mut bytes);
        let indices: Vec<_> = bytes
            .chunks_exact(8)
            .map(|chunk| {
                (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
            })
            .collect();
        (bytes, indices)
    };
    let (bytes, indices) = sample(input);
    assert_eq!(
        transcript
            .get_index_challenges(b"packed PolyFRIM domain index v2", domain, role.queries)
            .unwrap(),
        indices
    );
    frame(input, 3, b"packed PolyFRIM domain index v2", &bytes);
    frame(
        input,
        1,
        b"packed PolyFRIM joint projections v1",
        &encoded(&(&core, &roots)),
    );
    transcript.append_message(b"packed PolyFRIM joint projections v1", &(&core, &roots));
    input.extend(direct_projection_role_tail::<F, EF>(profile, 1, opening.role()).unwrap());
    let (task, rest) = direct_projection_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, factor,
    )
    .unwrap();
    assert!(rest.is_empty());
    assert_eq!(task.roots, ladder);
    let (coefficients, raw) = raw_prime_phase::<F>(input, rounds * role.width * EF::D);
    let weights: Vec<_> = coefficients
        .chunks_exact(EF::D)
        .map(|row| EF::from_base_fn(|i| F::from(usize::try_from(row[i]).unwrap())))
        .collect();
    assert_eq!(
        transcript.get_vec_challenge(
            b"packed PolyFRIM atomic joint lane weights v3",
            rounds * role.width
        ),
        weights
    );
    let mut before = before.clone();
    let (phase_receipt, producer) = receipt(&raw);
    let mut previous: [u8; 64] = phase_receipt[16..].try_into().unwrap();
    before.insert(previous, producer);
    frame(
        input,
        5,
        b"packed PolyFRIM atomic joint lane weights v3",
        &phase_receipt,
    );
    let originals: Vec<_> = weights
        .chunks_exact(role.width)
        .enumerate()
        .map(|(layer, row)| RollingRoot {
            root: Digest512(
                Sha512::digest(encoded(&(
                    b"packed PolyFRIM joint virtual layer v1".as_slice(),
                    &core,
                    layer,
                    &roots,
                    vec![row.to_vec()],
                )))
                .into(),
            ),
        })
        .collect();
    let fri = direct_fri_for_role::<F, EF>(profile, opening.role()).unwrap();
    let context = Digest512(
        Sha512::digest(encoded(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            EF::MODULUS_VALUE.to_string(),
            &fri,
        )))
        .into(),
    );
    frame(
        input,
        1,
        b"HasteBoots rolling batch FRI virtual all v2",
        &encoded(&(context, &originals)),
    );
    transcript.append_message(
        b"HasteBoots rolling batch FRI virtual all v2",
        &(context, &originals),
    );
    let mut alphas = Vec::new();
    for round in 0..rounds {
        input.extend(rolling_alpha_tail::<F, EF>());
        let (task, rest) = direct_rolling_prefix::<F, EF, P>(
            profile, pp, setup, statement, input, &before, views, factor, round,
        )
        .unwrap();
        assert!(rest.is_empty());
        assert_eq!(task.weights, weights);
        assert_eq!(task.alphas, alphas);
        assert_eq!(encoded(&task.originals), encoded(&originals));
        let mut missing = before.clone();
        missing.remove(&previous);
        assert!(
            direct_rolling_prefix::<F, EF, P>(
                profile, pp, setup, statement, input, &missing, views, factor, round
            )
            .is_none()
        );
        let (coefficients, raw) = raw_prime_phase::<F>(input, EF::D);
        let alpha = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
        assert_eq!(
            transcript.get_challenge(b"rolling FRI fold challenge"),
            alpha
        );
        alphas.push(alpha);
        let (phase_receipt, producer) = receipt(&raw);
        previous = phase_receipt[16..].try_into().unwrap();
        before.insert(previous, producer);
        frame(input, 5, b"rolling FRI fold challenge", &phase_receipt);
        if round + 1 < rounds {
            let derived = RollingRoot {
                root: Digest512([u8::try_from(round + factor + 51).unwrap(); 64]),
            };
            frame(
                input,
                1,
                b"rolling FRI derived root",
                &encoded(&(round + 1, &derived)),
            );
            transcript.append_message(b"rolling FRI derived root", &(round + 1, &derived));
        }
    }
    let terminal = EF::from_base(F::from(factor + 3));
    frame(input, 1, b"rolling FRI terminal", &encoded(&terminal));
    transcript.append_message(b"rolling FRI terminal", &terminal);
    frame(input, 1, b"index domain", &(domain as u64).to_le_bytes());
    frame(
        input,
        2,
        b"rolling FRI unbiased domain index",
        &((8 * role.queries) as u64).to_le_bytes(),
    );
    let (task, value) = direct_rolling_indices_at::<F, EF, P>(
        profile, pp, setup, statement, input, &before, views, factor,
    )
    .unwrap();
    assert_eq!(value, terminal);
    assert_eq!(task.alphas, alphas);
    let mut missing = before.clone();
    missing.remove(&previous);
    assert!(
        direct_rolling_indices_at::<F, EF, P>(
            profile, pp, setup, statement, input, &missing, views, factor
        )
        .is_none()
    );
    let (bytes, indices) = sample(input);
    assert_eq!(
        transcript
            .get_index_challenges(b"rolling FRI unbiased domain index", domain, role.queries)
            .unwrap(),
        indices
    );
    frame(input, 3, b"rolling FRI unbiased domain index", &bytes);
}

fn exercise_bundle<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
    P::SingleProof: Clone + DeserializeOwned,
{
    exercise_bundle_scoped::<F, EF, P>(bundle, false);
}

fn exercise_bundle_scoped<F, EF, P>(bundle: ProfileParameters<P>, primary_only: bool)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
    P::SingleProof: Clone + DeserializeOwned,
{
    assert!(!primary_only || bundle.profile().specification().backend == Backend::Brakedown);
    let width = bundle.profile().specification().roles[0].width;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let pp = super::super::classical::parameters(&bundle);
    let setup = super::super::classical::preprocess::<F, EF, _, _>(
        &bundle,
        cfg,
        &vec![NTTRGSW::<F>::zero(32, Basis::new(8)); 21],
        &[NTTGadgetRLWE::<F>::zero(32, Basis::new(5))],
        &mut StdRng::seed_from_u64(901),
    )
    .unwrap();
    let public = setup.inner.verifier();
    let statement = PublicStatement {
        left_a: vec![F::zero(); 21],
        left_b: F::zero(),
        right_a: vec![F::zero(); 21],
        right_b: F::zero(),
        output_a: vec![F::zero(); 21],
        output_b: F::zero(),
    };
    let digits = public
        .config
        .decomposition::<F>()
        .unwrap()
        .num_digits::<F>()
        .unwrap();
    let co: Vec<_> = (0..2 * digits + 1)
        .map(|component| {
            let mut root = Digest512::default();
            root.0[..8].copy_from_slice(&(component as u64).to_le_bytes());
            Commitment { root }
        })
        .collect();
    let variables = <P as CanonicalPcs<F, Sha512>>::num_vars(pp.evaluations);
    let tables: Vec<_> = (0..2 * digits + 1)
        .map(|i| {
            let values = if i == 0 {
                (0..width << variables)
                    .map(|index| F::from(index + 3))
                    .collect()
            } else {
                vec![F::from(i + 1); width << variables]
            };
            PackedTable::new(variables, width, values).unwrap()
        })
        .collect();
    let mut rng = StdRng::seed_from_u64(902);
    let ev: Vec<_> = tables
        .iter()
        .map(|table| {
            <P as CanonicalPcs<F, Sha512>>::commit(pp.evaluations, table, &mut rng)
                .unwrap_or_else(|e| panic!("{e}"))
                .0
        })
        .collect();
    let inputs = co[..2].to_vec();
    let accumulators = co[..4].to_vec();
    let endpoint = vec![F::zero(); 64];
    let prefix = encoded(&(
        12u32,
        EF::D,
        &public,
        contexts::<F, Sha512, _>(&pp).unwrap(),
        &statement,
    ));
    let mut bytes = prefix.clone();
    bytes.extend(encoded(&(&co, &ev, &inputs, &accumulators, &endpoint)));
    let decoded = recover::<F, EF, _>(&pp, &public, &statement, &bytes).unwrap();
    assert_eq!(
        encoded(&decoded),
        encoded(&(&co, &ev, &inputs, &accumulators, &endpoint))
    );
    let mut actual = bundle.profile().parent_transcript::<F>().unwrap();
    bind_inner::<F, EF, Sha512, _, stages::ClassicalShared>(
        &mut actual,
        &pp,
        &public,
        &statement,
        &co,
        &ev,
        &inputs,
        &accumulators,
        &endpoint,
    )
    .unwrap();
    let mut expected = bundle.profile().parent_transcript::<F>().unwrap();
    assert_eq!(encoded(&Raw(&bytes)), bytes);
    expected.append_message(
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
        &Raw(&bytes),
    );
    let mut a = [0; 64];
    let mut b = [0; 64];
    actual.get_challenge_bytes(b"outer prefix replay", &mut a);
    expected.get_challenge_bytes(b"outer prefix replay", &mut b);
    assert_eq!(a, b);

    // Interpret the first primary task from the outer message, then compare
    // its two first coin phases against the production relation verifier.
    // An invalid later sumcheck suffix must not change this already-bound task.
    let interpreted = first_product::<F, EF, _>(&pp, &public, &statement, &bytes).unwrap();
    let product = interpreted.shape;
    let (contexts, roots): (Vec<_>, Vec<_>) = interpreted.sources.into_iter().unzip();
    let mut boolean_values = Vec::new();
    for i in 0..2 * digits {
        boolean_values.push(vec![F::from(i + 1); width]);
        boolean_values.push(vec![F::zero(); width]);
    }
    boolean_values.push(vec![F::from(2 * digits + 1); width]);
    assert!(
        product
            .evaluate(&boolean_values)
            .unwrap()
            .iter()
            .all(|&v| v != F::zero())
    );
    let keys = bk::canonical::public_oracles::<F, Sha512, _>(pp.key, &public.br).unwrap();
    let mut factors = Vec::new();
    for i in 0..2 * digits {
        factors.push(CanonicalVerifierOracle {
            parameters: pp.evaluations,
            commitment: &ev[i],
        });
        factors.push(CanonicalVerifierOracle {
            parameters: keys[i].parameters,
            commitment: keys[i].commitment,
        });
    }
    factors.push(CanonicalVerifierOracle {
        parameters: pp.evaluations,
        commitment: &ev[2 * digits],
    });
    let first = vec![vec![F::zero(); product.validate().unwrap() + 1]; width];
    // Evaluation roots are real tables (the first is nonconstant); original
    // key tables are zero. The product residual is the nonzero final constant,
    // independent of the unbound later proof suffix.
    let table = tables.last().unwrap();
    let (dummy_root, dummy_state) =
        <P as CanonicalPcs<F, Sha512>>::commit(pp.evaluations, table, &mut rng)
            .unwrap_or_else(|e| panic!("{e}"));
    let query = vec![
        algebra::matrix_weighted::MatrixPair {
            zero: algebra::matrix_weighted::Matrix::identity(width).unwrap(),
            one: algebra::matrix_weighted::Matrix::identity(width).unwrap(),
        };
        variables
    ];
    let value = table.evaluate(&query).unwrap();
    let dummy = <P as CanonicalPcs<F, Sha512>>::open(
        pp.evaluations,
        &mut bundle.profile().parent_transcript::<F>().unwrap(),
        &dummy_root,
        &dummy_state,
        &query,
        &value,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let proof = relation::CanonicalRelationProof {
        zero: sumcheck::packed_zero::ZeroProof {
            first: first.clone(),
            rest: sumcheck::packed::PackedProof { rounds: vec![] },
        },
        values: vec![vec![F::zero(); width]; product.num_factors],
        openings: vec![dummy; product.num_factors],
    };
    let mut actual_task = bundle.profile().parent_transcript::<F>().unwrap();
    bind_inner::<F, EF, Sha512, _, stages::ClassicalShared>(
        &mut actual_task,
        &pp,
        &public,
        &statement,
        &co,
        &ev,
        &inputs,
        &accumulators,
        &endpoint,
    )
    .unwrap();
    let error =
        relation::verify_canonical::<F, Sha512, _>(&mut actual_task, &product, &factors, &proof)
            .unwrap_err();
    assert!(error.0.contains("incorrect packed proof length"), "{error}");
    let mut expected_task = bundle.profile().parent_transcript::<F>().unwrap();
    expected_task.append_message(
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
        &Raw(&bytes),
    );
    expected_task.append_message(
        <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
        &(&product, &contexts, &roots),
    );
    expected_task.append_message(b"packed zerocheck v1", &product);
    let equality: Vec<F> = expected_task.get_vec_challenge(
        b"packed zero atomic equality v4",
        width * (product.num_vars - 1),
    );
    let first_state = first_product::<F, EF, P>(&pp, &public, &statement, &bytes).unwrap();
    let mut query_input = initial_header::<F>(bundle.profile()).unwrap();
    frame(
        &mut query_input,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
        &bytes,
    );
    query_input.extend(initial_tail::<F, P>(&first_state).unwrap());
    let recovered =
        initial_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &query_input)
            .unwrap();
    assert_eq!(encoded(&recovered.sources), encoded(&first_state.sources));
    assert_eq!(encoded(&recovered.shape), encoded(&product));
    let (raw_values, raw) = raw_prime_phase::<F>(&query_input, equality.len());
    assert_eq!(
        raw_values,
        equality
            .iter()
            .map(|v| v.value().to_string().parse::<u128>().unwrap())
            .collect::<Vec<_>>()
    );
    let mut wrong = query_input.clone();
    wrong.push(0);
    assert!(
        initial_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong).is_none()
    );
    wrong = query_input.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        initial_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong).is_none()
    );
    wrong = query_input.clone();
    let at = wrong
        .windows(64)
        .position(|w| w == roots[0].root.0)
        .unwrap();
    wrong[at] ^= 1;
    assert!(
        initial_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong).is_none()
    );
    let (eq_receipt, producer) = receipt(&raw);
    let fingerprint: [u8; 64] = eq_receipt[16..].try_into().unwrap();
    let mut mixing_input = query_input.clone();
    frame(
        &mut mixing_input,
        5,
        b"packed zero atomic equality v4",
        &eq_receipt,
    );
    frame(
        &mut mixing_input,
        1,
        b"packed zero first message",
        &encoded(&first),
    );
    mixing_input.extend(mixing_tail::<F>(width).unwrap());
    let mut known = Producers::new();
    let frozen = known.clone();
    known.insert(fingerprint, producer.clone());
    // A producer discovered later cannot repair the first-query history snapshot.
    assert!(
        mixing_query::<F, EF, P>(
            bundle.profile(),
            &pp,
            &public,
            &statement,
            &mixing_input,
            &frozen
        )
        .is_none()
    );
    let mixed = mixing_query::<F, EF, P>(
        bundle.profile(),
        &pp,
        &public,
        &statement,
        &mixing_input,
        &known,
    )
    .unwrap();
    assert_eq!(encoded(&mixed.equality), encoded(&equality));
    assert_eq!(encoded(&mixed.first), encoded(&first));
    assert_eq!(encoded(&mixed.task.sources), encoded(&first_state.sources));
    assert_eq!(encoded(&mixed.task.shape), encoded(&product));
    let mut wrong_producers = known.clone();
    wrong_producers.get_mut(&fingerprint).unwrap().push(0);
    assert!(
        mixing_query::<F, EF, P>(
            bundle.profile(),
            &pp,
            &public,
            &statement,
            &mixing_input,
            &wrong_producers
        )
        .is_none()
    );
    let mut wrong_mixing = mixing_input.clone();
    *wrong_mixing.last_mut().unwrap() ^= 1;
    assert!(
        mixing_query::<F, EF, P>(
            bundle.profile(),
            &pp,
            &public,
            &statement,
            &wrong_mixing,
            &known
        )
        .is_none()
    );
    let mut nonzero = first.clone();
    nonzero[0][0] = F::one();
    let mut wrong_mixing = query_input.clone();
    frame(
        &mut wrong_mixing,
        5,
        b"packed zero atomic equality v4",
        &eq_receipt,
    );
    frame(
        &mut wrong_mixing,
        1,
        b"packed zero first message",
        &encoded(&nonzero),
    );
    wrong_mixing.extend(mixing_tail::<F>(width).unwrap());
    assert!(
        mixing_query::<F, EF, P>(
            bundle.profile(),
            &pp,
            &public,
            &statement,
            &wrong_mixing,
            &known
        )
        .is_none()
    );
    expected_task.append_message(b"packed zero first message", &first);
    let mixing: Vec<F> = expected_task
        .get_vec_challenge(b"packed zero atomic first coins v4", width * width + width);
    assert_eq!(
        raw_prime_phase::<F>(&mixing_input, mixing.len()).0,
        mixing
            .iter()
            .map(|v| v.value().to_string().parse::<u128>().unwrap())
            .collect::<Vec<_>>()
    );
    actual_task.get_challenge_bytes(b"initial task replay", &mut a);
    expected_task.get_challenge_bytes(b"initial task replay", &mut b);
    assert_eq!(a, b);
    let mut round_transcript = bundle.profile().parent_transcript::<F>().unwrap();
    round_transcript.append_message(
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
        &Raw(&bytes),
    );
    round_transcript.append_message(
        <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
        &(&product, &contexts, &roots),
    );
    round_transcript.append_message(b"packed zerocheck v1", &product);
    let _: Vec<F> =
        round_transcript.get_vec_challenge(b"packed zero atomic equality v4", equality.len());
    round_transcript.append_message(b"packed zero first message", &first);
    let _: Vec<F> =
        round_transcript.get_vec_challenge(b"packed zero atomic first coins v4", mixing.len());
    let (_, mixing_raw) = raw_prime_phase::<F>(&mixing_input, mixing.len());
    let (mix_receipt, mix_producer) = receipt(&mixing_raw);
    let mut round_input = mixing_input;
    frame(
        &mut round_input,
        5,
        b"packed zero atomic first coins v4",
        &mix_receipt,
    );
    known.insert(mix_receipt[16..].try_into().unwrap(), mix_producer);
    let reduced = reduced(&product);
    let claim = vec![F::zero(); width];
    frame(
        &mut round_input,
        1,
        b"packed sumcheck v1",
        &encoded(&reduced),
    );
    frame(&mut round_input, 1, b"packed claimed sum", &encoded(&claim));
    // Build nonzero, algebraically consistent messages from the independent
    // raw-XOF stream so later recurrence checks exercise nonzero claims.
    let mut fixture_input = round_input.clone();
    let mut fixture_expected = claim.clone();
    let mut rounds = Vec::new();
    for round in 0..reduced.num_vars {
        let mut evaluations = vec![F::zero(); reduced.validate().unwrap() + 1];
        for lane in 0..width {
            evaluations[2 * lane] = fixture_expected[lane] + F::one();
            evaluations[2 * lane + 1] = -F::one();
        }
        evaluations[2 * width] = F::from(round + 2);
        frame(
            &mut fixture_input,
            1,
            b"packed round",
            &encoded(&evaluations),
        );
        fixture_input.extend(round_tail::<F>(width).unwrap());
        let (coins, raw) = raw_prime_phase::<F>(&fixture_input, width);
        fixture_expected = coins
            .iter()
            .map(|&r| {
                let weights = sumcheck::packed::lagrange_weights(
                    evaluations.len(),
                    F::from(usize::try_from(r).unwrap()),
                );
                evaluations
                    .iter()
                    .zip(weights)
                    .fold(F::zero(), |v, (&e, w)| v + e * w)
            })
            .collect();
        frame(
            &mut fixture_input,
            5,
            b"packed independent challenges",
            &receipt(&raw).0,
        );
        rounds.push(evaluations);
    }
    let rest = sumcheck::packed::PackedProof {
        rounds: rounds.clone(),
    };
    let mut assignments = std::collections::HashMap::new();
    for i in 0..2 * digits {
        assignments.insert(encoded(&first_state.sources[2 * i]), tables[i].clone());
        assignments.insert(
            encoded(&first_state.sources[2 * i + 1]),
            PackedTable::new(variables, width, vec![F::zero(); width << variables]).unwrap(),
        );
    }
    assignments.insert(
        encoded(first_state.sources.last().unwrap()),
        tables.last().unwrap().clone(),
    );
    let mut last_equality = None;
    let mut index = 0;
    let checked = sumcheck::packed::verify_with_rounds(
        &mut round_transcript,
        &reduced,
        &claim,
        &rest,
        |_trans, round, pair| {
            assert_eq!(round, index);
            // Changing the current response changes the query input, but cannot
            // change its already-fixed source residual before the new coins.
            let mut alternative = rounds[round].clone();
            alternative[2 * width] += F::one();
            let mut alternative_input = round_input.clone();
            frame(
                &mut alternative_input,
                1,
                b"packed round",
                &encoded(&alternative),
            );
            alternative_input.extend(round_tail::<F>(width).unwrap());
            let alternative_task = round_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &alternative_input,
                &known,
                round,
            )
            .unwrap();
            let alternative_residual = alternative_task
                .assigned_residual(|source| assignments.get(&encoded(source)).cloned())
                .unwrap();
            let mut inconsistent = rounds[round].clone();
            inconsistent[0] += F::one();
            let mut wrong = round_input.clone();
            frame(&mut wrong, 1, b"packed round", &encoded(&inconsistent));
            wrong.extend(round_tail::<F>(width).unwrap());
            assert!(
                round_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &known,
                    round
                )
                .is_none()
            );
            frame(
                &mut round_input,
                1,
                b"packed round",
                &encoded(&rounds[round]),
            );
            round_input.extend(round_tail::<F>(width).unwrap());
            let interpreted = round_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &round_input,
                &known,
                round,
            )
            .unwrap();
            assert_eq!(encoded(&interpreted.evaluations), encoded(&rounds[round]));
            assert_eq!(interpreted.query.len(), round + 1);
            assert!(interpreted.assigned_residual(|_| None).is_none());
            let factors = interpreted
                .assigned_factors(|source| assignments.get(&encoded(source)).cloned())
                .unwrap();
            let residual = interpreted
                .assigned_residual(|source| assignments.get(&encoded(source)).cloned())
                .unwrap();
            assert_eq!(residual.len(), width);
            assert_eq!(encoded(&residual), encoded(&alternative_residual));
            assert!(
                interpreted
                    .assigned_residual(|_| PackedTable::new(0, width, vec![F::zero(); width]).ok())
                    .is_none()
            );
            assert!(
                factors
                    .iter()
                    .all(|table| table.num_vars() == reduced.num_vars - round)
            );
            // The constant source fixture is false despite consistent messages;
            // returning a residual must never imply PCS authentication.
            assert!(residual.iter().any(|&v| v != F::zero()));
            if round + 1 == reduced.num_vars {
                last_equality = Some(
                    factors
                        .last()
                        .unwrap()
                        .fold(pair)
                        .unwrap()
                        .values()
                        .to_vec(),
                );
            }
            let mut wrong = round_input.clone();
            wrong.push(0);
            assert!(
                round_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &known,
                    round
                )
                .is_none()
            );
            let (values, consumed) = raw_prime_phase::<F>(&round_input, width);
            // Compare transcript continuation after independently replaying this phase.
            let (phase_receipt, producer) = receipt(&consumed);
            frame(
                &mut round_input,
                5,
                b"packed independent challenges",
                &phase_receipt,
            );
            known.insert(phase_receipt[16..].try_into().unwrap(), producer);
            let coins: Vec<F> = values
                .iter()
                .map(|&v| F::from(usize::try_from(v).unwrap()))
                .collect();
            let expected_pair = sumcheck::packed::challenge_pair(&coins).unwrap();
            // The callback's authenticated matrix is the production challenge image.
            index += 1;
            assert_eq!(encoded(&expected_pair), encoded(pair));
            Ok(())
        },
    );
    assert!(checked.is_ok());
    assert_eq!(index, reduced.num_vars);
    // Check the whole ZeroCheck dispatcher too, including its private reduced
    // shape and first-message reduction, without treating PCS claims as proven.
    let mut whole = bundle.profile().parent_transcript::<F>().unwrap();
    whole.append_message(
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
        &Raw(&bytes),
    );
    whole.append_message(
        <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
        &(&product, &contexts, &roots),
    );
    let full_zero = sumcheck::packed_zero::ZeroProof {
        first: first.clone(),
        rest,
    };
    let subclaim = sumcheck::packed_zero::verify(&mut whole, &product, &full_zero).unwrap();
    assert_eq!(subclaim.query.len(), product.num_vars);
    assert_eq!(
        encoded(&subclaim.equality),
        encoded(&last_equality.unwrap())
    );
    assert_eq!(
        encoded(&subclaim.expected),
        encoded(&checked.unwrap().expected)
    );
    whole.get_challenge_bytes(b"complete primary zerocheck replay", &mut a);
    round_transcript.get_challenge_bytes(b"complete primary zerocheck replay", &mut b);
    assert_eq!(a, b);
    let mut terminal_values = vec![vec![F::zero(); width]; product.num_factors];
    for lane in 0..width {
        assert!(subclaim.equality[lane] != F::zero());
        terminal_values[product.num_factors - 1][lane] =
            (-subclaim.expected[lane] / subclaim.equality[lane]).canonicalized();
    }
    subclaim.check(&product, &terminal_values).unwrap();
    let mut opening_input = round_input.clone();
    frame(
        &mut opening_input,
        1,
        b"packed relation terminal values",
        &encoded(&terminal_values),
    );
    let opening = first_opening_task::<F, EF, P>(
        bundle.profile(),
        &pp,
        &public,
        &statement,
        &opening_input,
        &known,
    )
    .unwrap();
    assert_eq!(encoded(&opening.sources), encoded(&first_state.sources));
    assert_eq!(encoded(&opening.query), encoded(&subclaim.query));
    assert_eq!(encoded(&opening.values), encoded(&terminal_values));
    let assigned_first = assignments
        .get(&encoded(&opening.sources[0]))
        .unwrap()
        .evaluate(&opening.query)
        .unwrap();
    assert!(
        assigned_first
            .iter()
            .zip(&opening.values[0])
            .any(|(&actual, &claim)| actual != claim)
    );
    let mut malformed = terminal_values.clone();
    malformed.last_mut().unwrap()[0] += F::one();
    let mut wrong = round_input.clone();
    frame(
        &mut wrong,
        1,
        b"packed relation terminal values",
        &encoded(&malformed),
    );
    assert!(
        first_opening_task::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong, &known)
            .is_none()
    );
    let mut wrong = round_input.clone();
    frame(
        &mut wrong,
        1,
        b"packed relation terminal values",
        &encoded(&usize::MAX),
    );
    assert!(
        first_opening_task::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong, &known)
            .is_none()
    );
    let opening_proof = relation::CanonicalRelationProof {
        zero: full_zero,
        values: terminal_values,
        openings: proof.openings.clone(),
    };
    let prepare = || {
        let mut t = bundle.profile().parent_transcript::<F>().unwrap();
        t.append_message(
            <stages::ClassicalShared as stages::Mode>::DOMAIN,
            &Raw(&bytes),
        );
        t
    };
    let mut actual_opening = prepare();
    let actual_error = relation::verify_canonical::<F, Sha512, P>(
        &mut actual_opening,
        &product,
        &factors,
        &opening_proof,
    )
    .unwrap_err();
    let mut expected_opening = prepare();
    expected_opening.append_message(
        <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
        &(&product, &contexts, &roots),
    );
    sumcheck::packed_zero::verify(&mut expected_opening, &product, &opening_proof.zero).unwrap();
    expected_opening.append_message(b"packed relation terminal values", &opening.values);
    let expected_error = pp
        .evaluations
        .verify(
            &mut expected_opening,
            &opening.sources[0].1,
            &opening.query,
            &opening.values[0],
            &opening_proof.openings[0],
        )
        .unwrap_err();
    assert_eq!(actual_error.0, expected_error.to_string());
    actual_opening.get_challenge_bytes(b"first opening task replay", &mut a);
    expected_opening.get_challenge_bytes(b"first opening task replay", &mut b);
    assert_eq!(a, b);
    if bundle.profile().specification().backend == Backend::Brakedown {
        if bundle.profile().version() == 5 && !primary_only {
            let mut all = prepare();
            all.append_message(
                <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                &(&product, &contexts, &roots),
            );
            sumcheck::packed_zero::verify(&mut all, &product, &opening_proof.zero).unwrap();
            all.append_message(b"packed relation terminal values", &opening.values);
            exercise_brakedown_factors::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &opening,
                &mut opening_input.clone(),
                &mut all,
                &known,
            );
        }
        let (tail, count) = brakedown_first_tail::<F>(bundle.profile(), &opening).unwrap();
        let mut input = opening_input.clone();
        input.extend(&tail);
        let recovered = brakedown_first_query::<F, EF, P>(
            bundle.profile(),
            &pp,
            &public,
            &statement,
            &input,
            &known,
        )
        .unwrap();
        assert_eq!(recovered.1, count);
        assert_eq!(encoded(&recovered.0.query), encoded(&opening.query));
        let mut wrong = input.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(
            brakedown_first_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &wrong,
                &known
            )
            .is_none()
        );
        let at = tail
            .windows(64)
            .position(|window| window == opening.sources[0].1.root.0)
            .unwrap();
        let mut wrong = input.clone();
        wrong[opening_input.len() + at] ^= 1;
        assert!(
            brakedown_first_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &wrong,
                &known
            )
            .is_none()
        );
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            brakedown_first_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &wrong,
                &known
            )
            .is_none()
        );
        #[cfg(feature = "transcript-audit")]
        let observed_streams = std::sync::Arc::new(std::sync::Mutex::new(
            verifier_event_audit::RecordedStreams::default(),
        ));
        #[cfg(feature = "transcript-audit")]
        let _reader_observation = {
            let sink = std::sync::Arc::clone(&observed_streams);
            let inputs = std::sync::Arc::clone(&observed_streams);
            helper::classical_transcript::audit::observe_with_output_chunks(
                move |input| inputs.lock().unwrap().record_input(input).unwrap(),
                |_| {}, move |input, offset, bytes| {
                    sink.lock().unwrap().record(input, offset, bytes).unwrap();
                },
            ).unwrap()
        };
        let mut replay = prepare();
        replay.append_message(
            <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
            &(&product, &contexts, &roots),
        );
        sumcheck::packed_zero::verify(&mut replay, &product, &opening_proof.zero).unwrap();
        replay.append_message(b"packed relation terminal values", &opening.values);
        replay.append_message(b"mw brakedown row-code v2", &opening.sources[0].0);
        replay.append_message(
            b"mw commitment and query",
            &(&opening.sources[0].1, &opening.query, &opening.values[0]),
        );
        let random: Vec<F> = replay.get_vec_challenge(b"mw random linear test", count);
        assert_eq!(
            raw_prime_phase::<F>(&input, count).0,
            random
                .iter()
                .map(|v| v.value().to_string().parse::<u128>().unwrap())
                .collect::<Vec<_>>()
        );
        let bytes = encoded(&opening_proof.openings[0]);
        let (packet, used): (pcs::matrix_weighted::Opening<F, Digest512>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        replay.append_message(b"mw linear responses", &(&packet.test, &packet.evaluation));
        let role = &bundle.profile().specification().roles[0];
        let cols = 1usize << (role.num_vars - role.left_vars.unwrap());
        let blocks = cols.div_ceil(role.block_width.unwrap()).next_power_of_two();
        let length = (blocks * bundle.profile().specification().blowup).max(32);
        if replay.uses_atomic_brakedown_columns() {
            let (_, row_raw) = raw_prime_phase::<F>(&input, count);
            let (row_receipt, row_producer) = receipt(&row_raw);
            let mut column_known = known.clone();
            column_known.insert(row_receipt[16..].try_into().unwrap(), row_producer);
            let mut column_input = input.clone();
            frame(&mut column_input, 5, b"mw random linear test", &row_receipt);
            frame(
                &mut column_input,
                1,
                b"mw linear responses",
                &encoded(&(&packet.test, &packet.evaluation)),
            );
            let (tail, domain, _) = brakedown_column_tail(bundle.profile()).unwrap();
            column_input.extend(tail);
            let columns = brakedown_column_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &column_input,
                &column_known,
            )
            .unwrap();
            assert_eq!(columns.domain, length);
            assert_eq!(domain, length);
            assert_eq!(columns.random, random);
            assert_eq!(encoded(&columns.test), encoded(&packet.test));
            assert_eq!(encoded(&columns.evaluation), encoded(&packet.evaluation));
            assert_eq!(encoded(&columns.opening.sources), encoded(&opening.sources));
            assert!(
                brakedown_column_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &column_input,
                    &known
                )
                .is_none()
            );
            let mut wrong = column_input.clone();
            *wrong.last_mut().unwrap() ^= 1;
            assert!(
                brakedown_column_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &column_known
                )
                .is_none()
            );
            let mut wrong = column_input.clone();
            wrong.push(0);
            assert!(
                brakedown_column_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &column_known
                )
                .is_none()
            );
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut state = sha3::Shake256::default();
            Update::update(&mut state, &column_input);
            let mut bytes = vec![0; 8 * role.queries];
            state.finalize_xof().read(&mut bytes);
            let independently_sampled: Vec<_> = bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (u64::from_le_bytes(chunk.try_into().unwrap()) & (length as u64 - 1)) as usize
                })
                .collect();
            let sampled = replay
                .get_index_challenges(b"mw atomic column block v5", length, role.queries)
                .unwrap();
            assert_eq!(sampled.len(), role.queries);
            assert_eq!(sampled, independently_sampled);
            #[cfg(feature = "transcript-audit")]
            let observed_snapshot = observed_streams.lock().unwrap().clone();
            #[cfg(feature = "transcript-audit")]
            verifier_event_audit::exercise_primary_atomic_column_binding::<F, EF, P>(
                bundle.profile(), &pp, &public, &statement, &input, &column_input,
                &column_known, &tables[0], &random, &bytes, &observed_snapshot, &sampled, &packet,
                || {
                    let mut trans = prepare();
                    trans.append_message(
                        <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                        &(&product, &contexts, &roots),
                    );
                    sumcheck::packed_zero::verify(&mut trans, &product, &opening_proof.zero).unwrap();
                    trans.append_message(b"packed relation terminal values", &opening.values);
                    trans
                },
            );
        } else {
            let limit = u64::MAX - u64::MAX % (length as u64);
            for _ in 0..role.queries {
                loop {
                    let mut bytes = [0; 8];
                    replay.get_challenge_bytes(b"mw unbiased column", &mut bytes);
                    if u64::from_le_bytes(bytes) < limit {
                        break;
                    }
                }
            }
            #[cfg(feature = "transcript-audit")]
            let observed_snapshot = observed_streams.lock().unwrap().clone();
            #[cfg(feature = "transcript-audit")]
            verifier_event_audit::exercise_primary_column_binding::<F, EF, P>(
                bundle.profile(), &pp, &public, &statement, &input, &known,
                &opening, &random, &packet.test, &packet.evaluation, &tables[0], &observed_snapshot,
            );
        }
        replay.get_challenge_bytes(b"first opening task replay", &mut b);
        assert_eq!(a, b);
        if primary_only { return; }
    } else {
        let (tail, label, context) =
            pcs_seed_tail::<F, P>(bundle.profile(), pp.evaluations, &opening).unwrap();
        let mut input = opening_input.clone();
        input.extend(&tail);
        let recovered =
            pcs_seed_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &input, &known)
                .unwrap();
        assert_eq!(encoded(&recovered.sources), encoded(&opening.sources));
        assert_eq!(encoded(&recovered.query), encoded(&opening.query));
        let mut wrong = input.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(
            pcs_seed_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong, &known)
                .is_none()
        );
        let at = tail
            .windows(64)
            .position(|window| window == opening.sources[0].1.root.0)
            .unwrap();
        let mut wrong = input.clone();
        wrong[opening_input.len() + at] ^= 1;
        assert!(
            pcs_seed_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong, &known)
                .is_none()
        );
        let mut wrong = input.clone();
        wrong.push(0);
        assert!(
            pcs_seed_query::<F, EF, P>(bundle.profile(), &pp, &public, &statement, &wrong, &known)
                .is_none()
        );
        let mut replay = prepare();
        replay.append_message(
            <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
            &(&product, &contexts, &roots),
        );
        sumcheck::packed_zero::verify(&mut replay, &product, &opening_proof.zero).unwrap();
        replay.append_message(b"packed relation terminal values", &opening.values);
        // Replay the exact binding body decoded from the independently built tail.
        let mut binding_tail = tail.as_slice();
        let binding = match bundle.profile().specification().backend {
            Backend::Polyfrim | Backend::PolyfrimDictionary => {
                b"unmasked packed matrix ordered claims v1".as_slice()
            }
            Backend::FragmentedPipfri => b"fragmented ordered claims v1",
            Backend::FragmentedPipfriVirtual => b"fragmented virtual ordered claims v2",
            _ => unreachable!(),
        };
        replay.append_message(
            binding,
            &Raw(message(&mut binding_tail, 1, binding).unwrap()),
        );
        let mut child = replay
            .fork_classical_extension::<F, EF>(label, context)
            .unwrap();
        replay.get_challenge_bytes(b"first opening task replay", &mut b);
        assert_eq!(a, b);
        let seed = shake64(&input);
        // Audit every ordered factor boundary, including evaluation/key role
        // alternation. This deliberately exercises transcript links without
        // asserting that these fabricated earlier PCS bodies were accepted.
        let mut chain_parent = prepare();
        chain_parent.append_message(
            <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
            &(&product, &contexts, &roots),
        );
        sumcheck::packed_zero::verify(&mut chain_parent, &product, &opening_proof.zero).unwrap();
        chain_parent.append_message(b"packed relation terminal values", &opening.values);
        let mut chain_input = opening_input.clone();
        for factor in 0..opening.sources.len() {
            let parameters = if factor % 2 == 1 {
                pp.key
            } else {
                pp.evaluations
            };
            let (factor_tail, child_label, child_context) =
                factor_seed_tail(bundle.profile(), parameters, &opening, factor).unwrap();
            let binding_start = chain_input.len();
            chain_input.extend(&factor_tail);
            let recovered = factor_seed_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &chain_input,
                &known,
                factor,
            )
            .unwrap();
            assert_eq!(
                encoded(&recovered.sources[factor]),
                encoded(&opening.sources[factor])
            );
            assert_eq!(encoded(&recovered.query), encoded(&opening.query));
            assert_eq!(
                encoded(&recovered.values[factor]),
                encoded(&opening.values[factor])
            );
            assert!(
                factor_seed_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &chain_input,
                    &known,
                    opening.sources.len()
                )
                .is_none()
            );
            let mut wrong = chain_input.clone();
            wrong.push(0);
            assert!(
                factor_seed_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &known,
                    factor
                )
                .is_none()
            );
            let root_at = factor_tail
                .windows(64)
                .position(|window| window == opening.sources[factor].1.root.0)
                .unwrap();
            let mut wrong = chain_input.clone();
            wrong[binding_start + root_at] ^= 1;
            assert!(
                factor_seed_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &known,
                    factor
                )
                .is_none()
            );
            if factor > 0 {
                let mut opaque = chain_input.clone();
                opaque[binding_start - 1] ^= 1;
                let same_task = factor_seed_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &opaque,
                    &known,
                    factor,
                )
                .unwrap();
                assert_eq!(
                    encoded(&same_task.sources[factor]),
                    encoded(&opening.sources[factor])
                );
                assert_eq!(
                    encoded(&same_task.values[factor]),
                    encoded(&opening.values[factor])
                );
                // The previous finish's body has a trusted length of 64.
                let mut short = chain_input[..binding_start - 1].to_vec();
                short.extend_from_slice(&chain_input[binding_start..]);
                assert!(
                    factor_seed_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &short,
                        &known,
                        factor
                    )
                    .is_none()
                );
            }
            let mut factor_binding = factor_tail.as_slice();
            chain_parent.append_message(
                binding,
                &Raw(message(&mut factor_binding, 1, binding).unwrap()),
            );
            let mut linked = chain_parent
                .fork_classical_extension::<F, EF>(child_label, child_context)
                .unwrap();
            let factor_seed = shake64(&chain_input);
            let mut child_input =
                raw_child::<F, EF>(bundle.profile(), child_label, child_context, &factor_seed);

            let mut child_before = known.clone();
            child_before.insert(factor_seed, chain_input.clone());
            let (empty_receipt, empty_producer) = receipt(&[]);
            child_before.insert(empty_receipt[16..].try_into().unwrap(), empty_producer);
            let mut views = FirstViews::new();
            views.insert(chain_input.clone(), known.clone());
            let (inherited, remaining) = factor_child_prefix::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &child_input,
                &child_before,
                &views,
                factor,
            )
            .unwrap();
            assert_eq!(
                encoded(&inherited.sources[factor]),
                encoded(&opening.sources[factor])
            );
            assert!(remaining.is_empty());
            let mut missing = child_before.clone();
            missing.remove(&factor_seed);
            assert!(
                factor_child_prefix::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &child_input,
                    &missing,
                    &views,
                    factor
                )
                .is_none()
            );
            let mut late = views.clone();
            late.get_mut(&chain_input).unwrap().remove(&fingerprint);
            assert!(
                factor_child_prefix::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &child_input,
                    &child_before,
                    &late,
                    factor
                )
                .is_none()
            );
            if matches!(
                bundle.profile().specification().backend,
                Backend::Polyfrim | Backend::PolyfrimDictionary
            ) {
                exercise_direct_factor::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &opening,
                    factor,
                    &mut child_input,
                    &mut linked,
                    &child_before,
                    &views,
                );
            }
            if matches!(
                bundle.profile().specification().backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            ) {
                exercise_fragment_factor::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &opening,
                    factor,
                    &mut child_input,
                    &mut linked,
                    &child_before,
                    &views,
                );
            }
            frame(
                &mut child_input,
                2,
                b"ordered factor child replay",
                &64u64.to_le_bytes(),
            );
            let mut output = [0; 64];
            linked.get_challenge_bytes(b"ordered factor child replay", &mut output);
            assert_eq!(shake64(&child_input), output);
            frame(&mut child_input, 3, b"ordered factor child replay", &output);
            frame(
                &mut child_input,
                2,
                b"classical child finish",
                &64u64.to_le_bytes(),
            );
            let finish = shake64(&child_input);
            chain_parent.finish_classical_child(&mut linked).unwrap();
            frame(&mut chain_input, 3, b"classical child seed", &factor_seed);
            frame(&mut chain_input, 7, child_label, &finish);
        }
        exercise_first_ntt::<F, EF, P>(
            bundle.profile(),
            &pp,
            &public,
            &statement,
            &mut chain_input,
            &mut chain_parent,
            &known,
        );
        frame(
            &mut chain_input,
            2,
            b"all ordered factor links replay",
            &64u64.to_le_bytes(),
        );
        let mut output = [0; 64];
        chain_parent.get_challenge_bytes(b"all ordered factor links replay", &mut output);
        assert_eq!(shake64(&chain_input), output);
        if matches!(
            bundle.profile().specification().backend,
            Backend::Polyfrim | Backend::PolyfrimDictionary
        ) {
            let role = &bundle.profile().specification().roles[0];
            let rounds = role.num_vars;
            assert!(rounds > 0);
            let domain = (1usize << rounds) * bundle.profile().specification().blowup;
            let bits = domain.ilog2();
            let mut root = F::get_ntt_root(bits.max(5)).unwrap();
            for _ in bits..bits.max(5) {
                root *= root;
            }
            let core = pcs::packed_polyfrim::authenticated::Parameters::new(
                1usize << rounds,
                role.width,
                bundle.profile().specification().blowup,
                role.queries,
                EF::from_base(root),
            )
            .unwrap();
            let (query, values) = pp
                .evaluations
                .normalize_claim(opening.query.clone(), opening.values[0].clone())
                .ok()
                .unwrap();
            let queries = vec![
                query
                    .iter()
                    .map(|pair| algebra::matrix_weighted::MatrixPair {
                        zero: algebra::matrix_weighted::Matrix::new(
                            role.width,
                            pair.zero
                                .values()
                                .iter()
                                .copied()
                                .map(EF::from_base)
                                .collect(),
                        )
                        .unwrap(),
                        one: algebra::matrix_weighted::Matrix::new(
                            role.width,
                            pair.one
                                .values()
                                .iter()
                                .copied()
                                .map(EF::from_base)
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect::<Vec<_>>(),
            ];
            let claims = vec![values.into_iter().map(EF::from_base).collect::<Vec<_>>()];
            let source = opening.sources[0].1.root;
            // An adversarial ladder is permitted at this challenge boundary;
            // authentication and transition checks belong to the later verifier.
            let mut ladder_roots = vec![Digest512([19; 64]); rounds];
            ladder_roots[0] = source;
            let mut direct_input = raw_child::<F, EF>(bundle.profile(), label, context, &seed);
            let joint = encoded(&(
                &core,
                source,
                1usize,
                &queries,
                &claims,
                vec![ladder_roots.clone()],
            ));
            frame(
                &mut direct_input,
                1,
                b"packed PolyFRIM joint query proximity v1",
                &joint,
            );
            let after_joint = direct_input.len();
            child.append_message(b"packed PolyFRIM joint query proximity v1", &Raw(&joint));
            frame(
                &mut direct_input,
                1,
                b"packed PolyFRIM joint consistency member v1",
                &encoded(&0usize),
            );
            child.append_message(b"packed PolyFRIM joint consistency member v1", &0usize);
            let binding_body =
                encoded(&(&core, source, &ladder_roots[1..], &queries[0], &claims[0]));
            frame(
                &mut direct_input,
                1,
                b"packed PolyFRIM consistency v2",
                &binding_body,
            );
            child.append_message(b"packed PolyFRIM consistency v2", &Raw(&binding_body));
            frame(
                &mut direct_input,
                1,
                b"index domain",
                &(domain as u64).to_le_bytes(),
            );
            frame(
                &mut direct_input,
                2,
                b"packed PolyFRIM domain index v2",
                &((8 * role.queries) as u64).to_le_bytes(),
            );
            let mut before = known.clone();
            before.insert(seed, input.clone());
            let (empty, producer) = receipt(&[]);
            before.insert(empty[16..].try_into().unwrap(), producer);
            let mut views = FirstViews::new();
            views.insert(input.clone(), known.clone());
            let (task, recovered_roots, recovered_domain) = direct_first_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &direct_input,
                &before,
                &views,
            )
            .unwrap();
            assert_eq!(encoded(&task.sources), encoded(&opening.sources));
            assert_eq!(recovered_roots, ladder_roots);
            assert_eq!(recovered_domain, domain);
            for offset in [direct_input.len() - 1, direct_input.len() / 2] {
                let mut wrong = direct_input.clone();
                wrong[offset] ^= 1;
                assert!(
                    direct_first_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &wrong,
                        &before,
                        &views
                    )
                    .is_none()
                );
            }
            let mut wrong = direct_input.clone();
            wrong.push(0);
            assert!(
                direct_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &before,
                    &views
                )
                .is_none()
            );
            let mut wrong_source = ladder_roots.clone();
            wrong_source[0].0[0] ^= 1;
            let mut wrong_layer = ladder_roots.clone();
            assert!(rounds > 1);
            wrong_layer[1].0[0] ^= 1;
            let prefix = encoded(&(&core, source, 1usize, &queries, &claims));
            let mut huge_count = prefix;
            huge_count.extend(encoded(&1usize));
            huge_count.extend(encoded(&usize::MAX));
            for bad_joint in [
                encoded(&(&core, source, 1usize, &queries, &claims, vec![wrong_source])),
                encoded(&(&core, source, 1usize, &queries, &claims, vec![wrong_layer])),
                encoded(&(
                    &core,
                    source,
                    1usize,
                    &queries,
                    &claims,
                    vec![ladder_roots[..rounds - 1].to_vec()],
                )),
                huge_count,
            ] {
                let mut wrong = raw_child::<F, EF>(bundle.profile(), label, context, &seed);
                frame(
                    &mut wrong,
                    1,
                    b"packed PolyFRIM joint query proximity v1",
                    &bad_joint,
                );
                wrong.extend_from_slice(&direct_input[after_joint..]);
                assert!(
                    direct_first_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &wrong,
                        &before,
                        &views
                    )
                    .is_none()
                );
            }
            let mut missing = before.clone();
            missing.remove(&seed);
            assert!(
                direct_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &direct_input,
                    &missing,
                    &views
                )
                .is_none()
            );
            let mut late = views.clone();
            late.get_mut(&input).unwrap().remove(&fingerprint);
            assert!(
                direct_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &direct_input,
                    &before,
                    &late
                )
                .is_none()
            );
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut xof = sha3::Shake256::default();
            Update::update(&mut xof, &direct_input);
            let mut bytes = vec![0; 8 * role.queries];
            xof.finalize_xof().read(&mut bytes);
            let expected: Vec<_> = bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
                })
                .collect();
            assert_eq!(
                child
                    .get_index_challenges(b"packed PolyFRIM domain index v2", domain, role.queries)
                    .unwrap(),
                expected
            );
            frame(
                &mut direct_input,
                3,
                b"packed PolyFRIM domain index v2",
                &bytes,
            );
            let fresh_child = || {
                let mut parent = prepare();
                parent.append_message(
                    <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                    &(&product, &contexts, &roots),
                );
                sumcheck::packed_zero::verify(&mut parent, &product, &opening_proof.zero).unwrap();
                parent.append_message(b"packed relation terminal values", &opening.values);
                let mut binding_tail = tail.as_slice();
                parent.append_message(
                    binding,
                    &Raw(message(&mut binding_tail, 1, binding).unwrap()),
                );
                parent
                    .fork_classical_extension::<F, EF>(label, context)
                    .unwrap()
            };
            // Enter the actual verifier with a structurally valid packet and
            // invalid authentication. It must consume exactly this index phase
            // before rejecting, without entering projections or rolling FRI.
            let empty_pair = pcs::packed_polyfrim::authenticated::Pair::<EF, Digest512> {
                values: vec![],
                path: vec![],
            };
            let packet = pcs::packed_polyfrim::authenticated::proximity::batch::Proof {
                consistency: vec![pcs::packed_polyfrim::authenticated::Proof {
                    roots: ladder_roots[1..].to_vec(),
                    queries: vec![vec![empty_pair.clone(); rounds]; role.queries],
                }],
                proximity: pcs::rolling_fri::Proof {
                    derived: vec![],
                    terminal: EF::zero(),
                    queries: vec![],
                },
                packed: vec![vec![vec![empty_pair; rounds]]; role.queries],
            };
            let mut kernel = fresh_child();
            let error =
                pcs::packed_polyfrim::authenticated::proximity::batch::verify::<EF, Sha512>(
                    &mut kernel,
                    &core,
                    &source,
                    &queries,
                    &claims,
                    &packet,
                )
                .unwrap_err();
            assert_eq!(error.0, "pair authentication");
            let index_completed = direct_input.clone();
            frame(
                &mut direct_input,
                2,
                b"direct first consistency replay",
                &64u64.to_le_bytes(),
            );
            child.get_challenge_bytes(b"direct first consistency replay", &mut b);
            assert_eq!(shake64(&direct_input), b);
            kernel.get_challenge_bytes(b"direct first consistency replay", &mut a);
            assert_eq!(a, b);
            let mut projection_input = index_completed;
            let projection_body = encoded(&(&core, vec![ladder_roots.clone()]));
            frame(
                &mut projection_input,
                1,
                b"packed PolyFRIM joint projections v1",
                &projection_body,
            );
            projection_input.extend(direct_projection_tail::<F, EF>(bundle.profile()).unwrap());
            let projected = direct_projection_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &projection_input,
                &before,
                &views,
            )
            .unwrap();
            assert_eq!(projected.roots, ladder_roots);
            assert_eq!(encoded(&projected.opening.query), encoded(&opening.query));
            // An altered inline prior output cannot change this projection
            // task. Earlier consistency validity is a separate obligation.
            let mut wrong = projection_input.clone();
            let bytes_at = wrong
                .windows(bytes.len())
                .position(|window| window == bytes)
                .unwrap();
            wrong[bytes_at] ^= 1;
            let altered = direct_projection_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &wrong,
                &before,
                &views,
            )
            .unwrap();
            assert_eq!(altered.roots, projected.roots);
            assert_eq!(
                encoded(&altered.opening.query),
                encoded(&projected.opening.query)
            );
            let mut wrong = projection_input.clone();
            *wrong.last_mut().unwrap() ^= 1;
            assert!(
                direct_projection_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &before,
                    &views
                )
                .is_none()
            );
            let mut wrong = projection_input.clone();
            wrong.push(0);
            assert!(
                direct_projection_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &before,
                    &views
                )
                .is_none()
            );
            let (coefficients, consumed) =
                raw_prime_phase::<F>(&projection_input, rounds * role.width * EF::D);
            let weights: Vec<_> = coefficients
                .chunks_exact(EF::D)
                .map(|chunk| EF::from_base_fn(|i| F::from(usize::try_from(chunk[i]).unwrap())))
                .collect();
            let mut projection = fresh_child();
            projection.append_message(b"packed PolyFRIM joint query proximity v1", &Raw(&joint));
            projection.append_message(b"packed PolyFRIM joint consistency member v1", &0usize);
            projection.append_message(b"packed PolyFRIM consistency v2", &Raw(&binding_body));
            assert_eq!(
                projection
                    .get_index_challenges(b"packed PolyFRIM domain index v2", domain, role.queries)
                    .unwrap(),
                expected
            );
            projection.append_message(
                b"packed PolyFRIM joint projections v1",
                &Raw(&projection_body),
            );
            assert!(projection.uses_atomic_joint_projections());
            let sampled = projection.get_vec_challenge(
                b"packed PolyFRIM atomic joint lane weights v3",
                rounds * role.width,
            );
            assert_eq!(sampled, weights);
            frame(
                &mut projection_input,
                5,
                b"packed PolyFRIM atomic joint lane weights v3",
                &receipt(&consumed).0,
            );
            let completed_projection = projection_input.clone();
            frame(
                &mut projection_input,
                2,
                b"direct projection replay",
                &64u64.to_le_bytes(),
            );
            projection.get_challenge_bytes(b"direct projection replay", &mut b);
            assert_eq!(shake64(&projection_input), b);
            let mut rolling_replay = fresh_child();
            rolling_replay
                .append_message(b"packed PolyFRIM joint query proximity v1", &Raw(&joint));
            rolling_replay.append_message(b"packed PolyFRIM joint consistency member v1", &0usize);
            rolling_replay.append_message(b"packed PolyFRIM consistency v2", &Raw(&binding_body));
            assert_eq!(
                rolling_replay
                    .get_index_challenges(b"packed PolyFRIM domain index v2", domain, role.queries)
                    .unwrap(),
                expected
            );
            rolling_replay.append_message(
                b"packed PolyFRIM joint projections v1",
                &Raw(&projection_body),
            );
            assert_eq!(
                rolling_replay.get_vec_challenge(
                    b"packed PolyFRIM atomic joint lane weights v3",
                    rounds * role.width
                ),
                weights
            );
            let mut rolling_input = completed_projection;
            let (projection_receipt, projection_producer) = receipt(&consumed);
            let mut rolling_before = before.clone();
            let mut previous: [u8; 64] = projection_receipt[16..].try_into().unwrap();
            rolling_before.insert(previous, projection_producer);
            let originals: Vec<_> = weights
                .chunks_exact(role.width)
                .enumerate()
                .map(|(layer, row)| {
                    let rows = vec![row.to_vec()];
                    RollingRoot {
                        root: Digest512(
                            Sha512::digest(encoded(&(
                                b"packed PolyFRIM joint virtual layer v1".as_slice(),
                                &core,
                                layer,
                                vec![ladder_roots.clone()],
                                rows,
                            )))
                            .into(),
                        ),
                    }
                })
                .collect();
            let fri = direct_fri::<F, EF>(bundle.profile()).unwrap();
            let fri_context = Digest512(
                Sha512::digest(encoded(&(
                    b"HasteBoots rolling FRI parameters v1".as_slice(),
                    EF::MODULUS_VALUE.to_string(),
                    &fri,
                )))
                .into(),
            );
            frame(
                &mut rolling_input,
                1,
                b"HasteBoots rolling batch FRI virtual all v2",
                &encoded(&(fri_context, &originals)),
            );
            rolling_replay.append_message(
                b"HasteBoots rolling batch FRI virtual all v2",
                &(fri_context, &originals),
            );
            let mut alphas = Vec::new();
            let mut derived = Vec::new();
            let mut wrong_layer = None;
            for round in 0..rounds {
                rolling_input.extend(rolling_alpha_tail::<F, EF>());
                let task = direct_rolling_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &rolling_input,
                    &rolling_before,
                    &views,
                    round,
                )
                .unwrap();
                assert_eq!(task.weights, weights);
                assert_eq!(encoded(&task.originals), encoded(&originals));
                assert_eq!(encoded(&task.derived), encoded(&derived));
                assert_eq!(task.alphas, alphas);
                assert_eq!(
                    encoded(&task.direct.opening.sources),
                    encoded(&opening.sources)
                );
                let mut missing = rolling_before.clone();
                missing.remove(&previous);
                assert!(
                    direct_rolling_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &rolling_input,
                        &missing,
                        &views,
                        round
                    )
                    .is_none()
                );
                if let Some(offset) = wrong_layer {
                    let mut wrong = rolling_input.clone();
                    wrong[offset] ^= 1;
                    assert!(
                        direct_rolling_query::<F, EF, P>(
                            bundle.profile(),
                            &pp,
                            &public,
                            &statement,
                            &wrong,
                            &rolling_before,
                            &views,
                            round
                        )
                        .is_none()
                    );
                }
                let (coefficients, raw) = raw_prime_phase::<F>(&rolling_input, EF::D);
                let alpha =
                    EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
                assert_eq!(
                    rolling_replay.get_challenge(b"rolling FRI fold challenge"),
                    alpha
                );
                alphas.push(alpha);
                let (phase_receipt, producer) = receipt(&raw);
                previous = phase_receipt[16..].try_into().unwrap();
                rolling_before.insert(previous, producer);
                frame(
                    &mut rolling_input,
                    5,
                    b"rolling FRI fold challenge",
                    &phase_receipt,
                );
                if round + 1 < rounds {
                    let root = RollingRoot {
                        root: Digest512([u8::try_from(round + 41).unwrap(); 64]),
                    };
                    let start = rolling_input.len();
                    let label = b"rolling FRI derived root";
                    frame(&mut rolling_input, 1, label, &encoded(&(round + 1, &root)));
                    // One-byte kind, two u64 lengths and the label precede
                    // the canonical small layer index in this fixture.
                    wrong_layer = Some(start + 1 + 8 + label.len() + 8);
                    rolling_replay.append_message(label, &(round + 1, &root));
                    derived.push(root);
                }
            }
            let terminal = EF::from_base(F::from(7usize));
            frame(
                &mut rolling_input,
                1,
                b"rolling FRI terminal",
                &encoded(&terminal),
            );
            rolling_replay.append_message(b"rolling FRI terminal", &terminal);
            frame(
                &mut rolling_input,
                1,
                b"index domain",
                &(domain as u64).to_le_bytes(),
            );
            frame(
                &mut rolling_input,
                2,
                b"rolling FRI unbiased domain index",
                &((8 * role.queries) as u64).to_le_bytes(),
            );
            let (task, recovered_terminal) = direct_rolling_indices::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &rolling_input,
                &rolling_before,
                &views,
            )
            .unwrap();
            assert_eq!(task.alphas, alphas);
            assert_eq!(encoded(&task.derived), encoded(&derived));
            assert_eq!(recovered_terminal, terminal);
            let mut wrong = rolling_input.clone();
            wrong.push(0);
            assert!(
                direct_rolling_indices::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &rolling_before,
                    &views
                )
                .is_none()
            );
            let mut missing = rolling_before.clone();
            missing.remove(&previous);
            assert!(
                direct_rolling_indices::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &rolling_input,
                    &missing,
                    &views
                )
                .is_none()
            );
            let mut xof = sha3::Shake256::default();
            Update::update(&mut xof, &rolling_input);
            let mut sampled_bytes = vec![0; 8 * role.queries];
            xof.finalize_xof().read(&mut sampled_bytes);
            let expected_indices: Vec<_> = sampled_bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
                })
                .collect();
            assert_eq!(
                rolling_replay
                    .get_index_challenges(
                        b"rolling FRI unbiased domain index",
                        domain,
                        role.queries
                    )
                    .unwrap(),
                expected_indices
            );
            // Six fixed metadata frames include the parent binding, plus
            // one derived-root/terminal frame per rolling round.
            let mut cursor = rolling_input.as_slice();
            let mut metadata = 1;
            while !cursor.is_empty() {
                let kind = take(&mut cursor, 1).unwrap()[0];
                let label = sized(&mut cursor).unwrap();
                let _body = sized(&mut cursor).unwrap();
                if kind == 1
                    && ![
                        b"child label".as_slice(),
                        b"child context",
                        b"parent seed",
                        b"typed request kind",
                        b"field challenge kind",
                        b"extension basis",
                        b"index domain",
                    ]
                    .contains(&label)
                {
                    metadata += 1;
                }
            }
            assert_eq!(metadata, 6 + rounds);
            frame(
                &mut rolling_input,
                3,
                b"rolling FRI unbiased domain index",
                &sampled_bytes,
            );
            frame(
                &mut rolling_input,
                2,
                b"direct complete rolling replay",
                &64u64.to_le_bytes(),
            );
            rolling_replay.get_challenge_bytes(b"direct complete rolling replay", &mut b);
            assert_eq!(shake64(&rolling_input), b);
            // Restore the initialized child for the common constructor probe.
            let mut parent = prepare();
            parent.append_message(
                <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                &(&product, &contexts, &roots),
            );
            sumcheck::packed_zero::verify(&mut parent, &product, &opening_proof.zero).unwrap();
            parent.append_message(b"packed relation terminal values", &opening.values);
            let mut binding_tail = tail.as_slice();
            parent.append_message(
                binding,
                &Raw(message(&mut binding_tail, 1, binding).unwrap()),
            );
            child = parent
                .fork_classical_extension::<F, EF>(label, context)
                .unwrap();
        }
        if matches!(
            bundle.profile().specification().backend,
            Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
        ) {
            let mut child_input = raw_child::<F, EF>(bundle.profile(), label, context, &seed);
            child_input.extend(fragment_first_tail::<F, EF>(bundle.profile()).unwrap());
            let mut child_before = known.clone();
            child_before.insert(seed, input.clone());
            let (identity_receipt, identity_producer) = receipt(&[]);
            let identity_fingerprint: [u8; 64] = identity_receipt[16..].try_into().unwrap();
            child_before.insert(identity_fingerprint, identity_producer);
            let mut views = FirstViews::new();
            views.insert(input.clone(), known.clone());
            let projected = fragment_first_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &child_input,
                &child_before,
                &views,
            )
            .unwrap();
            assert_eq!(encoded(&projected.sources), encoded(&opening.sources));
            assert_eq!(encoded(&projected.query), encoded(&opening.query));
            let mut late_views = views.clone();
            late_views.get_mut(&input).unwrap().remove(&fingerprint);
            assert!(child_before.contains_key(&fingerprint));
            assert!(
                fragment_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &child_input,
                    &child_before,
                    &late_views
                )
                .is_none()
            );
            let mut missing_identity = child_before.clone();
            missing_identity.remove(&identity_fingerprint);
            assert!(
                fragment_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &child_input,
                    &missing_identity,
                    &views
                )
                .is_none()
            );
            let mut missing_seed = child_before.clone();
            missing_seed.remove(&seed);
            assert!(
                fragment_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &child_input,
                    &missing_seed,
                    &views
                )
                .is_none()
            );
            let mut wrong = child_input.clone();
            *wrong.last_mut().unwrap() ^= 1;
            assert!(
                fragment_first_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &child_before,
                    &views
                )
                .is_none()
            );
            let (values, _) = raw_prime_phase::<F>(&child_input, width * EF::D);
            let rho_label = if bundle.profile().specification().backend == Backend::FragmentedPipfri
            {
                b"fragmented lane projections".as_slice()
            } else {
                b"virtual bridge lane projections v2"
            };
            let rho: Vec<EF> = child.get_vec_challenge(rho_label, width);
            assert_eq!(
                values,
                rho.iter()
                    .flat_map(|value| value.as_base_slice())
                    .map(|v| v.value().to_string().parse::<u128>().unwrap())
                    .collect::<Vec<_>>()
            );
            let projection_input = child_input.clone();
            let (rho_receipt, rho_producer) =
                receipt(&raw_prime_phase::<F>(&child_input, width * EF::D).1);
            frame(&mut child_input, 5, rho_label, &rho_receipt);
            frame(
                &mut child_input,
                2,
                b"fragment child projection replay",
                &64u64.to_le_bytes(),
            );
            child.get_challenge_bytes(b"fragment child projection replay", &mut b);
            assert_eq!(shake64(&child_input), b);
            let mut parent = prepare();
            parent.append_message(
                <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                &(&product, &contexts, &roots),
            );
            sumcheck::packed_zero::verify(&mut parent, &product, &opening_proof.zero).unwrap();
            parent.append_message(b"packed relation terminal values", &opening.values);
            let mut body = tail.as_slice();
            parent.append_message(binding, &Raw(message(&mut body, 1, binding).unwrap()));
            let mut bridge = parent
                .fork_classical_extension::<F, EF>(label, context)
                .unwrap();
            let bridge_rho: Vec<EF> = bridge.get_vec_challenge(rho_label, width);
            assert_eq!(bridge_rho, rho);
            let n = role_vars_for_bridge(bundle.profile());
            let info = algebra::PolynomialInfo {
                num_variables: n,
                max_multiplicands: 2,
            };
            let claim = rho
                .iter()
                .zip(&opening.values[0])
                .fold(EF::zero(), |v, (&r, &value)| v + r * EF::from_base(value));
            let mut bridge_input = projection_input;
            frame(&mut bridge_input, 5, rho_label, &rho_receipt);
            frame(&mut bridge_input, 1, b"polynomial info", &encoded(&info));
            let mut before = child_before.clone();
            let rho_fingerprint: [u8; 64] = rho_receipt[16..].try_into().unwrap();
            before.insert(rho_fingerprint, rho_producer);
            let mut expected = claim;
            let mut point = Vec::new();
            let mut messages = Vec::new();
            let mut previous_fingerprint = rho_fingerprint;
            for round in 0..n {
                let evaluations = vec![
                    expected + EF::one(),
                    -EF::one(),
                    EF::from_base(F::from(round + 2)),
                ];
                let mut wrong = bridge_input.clone();
                let mut invalid = evaluations.clone();
                invalid[0] += EF::one();
                frame(
                    &mut wrong,
                    1,
                    b"sumcheck msg",
                    &encoded(&sumcheck::prover::ProverMsg::from_evaluations(invalid)),
                );
                wrong.extend(bridge_round_tail::<F, EF>());
                assert!(
                    fragment_round_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &wrong,
                        &before,
                        &views,
                        round
                    )
                    .is_none()
                );
                let msg = sumcheck::prover::ProverMsg::from_evaluations(evaluations.clone());
                frame(&mut bridge_input, 1, b"sumcheck msg", &encoded(&msg));
                bridge_input.extend(bridge_round_tail::<F, EF>());
                let recovered = fragment_round_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &bridge_input,
                    &before,
                    &views,
                    round,
                )
                .unwrap();
                assert_eq!(recovered.expected, expected);
                assert_eq!(recovered.point, point);
                assert_eq!(recovered.rho, rho);
                assert_eq!(recovered.evaluations, evaluations);
                assert_eq!(
                    encoded(&recovered.opening.sources),
                    encoded(&opening.sources)
                );
                let mut missing = before.clone();
                missing.remove(&previous_fingerprint);
                assert!(
                    fragment_round_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &bridge_input,
                        &missing,
                        &views,
                        round
                    )
                    .is_none()
                );
                let (coefficients, raw) = raw_prime_phase::<F>(&bridge_input, EF::D);
                let coin = EF::from_base_fn(|i| F::from(usize::try_from(coefficients[i]).unwrap()));
                expected = quadratic(&evaluations, coin);
                point.push(coin);
                messages.push(msg);
                let (receipt, producer) = receipt(&raw);
                previous_fingerprint = receipt[16..].try_into().unwrap();
                before.insert(previous_fingerprint, producer);
                frame(
                    &mut bridge_input,
                    5,
                    b"random point in each round",
                    &receipt,
                );
            }
            let sub = sumcheck::MLSumcheck::verify(&mut bridge, &info, claim, &messages).unwrap();
            assert_eq!(sub.point, point);
            assert_eq!(sub.expected_evaluations, expected);
            let completed_bridge_input = bridge_input.clone();
            frame(
                &mut bridge_input,
                2,
                b"fragment bridge rounds replay",
                &64u64.to_le_bytes(),
            );
            bridge.get_challenge_bytes(b"fragment bridge rounds replay", &mut b);
            assert_eq!(shake64(&bridge_input), b);
            let fresh_bridge = || {
                let mut parent = prepare();
                parent.append_message(
                    <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                    &(&product, &contexts, &roots),
                );
                sumcheck::packed_zero::verify(&mut parent, &product, &opening_proof.zero).unwrap();
                parent.append_message(b"packed relation terminal values", &opening.values);
                let mut raw = tail.as_slice();
                parent.append_message(binding, &Raw(message(&mut raw, 1, binding).unwrap()));
                let mut child = parent
                    .fork_classical_extension::<F, EF>(label, context)
                    .unwrap();
                let _: Vec<EF> = child.get_vec_challenge(rho_label, width);
                sumcheck::MLSumcheck::verify(&mut child, &info, claim, &messages).unwrap();
                child
            };
            use pcs::PolynomialCommitmentScheme;
            type Scalar<B, E> = pcs::multilinear::pipfri::PipFRIPCS<B, E, Sha512>;
            let spec = pcs::multilinear::pipfri::Specification::new(
                bundle.profile().specification().fragment_vars.unwrap(),
                bundle.profile().specification().blowup,
                bundle.profile().specification().roles[0].queries,
            )
            .unwrap();
            let scalar_parameters = Scalar::<F, EF>::try_setup(n, &spec).unwrap();
            let scalar_table = algebra::DenseMultilinearExtension::from_evaluations_vec(
                n,
                assignments
                    .get(&encoded(&opening.sources[0]))
                    .unwrap()
                    .values()
                    .to_vec(),
            );
            let (scalar_root, scalar_state) =
                <Scalar<F, EF> as PolynomialCommitmentScheme<
                    F,
                    EF,
                    pcs::multilinear::pipfri::Specification,
                >>::commit(&scalar_parameters, &scalar_table);
            assert_eq!(scalar_root.root, opening.sources[0].1.root);
            let mut scalar_prover = fresh_bridge();
            let mut scalar_verifier = fresh_bridge();
            let virtual_source =
                bundle.profile().specification().backend == Backend::FragmentedPipfriVirtual;
            let (value, u, forged_bytes, scalar_ladder, rolling_proof) = if virtual_source {
                let (value, proof) = Scalar::<F, EF>::try_open_virtual_at(
                    &scalar_parameters,
                    &scalar_root,
                    &scalar_state,
                    &point,
                    &mut scalar_prover,
                )
                .unwrap();
                Scalar::<F, EF>::verify_virtual(
                    &scalar_parameters,
                    &scalar_root,
                    &point,
                    value,
                    &proof,
                    &mut scalar_verifier,
                )
                .unwrap();
                (
                    value,
                    proof.fragment_evaluations.clone(),
                    encoded(&(&messages, value, &proof)),
                    proof.ladder.clone(),
                    proof.low_degree.clone(),
                )
            } else {
                let (value, proof) = Scalar::<F, EF>::try_open_at(
                    &scalar_parameters,
                    &scalar_root,
                    &scalar_state,
                    &point,
                    &mut scalar_prover,
                )
                .unwrap();
                assert!(<Scalar<F, EF> as PolynomialCommitmentScheme<
                    F,
                    EF,
                    pcs::multilinear::pipfri::Specification,
                >>::verify(
                    &scalar_parameters,
                    &scalar_root,
                    &point,
                    value,
                    &proof,
                    &mut scalar_verifier
                ));
                (
                    value,
                    proof.fragment_evaluations.clone(),
                    encoded(&(&messages, value, &proof)),
                    proof.ladder.clone(),
                    proof.low_degree.clone(),
                )
            };
            // Put the valid scalar proof behind the fabricated but internally
            // consistent bridge. The real matrix adapter must get through the
            // scalar verifier and reject at its terminal kernel equation.
            let (forged, used): (P::SingleProof, usize) =
                bincode::serde::decode_from_slice(&forged_bytes, bincode::config::standard())
                    .unwrap();
            assert_eq!(used, forged_bytes.len());
            let mut backend = prepare();
            backend.append_message(
                <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                &(&product, &contexts, &roots),
            );
            sumcheck::packed_zero::verify(&mut backend, &product, &opening_proof.zero).unwrap();
            backend.append_message(b"packed relation terminal values", &opening.values);
            let rejected = pp
                .evaluations
                .verify(
                    &mut backend,
                    &opening.sources[0].1,
                    &opening.query,
                    &opening.values[0],
                    &forged,
                )
                .unwrap_err();
            assert!(
                rejected
                    .to_string()
                    .contains("ordered matrix terminal equation"),
                "{rejected}"
            );
            let (_, _, fragment_count, scalar_context, _) =
                scalar_geometry::<F, EF>(bundle.profile()).unwrap();
            assert_eq!(u.len(), fragment_count);
            let mut gamma_input = completed_bridge_input.clone();
            let mut gamma_replay = fresh_bridge();
            if virtual_source {
                frame(
                    &mut gamma_input,
                    1,
                    b"unmasked virtual PipFRI PCS v2",
                    &encoded(&n),
                );
                gamma_replay.append_message(b"unmasked virtual PipFRI PCS v2", &n);
                let body = (2u32, scalar_context, &scalar_root, &point, value, &u);
                frame(
                    &mut gamma_input,
                    1,
                    b"unmasked scalar PipFRI virtual v2",
                    &encoded(&body),
                );
                gamma_replay.append_message(b"unmasked scalar PipFRI virtual v2", &body);
            } else {
                let adapter = (n, b"base table".as_slice());
                frame(
                    &mut gamma_input,
                    1,
                    b"ordinary PipFRI PCS adapter v1",
                    &encoded(&adapter),
                );
                gamma_replay.append_message(b"ordinary PipFRI PCS adapter v1", &adapter);
                let body = (scalar_context, &scalar_root, &point, value, &u);
                frame(
                    &mut gamma_input,
                    1,
                    b"HasteBoots ordinary PipFRI v1",
                    &encoded(&body),
                );
                gamma_replay.append_message(b"HasteBoots ordinary PipFRI v1", &body);
            }
            let (gamma_tail, gamma_label) = gamma_tail::<F, EF>(bundle.profile()).unwrap();
            gamma_input.extend(&gamma_tail);
            assert!(u.windows(2).any(|pair| pair[0] != pair[1]));
            let wrong_u: Vec<_> = u.iter().map(|&value| value + EF::one()).collect();
            let mut invalid_aggregate = completed_bridge_input.clone();
            if virtual_source {
                frame(
                    &mut invalid_aggregate,
                    1,
                    b"unmasked virtual PipFRI PCS v2",
                    &encoded(&n),
                );
                frame(
                    &mut invalid_aggregate,
                    1,
                    b"unmasked scalar PipFRI virtual v2",
                    &encoded(&(2u32, scalar_context, &scalar_root, &point, value, &wrong_u)),
                );
            } else {
                frame(
                    &mut invalid_aggregate,
                    1,
                    b"ordinary PipFRI PCS adapter v1",
                    &encoded(&(n, b"base table".as_slice())),
                );
                frame(
                    &mut invalid_aggregate,
                    1,
                    b"HasteBoots ordinary PipFRI v1",
                    &encoded(&(scalar_context, &scalar_root, &point, value, &wrong_u)),
                );
            }
            invalid_aggregate.extend(&gamma_tail);
            assert!(
                scalar_gamma_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &invalid_aggregate,
                    &before,
                    &views
                )
                .is_none()
            );
            let recovered = scalar_gamma_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &gamma_input,
                &before,
                &views,
            )
            .unwrap();
            assert_eq!(recovered.point, point);
            assert_eq!(recovered.bridge_expected, expected);
            assert_eq!(recovered.value, value);
            assert_eq!(recovered.fragments, u);
            assert_eq!(
                encoded(&recovered.opening.sources),
                encoded(&opening.sources)
            );
            let mut wrong = gamma_input.clone();
            *wrong.last_mut().unwrap() ^= 1;
            assert!(
                scalar_gamma_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &before,
                    &views
                )
                .is_none()
            );
            let gamma: EF = gamma_replay.get_challenge(gamma_label);
            assert_eq!(
                raw_prime_phase::<F>(&gamma_input, EF::D).0,
                gamma
                    .as_base_slice()
                    .iter()
                    .map(|v| v.value().to_string().parse::<u128>().unwrap())
                    .collect::<Vec<_>>()
            );
            let (_, rounds, _, scalar_context, fri_context) =
                scalar_geometry::<F, EF>(bundle.profile()).unwrap();
            let mut rolling_roots = Vec::new();
            if virtual_source {
                rolling_roots.push(RollingRoot {
                    root: Digest512(
                        Sha512::digest(encoded(&(
                            b"unmasked PipFRI virtual initial v2".as_slice(),
                            scalar_context,
                            &scalar_root,
                            &point,
                            gamma,
                        )))
                        .into(),
                    ),
                });
            }
            rolling_roots.extend(scalar_ladder.clone());
            assert_eq!(rolling_roots.len(), rounds);
            let (gamma_receipt, gamma_producer) =
                receipt(&raw_prime_phase::<F>(&gamma_input, EF::D).1);
            let mut rolling_input = gamma_input.clone();
            frame(&mut rolling_input, 5, gamma_label, &gamma_receipt);
            let mut rolling_before = before.clone();
            let gamma_fingerprint: [u8; 64] = gamma_receipt[16..].try_into().unwrap();
            rolling_before.insert(gamma_fingerprint, gamma_producer);
            let public_roots_label = if virtual_source {
                b"unmasked virtual PipFRI public roots v2".as_slice()
            } else {
                b"PipFRI public fold roots"
            };
            frame(
                &mut rolling_input,
                1,
                public_roots_label,
                &encoded(&scalar_ladder),
            );
            gamma_replay.append_message(public_roots_label, &scalar_ladder);
            let rolling_label = if virtual_source {
                b"HasteBoots rolling batch FRI virtual initial v1".as_slice()
            } else {
                b"HasteBoots rolling batch FRI v1"
            };
            frame(
                &mut rolling_input,
                1,
                rolling_label,
                &encoded(&(fri_context, &rolling_roots)),
            );
            gamma_replay.append_message(rolling_label, &(fri_context, &rolling_roots));
            let mut alphas = Vec::new();
            let mut previous = gamma_fingerprint;
            for round in 0..rounds {
                rolling_input.extend(rolling_alpha_tail::<F, EF>());
                let task = rolling_alpha_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &rolling_input,
                    &rolling_before,
                    &views,
                    round,
                )
                .unwrap();
                assert_eq!(task.gamma, gamma);
                assert_eq!(encoded(&task.originals), encoded(&rolling_roots));
                assert_eq!(task.derived.len(), round);
                assert_eq!(task.alphas, alphas);
                assert_eq!(task.scalar.point, point);
                let mut missing = rolling_before.clone();
                missing.remove(&previous);
                assert!(
                    rolling_alpha_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &rolling_input,
                        &missing,
                        &views,
                        round
                    )
                    .is_none()
                );
                let (values, raw) = raw_prime_phase::<F>(&rolling_input, EF::D);
                let alpha: EF = gamma_replay.get_challenge(b"rolling FRI fold challenge");
                assert_eq!(
                    values,
                    alpha
                        .as_base_slice()
                        .iter()
                        .map(|v| v.value().to_string().parse::<u128>().unwrap())
                        .collect::<Vec<_>>()
                );
                alphas.push(alpha);
                let (receipt, producer) = receipt(&raw);
                previous = receipt[16..].try_into().unwrap();
                rolling_before.insert(previous, producer);
                frame(
                    &mut rolling_input,
                    5,
                    b"rolling FRI fold challenge",
                    &receipt,
                );
                if round + 1 < rounds {
                    let body = (round + 1, &rolling_proof.derived[round]);
                    let mut wrong = rolling_input.clone();
                    frame(
                        &mut wrong,
                        1,
                        b"rolling FRI derived root",
                        &encoded(&(round + 2, &rolling_proof.derived[round])),
                    );
                    wrong.extend(rolling_alpha_tail::<F, EF>());
                    assert!(
                        rolling_alpha_query::<F, EF, P>(
                            bundle.profile(),
                            &pp,
                            &public,
                            &statement,
                            &wrong,
                            &rolling_before,
                            &views,
                            round + 1
                        )
                        .is_none()
                    );
                    frame(
                        &mut rolling_input,
                        1,
                        b"rolling FRI derived root",
                        &encoded(&body),
                    );
                    gamma_replay.append_message(b"rolling FRI derived root", &body);
                }
            }
            frame(
                &mut rolling_input,
                1,
                b"rolling FRI terminal",
                &encoded(&rolling_proof.terminal),
            );
            gamma_replay.append_message(b"rolling FRI terminal", &rolling_proof.terminal);
            let (index_tail, domain) = rolling_index_tail(bundle.profile()).unwrap();
            rolling_input.extend(index_tail);
            let (task, terminal) = rolling_index_query::<F, EF, P>(
                bundle.profile(),
                &pp,
                &public,
                &statement,
                &rolling_input,
                &rolling_before,
                &views,
            )
            .unwrap();
            assert_eq!(task.alphas, alphas);
            assert_eq!(terminal, rolling_proof.terminal);
            let mut wrong = rolling_input.clone();
            *wrong.last_mut().unwrap() ^= 1;
            assert!(
                rolling_index_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &wrong,
                    &rolling_before,
                    &views
                )
                .is_none()
            );
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let draws = bundle.profile().specification().roles[0].queries;
            let mut state = sha3::Shake256::default();
            Update::update(&mut state, &rolling_input);
            let mut bytes = vec![0; 8 * draws];
            state.finalize_xof().read(&mut bytes);
            let independently_sampled: Vec<_> = bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1)) as usize
                })
                .collect();
            assert_eq!(
                gamma_replay
                    .get_index_challenges(b"rolling FRI unbiased domain index", domain, draws)
                    .unwrap(),
                independently_sampled
            );
            if !virtual_source {
                frame(
                    &mut rolling_input,
                    3,
                    b"rolling FRI unbiased domain index",
                    &bytes,
                );
                rolling_input.extend(consistency_index_tail(bundle.profile()).unwrap());
                let (task, previous_indices) = consistency_index_query::<F, EF, P>(
                    bundle.profile(),
                    &pp,
                    &public,
                    &statement,
                    &rolling_input,
                    &rolling_before,
                    &views,
                )
                .unwrap();
                assert_eq!(task.alphas, alphas);
                assert_eq!(previous_indices, independently_sampled);
                let mut wrong = rolling_input.clone();
                *wrong.last_mut().unwrap() ^= 1;
                assert!(
                    consistency_index_query::<F, EF, P>(
                        bundle.profile(),
                        &pp,
                        &public,
                        &statement,
                        &wrong,
                        &rolling_before,
                        &views
                    )
                    .is_none()
                );
                let mut state = sha3::Shake256::default();
                Update::update(&mut state, &rolling_input);
                let mut consistency_bytes = vec![0; 8 * draws];
                state.finalize_xof().read(&mut consistency_bytes);
                let expected: Vec<_> = consistency_bytes
                    .chunks_exact(8)
                    .map(|chunk| {
                        (u64::from_le_bytes(chunk.try_into().unwrap()) & (domain as u64 - 1))
                            as usize
                    })
                    .collect();
                assert_eq!(
                    gamma_replay
                        .get_index_challenges(b"PipFRI consistency domain index", domain, draws)
                        .unwrap(),
                    expected
                );
            }
            // Count every non-sampling child metadata frame in the actual
            // reconstructed scalar prefix, plus its parent's ordered binding.
            let mut cursor = rolling_input.as_slice();
            let mut metadata_frames = 1;
            while !cursor.is_empty() {
                let kind = take(&mut cursor, 1).unwrap()[0];
                let label = sized(&mut cursor).unwrap();
                let _body = sized(&mut cursor).unwrap();
                if kind == 1
                    && ![
                        b"child label".as_slice(),
                        b"child context",
                        b"parent seed",
                        b"typed request kind",
                        b"field challenge kind",
                        b"extension basis",
                        b"index domain",
                    ]
                    .contains(&label)
                {
                    metadata_frames += 1;
                }
            }
            assert_eq!(metadata_frames, 6 + n + rounds);
            let mut rolling_probe = [0; 64];
            gamma_replay.get_challenge_bytes(b"full scalar adapter replay", &mut rolling_probe);
            scalar_prover.get_challenge_bytes(b"full scalar adapter replay", &mut a);
            scalar_verifier.get_challenge_bytes(b"full scalar adapter replay", &mut b);
            assert_eq!(a, b);
            assert_eq!(a, rolling_probe);
            // Recreate the initialized child for the independent constructor
            // probe below; this is a fresh replay, not a history repair.
            let mut replay = prepare();
            replay.append_message(
                <P as CanonicalPcs<F, Sha512>>::RELATION_DOMAIN,
                &(&product, &contexts, &roots),
            );
            sumcheck::packed_zero::verify(&mut replay, &product, &opening_proof.zero).unwrap();
            replay.append_message(b"packed relation terminal values", &opening.values);
            let mut binding_tail = tail.as_slice();
            replay.append_message(
                binding,
                &Raw(message(&mut binding_tail, 1, binding).unwrap()),
            );
            child = replay
                .fork_classical_extension::<F, EF>(label, context)
                .unwrap();
        }
        let mut child_input = raw_child::<F, EF>(bundle.profile(), label, context, &seed);
        frame(
            &mut child_input,
            2,
            b"first PCS child prefix replay",
            &64u64.to_le_bytes(),
        );
        child.get_challenge_bytes(b"first PCS child prefix replay", &mut b);
        assert_eq!(shake64(&child_input), b);
    }
    let mut invalid = bytes.clone();
    invalid.push(0);
    assert!(recover::<F, EF, _>(&pp, &public, &statement, &invalid).is_none());
    invalid = bytes.clone();
    invalid[0] ^= 1;
    assert!(recover::<F, EF, _>(&pp, &public, &statement, &invalid).is_none());
    invalid = prefix.clone();
    invalid.extend(encoded(&usize::MAX));
    assert!(recover::<F, EF, _>(&pp, &public, &statement, &invalid).is_none());
    invalid = prefix;
    invalid.extend(encoded(&(
        &co[..co.len() - 1],
        &ev,
        &inputs,
        &accumulators,
        &endpoint,
    )));
    assert!(recover::<F, EF, _>(&pp, &public, &statement, &invalid).is_none());
}

fn exercise_fragment_terminal_kernel<F, EF>()
where
    F: NTTField,
    EF: AbstractExtensionField<F>,
{
    use algebra::matrix_weighted::{Matrix, MatrixPair};
    let queries: Vec<_> = (0..2)
        .map(|claim| {
            (0..2)
                .map(|index| MatrixPair {
                    zero: Matrix::new(
                        2,
                        [2, 3, 5, 7]
                            .into_iter()
                            .map(|v| F::from(v + claim + 2 * index))
                            .collect(),
                    )
                    .unwrap(),
                    one: Matrix::new(
                        2,
                        [11, 13, 17, 19]
                            .into_iter()
                            .map(|v| F::from(v + 3 * claim + index))
                            .collect(),
                    )
                    .unwrap(),
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let rho: Vec<_> = (0..4)
        .map(|i| EF::from_base_fn(|j| F::from(2 + i + j)))
        .collect();
    let point: Vec<_> = (0..3)
        .map(|i| EF::from_base_fn(|j| F::from(7 + 2 * i + j)))
        .collect();
    let mut exhaustive = EF::zero();
    // Explicitly enumerate the row variables, then both source lanes. Matrix
    // products use reverse row multiplication, opposite to the audit kernel.
    for (query, challenges) in queries.iter().zip(rho.chunks_exact(2)) {
        for assignment in 0..4 {
            let mut row = challenges.to_vec();
            for (index, pair) in query.iter().enumerate().rev() {
                let matrix = if assignment >> index & 1 == 0 {
                    &pair.zero
                } else {
                    &pair.one
                };
                row = (0..2)
                    .map(|col| {
                        (0..2).fold(EF::zero(), |sum, r| {
                            sum + row[r] * EF::from_base(matrix.values()[r * 2 + col])
                        })
                    })
                    .collect();
            }
            let row_weight = (0..2).fold(EF::one(), |w, i| {
                w * if assignment >> i & 1 == 0 {
                    EF::one() - point[1 + i]
                } else {
                    point[1 + i]
                }
            });
            exhaustive += row_weight * ((EF::one() - point[0]) * row[0] + point[0] * row[1]);
        }
    }
    let compiled = fragment_terminal_kernel(2, &queries, &rho, &point).unwrap();
    assert_eq!(compiled, exhaustive);
    let reversed: Vec<_> = queries
        .iter()
        .map(|q| q.iter().cloned().rev().collect())
        .collect();
    assert_ne!(
        fragment_terminal_kernel(2, &reversed, &rho, &point).unwrap(),
        exhaustive
    );
    assert!(fragment_terminal_kernel(2, &queries, &rho[..3], &point).is_none());
    assert!(fragment_terminal_kernel(2, &queries, &rho, &point[..2]).is_none());
    assert!(fragment_terminal_kernel(3, &queries, &rho, &point).is_none());
    assert!(fragment_terminal_kernel::<F, EF>(2, &[], &[], &point).is_none());
}
#[test]
fn fragment_terminal_kernel_all_extensions() {
    exercise_fragment_terminal_kernel::<algebra::BabyBear, algebra::BabyBearExetension>();
    exercise_fragment_terminal_kernel::<algebra::BabyBear, algebra::BabyBearExtension5>();
    exercise_fragment_terminal_kernel::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_fragment_terminal_kernel::<algebra::BabyBear, algebra::BabyBearExtension8>();
    exercise_fragment_terminal_kernel::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    exercise_fragment_terminal_kernel::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    exercise_fragment_terminal_kernel::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
    exercise_fragment_terminal_kernel::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

fn exercise_accumulator_frozen_brakedown<F, EF>(version: u32)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::utils::code::{BlockReedSolomonCode, RowCode};
    use std::sync::Arc;
    let width = 8;
    let vars = 3;
    let left = 1;
    let spec = Specification {
        backend: Backend::Brakedown,
        roles: std::array::from_fn(|_| Role {
            num_vars: vars,
            width,
            queries: 8,
            left_vars: Some(left),
            block_width: Some(2),
        }),
        blowup: 2,
        fragment_vars: None,
    };
    let profile = if version == 4 {
        ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
    } else {
        ClassicalProfile::new_atomic_columns::<F, EF>(spec)
    }
    .unwrap();
    let bundle = profile.brakedown_parameters::<F, EF>().unwrap();
    let pp = super::super::classical::parameters(&bundle);
    let shape = crate::packed_accumulator::Shape::new(width, 3).unwrap();
    let initial = vec![F::zero(); 2 * width];
    let final_acc = vec![F::from(3usize); 2 * width];
    let mut words = vec![vec![F::zero(); width << vars]; 7];
    for half in 0..2 {
        for row in 0..3 {
            for coefficient in 0..width {
                let at = (half * 4 + row) * width + coefficient;
                words[0][at] = F::from(row);
                words[1][at] = F::from(row);
                words[3][at] = F::from(row + 1);
                words[4][at] = F::one();
            }
        }
    }
    let tables: Vec<_> = words
        .into_iter()
        .map(|word| PackedTable::new(vars, width, word).unwrap())
        .collect();
    let code = BlockReedSolomonCode::<F>::new(1 << (vars - left), 2, 2).unwrap();
    let mut sources = Vec::new();
    let mut views = std::collections::HashMap::new();
    for (slot, table) in tables.iter().enumerate() {
        let parameters = accumulator_parameters(&pp, slot).unwrap();
        let (root, _) = parameters.commit::<F, Sha512>(table).unwrap();
        let source = (parameters.context_digest::<F, Sha512>().unwrap(), root);
        let mut columns = vec![Vec::new(); code.codeword_blocks()];
        for row in 0..(1 << left) * width {
            let message: Vec<_> = (0..1 << (vars - left))
                .map(|right| table.at(row / width + (right << left))[row % width])
                .collect();
            let mut encoded = vec![F::zero(); code.codeword_blocks() * code.block_width()];
            code.encode_row(&message, &mut encoded);
            for (column, values) in columns.iter_mut().enumerate() {
                values.extend_from_slice(
                    &encoded[column * code.block_width()..(column + 1) * code.block_width()],
                );
            }
        }
        let mut known = FrozenWordView::new();
        let mut nodes: Vec<_> = columns
            .iter()
            .map(|column| {
                let mut input = b"HasteBoots/mw-column/v1".to_vec();
                input.extend(encoded(column));
                let digest = Digest512(Sha512::digest(&input).into());
                known.insert(digest, input);
                digest
            })
            .collect();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| {
                    let mut input = pair[0].0.to_vec();
                    input.extend(pair[1].0);
                    let digest = Digest512(Sha512::digest(&input).into());
                    known.insert(digest, input);
                    digest
                })
                .collect();
        }
        assert_eq!(nodes[0], source.1.root);
        views.insert(encoded(&source), Arc::new(known));
        sources.push(source);
    }
    let oracles: Vec<_> = sources
        .iter()
        .enumerate()
        .map(|(slot, (_, commitment))| CanonicalVerifierOracle {
            parameters: accumulator_parameters(&pp, slot).unwrap(),
            commitment,
        })
        .collect();
    let mut transcript = bundle.profile().parent_transcript::<F>().unwrap();
    let (base, _) = crate::packed_accumulator::audit::binding_queries::<F, Sha512, _>(
        &mut transcript,
        &shape,
        &initial,
        &final_acc,
        &oracles,
    )
    .unwrap();
    let task = AccumulatorTask {
        shape,
        initial,
        final_acc,
        sources,
        base,
    };
    let expected = accumulator_assigned_values(&pp, &task, |source| {
        task.sources
            .iter()
            .position(|candidate| encoded(candidate) == encoded(source))
            .map(|slot| tables[slot].clone())
    })
    .unwrap();
    let depth = code.codeword_blocks().ilog2() as usize;
    exercise_accumulator_late_history::<F, EF, _>(bundle.profile(), &pp, &task, &views, depth);
    let mut history = classical_history::History::default();
    replay_accumulator_word_graphs(&mut history, &task, &views, depth);
    let declaration: Vec<_> = task
        .sources
        .iter()
        .flat_map(|source| source.1.root.0)
        .collect();
    history.declare_input(&declaration);
    monomial_word_audit::exercise::<F, EF, _>(bundle.profile(), &pp, &task, &tables, &history);
    let mut seen = std::collections::HashSet::new();
    assert!(
        views.len() < task.sources.len(),
        "fixture must exercise real source aliases"
    );
    let (promises, values) =
        accumulator_brakedown_frozen_values(bundle.profile(), &pp, &task, |source| {
            let identity = encoded(source);
            assert!(
                seen.insert(identity.clone()),
                "aliased source requested a later view"
            );
            history.view(source.1.root)
        })
        .unwrap();
    assert_eq!(seen.len(), views.len());
    assert_eq!(promises.len(), 7);
    assert!(promises.iter().all(|&p| p));
    assert_eq!(encoded(&values), encoded(&expected));
    assert!(accumulator_values_valid(&pp, &task, &values));
    assert!(accumulator_brakedown_frozen_values(bundle.profile(), &pp, &task, |_| None).is_none());
    let mut corrupt = views.clone();
    let key = encoded(&task.sources[0]);
    let mut bad = corrupt[&key].as_ref().clone();
    bad.get_mut(&task.sources[0].1.root).unwrap()[0] ^= 1;
    corrupt.insert(key, Arc::new(bad));
    let (_, changed) =
        accumulator_brakedown_frozen_values(bundle.profile(), &pp, &task, |source| {
            corrupt.get(&encoded(source)).cloned()
        })
        .unwrap();
    assert!(!accumulator_values_valid(&pp, &task, &changed));
    for mutation in 0..5 {
        let mut spec = bundle.profile().specification().clone();
        match mutation {
            0 => spec.roles[0].left_vars = Some(2),
            1 => spec.roles[0].block_width = Some(4),
            2 => spec.blowup = 32,
            3 => spec.roles[0].queries += 1,
            _ => spec.roles[0].num_vars += 1,
        }
        let wrong = if version == 4 {
            ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
        } else {
            ClassicalProfile::new_atomic_columns::<F, EF>(spec)
        }
        .unwrap();
        let mut callbacks = 0;
        assert!(
            accumulator_brakedown_frozen_values(&wrong, &pp, &task, |source| {
                callbacks += 1;
                views.get(&encoded(source)).cloned()
            })
            .is_none()
        );
        assert_eq!(callbacks, 0);
    }
    for mutation in 0..3 {
        let mut wrong = AccumulatorTask {
            shape: task.shape.clone(),
            initial: task.initial.clone(),
            final_acc: task.final_acc.clone(),
            sources: task.sources.clone(),
            base: task.base.clone(),
        };
        match mutation {
            0 => wrong.sources[6].0.0[0] ^= 1,
            1 => {
                wrong.sources.pop();
            }
            _ => {
                wrong.base.pop();
            }
        }
        let mut callbacks = 0;
        assert!(
            accumulator_brakedown_frozen_values(bundle.profile(), &pp, &wrong, |source| {
                callbacks += 1;
                views.get(&encoded(source)).cloned()
            })
            .is_none()
        );
        assert_eq!(callbacks, 0);
    }
}
#[test]
fn accumulator_frozen_brakedown_words() {
    for version in [4, 5] {
        exercise_accumulator_frozen_brakedown::<algebra::BabyBear, algebra::BabyBearExtension6>(
            version,
        );
        exercise_accumulator_frozen_brakedown::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            version,
        );
    }
}

fn exercise_accumulator_frozen_polyfrim_bundle<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use std::sync::Arc;
    let pp = super::super::classical::parameters(&bundle);
    let profile = bundle.profile();
    let (core, domain) = direct_core::<F, EF>(profile).unwrap();
    let points = direct_source_points::<F, EF>(domain).unwrap();
    let (width, vars) = (8, 3);
    let shape = crate::packed_accumulator::Shape::new(width, 3).unwrap();
    let mut words = vec![vec![F::zero(); width << vars]; 7];
    for half in 0..2 {
        for row in 0..3 {
            for coefficient in 0..width {
                let at = (half * 4 + row) * width + coefficient;
                words[0][at] = F::from(row);
                words[1][at] = F::from(row);
                words[3][at] = F::from(row + 1);
                words[4][at] = F::one();
            }
        }
    }
    let tables: Vec<_> = words
        .into_iter()
        .map(|word| PackedTable::new(vars, width, word).unwrap())
        .collect();
    let mut sources = Vec::new();
    let mut views = std::collections::HashMap::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7471);
    for (slot, table) in tables.iter().enumerate() {
        let parameters = accumulator_parameters(&pp, slot).unwrap();
        let (root, _) = parameters.commit(table, &mut rng).ok().unwrap();
        let source = (parameters.context().ok().unwrap(), root);
        let lifted = PackedTable::new(
            vars,
            width,
            table.values().iter().copied().map(EF::from_base).collect(),
        )
        .unwrap();
        let polynomial = pcs::packed_polyfrim::Polynomial::from_table(&lifted).unwrap();
        let symbols: Vec<_> = points
            .iter()
            .map(|&point| {
                polynomial
                    .evaluate(point)
                    .into_iter()
                    .map(|v| v.canonicalized())
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut known = FrozenWordView::new();
        let mut nodes: Vec<_> = symbols
            .chunks_exact(2)
            .enumerate()
            .map(|(index, pair)| {
                let values: Vec<_> = pair.iter().flatten().copied().collect();
                let input = encoded(&(
                    b"packed PolyFRIM pair leaf v2",
                    &core,
                    0usize,
                    index,
                    &values,
                ));
                let digest = Digest512(Sha512::digest(&input).into());
                known.insert(digest, input);
                digest
            })
            .collect();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| {
                    let mut input = pair[0].0.to_vec();
                    input.extend(pair[1].0);
                    let digest = Digest512(Sha512::digest(&input).into());
                    known.insert(digest, input);
                    digest
                })
                .collect();
        }
        assert_eq!(nodes[0], source.1.root);
        views.insert(encoded(&source), Arc::new(known));
        sources.push(source);
    }
    let initial = vec![F::zero(); width * 2];
    let final_acc = vec![F::from(3usize); width * 2];
    let oracles: Vec<_> = sources
        .iter()
        .enumerate()
        .map(|(slot, (_, commitment))| CanonicalVerifierOracle {
            parameters: accumulator_parameters(&pp, slot).unwrap(),
            commitment,
        })
        .collect();
    let mut transcript = profile.parent_transcript::<F>().unwrap();
    let (base, _) = crate::packed_accumulator::audit::binding_queries::<F, Sha512, P>(
        &mut transcript,
        &shape,
        &initial,
        &final_acc,
        &oracles,
    )
    .unwrap();
    let task = AccumulatorTask {
        shape,
        initial,
        final_acc,
        sources,
        base,
    };
    exercise_accumulator_decoder_preflight::<F, EF, P>(profile, &pp, &task);
    let expected = accumulator_assigned_values(&pp, &task, |source| {
        task.sources
            .iter()
            .position(|candidate| encoded(candidate) == encoded(source))
            .map(|slot| tables[slot].clone())
    })
    .unwrap();
    let depth = (domain / 2).ilog2() as usize;
    exercise_accumulator_late_history::<F, EF, _>(profile, &pp, &task, &views, depth);
    let mut history = classical_history::History::default();
    replay_accumulator_word_graphs(&mut history, &task, &views, depth);
    let declaration: Vec<_> = task
        .sources
        .iter()
        .flat_map(|source| source.1.root.0)
        .collect();
    history.declare_input(&declaration);
    monomial_word_audit::exercise::<F, EF, _>(bundle.profile(), &pp, &task, &tables, &history);
    let mut seen = std::collections::HashSet::new();
    assert!(
        views.len() < task.sources.len(),
        "fixture must exercise real source aliases"
    );
    let (promises, values) =
        accumulator_polyfrim_frozen_values::<F, EF, P>(profile, &pp, &task, |source| {
            let identity = encoded(source);
            assert!(
                seen.insert(identity.clone()),
                "aliased source requested a later view"
            );
            history.view(source.1.root)
        })
        .unwrap();
    assert_eq!(seen.len(), views.len());
    assert_eq!(promises.len(), 7);
    assert!(promises.iter().all(|&p| p));
    assert_eq!(encoded(&values), encoded(&expected));
    assert!(accumulator_values_valid(&pp, &task, &values));
    assert!(
        accumulator_polyfrim_frozen_values::<F, EF, P>(profile, &pp, &task, |_| None).is_none()
    );
    let mut corrupt = views.clone();
    let key = encoded(&task.sources[0]);
    let mut bad = corrupt[&key].as_ref().clone();
    bad.get_mut(&task.sources[0].1.root).unwrap()[0] ^= 1;
    corrupt.insert(key, Arc::new(bad));
    let (_, changed) =
        accumulator_polyfrim_frozen_values::<F, EF, P>(profile, &pp, &task, |source| {
            corrupt.get(&encoded(source)).cloned()
        })
        .unwrap();
    assert!(!accumulator_values_valid(&pp, &task, &changed));
}
fn exercise_accumulator_frozen_polyfrim<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for version in [4, 5] {
        for backend in [Backend::Polyfrim, Backend::PolyfrimDictionary] {
            let spec = Specification {
                backend,
                roles: std::array::from_fn(|_| Role {
                    num_vars: 3,
                    width: 8,
                    queries: 8,
                    left_vars: None,
                    block_width: None,
                }),
                blowup: 2,
                fragment_vars: None,
            };
            let profile = if version == 4 {
                ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
            } else {
                ClassicalProfile::new_atomic_columns::<F, EF>(spec)
            }
            .unwrap();
            match backend {
                Backend::Polyfrim => exercise_accumulator_frozen_polyfrim_bundle::<F, EF, _>(
                    profile.polyfrim_parameters::<F, EF>().unwrap(),
                ),
                _ => exercise_accumulator_frozen_polyfrim_bundle::<F, EF, _>(
                    profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
                ),
            }
        }
    }
}
#[test]
fn accumulator_frozen_polyfrim_words() {
    exercise_accumulator_frozen_polyfrim::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_accumulator_frozen_polyfrim::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

// This fixture-only recorder also captures Merkle hashes on Rayon workers.
static FRAGMENT_HASH_RECORDS: std::sync::LazyLock<std::sync::Mutex<FrozenWordView>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(FrozenWordView::new()));

#[derive(Clone, Debug, Default)]
struct FragmentRecordedHash {
    state: Sha512,
    input: Vec<u8>,
}
impl pcs::utils::hash::Hash for FragmentRecordedHash {
    type Output = Digest512;
    fn update_hash_value(&mut self, input: &[u8]) {
        Digest::update(&mut self.state, input);
        self.input.extend(input);
    }
    fn output_reset(&mut self) -> Digest512 {
        let digest = Digest512(self.state.finalize_reset().into());
        let input = std::mem::take(&mut self.input);
        if let Some(old) = FRAGMENT_HASH_RECORDS
            .lock()
            .unwrap()
            .insert(digest, input.clone())
        {
            assert_eq!(old, input);
        }
        digest
    }
}
fn exercise_accumulator_frozen_fragment_bundle<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, FragmentRecordedHash>,
{
    use std::sync::Arc;
    let pp = super::super::classical::parameters(&bundle);
    let profile = bundle.profile();
    let (width, vars) = (8, 3);
    let shape = crate::packed_accumulator::Shape::new(width, 3).unwrap();
    let mut words = vec![vec![F::zero(); width << vars]; 7];
    for half in 0..2 {
        for row in 0..3 {
            for coefficient in 0..width {
                let at = (half * 4 + row) * width + coefficient;
                words[0][at] = F::from(row);
                words[1][at] = F::from(row);
                words[3][at] = F::from(row + 1);
                words[4][at] = F::one();
            }
        }
    }
    let tables: Vec<_> = words
        .into_iter()
        .map(|word| PackedTable::new(vars, width, word).unwrap())
        .collect();
    let mut sources = Vec::new();
    let mut views = std::collections::HashMap::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7472);
    for (slot, table) in tables.iter().enumerate() {
        let parameters = accumulator_parameters::<P>(&pp, slot).unwrap();
        let (root, _) = <P as CanonicalPcs<F, Sha512>>::commit(parameters, table, &mut rng)
            .ok()
            .unwrap();
        FRAGMENT_HASH_RECORDS.lock().unwrap().clear();
        let (recorded, _) =
            <P as CanonicalPcs<F, FragmentRecordedHash>>::commit(parameters, table, &mut rng)
                .ok()
                .unwrap();
        assert_eq!(root.root, recorded.root);
        let known = std::mem::take(&mut *FRAGMENT_HASH_RECORDS.lock().unwrap());
        let source = (
            <P as CanonicalPcs<F, Sha512>>::context(parameters)
                .ok()
                .unwrap(),
            root,
        );
        views.insert(encoded(&source), Arc::new(known));
        sources.push(source);
    }
    let initial = vec![F::zero(); width * 2];
    let final_acc = vec![F::from(3usize); width * 2];
    let oracles: Vec<_> = sources
        .iter()
        .enumerate()
        .map(|(slot, (_, commitment))| CanonicalVerifierOracle {
            parameters: accumulator_parameters::<P>(&pp, slot).unwrap(),
            commitment,
        })
        .collect();
    let mut transcript = profile.parent_transcript::<F>().unwrap();
    let (base, _) = crate::packed_accumulator::audit::binding_queries::<F, Sha512, P>(
        &mut transcript,
        &shape,
        &initial,
        &final_acc,
        &oracles,
    )
    .unwrap();
    let task = AccumulatorTask {
        shape,
        initial,
        final_acc,
        sources,
        base,
    };
    exercise_accumulator_decoder_preflight::<F, EF, P>(profile, &pp, &task);
    let expected = accumulator_assigned_values::<F, P>(&pp, &task, |source| {
        task.sources
            .iter()
            .position(|candidate| encoded(candidate) == encoded(source))
            .map(|slot| tables[slot].clone())
    })
    .unwrap();
    let depth = {
        let (_, r, _, _, _) = scalar_geometry::<F, EF>(profile).unwrap();
        (((1usize << r) * profile.specification().blowup) / 2).ilog2() as usize
    };
    exercise_accumulator_late_history::<F, EF, _>(profile, &pp, &task, &views, depth);
    let mut history = classical_history::History::default();
    replay_accumulator_word_graphs(&mut history, &task, &views, depth);
    let declaration: Vec<_> = task
        .sources
        .iter()
        .flat_map(|source| source.1.root.0)
        .collect();
    history.declare_input(&declaration);
    monomial_word_audit::exercise::<F, EF, _>(bundle.profile(), &pp, &task, &tables, &history);
    let mut seen = std::collections::HashSet::new();
    let (promises, values) =
        accumulator_fragment_frozen_values::<F, EF, P>(profile, &pp, &task, |source| {
            let identity = encoded(source);
            assert!(seen.insert(identity.clone()));
            history.view(source.1.root)
        })
        .unwrap();
    assert!(seen.len() < 7);
    assert_eq!(seen.len(), views.len());
    assert_eq!(promises.len(), 7);
    assert!(promises.iter().all(|&p| p));
    assert_eq!(encoded(&values), encoded(&expected));
    assert!(accumulator_values_valid::<F, P>(&pp, &task, &values));
    assert!(
        accumulator_fragment_frozen_values::<F, EF, P>(profile, &pp, &task, |_| None).is_none()
    );
    let mut corrupt = views.clone();
    let key = encoded(&task.sources[0]);
    let mut bad = corrupt[&key].as_ref().clone();
    bad.get_mut(&task.sources[0].1.root).unwrap()[0] ^= 1;
    corrupt.insert(key, Arc::new(bad));
    let (_, changed) =
        accumulator_fragment_frozen_values::<F, EF, P>(profile, &pp, &task, |source| {
            corrupt.get(&encoded(source)).cloned()
        })
        .unwrap();
    assert!(!accumulator_values_valid::<F, P>(&pp, &task, &changed));
}
fn exercise_accumulator_frozen_fragment<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for version in [4, 5] {
        for backend in [Backend::FragmentedPipfri, Backend::FragmentedPipfriVirtual] {
            let spec = Specification {
                backend,
                roles: std::array::from_fn(|_| Role {
                    num_vars: 3,
                    width: 8,
                    queries: 8,
                    left_vars: None,
                    block_width: None,
                }),
                blowup: 2,
                fragment_vars: Some(2),
            };
            let profile = if version == 4 {
                ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
            } else {
                ClassicalProfile::new_atomic_columns::<F, EF>(spec)
            }
            .unwrap();
            match backend {
                Backend::FragmentedPipfri => {
                    exercise_accumulator_frozen_fragment_bundle::<F, EF, _>(
                        profile.fragmented_parameters::<F, EF>().unwrap(),
                    )
                }
                _ => exercise_accumulator_frozen_fragment_bundle::<F, EF, _>(
                    profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
                ),
            }
        }
    }
}
#[test]
fn accumulator_frozen_fragment_words() {
    exercise_accumulator_frozen_fragment::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_accumulator_frozen_fragment::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

fn replay_accumulator_word_graphs<F: NTTField>(
    history: &mut classical_history::History,
    task: &AccumulatorTask<F>,
    views: &std::collections::HashMap<Vec<u8>, std::sync::Arc<FrozenWordView>>,
    depth: usize,
) {
    fn expose(
        history: &mut classical_history::History,
        known: &FrozenWordView,
        root: Digest512,
        depth: usize,
        seen: &mut std::collections::HashSet<Digest512>,
    ) {
        if !seen.insert(root) {
            return;
        }
        let input = known.get(&root).unwrap();
        if depth > 0 {
            assert_eq!(input.len(), 128);
            for child in input.chunks_exact(64) {
                expose(
                    history,
                    known,
                    Digest512(child.try_into().unwrap()),
                    depth - 1,
                    seen,
                );
            }
        }
        history.expose(root, input.clone());
    }
    let mut seen = std::collections::HashSet::new();
    for source in &task.sources {
        expose(
            history,
            &views[&encoded(source)],
            source.1.root,
            depth,
            &mut seen,
        );
    }
}
fn accumulator_history_values<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    history: &classical_history::History,
) -> Option<(Vec<bool>, Vec<Vec<Vec<F>>>)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let view = |source: &(Digest512, Commitment<Digest512>)| history.view(source.1.root);
    match profile.specification().backend {
        Backend::Brakedown => accumulator_brakedown_frozen_values(profile, pp, task, view),
        Backend::Polyfrim | Backend::PolyfrimDictionary => {
            accumulator_polyfrim_frozen_values::<F, EF, P>(profile, pp, task, view)
        }
        _ => accumulator_fragment_frozen_values::<F, EF, P>(profile, pp, task, view),
    }
}
fn exercise_accumulator_late_history<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &AccumulatorTask<F>,
    views: &std::collections::HashMap<Vec<u8>, std::sync::Arc<FrozenWordView>>,
    depth: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let mut history = classical_history::History::default();
    let declaration: Vec<_> = task
        .sources
        .iter()
        .flat_map(|source| source.1.root.0)
        .collect();
    history.declare_input(&declaration);
    let first: Vec<_> = task
        .sources
        .iter()
        .map(|source| history.view(source.1.root).unwrap())
        .collect();
    let (_, before) = accumulator_history_values::<F, EF, P>(profile, pp, task, &history).unwrap();
    replay_accumulator_word_graphs(&mut history, task, views, depth);
    history.declare_input(&declaration);
    let (_, after) = accumulator_history_values::<F, EF, P>(profile, pp, task, &history).unwrap();
    assert_eq!(encoded(&before), encoded(&after));
    assert!(!accumulator_values_valid(pp, task, &after));
    assert!(history.availability_hits() > 0);
    for (source, original) in task.sources.iter().zip(first) {
        assert!(std::sync::Arc::ptr_eq(
            &original,
            &history.view(source.1.root).unwrap()
        ));
    }
}

fn exercise_accumulator_geometry_bundle<F, P>(
    bundle: ProfileParameters<P>,
    n: usize,
    lwe: usize,
    degree: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let pp = super::super::classical::parameters(&bundle);
    let profile = bundle.profile();
    let width = pp.accumulators[0].width();
    let shape = crate::packed_accumulator::Shape::new(n, lwe).unwrap();
    let initial = pp.accumulators[0].normalize_values((0..2 * n).map(|i| F::from(i + 5)).collect());
    let final_acc =
        pp.accumulators[0].normalize_values((0..2 * n).map(|i| F::from(3 * i + 7)).collect());
    let sources: Vec<_> = (0..7)
        .map(|slot| {
            let mut root = Digest512::default();
            root.0[..8].copy_from_slice(&((slot + 1) as u64).to_le_bytes());
            (
                accumulator_parameters(&pp, slot)
                    .unwrap()
                    .context()
                    .ok()
                    .unwrap(),
                Commitment { root },
            )
        })
        .collect();
    let task = AccumulatorTask {
        shape,
        initial,
        final_acc,
        sources,
        base: Vec::new(),
    };
    let mut binding = Vec::new();
    frame(
        &mut binding,
        1,
        P::ACCUMULATOR_DOMAIN,
        &encoded(&(&task.shape, &task.initial, &task.final_acc, &task.sources)),
    );
    exercise_accumulator_isolated::<F, P>(profile, &pp, &task, &binding);
    println!(
        "HB_ACCUMULATOR_MAP_GEOMETRY {{\"prime\":\"{}\",\"degree\":{},\"width\":{},\"n\":{},\"lwe\":{},\"backend\":\"{:?}\",\"version\":{},\"query_counts\":{:?},\"status\":\"passed\",\"word_authentication\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        degree,
        width,
        n,
        lwe,
        profile.specification().backend,
        profile.version(),
        task.shape.opening_counts(width).unwrap()
    );
}
fn exercise_accumulator_geometry_field<F, EF>(widths: &[usize])
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for &width in widths {
        for (n, lwe) in [(32, 21), (1024, 728)] {
            let cfg = Config::new::<F>(n, lwe, 8, 5, 1, 1).unwrap();
            for version in [4, 5] {
                for backend in [
                    Backend::Brakedown,
                    Backend::Polyfrim,
                    Backend::PolyfrimDictionary,
                    Backend::FragmentedPipfri,
                    Backend::FragmentedPipfriVirtual,
                ] {
                    let roles = cfg.variables(width).unwrap().map(|num_vars| Role {
                        num_vars,
                        width,
                        queries: 8,
                        left_vars: (backend == Backend::Brakedown).then_some(num_vars / 2),
                        block_width: (backend == Backend::Brakedown).then_some(width),
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
                    let candidate = if version == 4 {
                        ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
                    } else {
                        ClassicalProfile::new_atomic_columns::<F, EF>(spec)
                    };
                    if width < EF::D {
                        assert!(candidate.is_err());
                        println!(
                            "HB_ACCUMULATOR_MAP_GEOMETRY {{\"prime\":\"{}\",\"degree\":{},\"width\":{},\"n\":{},\"lwe\":{},\"backend\":\"{:?}\",\"version\":{},\"status\":\"rejected_width_lt_degree\",\"word_authentication\":false,\"security_qualified\":false}}",
                            F::MODULUS_VALUE,
                            EF::D,
                            width,
                            n,
                            lwe,
                            backend,
                            version
                        );
                        continue;
                    }
                    let profile = candidate.unwrap();
                    match backend {
                        Backend::Brakedown => exercise_accumulator_geometry_bundle::<F, _>(
                            profile.brakedown_parameters::<F, EF>().unwrap(),
                            n,
                            lwe,
                            EF::D,
                        ),
                        Backend::Polyfrim => exercise_accumulator_geometry_bundle::<F, _>(
                            profile.polyfrim_parameters::<F, EF>().unwrap(),
                            n,
                            lwe,
                            EF::D,
                        ),
                        Backend::PolyfrimDictionary => {
                            exercise_accumulator_geometry_bundle::<F, _>(
                                profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
                                n,
                                lwe,
                                EF::D,
                            )
                        }
                        Backend::FragmentedPipfri => exercise_accumulator_geometry_bundle::<F, _>(
                            profile.fragmented_parameters::<F, EF>().unwrap(),
                            n,
                            lwe,
                            EF::D,
                        ),
                        Backend::FragmentedPipfriVirtual => {
                            exercise_accumulator_geometry_bundle::<F, _>(
                                profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
                                n,
                                lwe,
                                EF::D,
                            )
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn babybear_accumulator_query_geometries() {
    exercise_accumulator_geometry_field::<algebra::BabyBear, algebra::BabyBearExetension>(&[8, 16]);
    exercise_accumulator_geometry_field::<algebra::BabyBear, algebra::BabyBearExtension5>(&[8, 16]);
    exercise_accumulator_geometry_field::<algebra::BabyBear, algebra::BabyBearExtension6>(&[8, 16]);
    exercise_accumulator_geometry_field::<algebra::BabyBear, algebra::BabyBearExtension8>(&[8, 16]);
}
#[test]
fn goldilocks_accumulator_query_geometries() {
    exercise_accumulator_geometry_field::<algebra::Goldilocks, algebra::GoldilocksExtension>(&[
        4, 8,
    ]);
    exercise_accumulator_geometry_field::<algebra::Goldilocks, algebra::GoldilocksExtension3>(&[
        4, 8,
    ]);
    exercise_accumulator_geometry_field::<algebra::Goldilocks, algebra::GoldilocksExtension4>(&[
        4, 8,
    ]);
    exercise_accumulator_geometry_field::<algebra::Goldilocks, algebra::GoldilocksExtension5>(&[
        4, 8,
    ]);
}

fn exercise_backend<F, EF>(width: usize, version: u32, backend: Backend)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use Backend::*;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let roles = cfg.variables(width).unwrap().map(|num_vars| Role {
        num_vars,
        width,
        queries: 8,
        left_vars: (backend == Brakedown).then_some(num_vars / 2),
        block_width: (backend == Brakedown).then_some(width),
    });
    let spec = Specification {
        backend,
        roles,
        blowup: 2,
        fragment_vars: matches!(backend, FragmentedPipfri | FragmentedPipfriVirtual).then_some(4),
    };
    let profile = match version {
        4 => ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec),
        5 => ClassicalProfile::new_atomic_columns::<F, EF>(spec),
        _ => panic!("unsupported prefix audit schedule"),
    }
    .unwrap();
    match backend {
        Brakedown => exercise_bundle::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap()),
        Polyfrim => exercise_bundle::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap()),
        PolyfrimDictionary => {
            exercise_bundle::<F, EF, _>(profile.polyfrim_dictionary_parameters::<F, EF>().unwrap())
        }
        FragmentedPipfri => {
            exercise_bundle::<F, EF, _>(profile.fragmented_parameters::<F, EF>().unwrap())
        }
        FragmentedPipfriVirtual => {
            exercise_bundle::<F, EF, _>(profile.fragmented_virtual_parameters::<F, EF>().unwrap())
        }
    }
}
fn exercise<F, EF>(width: usize, version: u32)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use Backend::*;
    for backend in [
        Brakedown,
        Polyfrim,
        PolyfrimDictionary,
        FragmentedPipfri,
        FragmentedPipfriVirtual,
    ] {
        exercise_backend::<F, EF>(width, version, backend);
    }
}

#[test]
fn babybear_outer_prefix_interpretation() {
    for version in [4, 5] {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, version);
    }
}
#[test]
fn goldilocks_outer_prefix_interpretation() {
    for version in [4, 5] {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, version);
    }
}

#[test]
fn babybear_decomposition_brakedown_columns() {
    exercise_backend::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 5, Backend::Brakedown);
}
#[test]
fn goldilocks_decomposition_brakedown_columns() {
    exercise_backend::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
        4,
        5,
        Backend::Brakedown,
    );
}

#[test]
fn babybear_lookup_fragment_helpers() {
    for backend in [Backend::FragmentedPipfri, Backend::FragmentedPipfriVirtual] {
        exercise_backend::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 5, backend);
    }
}
#[test]
fn goldilocks_lookup_fragment_helpers() {
    for backend in [Backend::FragmentedPipfri, Backend::FragmentedPipfriVirtual] {
        exercise_backend::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 5, backend);
    }
}

fn proposed_extension_receipt<F: NTTField, EF: AbstractExtensionField<F>>(
    body: &mut Vec<u8>,
    before: &mut Producers,
    label: &'static [u8],
    value: EF,
) -> [u8; 64] {
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let width = ((128 - (p - 1).leading_zeros()) as usize).div_ceil(8);
    let mut raw = Vec::new();
    for i in 0..EF::D {
        let coefficient: u128 = value
            .as_base_slice()
            .get(i)
            .copied()
            .unwrap_or_else(F::zero)
            .canonicalized()
            .value()
            .to_string()
            .parse()
            .unwrap();
        raw.extend_from_slice(&coefficient.to_le_bytes()[..width]);
    }
    let (phase_receipt, producer) = receipt(&raw);
    let fingerprint = phase_receipt[16..].try_into().unwrap();
    before.insert(fingerprint, producer);
    frame(body, 5, label, &phase_receipt);
    fingerprint
}
fn exercise_lookup_reciprocal_retries<F: NTTField + Serialize, EF: AbstractExtensionField<F>>() {
    let requests: Vec<_> = (0..2)
        .map(|_| crate::packed_extension_lookup::deferred::Request {
            config: crate::packed_tuple_lookup::Config::new(
                1,
                vec![
                    vec![F::zero(), F::one(), F::from(2)],
                    vec![F::one(), F::zero(), F::from(3)],
                ],
                2,
            )
            .unwrap(),
            source_slots: vec![0, 1, 2],
        })
        .collect();
    let mut body = Vec::new();
    let mut before = Producers::new();
    let mut expected = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        frame(
            &mut body,
            1,
            b"shared lookup challenge request",
            &encoded(&index),
        );
        for repetition in 0..2 {
            body.extend(lookup_hash_tail::<F, EF>());
            let hash = EF::from_base(F::from(repetition + 3));
            let fingerprint = proposed_extension_receipt::<F, EF>(
                &mut body,
                &mut before,
                b"extension tuple hash challenge",
                hash,
            );
            let table = compressed_lookup_table(request, hash);
            let mut valid = EF::one();
            while valid == EF::zero() || table.iter().any(|&value| valid + value == EF::zero()) {
                valid += EF::one();
            }
            for (rejected, r) in [EF::zero(), -table[0], valid].into_iter().enumerate() {
                body.extend(lookup_scalar_tail::<F, EF>(
                    b"extension tuple reciprocal challenge",
                ));
                let LookupChallengeBoundary::Pending(task) =
                    lookup_challenge_walk::<F, EF>(&requests, &body, &before).unwrap()
                else {
                    panic!("pending reciprocal expected")
                };
                assert_eq!(
                    (task.request, task.repetition, task.rejected),
                    (index, repetition, rejected)
                );
                assert_eq!(task.phase, LookupChallengePhase::Reciprocal);
                assert_eq!(task.accepted, expected);
                let mut missing = before.clone();
                missing.remove(&fingerprint);
                assert!(lookup_challenge_walk::<F, EF>(&requests, &body, &missing).is_none());
                proposed_extension_receipt::<F, EF>(
                    &mut body,
                    &mut before,
                    b"extension tuple reciprocal challenge",
                    r,
                );
            }
            expected.push((index, repetition, hash, valid));
            let mut wrong = body.clone();
            wrong.extend(lookup_scalar_tail::<F, EF>(
                b"extension tuple reciprocal challenge",
            ));
            assert!(
                lookup_challenge_walk::<F, EF>(&requests, &wrong, &before).is_none()
                    || matches!(lookup_challenge_walk::<F, EF>(&requests, &wrong, &before), Some(LookupChallengeBoundary::Complete { rest, .. }) if !rest.is_empty())
            );
        }
    }
    let LookupChallengeBoundary::Complete { accepted, rest } =
        lookup_challenge_walk::<F, EF>(&requests, &body, &before).unwrap()
    else {
        panic!("complete request schedule expected")
    };
    assert_eq!(accepted, expected);
    assert!(rest.is_empty());
    assert_eq!(accepted.len(), 4);
}
#[test]
fn babybear_lookup_reciprocal_retries() {
    exercise_lookup_reciprocal_retries::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_lookup_reciprocal_retries() {
    exercise_lookup_reciprocal_retries::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

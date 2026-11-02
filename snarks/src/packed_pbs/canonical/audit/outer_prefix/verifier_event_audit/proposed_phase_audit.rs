//! Proposed past coins, not an honest-execution replay or a security theorem.
use super::*;
use std::collections::HashMap;

/// Selected replay's input/read order, not a complete joint-oracle ledger.
#[derive(Clone, Default)]
pub(in super::super) struct RecordedStreams {
    prefixes: HashMap<Vec<u8>, Vec<u8>>,
    first_inputs: HashMap<Vec<u8>, usize>,
    output_history: HashMap<Vec<u8>, Vec<(usize, usize)>>,
    next_event: usize,
}
impl RecordedStreams {
    pub(in super::super) fn record_input(&mut self, input: &[u8]) -> Result<(), &'static str> {
        let next = self.next_event.checked_add(1).ok_or("reader event overflow")?;
        self.first_inputs.entry(input.to_vec()).or_insert(self.next_event);
        self.next_event = next;
        Ok(())
    }
    pub(in super::super) fn record(
        &mut self, input: &[u8], offset: u128, output: &[u8],
    ) -> Result<(), &'static str> {
        if !self.first_inputs.contains_key(input) {
            return Err("reader input not recorded");
        }
        let next = self.next_event.checked_add(1).ok_or("reader event overflow")?;
        let offset = usize::try_from(offset).map_err(|_| "reader offset overflow")?;
        let end = offset.checked_add(output.len()).ok_or("reader span overflow")?;
        let previous = self.prefixes.get(input).map_or(&[][..], Vec::as_slice);
        if offset > previous.len() {
            return Err("missing earlier reader bytes");
        }
        let overlap = output.len().min(previous.len() - offset);
        if output[..overlap] != previous[offset..offset + overlap] {
            return Err("inconsistent repeated reader bytes");
        }
        let prefix = self.prefixes.entry(input.to_vec()).or_default();
        if end > prefix.len() {
            prefix.extend_from_slice(&output[overlap..]);
        }
        let observations = self.output_history.entry(input.to_vec()).or_default();
        if observations.last().map_or(true, |(_, length)| *length < prefix.len()) {
            observations.push((self.next_event, prefix.len()));
        }
        self.next_event = next;
        Ok(())
    }
    fn prefix(&self, input: &[u8]) -> Option<&[u8]> {
        self.prefixes.get(input).map(Vec::as_slice)
    }
    fn first_query_precedes(&self, earlier: &[u8], later: &[u8]) -> Option<bool> {
        Some(self.first_inputs.get(earlier)? < self.first_inputs.get(later)?)
    }
    /// Actual consumed prefix strictly before another input's first query.
    /// Repeated queries and later reads cannot enlarge this frozen prefix.
    fn prefix_before_first_query(&self, input: &[u8], boundary: &[u8]) -> Option<&[u8]> {
        let boundary = self.first_inputs.get(boundary)?;
        let length = self.output_history.get(input)?.iter().rev()
            .find(|(event, _)| event < boundary)?.1;
        Some(&self.prefixes.get(input)?[..length])
    }
}

pub(super) struct ByteProposal<'a> {
    pub request: &'a [u8],
    pub proposed_raw: &'a [u8],
}
impl ByteProposal<'_> {
    /// Actual bytes must come from the trusted stream for `request`.
    pub(super) fn consistent_with(&self, actual_raw: &[u8]) -> bool {
        self.proposed_raw == actual_raw
    }
}

/// Inline bytes need no fingerprint producer. Enclosing admissibility and any
/// stronger seed/finish-link producer requirements remain caller obligations.
pub(super) fn byte_proposal<'a>(
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
    request: &'a [u8],
    label: &[u8],
    count: usize,
) -> Option<ByteProposal<'a>> {
    if !history.input_is_original_view(view, candidate) {
        return None;
    }
    let mut rest = candidate.strip_prefix(request)?;
    let raw = message(&mut rest, 3, label)?;
    if raw.len() != count || rest.is_empty() {
        return None;
    }
    let mut tail = Vec::new();
    frame(
        &mut tail,
        2,
        label,
        &u64::try_from(count).ok()?.to_le_bytes(),
    );
    request.ends_with(&tail).then_some(ByteProposal {
        request,
        proposed_raw: raw,
    })
}

pub(super) struct ByteRun<'a> {
    pub root_request: &'a [u8],
    pub prior: Vec<ByteProposal<'a>>,
    pub current_request: &'a [u8],
}

impl ByteRun<'_> {
    /// Check completed draw bytes at a separate post-answer boundary. This is
    /// deliberately not an admission condition for a proposed first-family
    /// input: its inline past coins may not have been queried at that time.
    /// The pending current answer is not required or inspected here.
    fn recorded_prior_outputs_match(
        &self,
        history: &classical_xof_history::History,
        answered: &classical_xof_history::Checkpoint,
    ) -> bool {
        history.query_exposure_at(answered, self.root_request).is_some()
            && self.prior.iter().all(|prior| {
                history.output_prefix_at(answered, prior.request)
                    .is_some_and(|output| output.starts_with(prior.proposed_raw))
            })
    }
}

/// Interpret an arbitrarily long no-message byte prefix. The caller establishes
/// its unique block start and termination rule from the enclosing protocol.
pub(super) fn byte_run_proposal<'a>(
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
    root_request: &'a [u8],
    label: &[u8],
    bytes_per_draw: usize,
) -> Option<ByteRun<'a>> {
    if !history.input_is_original_view(view, candidate) {
        return None;
    }
    let descriptor = u64::try_from(bytes_per_draw).ok()?.to_le_bytes();
    let mut tail = Vec::new();
    frame(&mut tail, 2, label, &descriptor);
    if !root_request.ends_with(&tail) {
        return None;
    }
    let mut rest = candidate.strip_prefix(root_request)?;
    let mut current = root_request;
    let mut prior = Vec::new();
    while !rest.is_empty() {
        let raw = message(&mut rest, 3, label)?;
        if raw.len() != bytes_per_draw {
            return None;
        }
        // No prover message, metadata change or alternate request is permitted.
        if message(&mut rest, 2, label)? != descriptor {
            return None;
        }
        prior.push(ByteProposal {
            request: current,
            proposed_raw: raw,
        });
        current = &candidate[..candidate.len() - rest.len()];
    }
    Some(ByteRun {
        root_request,
        prior,
        current_request: current,
    })
}

pub(super) struct ColumnRun<'a> {
    pub bytes: ByteRun<'a>,
    /// Ordered accepted draws, retaining repeats until sampling is complete.
    pub prior_indices: Vec<usize>,
    pub rejected: usize,
    pub pending_attempt: usize,
    pub max_completed_attempts: usize,
}

/// Replay the v4 column sampler's exact acceptance rule on proposed bytes.
/// No candidate cutoff is imposed; current query output remains unread.
pub(super) fn column_run_proposal<'a>(
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
    root_request: &'a [u8],
    length: usize,
    count: usize,
) -> Option<ColumnRun<'a>> {
    let bound = u64::try_from(length).ok().filter(|&n| n > 0)?;
    if count == 0 {
        return None;
    }
    let bytes = byte_run_proposal(
        history,
        view,
        candidate,
        root_request,
        b"mw unbiased column",
        8,
    )?;
    let limit = u64::MAX - u64::MAX % bound;
    let mut prior_indices = Vec::new();
    let (mut rejected, mut attempts, mut maximum) = (0, 0, 0);
    for prior in &bytes.prior {
        attempts += 1;
        let sample = u64::from_le_bytes(prior.proposed_raw.try_into().ok()?);
        if sample < limit {
            prior_indices.push(usize::try_from(sample % bound).ok()?);
            maximum = maximum.max(attempts);
            attempts = 0;
            if prior_indices.len() >= count {
                return None;
            }
        } else {
            rejected += 1;
        }
    }
    Some(ColumnRun {
        bytes,
        prior_indices,
        rejected,
        pending_attempt: attempts + 1,
        max_completed_attempts: maximum,
    })
}

/// Select the maximal trailing v4 byte run from frame boundaries, rather than
/// allowing a caller to reset its accepted-draw counter at a descendant request.
/// Whole-stage syntax, trusted dimensions and source authentication are separate.
fn canonical_column_root_request(candidate: &[u8]) -> Option<&[u8]> {
    let label = b"mw unbiased column";
    let descriptor = 8u64.to_le_bytes();
    let mut rest = candidate;
    let mut root_end = None;
    let mut awaiting_response = false;
    while !rest.is_empty() {
        let kind = *take(&mut rest, 1)?.first()?;
        let frame_label = sized(&mut rest)?;
        let body = sized(&mut rest)?;
        if kind == 2 && frame_label == label && body == descriptor {
            // Only a matching inline response can connect two draw requests.
            if !awaiting_response {
                root_end = Some(candidate.len() - rest.len());
            }
            awaiting_response = false;
        } else if kind == 3
            && frame_label == label
            && body.len() == 8
            && root_end.is_some()
            && !awaiting_response
        {
            awaiting_response = true;
        } else {
            root_end = None;
            awaiting_response = false;
        }
    }
    if awaiting_response {
        return None;
    }
    Some(&candidate[..root_end?])
}

pub(super) fn canonical_column_run_proposal<'a>(
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
    length: usize,
    count: usize,
) -> Option<ColumnRun<'a>> {
    let root = canonical_column_root_request(candidate)?;
    column_run_proposal(history, view, candidate, root, length, count)
}

pub(super) struct LinearColumnRun<'a, F> {
    pub columns: ColumnRun<'a>,
    /// Prefix before the response message; the enclosing stage authenticates it.
    pub stage_prefix: &'a [u8],
    pub test: Vec<F>,
    pub evaluation: Vec<F>,
}

/// Bind a canonical v4 scalar run to its immediately preceding response body.
/// Trusted cells/domain/count and authentication of stage_prefix remain external.
pub(super) fn linear_column_run_proposal<'a, F: NTTField + Serialize + DeserializeOwned>(
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
    length: usize,
    count: usize,
    cells: usize,
) -> Option<LinearColumnRun<'a, F>> {
    let columns = canonical_column_run_proposal(history, view, candidate, length, count)?;
    let mut request_tail = Vec::new();
    frame(
        &mut request_tail,
        2,
        b"mw unbiased column",
        &8u64.to_le_bytes(),
    );
    let before = columns
        .bytes
        .root_request
        .strip_suffix(request_tail.as_slice())?;
    let mut rest = before;
    let mut last = None;
    while !rest.is_empty() {
        let start = before.len() - rest.len();
        let kind = *take(&mut rest, 1)?.first()?;
        let label = sized(&mut rest)?;
        let body = sized(&mut rest)?;
        last = Some((start, kind, label, body));
    }
    let (start, kind, label, mut body) = last?;
    if kind != 1 || label != b"mw linear responses" || cells == 0 || cells > body.len() {
        return None;
    }
    let test = vector::<F>(&mut body, cells)?;
    // Each canonical field element needs at least one serialized byte.
    if cells > body.len() {
        return None;
    }
    let evaluation = vector::<F>(&mut body, cells)?;
    if !body.is_empty() {
        return None;
    }
    Some(LinearColumnRun {
        columns,
        stage_prefix: &before[..start],
        test,
        evaluation,
    })
}

struct PrimaryColumnRun<'a, F> {
    opening: FirstOpening<F>,
    row: FieldProposal<'a, F>,
    response: LinearColumnRun<'a, F>,
}

/// Bind the first primary v4 run to the interpreted relation and PCS task.
/// Proposed field/byte stream consistency and frozen word assignment remain
/// separate obligations; the first-query producer view is never enlarged.
fn primary_column_run_proposal<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    history: &'a classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
) -> Option<PrimaryColumnRun<'a, F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.version() != 4 || profile.specification().backend != Backend::Brakedown {
        return None;
    }
    profile.validate_field::<F, EF>().ok()?;
    let role = &profile.specification().roles[0];
    let cols =
        1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(role.left_vars?)?).ok()?)?;
    let blocks = cols
        .div_ceil(role.block_width?)
        .checked_next_power_of_two()?;
    let domain = blocks.checked_mul(profile.specification().blowup)?.max(32);
    let cells = cols.checked_mul(role.width)?;
    let response =
        linear_column_run_proposal::<F>(history, view, candidate, domain, role.queries, cells)?;
    let known = history.producers(view)?;
    let (opening, rest) = first_opening_prefix::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        response.stage_prefix,
        &known,
    )?;
    if opening.query.len() != role.num_vars || opening.values.first()?.len() != role.width {
        return None;
    }
    let (row_tail, count) = brakedown_first_tail::<F>(profile, &opening)?;
    let mut rest = rest.strip_prefix(row_tail.as_slice())?;
    let request = &candidate[..response.stage_prefix.len().checked_sub(rest.len())?];
    let receipt = message(&mut rest, 5, b"mw random linear test")?;
    if !rest.is_empty() {
        return None;
    }
    let row = field_proposal::<F>(
        history,
        view,
        candidate,
        request,
        b"mw random linear test",
        count,
        receipt,
    )?;
    Some(PrimaryColumnRun {
        opening,
        row,
        response,
    })
}

struct PrimaryAtomicColumnQuery<'a, F> {
    request: &'a [u8],
    opening: FirstOpening<F>,
    row: FieldProposal<'a, F>,
    row_state: ScalarRowState,
    fixed_columns: Vec<Vec<F>>,
    failures: ScalarColumnFailures,
    domain: usize,
    queries: usize,
}

fn primary_atomic_column_query<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    history: &'a classical_xof_history::History,
    view: &classical_xof_history::View,
    input: &'a [u8],
    words: &classical_history::History,
) -> Option<PrimaryAtomicColumnQuery<'a, F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.version() != 5
        || profile.specification().backend != Backend::Brakedown
        || !history.input_is_original_view(view, input)
    {
        return None;
    }
    profile.validate_field::<F, EF>().ok()?;
    let known = history.producers(view)?;
    let columns = brakedown_column_query::<F, EF, P>(profile, pp, setup, statement, input, &known)?;
    let (opening, rest) =
        first_opening_prefix::<F, EF, P>(profile, pp, setup, statement, input, &known)?;
    let (tail, count) = brakedown_first_tail::<F>(profile, &opening)?;
    let mut rest = rest.strip_prefix(tail.as_slice())?;
    let request = &input[..input.len().checked_sub(rest.len())?];
    let receipt = message(&mut rest, 5, b"mw random linear test")?;
    let row = field_proposal::<F>(
        history,
        view,
        input,
        request,
        b"mw random linear test",
        count,
        receipt,
    )?;
    if row.coefficients != columns.random {
        return None;
    }
    let (parameters, fixed) = primary_task_fixed_word(profile, &columns.opening, words)?;
    let claim = columns.opening.values.get(columns.opening.selected)?;
    let row_state = scalar_row_state(
        &parameters,
        &fixed,
        &columns.opening.query,
        &row.coefficients,
        claim,
    )?;
    let failures = scalar_column_failures(
        &parameters,
        &fixed,
        &columns.opening.query,
        &row.coefficients,
        &columns.test,
        &columns.evaluation,
        claim,
    )?;
    Some(PrimaryAtomicColumnQuery {
        request: input,
        opening: columns.opening,
        row,
        row_state,
        fixed_columns: fixed,
        failures,
        domain: columns.domain,
        queries: profile.specification().roles[0].queries,
    })
}

struct ColumnStreamOutput<'a> {
    request: &'a [u8],
    raw: &'a [u8],
}
struct AtomicColumnTransition {
    ordered_indices: Vec<usize>,
    bad_after_sampling: bool,
}
fn primary_atomic_column_transition<F>(
    before: &PrimaryAtomicColumnQuery<'_, F>,
    output: &ColumnStreamOutput<'_>,
) -> Option<AtomicColumnTransition> {
    if output.request != before.request
        || output.raw.len() != before.queries.checked_mul(8)?
        || !before.domain.is_power_of_two()
        || before.failures.rejecting.len() != before.domain
    {
        return None;
    }
    let mask = u64::try_from(before.domain.checked_sub(1)?).ok()?;
    let ordered_indices = output
        .raw
        .chunks_exact(8)
        .map(|chunk| usize::try_from(u64::from_le_bytes(chunk.try_into().ok()?) & mask).ok())
        .collect::<Option<Vec<_>>>()?;
    let bad_after_sampling = !before.failures.claimed_value_matches
        || ordered_indices
            .iter()
            .any(|&index| before.failures.rejecting[index]);
    Some(AtomicColumnTransition {
        ordered_indices,
        bad_after_sampling,
    })
}

/// Conditional first-primary algebraic-path coupling. Stream provenance and
/// authentication remain caller obligations; this does not certify acceptance.
struct PrimaryAtomicPath {
    false_relation: bool,
    row_escape: bool,
    column_miss: bool,
    after: AtomicColumnTransition,
}
fn primary_atomic_path_transition<F: NTTField>(
    row_before: &PrimaryRowQuery<'_, F>,
    row_output: &RowStreamOutput<'_, F>,
    column_before: &PrimaryAtomicColumnQuery<'_, F>,
    column_output: &ColumnStreamOutput<'_>,
) -> Option<PrimaryAtomicPath> {
    if !field_row_proposal_consistent(row_before, row_output, &column_before.row)
        || row_before.fixed_columns != column_before.fixed_columns
    {
        return None;
    }
    let row_after = primary_row_transition(row_before, row_output)?;
    // Exact row request binding fixes the trusted opening geometry and task.
    // Compare all computed state fields as well as the completed source word.
    if row_after != column_before.row_state {
        return None;
    }
    if row_after.bad_after_rows
        && column_before.failures.claimed_value_matches
        && column_before
            .failures
            .rejecting
            .iter()
            .filter(|&&bad| bad)
            .count()
            < row_after.minimum_rejecting_columns
    {
        return None;
    }
    let after = primary_atomic_column_transition(column_before, column_output)?;
    let row_escape = row_before.false_relation && !row_after.bad_after_rows;
    let column_miss = row_after.bad_after_rows && !after.bad_after_sampling;
    Some(PrimaryAtomicPath {
        false_relation: row_before.false_relation,
        row_escape,
        column_miss,
        after,
    })
}

/// Couple the algebraic transition to trusted stream prefixes already recorded
/// at an explicit post-answer boundary. This boundary is not used to choose
/// the earlier bad set. It establishes recorded byte provenance only, not an
/// ideal-stream model or complete production reader instrumentation.
fn primary_recorded_atomic_path_transition<F: NTTField>(
    history: &classical_xof_history::History,
    answered: &classical_xof_history::Checkpoint,
    row_before: &PrimaryRowQuery<'_, F>,
    row_output: &RowStreamOutput<'_, F>,
    column_before: &PrimaryAtomicColumnQuery<'_, F>,
    column_output: &ColumnStreamOutput<'_>,
) -> Option<PrimaryAtomicPath> {
    if !history
        .output_prefix_at(answered, row_output.request)?
        .starts_with(row_output.consumed_raw)
        || !history
            .output_prefix_at(answered, column_output.request)?
            .starts_with(column_output.raw)
    {
        return None;
    }
    primary_atomic_path_transition(row_before, row_output, column_before, column_output)
}

struct AuthenticatedSourceMismatch {
    index: usize,
    status: Option<classical_history::FrozenPathStatus>,
}
struct AuthenticatedPrimaryPath {
    path: PrimaryAtomicPath,
    /// Valid root authentication does not by itself establish equality with
    /// the earlier completed word. Keep every unresolved source index explicit.
    source_mismatches: Vec<AuthenticatedSourceMismatch>,
}
fn primary_atomic_authenticated_columns<F: NTTField + Serialize>(
    before: &PrimaryAtomicColumnQuery<'_, F>,
    after: &AtomicColumnTransition,
    columns: &[pcs::matrix_weighted::Column<F, Digest512>],
) -> Option<Vec<usize>> {
    let root = &before.opening.sources.get(before.opening.selected)?.1.root;
    let mut indices = after.ordered_indices.clone();
    indices.sort_unstable();
    indices.dedup();
    if indices.is_empty() || columns.len() != indices.len() {
        return None;
    }
    let path_len = usize::try_from(before.domain.ilog2())
        .ok()?
        .checked_add(1)?;
    let mut mismatches = Vec::new();
    for (&index, column) in indices.iter().zip(columns) {
        let fixed = before.fixed_columns.get(index)?;
        if column.values.len() != fixed.len() || column.path.len() != path_len {
            return None;
        }
        let mut raw = b"HasteBoots/mw-column/v1".to_vec();
        raw.extend(encoded(&column.values));
        let leaf = Digest512(Sha512::digest(&raw).into());
        if column.path.first()? != &leaf
            || !pcs::utils::merkle_tree::MerkleTree::<Sha512>::check(root, index, &column.path)
        {
            return None;
        }
        if &column.values != fixed {
            mismatches.push(index);
        }
    }
    Some(mismatches)
}
fn primary_authenticated_path_transition<F: NTTField + Serialize>(
    history: &classical_xof_history::History,
    answered: &classical_xof_history::Checkpoint,
    row_before: &PrimaryRowQuery<'_, F>,
    row_output: &RowStreamOutput<'_, F>,
    column_before: &PrimaryAtomicColumnQuery<'_, F>,
    column_output: &ColumnStreamOutput<'_>,
    columns: &[pcs::matrix_weighted::Column<F, Digest512>],
    words: &classical_history::History,
) -> Option<AuthenticatedPrimaryPath> {
    let path = primary_recorded_atomic_path_transition(
        history, answered, row_before, row_output, column_before, column_output,
    )?;
    let mismatches = primary_atomic_authenticated_columns(column_before, &path.after, columns)?;
    let root = column_before
        .opening
        .sources
        .get(column_before.opening.selected)?
        .1
        .root;
    let mut indices = path.after.ordered_indices.clone();
    indices.sort_unstable();
    indices.dedup();
    let mut source_mismatches = Vec::new();
    for index in mismatches {
        let column = columns.get(indices.binary_search(&index).ok()?)?;
        let mut input = b"HasteBoots/mw-column/v1".to_vec();
        input.extend(encoded(&column.values));
        source_mismatches.push(AuthenticatedSourceMismatch {
            index,
            status: words.frozen_path_status(root, index, &column.path, &input),
        });
    }
    Some(AuthenticatedPrimaryPath {
        path,
        source_mismatches,
    })
}

pub(in super::super) fn exercise_primary_atomic_column_binding<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    row_request: &[u8],
    column_request: &[u8],
    known: &Producers,
    source_table: &PackedTable<F>,
    actual_row_coins: &[F],
    actual_column_raw: &[u8],
    observed_streams: &RecordedStreams,
    sampled: &[usize],
    packet: &pcs::matrix_weighted::Opening<F, Digest512>,
    mut opening_prefix: impl FnMut() -> Transcript<F>,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let transported = packet.columns.as_slice();
    let (root, mut words) = complete_primary_source_graph(profile, source_table);
    let mut history = classical_xof_history::History::default();
    for (digest, producer) in known {
        assert_eq!(*digest, shake64(producer));
        history.query(producer, *digest).unwrap();
        words.declare_input(producer);
    }
    words.declare_input(column_request);
    let column_boundary = history.checkpoint();
    let view = history
        .query_with_actor(
            column_request,
            shake64(column_request),
            classical_xof_history::QueryActor::Adversary,
        )
        .unwrap();
    {
        let before = primary_atomic_column_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &history,
            &view,
            column_request,
            &words,
        )
        .unwrap();
        assert_eq!(before.opening.sources[0].1.root, root);
        assert_eq!(before.row.request, row_request);
        assert!(!before.row.request_was_queried);
        assert!(before.row_state.false_relation && before.row_state.bad_after_rows);
        if before.failures.claimed_value_matches {
            assert!(
                before.failures.rejecting.iter().filter(|&&bad| bad).count()
                    >= before.row_state.minimum_rejecting_columns
            );
        }
        let output = ColumnStreamOutput {
            request: column_request,
            raw: actual_column_raw,
        };
        let after = primary_atomic_column_transition(&before, &output).unwrap();
        assert_eq!(after.ordered_indices, sampled);
        let mut distinct = sampled.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            after.bad_after_sampling,
            !before.failures.claimed_value_matches
                || distinct
                    .iter()
                    .any(|&index| before.failures.rejecting[index])
        );
        let duplicate_raw = vec![0; actual_column_raw.len()];
        let duplicate = primary_atomic_column_transition(
            &before,
            &ColumnStreamOutput {
                request: column_request,
                raw: &duplicate_raw,
            },
        )
        .unwrap();
        assert_eq!(duplicate.ordered_indices, vec![0; before.queries]);
        assert!(
            primary_atomic_column_transition(
                &before,
                &ColumnStreamOutput {
                    request: b"wrong",
                    raw: actual_column_raw
                }
            )
            .is_none()
        );
        assert!(
            primary_atomic_column_transition(
                &before,
                &ColumnStreamOutput {
                    request: column_request,
                    raw: &actual_column_raw[..actual_column_raw.len() - 1]
                }
            )
            .is_none()
        );
    }
    assert!(matches!(
        history.query_exposure_at(&column_boundary, column_request),
        Some(classical_xof_history::QueryExposure::Fresh)
    ));
    let later_column_boundary = history.checkpoint();
    let Some(classical_xof_history::QueryExposure::PreviouslyQueried { first }) =
        history.query_exposure_at(&later_column_boundary, column_request)
    else {
        panic!("replayed column phase must retain its first query");
    };
    assert!(history.input_is_original_view(&first, column_request));
    let first_ledger =
        primary_query_ledger::<F, EF, P>(profile, pp, setup, statement, &history, &view, &words)
            .unwrap();
    assert_eq!(first_ledger.row_candidates, 0);
    assert_eq!(first_ledger.syntactic_families, 1);
    assert_eq!(first_ledger.admitted_families, 1);
    assert_eq!(first_ledger.bad_families, 1);
    let repeat = history
        .query_with_actor(
            column_request,
            shake64(column_request),
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    let repeated_ledger =
        primary_query_ledger::<F, EF, P>(profile, pp, setup, statement, &history, &repeat, &words)
            .unwrap();
    assert_eq!(
        repeated_ledger.distinct_inputs,
        first_ledger.distinct_inputs
    );
    assert_eq!(repeated_ledger.syntactic_families, 1);
    let row_boundary = history.checkpoint();
    let row_view = history
        .query_with_actor(
            row_request,
            shake64(row_request),
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    assert_eq!(
        history.first_query_actor(&row_view, row_request),
        Some(classical_xof_history::QueryActor::Verifier)
    );
    assert_eq!(
        history.first_query_actor(&view, column_request),
        Some(classical_xof_history::QueryActor::Adversary)
    );
    assert!(matches!(
        history.query_exposure_at(&row_boundary, row_request),
        Some(classical_xof_history::QueryExposure::Fresh)
    ));
    let row_before = primary_row_query_state::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &row_view,
        row_request,
        &words,
    )
    .unwrap();
    let raw = observed_streams.prefix(row_request).expect("observed row reader").to_vec();
    assert_eq!(observed_streams.prefix(column_request), Some(actual_column_raw));
    assert_eq!(observed_streams.first_query_precedes(row_request, column_request), Some(true));
    assert_eq!(observed_streams.prefix_before_first_query(row_request, column_request), Some(raw.as_slice()));
    assert!(observed_streams.prefix_before_first_query(column_request, column_request).is_none());
    let actual = RowStreamOutput {
        request: row_request,
        coefficients: actual_row_coins,
        consumed_raw: &raw,
    };
    let short_outputs = history.checkpoint();
    let row_completion = shake64(row_request);
    history
        .query_output_prefix(
            row_request,
            if raw.len() < 64 { &row_completion } else { &raw },
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    let column_completion = shake64(column_request);
    history
        .query_output_prefix(
            column_request,
            if actual_column_raw.len() < 64 {
                &column_completion
            } else {
                actual_column_raw
            },
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    let recorded_outputs = history.checkpoint();
    let mut before = primary_atomic_column_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &view,
        column_request,
        &words,
    )
    .unwrap();
    let column_output = ColumnStreamOutput {
        request: column_request,
        raw: actual_column_raw,
    };
    let path = primary_recorded_atomic_path_transition(
        &history, &recorded_outputs, &row_before, &actual, &before, &column_output,
    ).unwrap();
    if raw.len() > 64 || actual_column_raw.len() > 64 {
        assert!(primary_recorded_atomic_path_transition(
            &history, &short_outputs, &row_before, &actual, &before, &column_output,
        ).is_none());
    }
    assert!(primary_recorded_atomic_path_transition(
        &classical_xof_history::History::default(), &recorded_outputs,
        &row_before, &actual, &before, &column_output,
    ).is_none());
    // The enclosing adversarial fixture changes the sumcheck suffix but
    // retains the old opening packet. Its paths belong to a different request.
    assert!(
        primary_authenticated_path_transition(
            &history,
            &recorded_outputs,
            &row_before,
            &actual,
            &before,
            &column_output,
            transported,
            &words,
        )
        .is_none()
    );
    let leaves: Vec<_> = before
        .fixed_columns
        .iter()
        .map(|column| {
            let mut raw = b"HasteBoots/mw-column/v1".to_vec();
            raw.extend(encoded(column));
            Digest512(Sha512::digest(&raw).into())
        })
        .collect();
    let mut tree = pcs::utils::merkle_tree::MerkleTree::<Sha512>::new();
    tree.generate(&leaves);
    assert_eq!(tree.root, root);
    let mut indices = sampled.to_vec();
    indices.sort_unstable();
    indices.dedup();
    let rebound: Vec<_> = indices
        .iter()
        .map(|&index| pcs::matrix_weighted::Column {
            values: before.fixed_columns[index].clone(),
            path: tree.query(index),
        })
        .collect();
    let transported = rebound.as_slice();
    let authenticated = primary_authenticated_path_transition(
        &history,
        &recorded_outputs,
        &row_before,
        &actual,
        &before,
        &column_output,
        transported,
        &words,
    )
    .unwrap();
    // Power-of-two masking ignores this high bit: the changed stream has the
    // same indices and valid paths, but is not the recorded oracle output.
    assert!(u64::try_from(before.domain).unwrap() < (1u64 << 63));
    let mut unrecorded_raw = actual_column_raw.to_vec();
    unrecorded_raw[7] ^= 0x80;
    let unrecorded_output = ColumnStreamOutput {
        request: column_request,
        raw: &unrecorded_raw,
    };
    let unrecorded_path = primary_atomic_path_transition(
        &row_before, &actual, &before, &unrecorded_output,
    ).unwrap();
    assert_eq!(unrecorded_path.after.ordered_indices, sampled);
    assert!(primary_atomic_authenticated_columns(
        &before, &unrecorded_path.after, transported,
    ).unwrap().is_empty());
    assert!(primary_authenticated_path_transition(
        &history, &recorded_outputs, &row_before, &actual, &before,
        &unrecorded_output, transported, &words,
    ).is_none());
    if raw.len() > 64 || actual_column_raw.len() > 64 {
        assert!(primary_authenticated_path_transition(
            &history, &short_outputs, &row_before, &actual, &before,
            &column_output, transported, &words,
        ).is_none());
    }
    assert!(primary_authenticated_path_transition(
        &classical_xof_history::History::default(), &recorded_outputs,
        &row_before, &actual, &before, &column_output, transported, &words,
    ).is_none());
    let mut rebound_packet = packet.clone();
    rebound_packet.columns = rebound.clone();
    let (parameters, _) = primary_task_fixed_word(profile, &before.opening, &words).unwrap();
    let production = parameters.verify::<F, Sha512>(
        &mut opening_prefix(),
        &before.opening.sources[before.opening.selected].1,
        &before.opening.query,
        &before.opening.values[before.opening.selected],
        &rebound_packet,
    );
    assert_eq!(
        production.is_err(),
        authenticated.path.after.bad_after_sampling
    );
    if let Err(error) = production {
        assert!(
            matches!(
                error.0,
                "linear response inconsistent with committed block" | "incorrect opening value"
            ),
            "authentication must succeed before the scalar predicate rejects: {}",
            error.0
        );
    }
    for (&index, column) in indices.iter().zip(transported) {
        let mut input = b"HasteBoots/mw-column/v1".to_vec();
        input.extend(encoded(&column.values));
        assert_eq!(
            words.frozen_path_status(root, index, &column.path, &input),
            Some(classical_history::FrozenPathStatus::Known)
        );
    }
    let mut incomplete = classical_history::History::default();
    incomplete.declare_input(column_request);
    let unknown_row = primary_row_query_state::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &row_view,
        row_request,
        &incomplete,
    )
    .unwrap();
    let unknown_column = primary_atomic_column_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &view,
        column_request,
        &incomplete,
    )
    .unwrap();
    let source_gap = primary_authenticated_path_transition(
        &history,
        &recorded_outputs,
        &unknown_row,
        &actual,
        &unknown_column,
        &column_output,
        transported,
        &incomplete,
    )
    .unwrap();
    assert!(!source_gap.source_mismatches.is_empty());
    for mismatch in &source_gap.source_mismatches {
        assert!(indices.binary_search(&mismatch.index).is_ok());
        assert!(matches!(&mismatch.status,
            Some(classical_history::FrozenPathStatus::Missing {
                digest, declared_at: 0, answered_at: None, root_boundary: 0, ..
            }) if *digest == root));
    }
    let root_input = words.known().get(&root).unwrap().clone();
    incomplete.expose(root, root_input);
    assert_eq!(incomplete.availability_hits(), 1);
    let source_gap_late = primary_authenticated_path_transition(
        &history,
        &recorded_outputs,
        &unknown_row,
        &actual,
        &unknown_column,
        &column_output,
        transported,
        &incomplete,
    )
    .unwrap();
    assert_eq!(
        source_gap_late.source_mismatches.len(),
        source_gap.source_mismatches.len()
    );
    for mismatch in &source_gap_late.source_mismatches {
        assert!(matches!(&mismatch.status,
            Some(classical_history::FrozenPathStatus::Missing {
                digest, declared_at: 0, answered_at: Some(1), root_boundary: 0, ..
            }) if *digest == root));
    }
    assert!(authenticated.source_mismatches.is_empty());
    assert_eq!(authenticated.path.after.ordered_indices, sampled);
    assert_eq!(
        authenticated.path.after.bad_after_sampling,
        path.after.bad_after_sampling
    );
    assert!(
        primary_authenticated_path_transition(
            &history,
            &recorded_outputs,
            &row_before,
            &actual,
            &before,
            &column_output,
            &[],
            &words
        )
        .is_none()
    );
    let mut corrupted = transported.to_vec();
    corrupted[0].path.clear();
    assert!(
        primary_authenticated_path_transition(
            &history,
            &recorded_outputs,
            &row_before,
            &actual,
            &before,
            &column_output,
            &corrupted,
            &words,
        )
        .is_none()
    );
    corrupted = transported.to_vec();
    corrupted[0].values[0] += F::one();
    assert!(
        primary_authenticated_path_transition(
            &history,
            &recorded_outputs,
            &row_before,
            &actual,
            &before,
            &column_output,
            &corrupted,
            &words,
        )
        .is_none()
    );
    let index = *sampled.iter().min().unwrap();
    before.fixed_columns[index][0] += F::one();
    assert_eq!(
        primary_atomic_authenticated_columns(&before, &path.after, transported).unwrap(),
        vec![index]
    );
    before.fixed_columns[index][0] -= F::one();
    assert!(path.false_relation);
    assert_eq!(path.after.ordered_indices, sampled);
    assert!(
        !path.false_relation
            || path.after.bad_after_sampling
            || path.row_escape
            || path.column_miss
    );
    assert!(!(path.row_escape && path.column_miss));
    assert!(
        primary_atomic_path_transition(
            &row_before,
            &actual,
            &before,
            &ColumnStreamOutput {
                request: b"wrong column path",
                raw: actual_column_raw
            },
        )
        .is_none()
    );
    assert!(
        primary_atomic_path_transition(
            &row_before,
            &RowStreamOutput {
                request: b"wrong row path",
                coefficients: actual_row_coins,
                consumed_raw: &raw
            },
            &before,
            &column_output,
        )
        .is_none()
    );
    // Matching request/receipt and row flags do not authorize a different
    // source completion. Preserve those fields while changing the word.
    before.fixed_columns[0][0] += F::one();
    assert!(
        primary_atomic_path_transition(&row_before, &actual, &before, &column_output).is_none()
    );
    before.fixed_columns[0][0] -= F::one();
    before.row_state.minimum_rejecting_columns += 1;
    assert!(
        primary_atomic_path_transition(&row_before, &actual, &before, &column_output).is_none()
    );
    before.row_state.minimum_rejecting_columns -= 1;
    assert!(
        primary_atomic_path_transition(&row_before, &actual, &before, &column_output).is_some()
    );
    assert!(field_row_proposal_consistent(
        &row_before,
        &actual,
        &before.row
    ));
    assert_eq!(
        primary_row_transition(&row_before, &actual)
            .unwrap()
            .bad_after_rows,
        before.row_state.bad_after_rows
    );
    assert!(
        primary_atomic_column_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &history,
            &row_view,
            column_request,
            &words
        )
        .is_none()
    );
    let after_rows = primary_query_ledger::<F, EF, P>(
        profile, pp, setup, statement, &history, &row_view, &words,
    )
    .unwrap();
    assert_eq!(after_rows.admitted_rows, 1);
    assert_eq!(after_rows.false_rows, 1);
    assert_eq!(after_rows.admitted_families, 1);
    assert_eq!(after_rows.bad_families, 1);
    assert_eq!(after_rows.false_row_actors.verifier, 1);
    assert_eq!(after_rows.false_row_actors.adversary, 0);
    assert_eq!(after_rows.bad_family_actors.adversary, 1);
    assert_eq!(after_rows.bad_family_actors.verifier, 0);
    assert_eq!(after_rows.input_actors.adversary, 1);
    assert_eq!(after_rows.input_actors.verifier, 1);
    assert!(after_rows.input_actors.unknown > 0);

    let old =
        primary_query_ledger::<F, EF, P>(profile, pp, setup, statement, &history, &view, &words)
            .unwrap();
    assert_eq!(old.row_candidates, 0);
    // Preserve the trusted byte-count suffix while corrupting the header.
    let mut wrong_header = column_request.to_vec();
    wrong_header[0] ^= 1;
    history
        .query(&wrong_header, shake64(&wrong_header))
        .unwrap();
    // Preserve the byte-count suffix while changing the index domain.
    let mut domain_frame = Vec::new();
    let role = &profile.specification().roles[0];
    let domain = primary_atomic_column_query::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &view,
        column_request,
        &words,
    )
    .unwrap()
    .domain;
    frame(
        &mut domain_frame,
        1,
        b"index domain",
        &(domain as u64).to_le_bytes(),
    );
    let mut byte_tail = Vec::new();
    frame(
        &mut byte_tail,
        2,
        b"mw atomic column block v5",
        &((role.queries * 8) as u64).to_le_bytes(),
    );
    let offset = column_request.len() - byte_tail.len() - domain_frame.len();
    assert_eq!(
        &column_request[offset..offset + domain_frame.len()],
        &domain_frame
    );
    let mut wrong_domain = column_request.to_vec();
    wrong_domain[offset + domain_frame.len() - 8] ^= 1;
    let last = history
        .query(&wrong_domain, shake64(&wrong_domain))
        .unwrap();
    let classified =
        primary_query_ledger::<F, EF, P>(profile, pp, setup, statement, &history, &last, &words)
            .unwrap();
    assert_eq!(classified.syntactic_families, 3);
    assert_eq!(classified.admitted_families, 1);
    assert_eq!(classified.unclassified_families, 2);
    assert_eq!(classified.header_mismatch_families, 1);
    assert_eq!(classified.other_unclassified_families, 1);
    let (receipt, producer) = receipt(&raw);
    let digest: [u8; 64] = receipt[16..].try_into().unwrap();
    let mut late = classical_xof_history::History::default();
    for (key, input) in known {
        if *key != digest {
            late.query(input, *key).unwrap();
        }
    }
    let early = late.query(column_request, shake64(column_request)).unwrap();
    assert!(
        primary_atomic_column_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &late,
            &early,
            column_request,
            &words
        )
        .is_none()
    );
    assert!(matches!(
        field_fingerprint_availability(&late, &early, column_request),
        Some(FieldFingerprintAvailability::Missing(_))
    ));
    late.query(&producer, digest).unwrap();
    assert!(late.availability_hits() > 0);
    let repeated = late.query(column_request, shake64(column_request)).unwrap();
    assert!(
        primary_atomic_column_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &late,
            &repeated,
            column_request,
            &words
        )
        .is_none()
    );
    let boundary_input = b"v5 ledger boundary after late receipt";
    let boundary = late.query(boundary_input, shake64(boundary_input)).unwrap();
    let late_ledger =
        primary_query_ledger::<F, EF, P>(profile, pp, setup, statement, &late, &boundary, &words)
            .unwrap();
    assert_eq!(late_ledger.syntactic_families, 1);
    assert_eq!(late_ledger.admitted_families, 0);
    assert_eq!(late_ledger.missing_receipt_families, 1);
    let mut malformed = column_request.to_vec();
    *malformed.last_mut().unwrap() ^= 1;
    let wrong = late.query(&malformed, shake64(&malformed)).unwrap();
    assert!(
        primary_atomic_column_query::<F, EF, P>(
            profile, pp, setup, statement, &late, &wrong, &malformed, &words
        )
        .is_none()
    );
    let prime: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let cap = actual_row_coins.len();
    assert_eq!(
        field_stop_request(profile, prime, cap, row_request),
        FieldStopRequest::Eligible {
            coefficients: cap as u64
        }
    );
    assert_eq!(
        field_stop_request(profile, prime, cap, column_request),
        FieldStopRequest::NotField
    );
    let synthetic_request = |count: u64, modulus: u128| {
        let mut request = initial_header::<F>(profile).unwrap();
        frame(
            &mut request,
            1,
            b"opaque adversarial state",
            b"not a valid primary task",
        );
        let mut descriptor = modulus.to_le_bytes().to_vec();
        descriptor.extend(count.to_le_bytes());
        frame(&mut request, 4, b"syntactic sampler request", &descriptor);
        request
    };
    let syntactic = synthetic_request(cap as u64, prime);
    assert_eq!(
        field_stop_request(profile, prime, cap, &syntactic),
        FieldStopRequest::Eligible {
            coefficients: cap as u64
        }
    );
    assert_eq!(
        field_stop_request(profile, prime, cap, &synthetic_request(0, prime)),
        FieldStopRequest::Eligible { coefficients: 0 }
    );
    assert_eq!(
        field_stop_request(profile, prime, cap, &synthetic_request(1, prime + 2)),
        FieldStopRequest::ForeignModulus
    );
    assert_eq!(
        field_stop_request(profile, prime, cap, &syntactic[..syntactic.len() - 1]),
        FieldStopRequest::Malformed
    );
    let mut foreign = syntactic.clone();
    let profile_id = profile.id().0;
    let offset = foreign
        .windows(64)
        .position(|window| window == profile_id)
        .unwrap();
    foreign[offset] ^= 1;
    assert_eq!(
        field_stop_request(profile, prime, cap, &foreign),
        FieldStopRequest::ForeignProfile
    );
    let oversized = synthetic_request(u64::MAX, prime);
    assert_eq!(
        field_stop_request(profile, prime, cap, &oversized),
        FieldStopRequest::AboveCeiling {
            coefficients: u64::MAX
        }
    );
    history
        .query_with_actor(
            &syntactic,
            shake64(&syntactic),
            classical_xof_history::QueryActor::Adversary,
        )
        .unwrap();
    history
        .query_with_actor(
            &syntactic,
            shake64(&syntactic),
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    let stop_boundary = history
        .query_with_actor(
            &oversized,
            shake64(&oversized),
            classical_xof_history::QueryActor::Adversary,
        )
        .unwrap();
    let stop_ledger = field_stop_ledger(profile, prime, cap, &history, &stop_boundary).unwrap();
    assert_eq!(stop_ledger.eligible_actors.adversary, 1);
    assert_eq!(stop_ledger.eligible_actors.verifier, 1);
    assert_eq!(stop_ledger.eligible_actors.total(), 2);
    assert_eq!(stop_ledger.requested_coefficients, 2 * (cap as u128));
    assert_eq!(stop_ledger.above_ceiling, 1);
}

struct PrimaryRowQuery<'a, F> {
    request: &'a [u8],
    opening: FirstOpening<F>,
    coefficient_count: usize,
    source_near_and_padded: bool,
    assigned_value: Vec<F>,
    false_relation: bool,
    fixed_parameters: pcs::matrix_weighted::Parameters<pcs::utils::code::BlockReedSolomonCode<F>>,
    fixed_columns: Vec<Vec<F>>,
}

/// Pre-row state from the exact first query view. No current answer or proposed
/// row coefficients are read; source history completeness remains a premise.
fn primary_row_query_state<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    request: &'a [u8],
    words: &classical_history::History,
) -> Option<PrimaryRowQuery<'a, F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if !matches!(profile.version(), 4 | 5) || !history.input_is_original_view(view, request) {
        return None;
    }
    profile.validate_field::<F, EF>().ok()?;
    let known = history.producers(view)?;
    let (opening, coefficient_count) =
        brakedown_first_query::<F, EF, P>(profile, pp, setup, statement, request, &known)?;
    let frozen = primary_frozen_values(profile, pp, &opening, words)?;
    let source_near_and_padded = *frozen.near.get(opening.selected)?;
    let assigned_value = frozen.values.get(opening.selected)?.clone();
    let false_relation =
        !source_near_and_padded || assigned_value != *opening.values.get(opening.selected)?;
    let (fixed_parameters, fixed_columns) = primary_task_fixed_word(profile, &opening, words)?;
    Some(PrimaryRowQuery {
        request,
        opening,
        coefficient_count,
        source_near_and_padded,
        assigned_value,
        false_relation,
        fixed_parameters,
        fixed_columns,
    })
}

/// The caller supplies the real sampler output for this exact request.
/// Shape/receipt checks do not establish that oracle-output provenance.
struct RowStreamOutput<'a, F> {
    request: &'a [u8],
    coefficients: &'a [F],
    consumed_raw: &'a [u8],
}

fn row_stream_matches_pre<F: NTTField>(
    before: &PrimaryRowQuery<'_, F>,
    output: &RowStreamOutput<'_, F>,
) -> bool {
    before.request == output.request
        && output.coefficients.len() == before.coefficient_count
        && replay_raw_prime_values::<F>(output.consumed_raw, before.coefficient_count)
            .is_some_and(|values| values == output.coefficients)
}

fn primary_row_transition<F: NTTField>(
    before: &PrimaryRowQuery<'_, F>,
    output: &RowStreamOutput<'_, F>,
) -> Option<ScalarRowState> {
    if !row_stream_matches_pre(before, output) {
        return None;
    }
    let after = scalar_row_state(
        &before.fixed_parameters,
        &before.fixed_columns,
        &before.opening.query,
        output.coefficients,
        before.opening.values.get(before.opening.selected)?,
    )?;
    if after.source_near_and_padded != before.source_near_and_padded
        || after.false_relation != before.false_relation
    {
        return None;
    }
    Some(after)
}

fn field_row_proposal_consistent<F: NTTField>(
    before: &PrimaryRowQuery<'_, F>,
    output: &RowStreamOutput<'_, F>,
    proposed: &FieldProposal<'_, F>,
) -> bool {
    row_stream_matches_pre(before, output)
        && proposed.request == before.request
        && proposed.coefficients == output.coefficients
        && proposed.consistent_with(output.consumed_raw)
}

fn primary_row_proposal_consistent<F: NTTField>(
    before: &PrimaryRowQuery<'_, F>,
    output: &RowStreamOutput<'_, F>,
    proposed: &PrimaryColumnRun<'_, F>,
) -> bool {
    field_row_proposal_consistent(before, output, &proposed.row)
}

/// Post-answer provenance for the v4 row and completed column draws. This
/// does not inspect the pending draw or change first-family admission.
fn primary_recorded_column_run_transition<F: NTTField>(
    history: &classical_xof_history::History,
    answered: &classical_xof_history::Checkpoint,
    before: &PrimaryRowQuery<'_, F>,
    output: &RowStreamOutput<'_, F>,
    proposed: &PrimaryColumnRun<'_, F>,
) -> Option<ScalarRowState> {
    if !primary_row_proposal_consistent(before, output, proposed)
        || !history.output_prefix_at(answered, output.request)?
            .starts_with(output.consumed_raw)
        || !proposed.response.columns.bytes.recorded_prior_outputs_match(history, answered)
    {
        return None;
    }
    primary_row_transition(before, output)
}

struct PrimaryFamilyEntry<'a> {
    root_request: &'a [u8],
    first_input: &'a [u8],
    first_view: classical_xof_history::View,
    task_admissible: bool,
    row_state: Option<ScalarRowState>,
}

/// Select by syntax before attempting semantic admission. A producer learned
/// after the first family input cannot repair its original interpretation.
/// Complete synchronized SHA/XOF histories remain a caller obligation.
fn primary_family_entry<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    history: &'a classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &'a [u8],
    words: &classical_history::History,
) -> Option<PrimaryFamilyEntry<'a>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.version() != 4 || profile.specification().backend != Backend::Brakedown {
        return None;
    }
    let role = &profile.specification().roles[0];
    let cols =
        1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(role.left_vars?)?).ok()?)?;
    let domain = cols
        .div_ceil(role.block_width?)
        .checked_next_power_of_two()?
        .checked_mul(profile.specification().blowup)?
        .max(32);
    let current = canonical_column_run_proposal(history, view, candidate, domain, role.queries)?;
    let root = current.bytes.root_request;
    let (first_input, first_view) = history.first_query_matching(view, |input| {
        let Some(original) = history.first_view(input) else {
            return false;
        };
        canonical_column_run_proposal(history, &original, input, domain, role.queries)
            .is_some_and(|run| run.bytes.root_request == root)
    })?;
    let bound = primary_column_run_proposal::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        history,
        &first_view,
        first_input,
    );
    let task_admissible = bound.is_some();
    let row_state = bound
        .as_ref()
        .and_then(|bound| primary_row_state(profile, bound, words));
    Some(PrimaryFamilyEntry {
        root_request: root,
        first_input,
        first_view,
        task_admissible,
        row_state,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct MissingFieldFingerprint {
    digest: [u8; 64],
    offset: usize,
}
#[derive(Debug, PartialEq, Eq)]
enum FieldFingerprintAvailability {
    Available { frames: usize },
    Missing(MissingFieldFingerprint),
    Malformed,
}

/// Framed fingerprint availability only, not descriptor/producer validity or
/// stage admission. A missing digest identifies an exact declared input window.
fn field_fingerprint_availability(
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    input: &[u8],
) -> Option<FieldFingerprintAvailability> {
    if !history.input_is_original_view(view, input) {
        return None;
    }
    let parsed = (|| {
        let mut rest = input;
        let mut frames = 0;
        while !rest.is_empty() {
            let kind = *take(&mut rest, 1)?.first()?;
            let _label = sized(&mut rest)?;
            let body = sized(&mut rest)?;
            if kind > 8 {
                return Some(FieldFingerprintAvailability::Malformed);
            }
            if kind == 5 {
                if body.len() != 80 {
                    return Some(FieldFingerprintAvailability::Malformed);
                }
                frames += 1;
                let digest: [u8; 64] = body[16..].try_into().ok()?;
                if history.producer(view, &digest).is_none() {
                    return Some(FieldFingerprintAvailability::Missing(
                        MissingFieldFingerprint {
                            digest,
                            offset: input.len().checked_sub(rest.len())?.checked_sub(64)?,
                        },
                    ));
                }
            }
        }
        Some(FieldFingerprintAvailability::Available { frames })
    })();
    Some(parsed.unwrap_or(FieldFingerprintAvailability::Malformed))
}

enum UnclassifiedPrimaryReason {
    HeaderMismatch,
    MissingFieldFingerprint,
    Other,
}
fn unclassified_primary_reason<F: NTTField>(
    profile: &ClassicalProfile,
    history: &classical_xof_history::History,
    view: &classical_xof_history::View,
    input: &[u8],
) -> Option<UnclassifiedPrimaryReason> {
    if !history.input_is_original_view(view, input) {
        return None;
    }
    if !input.starts_with(&initial_header::<F>(profile)?) {
        return Some(UnclassifiedPrimaryReason::HeaderMismatch);
    }
    Some(
        match field_fingerprint_availability(history, view, input)? {
            FieldFingerprintAvailability::Missing(_) => {
                UnclassifiedPrimaryReason::MissingFieldFingerprint
            }
            _ => UnclassifiedPrimaryReason::Other,
        },
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ActorCounts {
    unknown: usize,
    adversary: usize,
    verifier: usize,
    setup: usize,
}
impl ActorCounts {
    fn add(&mut self, actor: classical_xof_history::QueryActor) {
        use classical_xof_history::QueryActor;
        match actor {
            QueryActor::Unknown => self.unknown += 1,
            QueryActor::Adversary => self.adversary += 1,
            QueryActor::Verifier => self.verifier += 1,
            QueryActor::Setup => self.setup += 1,
        }
    }
    fn total(&self) -> usize {
        self.unknown + self.adversary + self.verifier + self.setup
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FieldStopRequest {
    Eligible { coefficients: u64 },
    NotField,
    Malformed,
    ForeignProfile,
    ForeignModulus,
    AboveCeiling { coefficients: u64 },
}
/// A syntactic superclass for sampler-stop accounting, not stage admission.
/// Only the final flat base-field descriptor determines the rejection sampler.
fn field_stop_request(
    profile: &ClassicalProfile,
    prime: u128,
    coefficient_ceiling: usize,
    input: &[u8],
) -> FieldStopRequest {
    let mut prefix = Vec::new();
    frame(
        &mut prefix,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    let Some(mut rest) = input.strip_prefix(prefix.as_slice()) else {
        return FieldStopRequest::NotField;
    };
    let parsed = (|| {
        let application = message(&mut rest, 0, b"application")?;
        if ![
            b"HasteBoots typed classical prime v1".as_slice(),
            b"HasteBoots typed classical extension v1",
            b"HasteBoots framed SHAKE256 child v1",
        ]
        .contains(&application)
        {
            return Some(FieldStopRequest::Malformed);
        }
        if message(&mut rest, 0, b"trusted profile")? != profile.id().0 {
            return Some(FieldStopRequest::ForeignProfile);
        }
        let mut last = None;
        while !rest.is_empty() {
            let kind = *take(&mut rest, 1)?.first()?;
            let _label = sized(&mut rest)?;
            let body = sized(&mut rest)?;
            if !(1..=8).contains(&kind) {
                return Some(FieldStopRequest::Malformed);
            }
            last = Some((kind, body));
        }
        let Some((4, descriptor)) = last else {
            return Some(FieldStopRequest::NotField);
        };
        if descriptor.len() != 24 {
            return Some(FieldStopRequest::Malformed);
        }
        if u128::from_le_bytes(descriptor[..16].try_into().ok()?) != prime {
            return Some(FieldStopRequest::ForeignModulus);
        }
        let coefficients = u64::from_le_bytes(descriptor[16..].try_into().ok()?);
        if u128::from(coefficients) > coefficient_ceiling as u128 {
            return Some(FieldStopRequest::AboveCeiling { coefficients });
        }
        Some(FieldStopRequest::Eligible { coefficients })
    })();
    parsed.unwrap_or(FieldStopRequest::Malformed)
}
#[derive(Debug, Default)]
struct FieldStopLedger {
    distinct_inputs: usize,
    eligible_actors: ActorCounts,
    requested_coefficients: u128,
    above_ceiling: usize,
    other_inputs: usize,
}
fn field_stop_ledger(
    profile: &ClassicalProfile,
    prime: u128,
    coefficient_ceiling: usize,
    history: &classical_xof_history::History,
    boundary: &classical_xof_history::View,
) -> Option<FieldStopLedger> {
    let mut ledger = FieldStopLedger::default();
    for (input, original) in history.query_inputs_at(boundary)? {
        ledger.distinct_inputs += 1;
        match field_stop_request(profile, prime, coefficient_ceiling, input) {
            FieldStopRequest::Eligible { coefficients } => {
                ledger
                    .eligible_actors
                    .add(history.first_query_actor(&original, input)?);
                ledger.requested_coefficients = ledger
                    .requested_coefficients
                    .checked_add(u128::from(coefficients))?;
            }
            FieldStopRequest::AboveCeiling { .. } => ledger.above_ceiling += 1,
            _ => ledger.other_inputs += 1,
        }
    }
    debug_assert_eq!(
        ledger.eligible_actors.total() + ledger.above_ceiling + ledger.other_inputs,
        ledger.distinct_inputs
    );
    debug_assert!(
        ledger.requested_coefficients
            <= (coefficient_ceiling as u128) * (ledger.eligible_actors.total() as u128)
    );
    Some(ledger)
}

/// Pure byte-family identity, independent of proposed accepted draws, source
/// admission and later producer availability. Every descendant belongs to the
/// same maximal trailing run, including nodes beyond a verifier's draw quota.
fn column_stop_family_root<'a>(profile: &ClassicalProfile, input: &'a [u8]) -> Option<&'a [u8]> {
    if profile.version() != 4 || profile.specification().backend != Backend::Brakedown {
        return None;
    }
    let mut rest = input;
    if message(&mut rest, 0, b"protocol")? != b"HasteBoots framed SHAKE256 v1" {
        return None;
    }
    let application = message(&mut rest, 0, b"application")?;
    if ![
        b"HasteBoots typed classical prime v1".as_slice(),
        b"HasteBoots typed classical extension v1",
        b"HasteBoots framed SHAKE256 child v1",
    ]
    .contains(&application)
        || message(&mut rest, 0, b"trusted profile")? != profile.id().0
    {
        return None;
    }
    canonical_column_root_request(input)
}
#[derive(Debug, Default)]
struct ColumnStopLedger {
    distinct_inputs: usize,
    member_inputs: usize,
    families: usize,
    family_actors: ActorCounts,
}
fn column_stop_ledger(
    profile: &ClassicalProfile,
    history: &classical_xof_history::History,
    boundary: &classical_xof_history::View,
) -> Option<ColumnStopLedger> {
    let mut ledger = ColumnStopLedger::default();
    let mut roots = std::collections::HashSet::new();
    for (input, _) in history.query_inputs_at(boundary)? {
        ledger.distinct_inputs += 1;
        let Some(root) = column_stop_family_root(profile, input) else {
            continue;
        };
        ledger.member_inputs += 1;
        if roots.insert(root.to_vec()) {
            let (first_input, first_view) = history
                .first_query_matching(boundary, |candidate| {
                    column_stop_family_root(profile, candidate) == Some(root)
                })?;
            ledger.families += 1;
            ledger
                .family_actors
                .add(history.first_query_actor(&first_view, first_input)?);
        }
    }
    debug_assert_eq!(ledger.family_actors.total(), ledger.families);
    debug_assert!(
        ledger.families <= ledger.member_inputs && ledger.member_inputs <= ledger.distinct_inputs
    );
    Some(ledger)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PrimaryQueryLedger {
    distinct_inputs: usize,
    input_actors: ActorCounts,
    false_row_actors: ActorCounts,
    bad_family_actors: ActorCounts,
    row_candidates: usize,
    admitted_rows: usize,
    false_rows: usize,
    unclassified_rows: usize,
    syntactic_families: usize,
    admitted_families: usize,
    bad_families: usize,
    unclassified_families: usize,
    header_mismatch_rows: usize,
    missing_receipt_rows: usize,
    other_unclassified_rows: usize,
    header_mismatch_families: usize,
    missing_receipt_families: usize,
    other_unclassified_families: usize,
}

/// Observed first-query counts, not an adversarial query ceiling or a security
/// bound. Every unresolved syntactic entry remains explicit in the result.
fn primary_query_ledger<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    history: &classical_xof_history::History,
    boundary: &classical_xof_history::View,
    words: &classical_history::History,
) -> Option<PrimaryQueryLedger>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    if !matches!(profile.version(), 4 | 5) || profile.specification().backend != Backend::Brakedown
    {
        return None;
    }
    profile.validate_field::<F, EF>().ok()?;
    let role = &profile.specification().roles[0];
    let rows =
        (1usize.checked_shl(u32::try_from(role.left_vars?).ok()?)?).checked_mul(role.width)?;
    let count = rows.checked_mul(role.width)?;
    let cols =
        1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(role.left_vars?)?).ok()?)?;
    let domain = cols
        .div_ceil(role.block_width?)
        .checked_next_power_of_two()?
        .checked_mul(profile.specification().blowup)?
        .max(32);
    let prime: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let mut descriptor = prime.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    let mut row_tail = Vec::new();
    frame(&mut row_tail, 4, b"mw random linear test", &descriptor);
    let mut atomic_tail = Vec::new();
    frame(
        &mut atomic_tail,
        2,
        b"mw atomic column block v5",
        &u64::try_from(role.queries.checked_mul(8)?)
            .ok()?
            .to_le_bytes(),
    );
    let mut ledger = PrimaryQueryLedger::default();
    let mut roots = std::collections::HashSet::new();
    for (input, original) in history.query_inputs_at(boundary)? {
        ledger.distinct_inputs += 1;
        let actor = history.first_query_actor(&original, input)?;
        ledger.input_actors.add(actor);
        if input.ends_with(&row_tail) {
            ledger.row_candidates += 1;
            if let Some(before) = primary_row_query_state::<F, EF, P>(
                profile, pp, setup, statement, history, &original, input, words,
            ) {
                ledger.admitted_rows += 1;
                ledger.false_rows += usize::from(before.false_relation);
                if before.false_relation {
                    ledger.false_row_actors.add(actor);
                }
            } else {
                ledger.unclassified_rows += 1;
                match unclassified_primary_reason::<F>(profile, history, &original, input)? {
                    UnclassifiedPrimaryReason::HeaderMismatch => ledger.header_mismatch_rows += 1,
                    UnclassifiedPrimaryReason::MissingFieldFingerprint => {
                        ledger.missing_receipt_rows += 1
                    }
                    UnclassifiedPrimaryReason::Other => ledger.other_unclassified_rows += 1,
                }
            }
        }
        if profile.version() == 5 {
            // Each distinct atomic request is a singleton sampling family.
            // Match only the byte request tail: malformed domains remain
            // explicit unresolved candidates rather than disappearing.
            if input.ends_with(&atomic_tail) {
                ledger.syntactic_families += 1;
                if let Some(before) = primary_atomic_column_query::<F, EF, P>(
                    profile, pp, setup, statement, history, &original, input, words,
                ) {
                    ledger.admitted_families += 1;
                    ledger.bad_families += usize::from(before.row_state.bad_after_rows);
                    if before.row_state.bad_after_rows {
                        ledger.bad_family_actors.add(actor);
                    }
                } else {
                    ledger.unclassified_families += 1;
                    match unclassified_primary_reason::<F>(profile, history, &original, input)? {
                        UnclassifiedPrimaryReason::HeaderMismatch => {
                            ledger.header_mismatch_families += 1
                        }
                        UnclassifiedPrimaryReason::MissingFieldFingerprint => {
                            ledger.missing_receipt_families += 1
                        }
                        UnclassifiedPrimaryReason::Other => ledger.other_unclassified_families += 1,
                    }
                }
            }
            continue;
        }
        if let Some(run) =
            canonical_column_run_proposal(history, &original, input, domain, role.queries)
        {
            if roots.insert(run.bytes.root_request.to_vec()) {
                ledger.syntactic_families += 1;
                let entry = primary_family_entry::<F, EF, P>(
                    profile, pp, setup, statement, history, &original, input, words,
                )?;
                if entry.task_admissible && entry.row_state.is_some() {
                    ledger.admitted_families += 1;
                    ledger.bad_families += usize::from(entry.row_state.as_ref()?.bad_after_rows);
                    if entry.row_state.as_ref()?.bad_after_rows {
                        ledger
                            .bad_family_actors
                            .add(history.first_query_actor(&entry.first_view, entry.first_input)?);
                    }
                } else {
                    ledger.unclassified_families += 1;
                    match unclassified_primary_reason::<F>(
                        profile,
                        history,
                        &entry.first_view,
                        entry.first_input,
                    )? {
                        UnclassifiedPrimaryReason::HeaderMismatch => {
                            ledger.header_mismatch_families += 1
                        }
                        UnclassifiedPrimaryReason::MissingFieldFingerprint => {
                            ledger.missing_receipt_families += 1
                        }
                        UnclassifiedPrimaryReason::Other => ledger.other_unclassified_families += 1,
                    }
                }
            }
        }
    }
    debug_assert_eq!(ledger.input_actors.total(), ledger.distinct_inputs);
    debug_assert_eq!(ledger.false_row_actors.total(), ledger.false_rows);
    debug_assert_eq!(ledger.bad_family_actors.total(), ledger.bad_families);
    for actor in [
        classical_xof_history::QueryActor::Unknown,
        classical_xof_history::QueryActor::Adversary,
        classical_xof_history::QueryActor::Verifier,
        classical_xof_history::QueryActor::Setup,
    ] {
        let get = |counts: &ActorCounts| match actor {
            classical_xof_history::QueryActor::Unknown => counts.unknown,
            classical_xof_history::QueryActor::Adversary => counts.adversary,
            classical_xof_history::QueryActor::Verifier => counts.verifier,
            classical_xof_history::QueryActor::Setup => counts.setup,
        };
        debug_assert!(
            get(&ledger.false_row_actors) + get(&ledger.bad_family_actors)
                <= get(&ledger.input_actors)
        );
    }
    Some(ledger)
}

#[derive(Debug, PartialEq, Eq)]
struct ScalarRowState {
    source_near_and_padded: bool,
    projected_test_rs_near: bool,
    projected_test_near_and_padded: bool,
    false_relation: bool,
    bad_after_rows: bool,
    /// Lower bound when the final claimed-value equation holds.
    minimum_rejecting_columns: usize,
}

/// Universal intermediate predicate, independent of the prover's responses.
/// Fixed-source timing and the probability of an escaping row matrix are not
/// established by evaluating this deterministic predicate.
fn scalar_row_state<F: NTTField>(
    parameters: &pcs::matrix_weighted::Parameters<pcs::utils::code::BlockReedSolomonCode<F>>,
    columns: &[Vec<F>],
    query: &[algebra::matrix_weighted::MatrixPair<F>],
    random: &[F],
    claim: &[F],
) -> Option<ScalarRowState> {
    use algebra::transformation::AbstractNTT;
    use pcs::utils::code::RowCode;
    let width = parameters.width();
    let left = parameters.left_vars();
    let code = parameters.code();
    let domain = code.codeword_blocks();
    let block = code.block_width();
    let rows = (1usize.checked_shl(u32::try_from(left).ok()?)?).checked_mul(width)?;
    let cells = rows.checked_mul(block)?;
    if query.len() != parameters.num_vars()
        || claim.len() != width
        || random.len() != width.checked_mul(rows)?
        || columns.len() != domain
        || columns.iter().any(|column| column.len() != cells)
    {
        return None;
    }
    for pair in query {
        pair.validate(width).ok()?;
    }
    let (near, assigned) = classical_assignment::brakedown_assignment(
        columns,
        parameters.num_vars(),
        width,
        left,
        code,
    );
    let false_relation = !near || assigned.evaluate(query).ok()? != claim;
    let projected: Vec<Vec<F>> = columns
        .iter()
        .map(|column| {
            (0..width)
                .flat_map(|lane| {
                    (0..block).map(move |coordinate| {
                        (0..rows).fold(F::zero(), |value, row| {
                            value + random[lane * rows + row] * column[row * block + coordinate]
                        })
                    })
                })
                .collect()
        })
        .collect();
    let distance = domain.checked_sub(code.message_blocks())?.checked_add(1)?;
    let radius = (distance - 1) / 3;
    let mut points = vec![F::zero(); domain];
    points[1] = F::one();
    F::get_ntt_table(domain.ilog2())
        .ok()?
        .transform_slice(&mut points);
    let decoded = classical_decode::joint(&points, &projected, code.message_blocks(), radius);
    let projected_rs_near = decoded.is_some();
    let projected_near = decoded.is_some_and(|coefficients| {
        coefficients.len() == width * block
            && (0..width).all(|lane| {
                (0..code.message_blocks()).all(|coefficient| {
                    (0..block).all(|coordinate| {
                        coefficient * block + coordinate < code.message_len()
                            || coefficients[lane * block + coordinate][coefficient] == F::zero()
                    })
                })
            })
    });
    let bad = false_relation && (near || !projected_near);
    Some(ScalarRowState {
        source_near_and_padded: near,
        projected_test_rs_near: projected_rs_near,
        projected_test_near_and_padded: projected_near,
        false_relation,
        bad_after_rows: bad,
        minimum_rejecting_columns: if !bad {
            0
        } else if near {
            distance - radius
        } else {
            radius + 1
        },
    })
}

struct ScalarColumnFailures {
    rejecting: Vec<bool>,
    claimed_value_matches: bool,
}

/// Reference local predicate on a fixed completed word. Merkle authentication,
/// stream consistency and first-declaration timing are separate obligations.
fn scalar_column_failures<F, C>(
    parameters: &pcs::matrix_weighted::Parameters<C>,
    columns: &[Vec<F>],
    query: &[algebra::matrix_weighted::MatrixPair<F>],
    random: &[F],
    test: &[F],
    evaluation: &[F],
    claim: &[F],
) -> Option<ScalarColumnFailures>
where
    F: NTTField,
    C: pcs::utils::code::RowCode<F>,
{
    use algebra::matrix_weighted::matrix_weights;
    let width = parameters.width();
    let left = parameters.left_vars();
    let rows = (1usize.checked_shl(u32::try_from(left).ok()?)?).checked_mul(width)?;
    let right = parameters.num_vars().checked_sub(left)?;
    let cols = 1usize.checked_shl(u32::try_from(right).ok()?)?;
    let code = parameters.code();
    let domain = code.codeword_blocks();
    let block = code.block_width();
    let stride = domain.checked_mul(block)?;
    if query.len() != parameters.num_vars()
        || code.message_len() != cols
        || columns.len() != domain
        || claim.len() != width
        || random.len() != width.checked_mul(rows)?
        || test.len() != width.checked_mul(cols)?
        || evaluation.len() != test.len()
        || columns.iter().any(|column| column.len() != rows * block)
    {
        return None;
    }
    for pair in query {
        pair.validate(width).ok()?;
    }
    let matrices = matrix_weights(width, &query[..left]).ok()?;
    let mut structured = vec![F::zero(); width * rows];
    for (index, matrix) in matrices.iter().enumerate() {
        for lane in 0..width {
            for coordinate in 0..width {
                structured[lane * rows + index * width + coordinate] =
                    matrix.values()[lane * width + coordinate];
            }
        }
    }
    let encode_response = |response: &[F]| {
        let mut encoded = vec![F::zero(); width * stride];
        for lane in 0..width {
            code.encode_row(
                &response[lane * cols..(lane + 1) * cols],
                &mut encoded[lane * stride..(lane + 1) * stride],
            );
        }
        encoded
    };
    let encoded_test = encode_response(test);
    let encoded_evaluation = encode_response(evaluation);
    let rejecting = columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            (0..width).any(|lane| {
                (0..block).any(|coordinate| {
                    let dot = |weights: &[F]| {
                        (0..rows).fold(F::zero(), |value, row| {
                            value + weights[lane * rows + row] * column[row * block + coordinate]
                        })
                    };
                    let at = lane * stride + index * block + coordinate;
                    dot(random) != encoded_test[at] || dot(&structured) != encoded_evaluation[at]
                })
            })
        })
        .collect();
    let values = (0..cols)
        .flat_map(|right| (0..width).map(move |lane| evaluation[lane * cols + right]))
        .collect();
    let mut table = PackedTable::new(right, width, values).ok()?;
    for pair in &query[left..] {
        table.fold_in_place(pair).ok()?;
    }
    Some(ScalarColumnFailures {
        rejecting,
        claimed_value_matches: table.values() == claim,
    })
}

/// Shared trusted geometry and immutable source for both component predicates.
fn primary_task_fixed_word<F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    opening: &FirstOpening<F>,
    words: &classical_history::History,
) -> Option<(
    pcs::matrix_weighted::Parameters<pcs::utils::code::BlockReedSolomonCode<F>>,
    Vec<Vec<F>>,
)> {
    use pcs::utils::code::{BlockReedSolomonCode, RowCode};
    if !matches!(profile.version(), 4 | 5) || profile.specification().backend != Backend::Brakedown
    {
        return None;
    }
    let role = &profile.specification().roles[0];
    let left = role.left_vars?;
    let right = 1usize.checked_shl(u32::try_from(role.num_vars.checked_sub(left)?).ok()?)?;
    let code =
        BlockReedSolomonCode::<F>::new(right, role.block_width?, profile.specification().blowup)
            .ok()?;
    let parameters = pcs::matrix_weighted::Parameters::new_encoded::<F>(
        role.num_vars,
        role.width,
        left,
        role.queries,
        code,
    )
    .ok()?;
    let source = opening.sources.get(opening.selected)?;
    if source.0 != parameters.context_digest::<F, Sha512>().ok()? {
        return None;
    }
    let code = parameters.code();
    let cells = (1usize.checked_shl(u32::try_from(left).ok()?)?)
        .checked_mul(role.width)?
        .checked_mul(code.block_width())?;
    let frozen = words.view(source.1.root)?;
    let columns = classical_assignment::frozen_brakedown_columns::<F>(
        &frozen,
        source.1.root,
        code.codeword_blocks().ilog2() as usize,
        cells,
    )?;
    Some((parameters, columns))
}

fn primary_fixed_word<F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    bound: &PrimaryColumnRun<'_, F>,
    words: &classical_history::History,
) -> Option<(
    pcs::matrix_weighted::Parameters<pcs::utils::code::BlockReedSolomonCode<F>>,
    Vec<Vec<F>>,
)> {
    primary_task_fixed_word(profile, &bound.opening, words)
}

fn primary_column_failures<F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    bound: &PrimaryColumnRun<'_, F>,
    words: &classical_history::History,
) -> Option<ScalarColumnFailures> {
    let (parameters, columns) = primary_fixed_word(profile, bound, words)?;
    scalar_column_failures(
        &parameters,
        &columns,
        &bound.opening.query,
        &bound.row.coefficients,
        &bound.response.test,
        &bound.response.evaluation,
        bound.opening.values.get(bound.opening.selected)?,
    )
}

fn primary_row_state<F: NTTField + Serialize + DeserializeOwned>(
    profile: &ClassicalProfile,
    bound: &PrimaryColumnRun<'_, F>,
    words: &classical_history::History,
) -> Option<ScalarRowState> {
    let (parameters, columns) = primary_fixed_word(profile, bound, words)?;
    scalar_row_state(
        &parameters,
        &columns,
        &bound.opening.query,
        &bound.row.coefficients,
        bound.opening.values.get(bound.opening.selected)?,
    )
}

struct PrimaryFrozenValues<F> {
    near: Vec<bool>,
    values: Vec<Vec<F>>,
    unique_sources: usize,
}

/// Assign only from the SHA history's immutable first-declaration views.
/// The caller must synchronize SHA/XOF event histories and charge availability
/// exceptions. This does not turn missing preimages into proof admission.
fn primary_frozen_values<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    task: &FirstOpening<F>,
    words: &classical_history::History,
) -> Option<PrimaryFrozenValues<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    use pcs::utils::code::{BlockReedSolomonCode, RowCode};
    if !matches!(profile.version(), 4 | 5)
        || profile.specification().backend != Backend::Brakedown
        || !matches!(task.family, OpeningFamily::Primary)
        || task.selected != 0
        || task.sources.is_empty()
        || task.sources.len() != task.values.len()
    {
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
    let context = expected.context_digest::<F, Sha512>().ok()?;
    if task.query.len() != role.num_vars {
        return None;
    }
    for pair in &task.query {
        pair.validate(role.width).ok()?;
    }
    // Validate every geometry/context before touching a root's frozen view.
    for (index, source) in task.sources.iter().enumerate() {
        let parameters = task.parameters(pp, index)?;
        if parameters.num_vars() != role.num_vars
            || parameters.width() != role.width
            || parameters.context().ok()? != context
            || source.0 != context
        {
            return None;
        }
        parameters.validate_values(task.values.get(index)?).ok()?;
    }
    let code = expected.code();
    let cells = (1usize.checked_shl(u32::try_from(left).ok()?)?)
        .checked_mul(role.width)?
        .checked_mul(code.block_width())?;
    let mut assignments = std::collections::HashMap::<Vec<u8>, (bool, Vec<F>)>::new();
    let mut near = Vec::new();
    let mut values = Vec::new();
    for (index, source) in task.sources.iter().enumerate() {
        let identity = encoded(source);
        if !assignments.contains_key(&identity) {
            let frozen = words.view(source.1.root)?;
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
            let parameters = task.parameters(pp, index)?;
            let evaluated = parameters.normalize_values(table.evaluate(&task.query).ok()?);
            parameters.validate_values(&evaluated).ok()?;
            assignments.insert(identity.clone(), (promised, evaluated));
        }
        let (promised, evaluated) = assignments.get(&identity)?;
        near.push(*promised);
        values.push(evaluated.clone());
    }
    Some(PrimaryFrozenValues {
        near,
        values,
        unique_sources: assignments.len(),
    })
}

fn complete_primary_source_graph<F: NTTField + Serialize>(
    profile: &ClassicalProfile,
    source_table: &PackedTable<F>,
) -> (Digest512, classical_history::History) {
    source_table.validate().unwrap();
    assert_eq!(
        source_table.num_vars(),
        profile.specification().roles[0].num_vars
    );
    assert_eq!(source_table.width(), profile.specification().roles[0].width);
    use pcs::utils::code::{BlockReedSolomonCode, RowCode};
    let role = &profile.specification().roles[0];
    let left = role.left_vars.unwrap();
    let right = 1usize << (role.num_vars - left);
    let code = BlockReedSolomonCode::<F>::new(
        right,
        role.block_width.unwrap(),
        profile.specification().blowup,
    )
    .unwrap();
    let rows = (1usize << left) * role.width;
    let mut columns = vec![Vec::new(); code.codeword_blocks()];
    for row in 0..rows {
        let message: Vec<_> = (0..right)
            .map(|right| source_table.at(row / role.width + (right << left))[row % role.width])
            .collect();
        let mut output = vec![F::zero(); code.codeword_blocks() * code.block_width()];
        code.encode_row(&message, &mut output);
        for (index, column) in columns.iter_mut().enumerate() {
            column.extend_from_slice(
                &output[index * code.block_width()..(index + 1) * code.block_width()],
            );
        }
    }
    let mut actual_words = classical_history::History::default();
    let mut nodes: Vec<_> = columns
        .iter()
        .map(|column| {
            let mut raw = b"HasteBoots/mw-column/v1".to_vec();
            raw.extend(encoded(column));
            let digest = Digest512(Sha512::digest(&raw).into());
            actual_words.expose(digest, raw);
            digest
        })
        .collect();
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| {
                let mut raw = pair[0].0.to_vec();
                raw.extend(pair[1].0);
                let digest = Digest512(Sha512::digest(&raw).into());
                actual_words.expose(digest, raw);
                digest
            })
            .collect();
    }
    (nodes[0], actual_words)
}

pub(in super::super) fn exercise_primary_column_binding<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    row_request: &[u8],
    known: &Producers,
    opening: &FirstOpening<F>,
    random: &[F],
    test: &[F],
    evaluation: &[F],
    source_table: &PackedTable<F>,
    observed_streams: &RecordedStreams,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let raw = observed_streams.prefix(row_request).expect("observed v4 row reader").to_vec();
    let (row_receipt, row_producer) = receipt(&raw);
    let mut history = classical_xof_history::History::default();
    for (digest, producer) in known {
        assert_eq!(*digest, shake64(producer));
        history.query(producer, *digest).unwrap();
    }
    history
        .query(&row_producer, shake64(&row_producer))
        .unwrap();
    let mut candidate = row_request.to_vec();
    frame(&mut candidate, 5, b"mw random linear test", &row_receipt);
    frame(
        &mut candidate,
        1,
        b"mw linear responses",
        &encoded(&(test, evaluation)),
    );
    frame(
        &mut candidate,
        2,
        b"mw unbiased column",
        &8u64.to_le_bytes(),
    );
    let family_root = candidate.clone();
    // The first input may be a descendant with an unavailable receipt producer.
    let mut unavailable = classical_xof_history::History::default();
    let row_digest = shake64(&row_producer);
    for (digest, producer) in known {
        if *digest != row_digest {
            unavailable.query(producer, *digest).unwrap();
        }
    }
    let mut first_descendant = family_root.clone();
    frame(
        &mut first_descendant,
        3,
        b"mw unbiased column",
        &7u64.to_le_bytes(),
    );
    frame(
        &mut first_descendant,
        2,
        b"mw unbiased column",
        &8u64.to_le_bytes(),
    );
    let mut words = classical_history::History::default();
    words.declare_input(&first_descendant);
    let early = unavailable
        .query(&first_descendant, shake64(&first_descendant))
        .unwrap();
    let entry = primary_family_entry::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &unavailable,
        &early,
        &first_descendant,
        &words,
    )
    .unwrap();
    assert!(!entry.task_admissible && entry.row_state.is_none());
    assert_eq!(entry.first_input, first_descendant);
    unavailable.query(&row_producer, row_digest).unwrap();
    assert!(
        unavailable.availability_hits() > 0,
        "late receipt output hits the earlier proposed fingerprint"
    );
    let later = unavailable
        .query(&family_root, shake64(&family_root))
        .unwrap();
    assert!(
        primary_column_run_proposal::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &unavailable,
            &later,
            &family_root
        )
        .is_some()
    );
    let entry = primary_family_entry::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &unavailable,
        &later,
        &family_root,
        &words,
    )
    .unwrap();
    assert_eq!(entry.first_input, first_descendant);
    assert_eq!(entry.root_request, family_root);
    assert!(unavailable.input_is_original_view(&entry.first_view, entry.first_input));
    assert!(
        !entry.task_admissible && entry.row_state.is_none(),
        "later knowledge cannot reclassify the first family input"
    );
    let missing_family = primary_query_ledger::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &unavailable,
        &later,
        &words,
    )
    .unwrap();
    assert_eq!(missing_family.unclassified_families, 1);
    assert_eq!(missing_family.missing_receipt_families, 1);
    assert_eq!(missing_family.header_mismatch_families, 0);
    for accepted in 0..2 {
        let view = history.query(&candidate, shake64(&candidate)).unwrap();
        let bound = primary_column_run_proposal::<F, EF, P>(
            profile, pp, setup, statement, &history, &view, &candidate,
        )
        .unwrap();
        assert_eq!(encoded(&bound.opening.sources), encoded(&opening.sources));
        assert_eq!(encoded(&bound.opening.query), encoded(&opening.query));
        assert_eq!(encoded(&bound.opening.values), encoded(&opening.values));
        assert_eq!(bound.row.coefficients, random);
        assert!(bound.row.consistent_with(&raw));
        assert!(!bound.row.request_was_queried);
        assert_eq!(bound.response.test, test);
        assert_eq!(bound.response.evaluation, evaluation);
        assert_eq!(bound.response.columns.prior_indices.len(), accepted);
        let mut words = classical_history::History::default();
        words.declare_input(&candidate);
        let fixed = primary_frozen_values(profile, pp, &bound.opening, &words).unwrap();
        assert!(
            fixed
                .values
                .iter()
                .flatten()
                .all(|&value| value == F::zero())
        );
        let failures = primary_column_failures(profile, &bound, &words).unwrap();
        let row_state = primary_row_state(profile, &bound, &words).unwrap();
        let entry = primary_family_entry::<F, EF, P>(
            profile, pp, setup, statement, &history, &view, &candidate, &words,
        )
        .unwrap();
        assert_eq!(entry.first_input, family_root);
        assert_eq!(entry.root_request, family_root);
        assert!(entry.task_admissible);
        assert_eq!(
            entry.row_state.as_ref().unwrap().bad_after_rows,
            row_state.bad_after_rows
        );

        if row_state.bad_after_rows && failures.claimed_value_matches {
            assert!(
                failures.rejecting.iter().filter(|&&bad| bad).count()
                    >= row_state.minimum_rejecting_columns
            );
        }

        let role = &profile.specification().roles[0];
        let cols = 1usize << (role.num_vars - role.left_vars.unwrap());
        let domain = (cols.div_ceil(role.block_width.unwrap()).next_power_of_two()
            * profile.specification().blowup)
            .max(32);
        assert_eq!(failures.rejecting.len(), domain);
        let mut malformed = candidate.clone();
        malformed[0] ^= 1;
        let wrong = history.query(&malformed, shake64(&malformed)).unwrap();
        assert!(
            primary_column_run_proposal::<F, EF, P>(
                profile, pp, setup, statement, &history, &wrong, &malformed
            )
            .is_none()
        );
        frame(
            &mut candidate,
            3,
            b"mw unbiased column",
            &7u64.to_le_bytes(),
        );
        frame(
            &mut candidate,
            2,
            b"mw unbiased column",
            &8u64.to_le_bytes(),
        );
    }
    // The row request can be queried after its column family. Its pre-state
    // still depends only on its own first producer view and fixed source word.
    let mut row_words = classical_history::History::default();
    row_words.declare_input(row_request);
    let row_view = history.query(row_request, shake64(row_request)).unwrap();
    let before = primary_row_query_state::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &row_view,
        row_request,
        &row_words,
    )
    .unwrap();
    assert_eq!(before.request, row_request);
    assert_eq!(before.coefficient_count, random.len());
    assert_eq!(encoded(&before.opening.sources), encoded(&opening.sources));
    assert!(before.source_near_and_padded);
    assert!(
        before
            .assigned_value
            .iter()
            .all(|&value| value == F::zero())
    );
    assert_eq!(
        before.false_relation,
        before.assigned_value != opening.values[0]
    );
    let actual = RowStreamOutput {
        request: row_request,
        coefficients: random,
        consumed_raw: &raw,
    };
    let after = primary_row_transition(&before, &actual).unwrap();
    assert_eq!(after.false_relation, before.false_relation);
    let root_view = history.first_view(&family_root).unwrap();
    let proposed = primary_column_run_proposal::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &root_view,
        &family_root,
    )
    .unwrap();
    assert!(primary_row_proposal_consistent(&before, &actual, &proposed));
    let proposed_state = primary_row_state(profile, &proposed, &row_words).unwrap();
    assert_eq!(after.bad_after_rows, proposed_state.bad_after_rows);
    assert_eq!(
        after.minimum_rejecting_columns,
        proposed_state.minimum_rejecting_columns
    );
    assert!(
        primary_row_transition(
            &before,
            &RowStreamOutput {
                request: b"wrong request",
                ..actual
            }
        )
        .is_none()
    );
    assert!(
        primary_row_transition(
            &before,
            &RowStreamOutput {
                coefficients: &random[..random.len() - 1],
                ..actual
            }
        )
        .is_none()
    );
    assert!(
        primary_row_transition(
            &before,
            &RowStreamOutput {
                consumed_raw: &raw[..raw.len() - 1],
                ..actual
            }
        )
        .is_none()
    );
    assert!(replay_raw_prime_values::<F>(&raw, usize::MAX).is_none());
    let mut changed_coins = random.to_vec();
    changed_coins[0] += F::one();
    assert!(
        primary_row_transition(
            &before,
            &RowStreamOutput {
                coefficients: &changed_coins,
                ..actual
            }
        )
        .is_none()
    );
    // A counterfactual stream can decode to the same coefficients after an
    // extra rejected candidate, but cannot match the original proposed receipt.
    let prime: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let bytes = ((128 - (prime - 1).leading_zeros()) as usize).div_ceil(8);
    let mut different_raw = prime.to_le_bytes()[..bytes].to_vec();
    different_raw.extend_from_slice(&raw);
    let counterfactual = RowStreamOutput {
        consumed_raw: &different_raw,
        ..actual
    };
    assert!(primary_row_transition(&before, &counterfactual).is_some());
    assert!(!primary_row_proposal_consistent(
        &before,
        &counterfactual,
        &proposed
    ));
    let mut trailing = raw.clone();
    trailing.extend_from_slice(&prime.to_le_bytes()[..bytes]);
    assert!(
        primary_row_transition(
            &before,
            &RowStreamOutput {
                consumed_raw: &trailing,
                ..actual
            }
        )
        .is_none()
    );
    let ledger = primary_query_ledger::<F, EF, P>(
        profile, pp, setup, statement, &history, &row_view, &row_words,
    )
    .unwrap();
    assert_eq!(ledger.row_candidates, 1);
    assert_eq!(ledger.admitted_rows, 1);
    assert_eq!(ledger.false_rows, usize::from(before.false_relation));
    assert_eq!(ledger.admitted_families, 1);
    assert!(
        ledger.unclassified_families > 0,
        "malformed family inputs cannot silently count as admitted"
    );
    let root_boundary = history.first_view(&family_root).unwrap();
    let earlier = primary_query_ledger::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &root_boundary,
        &row_words,
    )
    .unwrap();
    assert_eq!(
        earlier.row_candidates, 0,
        "row request was queried after its column family"
    );
    assert_eq!(earlier.admitted_families, 1);
    history.query(row_request, shake64(row_request)).unwrap();
    assert_eq!(
        ledger,
        primary_query_ledger::<F, EF, P>(
            profile, pp, setup, statement, &history, &row_view, &row_words
        )
        .unwrap()
    );
    let mut malformed_row = row_request.to_vec();
    malformed_row[0] ^= 1;
    let new_boundary = history
        .query(&malformed_row, shake64(&malformed_row))
        .unwrap();
    let current = primary_query_ledger::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &new_boundary,
        &row_words,
    )
    .unwrap();
    assert_eq!(current.distinct_inputs, ledger.distinct_inputs + 1);
    assert_eq!(current.row_candidates, ledger.row_candidates + 1);
    assert_eq!(current.admitted_rows, ledger.admitted_rows);
    assert_eq!(current.unclassified_rows, ledger.unclassified_rows + 1);
    assert_eq!(
        ledger,
        primary_query_ledger::<F, EF, P>(
            profile, pp, setup, statement, &history, &row_view, &row_words
        )
        .unwrap()
    );
    let (source_root, mut actual_words) = complete_primary_source_graph(profile, source_table);
    assert_eq!(source_root, opening.sources[0].1.root);
    for producer in known.values() {
        actual_words.declare_input(producer);
    }
    actual_words.declare_input(&row_producer);
    actual_words.declare_input(&family_root);
    let real_before = primary_row_query_state::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &row_view,
        row_request,
        &actual_words,
    )
    .unwrap();
    assert_eq!(
        real_before.assigned_value,
        source_table.evaluate(&opening.query).unwrap()
    );
    assert!(real_before.false_relation);
    let current = primary_query_ledger::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &history,
        &new_boundary,
        &actual_words,
    )
    .unwrap();
    assert_eq!(current.false_rows, 1);
    assert_eq!(current.bad_families, 1);
    assert_eq!(current.admitted_rows, 1);
    assert_eq!(current.admitted_families, 1);
    println!(
        "HB_FIRST_PRIMARY_QUERY_LEDGER {{\"prime\":\"{}\",\"distinct_inputs\":{},\"row_candidates\":{},\"admitted_rows\":{},\"false_rows\":{},\"unclassified_rows\":{},\"syntactic_families\":{},\"admitted_families\":{},\"bad_families\":{},\"unclassified_families\":{},\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        current.distinct_inputs,
        current.row_candidates,
        current.admitted_rows,
        current.false_rows,
        current.unclassified_rows,
        current.syntactic_families,
        current.admitted_families,
        current.bad_families,
        current.unclassified_families
    );
    let mut alternate = classical_xof_history::History::default();
    for (digest, producer) in known {
        alternate.query(producer, *digest).unwrap();
    }
    let alternate_view = alternate.query(row_request, [0xa5; 64]).unwrap();
    let other = primary_row_query_state::<F, EF, P>(
        profile,
        pp,
        setup,
        statement,
        &alternate,
        &alternate_view,
        row_request,
        &row_words,
    )
    .unwrap();
    assert_eq!(before.assigned_value, other.assigned_value);
    assert_eq!(
        before.false_relation, other.false_relation,
        "current answers cannot affect pre-row classification"
    );
    assert!(
        primary_row_query_state::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &history,
            &alternate_view,
            row_request,
            &row_words
        )
        .is_none()
    );
    // Hide one genuinely referenced earlier receipt at the row's first query.
    let (digest, producer) = known
        .iter()
        .find(|(digest, _)| {
            row_request
                .windows(64)
                .any(|window| window == digest.as_slice())
        })
        .unwrap();
    let mut late = classical_xof_history::History::default();
    for (key, input) in known {
        if key != digest {
            late.query(input, *key).unwrap();
        }
    }
    let early = late.query(row_request, shake64(row_request)).unwrap();
    assert!(
        primary_row_query_state::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &late,
            &early,
            row_request,
            &row_words
        )
        .is_none()
    );
    late.query(producer, *digest).unwrap();
    assert!(late.availability_hits() > 0);
    let later = late.query(&family_root, shake64(&family_root)).unwrap();
    let enlarged = late.producers(&later).unwrap();
    let missing_row =
        primary_query_ledger::<F, EF, P>(profile, pp, setup, statement, &late, &later, &row_words)
            .unwrap();
    assert_eq!(missing_row.missing_receipt_rows, 1);

    assert!(
        brakedown_first_query::<F, EF, P>(profile, pp, setup, statement, row_request, &enlarged)
            .is_some()
    );
    assert!(
        primary_row_query_state::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &late,
            &later,
            row_request,
            &row_words
        )
        .is_none()
    );
    let repeated = late.query(row_request, shake64(row_request)).unwrap();
    assert!(
        primary_row_query_state::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &late,
            &repeated,
            row_request,
            &row_words
        )
        .is_none(),
        "later producers cannot repair an original row view"
    );
    assert_eq!(current.header_mismatch_rows, current.unclassified_rows);
    assert_eq!(
        current.header_mismatch_families,
        current.unclassified_families
    );
    println!(
        "HB_FIRST_PRIMARY_QUERY_DIAGNOSTICS {{\"prime\":\"{}\",\"header_mismatch_rows\":{},\"missing_receipt_rows\":{},\"other_rows\":{},\"header_mismatch_families\":{},\"missing_receipt_families\":{},\"other_families\":{},\"late_row_missing\":{},\"late_family_missing\":{},\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        current.header_mismatch_rows,
        current.missing_receipt_rows,
        current.other_unclassified_rows,
        current.header_mismatch_families,
        current.missing_receipt_families,
        current.other_unclassified_families,
        missing_row.missing_receipt_rows,
        missing_family.missing_receipt_families
    );
    // Couple the actual row bytes and completed sequential draws only after
    // all first-query ledger checks. These later observations cannot enlarge
    // any of the frozen views checked above.
    let short_outputs = history.checkpoint();
    let completion = shake64(row_request);
    history.query_output_prefix(
        row_request,
        if raw.len() < 64 { &completion } else { &raw },
        classical_xof_history::QueryActor::Verifier,
    ).unwrap();
    let root_output = observed_streams.prefix(&family_root).expect("observed v4 column reader");
    assert_eq!(root_output.len(), 8);
    assert_eq!(observed_streams.first_query_precedes(row_request, &family_root), Some(true));
    assert_eq!(observed_streams.prefix_before_first_query(row_request, &family_root), Some(raw.as_slice()));
    assert!(observed_streams.prefix_before_first_query(&family_root, &family_root).is_none());
    let mut actual_descendant = family_root.clone();
    frame(&mut actual_descendant, 3, b"mw unbiased column", &root_output[..8]);
    frame(&mut actual_descendant, 2, b"mw unbiased column", &8u64.to_le_bytes());
    assert_eq!(observed_streams.prefix_before_first_query(&family_root, &actual_descendant), Some(root_output));
    let actual_view = history.query(&actual_descendant, shake64(&actual_descendant)).unwrap();
    let mut changed_output = root_output[..8].to_vec();
    changed_output[7] ^= 0x80;
    let mut forged_descendant = family_root.clone();
    frame(&mut forged_descendant, 3, b"mw unbiased column", &changed_output);
    frame(&mut forged_descendant, 2, b"mw unbiased column", &8u64.to_le_bytes());
    let forged_view = history.query(&forged_descendant, shake64(&forged_descendant)).unwrap();
    let answered = history.checkpoint();
    let matching = primary_column_run_proposal::<F, EF, P>(
        profile, pp, setup, statement, &history, &actual_view, &actual_descendant,
    ).unwrap();
    let forged = primary_column_run_proposal::<F, EF, P>(
        profile, pp, setup, statement, &history, &forged_view, &forged_descendant,
    ).unwrap();
    assert_eq!(matching.response.columns.prior_indices.len(), 1);
    assert_eq!(matching.response.columns.prior_indices, forged.response.columns.prior_indices);
    assert_eq!(primary_recorded_column_run_transition(
        &history, &answered, &before, &actual, &matching,
    ), Some(after));
    assert!(primary_recorded_column_run_transition(
        &history, &answered, &before, &actual, &forged,
    ).is_none());
    if raw.len() > 64 {
        assert!(primary_recorded_column_run_transition(
            &history, &short_outputs, &before, &actual, &matching,
        ).is_none());
    }
    assert!(primary_recorded_column_run_transition(
        &classical_xof_history::History::default(), &answered, &before, &actual, &matching,
    ).is_none());

    // Count the whole syntactic family even if its earliest queried node is
    // beyond the semantic accepted-draw quota or off the eventual oracle path.
    let mut stop_history = classical_xof_history::History::default();
    let mut stop_root = initial_header::<F>(profile).unwrap();
    frame(
        &mut stop_root,
        1,
        b"opaque column-stop stage",
        b"syntactic superclass",
    );
    frame(
        &mut stop_root,
        2,
        b"mw unbiased column",
        &8u64.to_le_bytes(),
    );
    let quota = profile
        .specification()
        .roles
        .iter()
        .map(|role| role.queries)
        .max()
        .unwrap();
    let mut beyond_quota = stop_root.clone();
    for _ in 0..=quota {
        frame(
            &mut beyond_quota,
            3,
            b"mw unbiased column",
            &0u64.to_le_bytes(),
        );
        frame(
            &mut beyond_quota,
            2,
            b"mw unbiased column",
            &8u64.to_le_bytes(),
        );
    }
    let first = stop_history
        .query_with_actor(
            &beyond_quota,
            shake64(&beyond_quota),
            classical_xof_history::QueryActor::Adversary,
        )
        .unwrap();
    assert!(
        canonical_column_run_proposal(&stop_history, &first, &beyond_quota, 32, quota).is_none()
    );
    assert_eq!(
        column_stop_family_root(profile, &beyond_quota),
        Some(stop_root.as_slice())
    );
    stop_history
        .query_with_actor(
            &stop_root,
            shake64(&stop_root),
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    stop_history
        .query_with_actor(
            &beyond_quota,
            shake64(&beyond_quota),
            classical_xof_history::QueryActor::Verifier,
        )
        .unwrap();
    let mut other_root = initial_header::<F>(profile).unwrap();
    frame(
        &mut other_root,
        1,
        b"opaque column-stop stage",
        b"another family",
    );
    frame(
        &mut other_root,
        2,
        b"mw unbiased column",
        &8u64.to_le_bytes(),
    );
    let boundary = stop_history
        .query_with_actor(
            &other_root,
            shake64(&other_root),
            classical_xof_history::QueryActor::Setup,
        )
        .unwrap();
    let stops = column_stop_ledger(profile, &stop_history, &boundary).unwrap();
    assert_eq!(stops.distinct_inputs, 3);
    assert_eq!(stops.member_inputs, 3);
    assert_eq!(stops.families, 2);
    assert_eq!(stops.family_actors.adversary, 1);
    assert_eq!(stops.family_actors.verifier, 0);
    assert_eq!(stops.family_actors.setup, 1);
    let mut malformed = stop_root.clone();
    *malformed.last_mut().unwrap() ^= 1;
    assert!(column_stop_family_root(profile, &malformed).is_none());
}

pub(super) struct FieldProposal<'a, F> {
    pub coefficients: Vec<F>,
    pub request: &'a [u8],
    pub proposed_raw: &'a [u8],
    /// Query availability is deliberately distinct from stream consistency.
    pub request_was_queried: bool,
}
impl<F> FieldProposal<'_, F> {
    /// Caller supplies the trusted actual stream prefix for `request`.
    /// Interpretation itself never queries that stream or reads current coins.
    pub(super) fn consistent_with(&self, actual_raw: &[u8]) -> bool {
        self.proposed_raw == actual_raw
    }
}

/// The caller must admit the enclosing candidate syntax and supply the stage's
/// trusted count and label. Candidate/view and request/receipt bindings are exact.
/// This checks their binding and recovers only a producer available at `view`.
/// An unqueried sampling request returns an explicit deferred obligation.
pub(super) fn field_proposal<'a, F: NTTField>(
    history: &'a classical_xof_history::History,
    view: &classical_xof_history::View,
    candidate: &[u8],
    request: &'a [u8],
    label: &[u8],
    count: usize,
    receipt: &[u8],
) -> Option<FieldProposal<'a, F>> {
    let prime: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    if prime < 2 || receipt.len() != 80 {
        return None;
    }
    if !history.input_is_original_view(view, candidate) {
        return None;
    }
    let mut after_request = candidate.strip_prefix(request)?;
    if message(&mut after_request, 5, label)? != receipt || after_request.is_empty() {
        return None;
    }
    let mut descriptor = prime.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    let mut tail = Vec::new();
    frame(&mut tail, 4, label, &descriptor);
    if !request.ends_with(&tail) {
        return None;
    }
    let digest: [u8; 64] = receipt[16..].try_into().ok()?;
    let producer = history.producer(view, &digest)?;
    let raw = producer.strip_prefix(RECEIPT_DOMAIN)?;
    let width = (128 - (prime - 1).leading_zeros()).div_ceil(8) as usize;
    // The legacy decoder reserves the trusted count. Bound it by the actual
    // known producer before calling it, never by an adversarial descriptor.
    if count > raw.len() / width {
        return None;
    }
    let known = Producers::from([(digest, producer.to_vec())]);
    let coefficients = replay_receipt::<F>(receipt, count, &known)?;
    Some(FieldProposal {
        coefficients,
        request,
        proposed_raw: raw,
        request_was_queried: history.input_was_queried(view, request),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{One, Zero};

    #[test]
    fn recorded_reader_chunks_merge_replays_and_reject_gaps_or_conflicts() {
        let mut streams = RecordedStreams::default();
        assert!(streams.record(b"stream", 0, &[1, 2]).is_err());
        streams.record_input(b"stream").unwrap();
        streams.record(b"stream", 0, &[1, 2]).unwrap();
        streams.record(b"stream", 1, &[2, 3]).unwrap();
        streams.record(b"stream", 0, &[1]).unwrap();
        assert_eq!(streams.prefix(b"stream"), Some(&[1, 2, 3][..]));
        assert!(streams.record(b"stream", 2, &[9]).is_err());
        assert!(streams.record(b"stream", 4, &[4]).is_err());
        streams.record_input(b"unseen").unwrap();
        assert!(streams.record(b"unseen", 1, &[0]).is_err());
        assert!(streams.record(b"unseen", u128::MAX, &[0]).is_err());
        assert!(streams.prefix(b"unseen").is_none());
        assert_eq!(streams.prefix(b"stream"), Some(&[1, 2, 3][..]));
        streams.record_input(b"empty read").unwrap();
        streams.record(b"empty read", 0, &[]).unwrap();
        assert_eq!(streams.prefix(b"empty read"), Some(&[][..]));
    }

    #[test]
    fn observed_prefixes_freeze_at_original_query_boundaries() {
        let mut streams = RecordedStreams::default();
        streams.record_input(b"row").unwrap();
        streams.record(b"row", 0, &[1, 2]).unwrap();
        streams.record_input(b"column").unwrap();
        streams.record(b"row", 2, &[3]).unwrap();
        streams.record_input(b"column").unwrap();
        assert_eq!(streams.first_query_precedes(b"row", b"column"), Some(true));
        assert_eq!(streams.first_query_precedes(b"column", b"row"), Some(false));
        assert_eq!(streams.first_query_precedes(b"row", b"unknown"), None);
        assert_eq!(streams.prefix_before_first_query(b"row", b"column"), Some(&[1, 2][..]));
        assert!(streams.prefix_before_first_query(b"row", b"row").is_none());
        assert!(streams.prefix_before_first_query(b"column", b"column").is_none());
        streams.record_input(b"empty").unwrap();
        streams.record(b"empty", 0, &[]).unwrap();
        streams.record_input(b"later").unwrap();
        assert_eq!(streams.prefix_before_first_query(b"row", b"later"), Some(&[1, 2, 3][..]));
        assert_eq!(streams.prefix_before_first_query(b"empty", b"later"), Some(&[][..]));
        assert!(streams.prefix_before_first_query(b"row", b"unknown").is_none());
    }

    fn byte_calls<F: NTTField, EF: AbstractExtensionField<F>>(
        label: &'static [u8],
        width: usize,
        calls: usize,
        queries: usize,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        use helper::FiatShamirTranscript;
        let profile = ClassicalProfile::new_atomic_zerocheck::<F, EF>(Specification {
            backend: Backend::Brakedown,
            roles: std::array::from_fn(|_| Role {
                num_vars: 3,
                width: 8,
                queries,
                left_vars: Some(1),
                block_width: Some(2),
            }),
            blowup: 2,
            fragment_vars: None,
        })
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let sink = Arc::clone(&seen);
        let guard = helper::classical_transcript::audit::observe(move |input| {
            sink.lock().unwrap().push(input.to_vec());
        })
        .unwrap();
        let mut transcript = profile.parent_transcript::<F>().unwrap();
        let mut outputs = Vec::new();
        for _ in 0..calls {
            let mut output = vec![0; width];
            transcript.get_challenge_bytes(label, &mut output);
            outputs.push(output);
        }
        drop(guard);
        let inputs = seen.lock().unwrap().clone();
        assert_eq!(inputs.len(), calls);
        (inputs, outputs)
    }

    #[test]
    fn sequential_column_past_bytes_require_recorded_streams_separately_from_proposals() {
        let label = b"mw unbiased column";
        let (inputs, outputs) = byte_calls::<algebra::BabyBear, algebra::BabyBearExtension6>(
            label, 8, 2, 4,
        );
        let mut history = classical_xof_history::History::default();
        let empty = history.checkpoint();
        history.query(&inputs[0], shake64(&inputs[0])).unwrap();
        let completed = history.checkpoint();
        let view = history.query(&inputs[1], shake64(&inputs[1])).unwrap();
        let actual = canonical_column_run_proposal(
            &history, &view, &inputs[1], 32, 4,
        ).unwrap();
        assert_eq!(actual.prior_indices.len(), 1);
        assert!(actual.bytes.recorded_prior_outputs_match(&history, &completed));
        assert!(!actual.bytes.recorded_prior_outputs_match(&history, &empty));
        assert!(!actual.bytes.recorded_prior_outputs_match(
            &history, &classical_xof_history::History::default().checkpoint(),
        ));
        assert!(matches!(history.query_exposure_at(&completed, &inputs[1]),
            Some(classical_xof_history::QueryExposure::Fresh)));

        // Same accepted index, different past coins. Syntactic/semantic
        // proposal admission must retain this adversarial trial; only the
        // separate recorded-output consistency check rejects its coins.
        let mut forged = inputs[0].clone();
        let mut changed = outputs[0].clone();
        changed[7] ^= 0x80;
        frame(&mut forged, 3, label, &changed);
        frame(&mut forged, 2, label, &8u64.to_le_bytes());
        let forged_view = history.query(&forged, shake64(&forged)).unwrap();
        let proposed = canonical_column_run_proposal(
            &history, &forged_view, &forged, 32, 4,
        ).unwrap();
        assert_eq!(proposed.prior_indices, actual.prior_indices);
        assert!(!proposed.bytes.recorded_prior_outputs_match(&history, &completed));

        // A first descendant may precede its proposed parent's query. A
        // later matching parent answer establishes consistency at the later
        // boundary without changing the descendant's original exposure.
        let mut late = classical_xof_history::History::default();
        let first = late.query(&inputs[1], shake64(&inputs[1])).unwrap();
        let before_parent = late.checkpoint();
        late.query(&inputs[0], shake64(&inputs[0])).unwrap();
        let after_parent = late.checkpoint();
        let proposed = canonical_column_run_proposal(
            &late, &first, &inputs[1], 32, 4,
        ).unwrap();
        assert!(!proposed.bytes.recorded_prior_outputs_match(&late, &before_parent));
        assert!(proposed.bytes.recorded_prior_outputs_match(&late, &after_parent));
        assert!(!late.input_was_queried(&first, &inputs[0]));
        let root = canonical_column_run_proposal(
            &late, &late.first_view(&inputs[0]).unwrap(), &inputs[0], 32, 4,
        ).unwrap();
        assert!(root.bytes.recorded_prior_outputs_match(&late, &before_parent));
        assert!(!root.bytes.recorded_prior_outputs_match(
            &late, &classical_xof_history::History::default().checkpoint(),
        ));
    }

    #[test]
    fn inline_byte_proposals_bind_original_views_without_producer_requirements() {
        fn exercise<F: NTTField, EF: AbstractExtensionField<F>>() {
            let label = b"ordinary earlier bytes";
            for count in [0, 8, 64] {
                let (inputs, outputs) = byte_calls::<F, EF>(label, count, 1, 4);
                let request = &inputs[0];
                let raw = vec![0xa5; count];
                let mut input = request.clone();
                frame(&mut input, 3, label, &raw);
                frame(&mut input, 2, b"current bytes", &32u64.to_le_bytes());
                let mut history = classical_xof_history::History::default();
                let view = history.query(&input, shake64(&input)).unwrap();
                let proposal =
                    byte_proposal(&history, &view, &input, request, label, count).unwrap();
                assert_eq!(proposal.proposed_raw, raw);
                assert!(!history.input_was_queried(&view, proposal.request));
                assert_eq!(proposal.consistent_with(&outputs[0]), count == 0);
                history.query(request, shake64(request)).unwrap();
                let old = history.query(&input, shake64(&input)).unwrap();
                let proposal =
                    byte_proposal(&history, &old, &input, request, label, count).unwrap();
                assert!(!history.input_was_queried(&old, proposal.request));
                let mut later_input = request.clone();
                frame(&mut later_input, 3, label, &raw);
                frame(&mut later_input, 2, b"later bytes", &32u64.to_le_bytes());
                let later = history.query(&later_input, shake64(&later_input)).unwrap();
                let proposal =
                    byte_proposal(&history, &later, &later_input, request, label, count).unwrap();
                assert!(history.input_was_queried(&later, proposal.request));
                assert_eq!(proposal.consistent_with(&outputs[0]), count == 0);
                assert!(byte_proposal(&history, &later, &input, request, label, count).is_none());
                assert!(byte_proposal(&history, &view, &input, request, b"wrong", count).is_none());
                assert!(
                    byte_proposal(&history, &view, &input, request, label, count + 1).is_none()
                );
                let mut foreign = classical_xof_history::History::default();
                let other = foreign.query(&input, shake64(&input)).unwrap();
                assert!(byte_proposal(&history, &other, &input, request, label, count).is_none());
                let mut old_tail = Vec::new();
                frame(&mut old_tail, 2, label, &(count as u64).to_le_bytes());
                let mut huge = request.strip_suffix(old_tail.as_slice()).unwrap().to_vec();
                frame(&mut huge, 2, label, &(usize::MAX as u64).to_le_bytes());
                let mut huge_input = huge.clone();
                frame(&mut huge_input, 3, label, &raw);
                frame(&mut huge_input, 2, b"current bytes", &32u64.to_le_bytes());
                let huge_view = history.query(&huge_input, shake64(&huge_input)).unwrap();
                assert!(
                    byte_proposal(&history, &huge_view, &huge_input, &huge, label, usize::MAX)
                        .is_none()
                );
            }
        }
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    #[test]
    fn column_run_proposals_preserve_rejections_repeats_and_no_message_blocks() {
        fn exercise<F: NTTField, EF: AbstractExtensionField<F>>() {
            let label = b"mw unbiased column";
            let (inputs, outputs) = byte_calls::<F, EF>(label, 8, 5, 4);
            let root = &inputs[0];
            let current = &inputs[3];
            let mut history = classical_xof_history::History::default();
            let view = history.query(current, shake64(current)).unwrap();
            let run = column_run_proposal(&history, &view, current, root, 32, 4).unwrap();
            assert_eq!(run.bytes.root_request, root);
            assert_eq!(run.bytes.current_request, current);
            assert_eq!(run.bytes.prior.len(), 3);
            for (index, prior) in run.bytes.prior.iter().enumerate() {
                assert_eq!(prior.request, inputs[index]);
                assert!(prior.consistent_with(&outputs[index]));
                assert!(!history.input_was_queried(&view, prior.request));
            }
            let limit = u64::MAX - u64::MAX % 32;
            let expected = outputs[..3]
                .iter()
                .map(|bytes| u64::from_le_bytes(bytes.as_slice().try_into().unwrap()))
                .filter(|&sample| sample < limit)
                .map(|sample| (sample % 32) as usize)
                .collect::<Vec<_>>();
            assert_eq!(run.prior_indices, expected);
            let proposed = |samples: &[u64]| {
                let mut input = root.clone();
                for sample in samples {
                    frame(&mut input, 3, label, &sample.to_le_bytes());
                    frame(&mut input, 2, label, &8u64.to_le_bytes());
                }
                input
            };
            for (samples, expected_pending, expected_maximum, expected_indices) in [
                (vec![u64::MAX; 513], 514, 0, vec![]),
                (
                    {
                        let mut v = vec![u64::MAX; 513];
                        v.push(7);
                        v
                    },
                    1,
                    514,
                    vec![7],
                ),
                (vec![limit, u64::MAX, limit - 1], 1, 3, vec![31]),
                (vec![7, 7], 1, 1, vec![7, 7]),
            ] {
                let input = proposed(&samples);
                let view = history.query(&input, shake64(&input)).unwrap();
                let run = column_run_proposal(&history, &view, &input, root, 32, 3).unwrap();
                assert_eq!(run.prior_indices, expected_indices);
                assert_eq!(run.pending_attempt, expected_pending);
                assert_eq!(run.max_completed_attempts, expected_maximum);
                assert_eq!(run.rejected, samples.len() - run.prior_indices.len());
            }
            let complete = proposed(&[7, 7]);
            let view = history.query(&complete, shake64(&complete)).unwrap();
            assert!(column_run_proposal(&history, &view, &complete, root, 32, 2).is_none());
            assert!(column_run_proposal(&history, &view, &complete, root, 0, 3).is_none());
            assert!(column_run_proposal(&history, &view, &complete, root, 32, 0).is_none());
            let mut advanced = root.clone();
            frame(&mut advanced, 3, label, &7u64.to_le_bytes());
            frame(
                &mut advanced,
                1,
                b"prover message",
                b"forbidden inside sampling",
            );
            frame(&mut advanced, 2, label, &8u64.to_le_bytes());
            let mut wrong_count = root.clone();
            frame(&mut wrong_count, 3, label, &7u64.to_le_bytes());
            frame(&mut wrong_count, 2, label, &9u64.to_le_bytes());
            for input in [advanced, wrong_count] {
                let view = history.query(&input, shake64(&input)).unwrap();
                assert!(column_run_proposal(&history, &view, &input, root, 32, 4).is_none());
            }
        }
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    #[test]
    fn canonical_column_roots_cannot_reset_completed_draws() {
        type F = algebra::BabyBear;
        type EF = algebra::BabyBearExtension6;
        let (inputs, _) = byte_calls::<F, EF>(b"mw unbiased column", 8, 1, 4);
        let root = &inputs[0];
        let mut candidate = root.clone();
        frame(
            &mut candidate,
            3,
            b"mw unbiased column",
            &7u64.to_le_bytes(),
        );
        frame(
            &mut candidate,
            2,
            b"mw unbiased column",
            &8u64.to_le_bytes(),
        );
        let mut history = classical_xof_history::History::default();
        let view = history.query(&candidate, shake64(&candidate)).unwrap();
        // A supplied descendant root can hide an already completed draw.
        assert!(column_run_proposal(&history, &view, &candidate, &candidate, 32, 1).is_some());
        assert!(canonical_column_run_proposal(&history, &view, &candidate, 32, 1).is_none());
        let run = canonical_column_run_proposal(&history, &view, &candidate, 32, 2).unwrap();
        assert_eq!(run.bytes.root_request, root);
        assert_eq!(run.prior_indices, vec![7]);
        // A framed response body containing request bytes is not a boundary.
        let mut separate = root.clone();
        frame(&mut separate, 3, b"mw unbiased column", &7u64.to_le_bytes());
        frame(&mut separate, 1, b"new stage", &candidate);
        frame(&mut separate, 2, b"mw unbiased column", &8u64.to_le_bytes());
        let view = history.query(&separate, shake64(&separate)).unwrap();
        let run = canonical_column_run_proposal(&history, &view, &separate, 32, 1).unwrap();
        assert_eq!(run.bytes.root_request, separate);
        assert!(run.prior_indices.is_empty());
        let mut truncated = separate.clone();
        truncated.pop();
        let view = history.query(&truncated, shake64(&truncated)).unwrap();
        assert!(canonical_column_run_proposal(&history, &view, &truncated, 32, 2).is_none());
    }

    #[test]
    fn scalar_column_runs_bind_exact_response_shapes() {
        type F = algebra::BabyBear;
        type EF = algebra::BabyBearExtension6;
        let (inputs, _) = byte_calls::<F, EF>(b"mw unbiased column", 8, 1, 4);
        let mut tail = Vec::new();
        frame(&mut tail, 2, b"mw unbiased column", &8u64.to_le_bytes());
        let prefix = inputs[0].strip_suffix(tail.as_slice()).unwrap();
        let test = vec![F::zero(); 4];
        let evaluation = vec![F::one(); 4];
        let body = encoded(&(&test, &evaluation));
        let mut history = classical_xof_history::History::default();
        let mut check = |label: &[u8], body: &[u8], gap: bool, cells: usize| {
            let mut input = prefix.to_vec();
            frame(&mut input, 1, label, body);
            if gap {
                frame(&mut input, 1, b"intervening message", b"");
            }
            input.extend_from_slice(&tail);
            let view = history.query(&input, shake64(&input)).unwrap();
            let result = linear_column_run_proposal::<F>(&history, &view, &input, 32, 4, cells);
            if let Some(run) = &result {
                assert_eq!(run.test, test);
                assert_eq!(run.evaluation, evaluation);
                assert_eq!(run.stage_prefix, prefix);
                assert_eq!(run.columns.bytes.root_request, input);
            }
            result.is_some()
        };
        assert!(check(b"mw linear responses", &body, false, 4));
        assert!(!check(b"mw linear responses", &body, false, 3));
        assert!(!check(b"mw linear responses", &body, false, usize::MAX));
        assert!(!check(b"mw aggregate responses", &body, false, 4));
        assert!(!check(b"mw linear responses", &body, true, 4));
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(!check(b"mw linear responses", &trailing, false, 4));
        assert!(!check(
            b"mw linear responses",
            &body[..body.len() - 1],
            false,
            4
        ));
    }

    #[test]
    fn babybear_primary_v4_column_task_binding() {
        exercise_backend::<algebra::BabyBear, algebra::BabyBearExtension6>(
            8,
            4,
            Backend::Brakedown,
        );
    }

    #[test]
    fn goldilocks_primary_v4_column_task_binding() {
        exercise_backend::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
            4,
            4,
            Backend::Brakedown,
        );
    }

    fn exercise_primary_frozen_words<F, EF>()
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F>,
    {
        use algebra::matrix_weighted::{Matrix, MatrixPair};
        use pcs::utils::code::RowCode;
        let width = EF::D.next_power_of_two();
        let profile = ClassicalProfile::new_atomic_zerocheck::<F, EF>(Specification {
            backend: Backend::Brakedown,
            roles: std::array::from_fn(|_| Role {
                num_vars: 3,
                width,
                queries: 4,
                left_vars: Some(1),
                block_width: Some(2),
            }),
            blowup: 2,
            fragment_vars: None,
        })
        .unwrap();
        let bundle = profile.brakedown_parameters::<F, EF>().unwrap();
        let pp = crate::packed_pbs::canonical::classical::parameters(&bundle);
        let parameters = pp.evaluations;
        let table =
            PackedTable::new(3, width, (1usize..=8 * width).map(F::from).collect()).unwrap();
        let (commitment, state) = parameters.commit::<F, Sha512>(&table).unwrap();
        let context = parameters.context_digest::<F, Sha512>().unwrap();
        let pair = MatrixPair {
            zero: Matrix::identity(width).unwrap(),
            one: Matrix::new(width, vec![F::zero(); width * width]).unwrap(),
        };
        let query = vec![pair; 3];
        let evaluated = table.evaluate(&query).unwrap();
        assert!(evaluated.iter().any(|&v| v != F::zero()));
        let mut task = FirstOpening {
            family: OpeningFamily::Primary,
            selected: 0,
            sources: vec![(context, commitment.clone()); 2],
            query,
            values: vec![evaluated.clone(); 2],
        };
        let code = parameters.code();
        let mut columns = vec![Vec::new(); code.codeword_blocks()];
        for row in 0..2 * width {
            let message: Vec<_> = (0..4)
                .map(|right| table.at(row / width + (right << 1))[row % width])
                .collect();
            let mut output = vec![F::zero(); code.codeword_blocks() * code.block_width()];
            code.encode_row(&message, &mut output);
            for (index, column) in columns.iter_mut().enumerate() {
                column.extend_from_slice(&output[index * 2..index * 2 + 2]);
            }
        }
        let mut row_transcript = bundle.profile().parent_transcript::<F>().unwrap();
        row_transcript.append_message(b"mw brakedown row-code v2", &context);
        row_transcript.append_message(
            b"mw commitment and query",
            &(&commitment, &task.query, &task.values[0]),
        );
        let random = row_transcript.get_vec_challenge(b"mw random linear test", width * width * 2);
        let mut prover = bundle.profile().parent_transcript::<F>().unwrap();
        let proof = parameters
            .open::<F, Sha512>(
                &mut prover,
                &commitment,
                &state,
                &task.query,
                &task.values[0],
            )
            .unwrap();
        let valid = scalar_column_failures(
            parameters,
            &columns,
            &task.query,
            &random,
            &proof.test,
            &proof.evaluation,
            &task.values[0],
        )
        .unwrap();
        assert!(valid.rejecting.iter().all(|&bad| !bad));
        assert!(valid.claimed_value_matches);
        let mut verifier = bundle.profile().parent_transcript::<F>().unwrap();
        parameters
            .verify::<F, Sha512>(
                &mut verifier,
                &commitment,
                &task.query,
                &task.values[0],
                &proof,
            )
            .unwrap();
        let mut changed = proof.clone();
        changed.test[0] += F::one();
        // Rebind the changed response before sampling: old paths target a
        // different Fiat-Shamir run and would reject before the dot-product test.
        row_transcript.append_message(
            b"mw linear responses",
            &(&changed.test, &changed.evaluation),
        );
        let domain = code.codeword_blocks();
        let limit = u64::MAX - u64::MAX % (domain as u64);
        let mut indices = Vec::new();
        for _ in 0..parameters.queries() {
            loop {
                let mut bytes = [0; 8];
                row_transcript.get_challenge_bytes(b"mw unbiased column", &mut bytes);
                let sample = u64::from_le_bytes(bytes);
                if sample < limit {
                    indices.push((sample % (domain as u64)) as usize);
                    break;
                }
            }
        }
        indices.sort_unstable();
        indices.dedup();
        let leaves: Vec<_> = columns
            .iter()
            .map(|column| {
                let mut raw = b"HasteBoots/mw-column/v1".to_vec();
                raw.extend(encoded(column));
                Digest512(Sha512::digest(&raw).into())
            })
            .collect();
        let mut tree = pcs::utils::merkle_tree::MerkleTree::<Sha512>::new();
        tree.generate(&leaves);
        assert_eq!(tree.root, commitment.root);
        changed.columns = indices
            .into_iter()
            .map(|index| pcs::matrix_weighted::Column {
                values: columns[index].clone(),
                path: tree.query(index),
            })
            .collect();

        let invalid = scalar_column_failures(
            parameters,
            &columns,
            &task.query,
            &random,
            &changed.test,
            &changed.evaluation,
            &task.values[0],
        )
        .unwrap();
        assert!(invalid.rejecting.iter().all(|&bad| bad));
        assert!(
            invalid.claimed_value_matches,
            "response test mutation preserves the final evaluation"
        );
        let mut verifier = bundle.profile().parent_transcript::<F>().unwrap();
        assert!(
            parameters
                .verify::<F, Sha512>(
                    &mut verifier,
                    &commitment,
                    &task.query,
                    &task.values[0],
                    &changed
                )
                .unwrap_err()
                .to_string()
                .contains("linear response inconsistent")
        );
        assert!(
            scalar_column_failures(
                parameters,
                &columns,
                &task.query,
                &random[..random.len() - 1],
                &proof.test,
                &proof.evaluation,
                &task.values[0]
            )
            .is_none()
        );
        // A valid common nearby word and a false, final-equation-consistent
        // structured response must leave at least D-t rejecting columns.
        let distance = code.codeword_blocks() - code.message_blocks() + 1;
        let radius = (distance - 1) / 3;
        let mut nearby = columns.clone();
        for column in nearby.iter_mut().take(radius) {
            column[0] += F::one();
        }
        let (near, decoded) =
            classical_assignment::brakedown_assignment(&nearby, 3, width, 1, code);
        assert!(near);
        assert_eq!(decoded.values(), table.values());
        let mut false_evaluation = proof.evaluation.clone();
        false_evaluation[0] += F::one();
        let mut false_claim = task.values[0].clone();
        false_claim[0] += F::one();
        let false_near = scalar_column_failures(
            parameters,
            &nearby,
            &task.query,
            &random,
            &proof.test,
            &false_evaluation,
            &false_claim,
        )
        .unwrap();
        assert!(false_near.claimed_value_matches);
        let near_state =
            scalar_row_state(parameters, &nearby, &task.query, &random, &false_claim).unwrap();
        assert!(
            near_state.source_near_and_padded
                && near_state.false_relation
                && near_state.bad_after_rows
        );
        assert!(near_state.projected_test_near_and_padded);
        assert_eq!(near_state.minimum_rejecting_columns, distance - radius);
        assert!(
            false_near.rejecting.iter().filter(|&&bad| bad).count()
                >= near_state.minimum_rejecting_columns
        );
        // A reciprocal word has distance >= N-m from degree-<m RS: multiplying
        // an agreeing polynomial by X leaves a degree-<=m root equation.
        let mut points = vec![F::zero(); code.codeword_blocks()];
        points[1] = F::one();
        F::get_ntt_table(code.codeword_blocks().ilog2())
            .unwrap()
            .transform_slice(&mut points);
        let mut far = vec![vec![F::zero(); 2 * width * code.block_width()]; code.codeword_blocks()];
        for (column, point) in far.iter_mut().zip(points) {
            column[0] = F::one() / point;
        }
        let mut exposing = vec![F::zero(); random.len()];
        exposing[0] = F::one();
        let zero_claim = vec![F::zero(); width];
        let far_state =
            scalar_row_state(parameters, &far, &task.query, &exposing, &zero_claim).unwrap();
        assert!(!far_state.source_near_and_padded && !far_state.projected_test_near_and_padded);
        assert!(far_state.false_relation && far_state.bad_after_rows);
        assert_eq!(far_state.minimum_rejecting_columns, radius + 1);
        let zero_response = vec![F::zero(); proof.test.len()];
        let far_failures = scalar_column_failures(
            parameters,
            &far,
            &task.query,
            &exposing,
            &zero_response,
            &zero_response,
            &zero_claim,
        )
        .unwrap();
        assert!(far_failures.claimed_value_matches);
        assert!(
            far_failures.rejecting.iter().filter(|&&bad| bad).count()
                >= far_state.minimum_rejecting_columns
        );
        let hidden = scalar_row_state(
            parameters,
            &far,
            &task.query,
            &vec![F::zero(); random.len()],
            &zero_claim,
        )
        .unwrap();
        assert!(hidden.false_relation && hidden.projected_test_near_and_padded);
        assert!(
            !hidden.bad_after_rows,
            "exceptional row choices must remain explicit escape events"
        );

        assert!(false_near.rejecting.iter().filter(|&&bad| bad).count() >= distance - radius);
        let mut wrong_claim = task.values[0].clone();
        wrong_claim[0] += F::one();
        let wrong = scalar_column_failures(
            parameters,
            &columns,
            &task.query,
            &random,
            &proof.test,
            &proof.evaluation,
            &wrong_claim,
        )
        .unwrap();
        assert!(wrong.rejecting.iter().all(|&bad| !bad));
        assert!(!wrong.claimed_value_matches);
        let mut events = Vec::new();
        let mut nodes: Vec<_> = columns
            .iter()
            .map(|column| {
                let mut raw = b"HasteBoots/mw-column/v1".to_vec();
                raw.extend(encoded(column));
                let digest = Digest512(Sha512::digest(&raw).into());
                events.push((digest, raw));
                digest
            })
            .collect();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| {
                    let mut raw = pair[0].0.to_vec();
                    raw.extend(pair[1].0);
                    let digest = Digest512(Sha512::digest(&raw).into());
                    events.push((digest, raw));
                    digest
                })
                .collect();
        }
        assert_eq!(nodes[0], commitment.root);
        let mut early = classical_history::History::default();
        early.declare_input(&commitment.root.0);
        let before = primary_frozen_values(bundle.profile(), &pp, &task, &early).unwrap();
        assert!(before.values.iter().flatten().all(|&v| v == F::zero()));
        let mut complete = classical_history::History::default();
        for (digest, raw) in events {
            early.expose(digest, raw.clone());
            complete.expose(digest, raw);
        }
        complete.declare_input(&commitment.root.0);
        let after = primary_frozen_values(bundle.profile(), &pp, &task, &early).unwrap();
        assert_eq!(
            before.values, after.values,
            "later preimages cannot repair an assignment"
        );
        let assigned = primary_frozen_values(bundle.profile(), &pp, &task, &complete).unwrap();
        assert_eq!(
            assigned.unique_sources, 1,
            "exact aliases share one assignment"
        );
        assert!(assigned.near.iter().all(|&v| v));
        assert_eq!(assigned.values, vec![evaluated; 2]);
        task.sources[1].0.0[0] ^= 1;
        assert!(primary_frozen_values(bundle.profile(), &pp, &task, &complete).is_none());
    }

    #[test]
    fn babybear_primary_frozen_words_preserve_first_declarations() {
        exercise_primary_frozen_words::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_primary_frozen_words_preserve_first_declarations() {
        exercise_primary_frozen_words::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    fn exercise_padded_and_far_row_states<F: NTTField>(width: usize) {
        use algebra::matrix_weighted::{Matrix, MatrixPair};
        use pcs::utils::code::{BlockReedSolomonCode, RowCode};
        // Native symbol degree equals the number of independent test rows.
        // There is one real scalar and width-1 forbidden padded coordinates.
        let code = BlockReedSolomonCode::<F>::new(1, width, 2).unwrap();
        let parameters =
            pcs::matrix_weighted::Parameters::new_encoded::<F>(1, width, 1, 4, code).unwrap();
        let code = parameters.code();
        assert!(width <= code.block_width());
        let domain = code.codeword_blocks();
        let rows = 2 * width;
        let zero = Matrix::new(width, vec![F::zero(); width * width]).unwrap();
        let query = vec![MatrixPair {
            zero: zero.clone(),
            one: zero,
        }];
        let claim = vec![F::zero(); width];
        let response = vec![F::zero(); width];
        let mut padded = vec![vec![F::zero(); rows * code.block_width()]; domain];
        for column in &mut padded {
            column[1] = F::one();
        }
        let mut exposing = vec![F::zero(); width * rows];
        exposing[0] = F::one();
        let state = scalar_row_state(&parameters, &padded, &query, &exposing, &claim).unwrap();
        assert!(!state.source_near_and_padded && state.false_relation);
        assert!(
            state.projected_test_rs_near,
            "padding must be distinguished from RS distance"
        );
        assert!(!state.projected_test_near_and_padded && state.bad_after_rows);
        let checks = scalar_column_failures(
            &parameters,
            &padded,
            &query,
            &exposing,
            &response,
            &response,
            &claim,
        )
        .unwrap();
        assert!(checks.claimed_value_matches);
        assert!(checks.rejecting.iter().all(|&bad| bad));
        assert!(checks.rejecting.len() >= state.minimum_rejecting_columns);
        // Every row is nonzero, but all kill the padding residual in row zero.
        let mut killing = vec![F::zero(); width * rows];
        for lane in 0..width {
            killing[lane * rows + 1] = F::one();
        }
        let hidden = scalar_row_state(&parameters, &padded, &query, &killing, &claim).unwrap();
        assert!(
            hidden.false_relation
                && hidden.projected_test_rs_near
                && hidden.projected_test_near_and_padded
        );
        assert!(!hidden.bad_after_rows);
        let mut points = vec![F::zero(); domain];
        points[1] = F::one();
        F::get_ntt_table(domain.ilog2())
            .unwrap()
            .transform_slice(&mut points);
        let mut far = vec![vec![F::zero(); rows * code.block_width()]; domain];
        for (column, point) in far.iter_mut().zip(points) {
            column[0] = F::one() / point;
        }
        let state = scalar_row_state(&parameters, &far, &query, &exposing, &claim).unwrap();
        assert!(!state.source_near_and_padded && !state.projected_test_rs_near);
        assert!(state.false_relation && state.bad_after_rows);
        let checks = scalar_column_failures(
            &parameters,
            &far,
            &query,
            &exposing,
            &response,
            &response,
            &claim,
        )
        .unwrap();
        assert!(checks.claimed_value_matches && checks.rejecting.iter().all(|&bad| bad));
        assert!(checks.rejecting.len() >= state.minimum_rejecting_columns);
        let hidden = scalar_row_state(&parameters, &far, &query, &killing, &claim).unwrap();
        assert!(
            hidden.false_relation
                && hidden.projected_test_near_and_padded
                && !hidden.bad_after_rows
        );
    }

    #[test]
    fn babybear_native_symbol_padding_and_far_row_states() {
        exercise_padded_and_far_row_states::<algebra::BabyBear>(8);
    }
    #[test]
    fn goldilocks_native_symbol_padding_and_far_row_states() {
        exercise_padded_and_far_row_states::<algebra::Goldilocks>(4);
    }

    fn exercise_one_variable_reduction<F, EF>()
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F>,
    {
        let width = EF::D.next_power_of_two();
        let profile = ClassicalProfile::new_atomic_zerocheck::<F, EF>(Specification {
            backend: Backend::Brakedown,
            roles: std::array::from_fn(|_| Role {
                num_vars: 1,
                width,
                queries: 4,
                left_vars: Some(0),
                block_width: Some(width),
            }),
            blowup: 2,
            fragment_vars: None,
        })
        .unwrap();
        let shape = sumcheck::packed::PackedShape {
            num_vars: 1,
            width,
            num_factors: 2,
            terms: vec![(F::one(), vec![0, 1])],
        };
        let mut first_values = vec![F::zero(); width];
        first_values.extend(vec![F::one(); width]);
        let second_values = first_values.iter().map(|&x| F::one() - x).collect();
        let factors = vec![
            PackedTable::new(1, width, first_values).unwrap(),
            PackedTable::new(1, width, second_values).unwrap(),
        ];
        let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let sink = Arc::clone(&seen);
        let guard = helper::classical_transcript::audit::observe(move |input| {
            sink.lock().unwrap().push(input.to_vec())
        })
        .unwrap();
        let mut prover = profile.parent_transcript::<F>().unwrap();
        let (proof, subclaim) =
            sumcheck::packed_zero::prove(&mut prover, &shape, &factors).unwrap();
        drop(guard);
        assert!(proof.rest.rounds.is_empty());
        assert!(proof.first.iter().flatten().any(|&x| x != F::zero()));
        let mut verifier = profile.parent_transcript::<F>().unwrap();
        let verified = sumcheck::packed_zero::verify(&mut verifier, &shape, &proof).unwrap();
        assert_eq!(encoded(&verified.query), encoded(&subclaim.query));
        let queries = seen.lock().unwrap();
        let producers: Vec<_> = queries
            .iter()
            .filter(|input| input.starts_with(RECEIPT_DOMAIN) && input.len() > RECEIPT_DOMAIN.len())
            .collect();
        assert_eq!(producers.len(), 1);
        let raw = &producers[0][RECEIPT_DOMAIN.len()..];
        let (receipt, producer) = receipt(raw);
        let known = Producers::from([(receipt[16..].try_into().unwrap(), producer)]);
        let mut suffix = Vec::new();
        frame(
            &mut suffix,
            5,
            b"packed zero atomic first coins v4",
            &receipt,
        );
        frame(
            &mut suffix,
            1,
            b"packed sumcheck v1",
            &encoded(&reduced(&shape)),
        );
        frame(
            &mut suffix,
            1,
            b"packed claimed sum",
            &encoded(&subclaim.expected),
        );
        let mut terminal = Vec::new();
        frame(
            &mut terminal,
            1,
            b"packed relation terminal values",
            b"next stage",
        );
        suffix.extend_from_slice(&terminal);
        let initial = || InitialMixing {
            task: InitialProduct {
                shape: shape.clone(),
                sources: Vec::new(),
            },
            equality: Vec::new(),
            first: proof.first.clone(),
        };
        let (task, rest) = first_reduced_prefix(initial(), &suffix, &known).unwrap();
        assert_eq!(rest, terminal);
        assert_eq!(encoded(&task.query), encoded(&verified.query));
        assert_eq!(task.expected, verified.expected);
        assert_eq!(task.equality_table().unwrap().values(), verified.equality);
        assert!(first_reduced_prefix(initial(), &suffix, &Producers::new()).is_none());
        let mut wrong = Vec::new();
        frame(
            &mut wrong,
            5,
            b"packed zero atomic first coins v4",
            &receipt,
        );
        frame(
            &mut wrong,
            1,
            b"packed sumcheck v1",
            &encoded(&reduced(&shape)),
        );
        let mut claim = subclaim.expected.clone();
        claim[0] += F::one();
        frame(&mut wrong, 1, b"packed claimed sum", &encoded(&claim));
        assert!(first_reduced_prefix(initial(), &wrong, &known).is_none());
    }
    #[test]
    fn babybear_one_variable_first_reduction_matches_verifier() {
        exercise_one_variable_reduction::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_one_variable_first_reduction_matches_verifier() {
        exercise_one_variable_reduction::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    fn exercise_missing_fingerprint_witness<F: NTTField, EF: AbstractExtensionField<F>>() {
        let request = make_request::<F, EF>(1);
        let prime: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let bytes = ((128 - (prime - 1).leading_zeros()) as usize).div_ceil(8);
        let raw = 1u128.to_le_bytes()[..bytes].to_vec();
        let (receipt, producer) = receipt(&raw);
        let input = candidate::<F>(&request, &receipt, b"pending");
        let mut history = classical_xof_history::History::default();
        let original = history.query(&input, shake64(&input)).unwrap();
        let FieldFingerprintAvailability::Missing(witness) =
            field_fingerprint_availability(&history, &original, &input).unwrap()
        else {
            panic!("missing producer must have a window witness")
        };
        assert_eq!(&input[witness.offset..witness.offset + 64], witness.digest);
        assert_eq!(witness.digest, receipt[16..]);
        history.query(&producer, shake64(&producer)).unwrap();
        assert!(history.availability_hits() > 0);
        let repeated = history.query(&input, shake64(&input)).unwrap();
        assert_eq!(
            field_fingerprint_availability(&history, &repeated, &input),
            Some(FieldFingerprintAvailability::Missing(witness))
        );
        let fresh = candidate::<F>(&request, &receipt, b"fresh pending");
        let view = history.query(&fresh, shake64(&fresh)).unwrap();
        assert_eq!(
            field_fingerprint_availability(&history, &view, &fresh),
            Some(FieldFingerprintAvailability::Available { frames: 1 })
        );
        let short = candidate::<F>(&request, &receipt[..79], b"short");
        let view = history.query(&short, shake64(&short)).unwrap();
        assert_eq!(
            field_fingerprint_availability(&history, &view, &short),
            Some(FieldFingerprintAvailability::Malformed)
        );
        let mut truncated = fresh.clone();
        truncated.pop();
        let view = history.query(&truncated, shake64(&truncated)).unwrap();
        assert_eq!(
            field_fingerprint_availability(&history, &view, &truncated),
            Some(FieldFingerprintAvailability::Malformed)
        );
        let mut opaque = request.clone();
        frame(&mut opaque, 1, b"opaque body", &receipt);
        frame(&mut opaque, 2, b"pending bytes", &8u64.to_le_bytes());
        let view = history.query(&opaque, shake64(&opaque)).unwrap();
        assert_eq!(
            field_fingerprint_availability(&history, &view, &opaque),
            Some(FieldFingerprintAvailability::Available { frames: 0 })
        );
        let mut foreign = classical_xof_history::History::default();
        let view = foreign.query(&fresh, shake64(&fresh)).unwrap();
        assert!(field_fingerprint_availability(&history, &view, &fresh).is_none());
    }
    #[test]
    fn babybear_missing_field_fingerprints_have_original_window_witnesses() {
        exercise_missing_fingerprint_witness::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_missing_field_fingerprints_have_original_window_witnesses() {
        exercise_missing_fingerprint_witness::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
        );
    }

    fn exercise_v5_first_primary<F, EF>(width: usize)
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        let config = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
        let roles = config.variables(width).unwrap().map(|num_vars| Role {
            num_vars,
            width,
            queries: 8,
            left_vars: Some(num_vars / 2),
            block_width: Some(width),
        });
        let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
            backend: Backend::Brakedown,
            roles,
            blowup: 2,
            fragment_vars: None,
        })
        .unwrap();
        exercise_bundle_scoped::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap(), true);
    }
    #[test]
    fn babybear_v5_first_primary_query_and_transition() {
        exercise_v5_first_primary::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
    }
    #[test]
    fn goldilocks_v5_first_primary_query_and_transition() {
        exercise_v5_first_primary::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
    }

    fn make_request<F: NTTField, EF: AbstractExtensionField<F>>(count: usize) -> Vec<u8> {
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
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut input = Vec::new();
        frame(&mut input, 0, b"protocol", b"HasteBoots framed SHAKE256 v1");
        frame(
            &mut input,
            0,
            b"application",
            b"HasteBoots typed classical prime v1",
        );
        frame(&mut input, 0, b"trusted profile", &profile.id().0);
        frame(&mut input, 1, b"typed prime field", &p.to_le_bytes());
        frame(&mut input, 1, b"typed request kind", b"vector");
        frame(&mut input, 1, b"field challenge kind", b"prime vector");
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((count as u64).to_le_bytes());
        frame(&mut input, 4, b"earlier", &descriptor);
        input
    }
    fn candidate<F: NTTField>(request: &[u8], receipt: &[u8], label: &[u8]) -> Vec<u8> {
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut input = request.to_vec();
        frame(&mut input, 5, b"earlier", receipt);
        frame(&mut input, 1, b"typed request kind", b"scalar");
        frame(&mut input, 1, b"field challenge kind", b"prime vector");
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend(1u64.to_le_bytes());
        frame(&mut input, 4, label, &descriptor);
        input
    }
    fn run<F: NTTField, EF: AbstractExtensionField<F>>() {
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let width = (128 - (p - 1).leading_zeros()).div_ceil(8) as usize;
        for count in [0, 2] {
            let request = make_request::<F, EF>(count);
            let raw = if count == 0 {
                Vec::new()
            } else {
                [p, 1, 7]
                    .into_iter()
                    .flat_map(|v| v.to_le_bytes()[..width].to_vec())
                    .collect()
            };
            let (receipt_data, producer) = receipt(&raw);
            let input = candidate::<F>(&request, &receipt_data, b"current");
            let mut history = classical_xof_history::History::default();
            history.query(&producer, shake64(&producer)).unwrap();
            let alternative = if count == 2 {
                let raw: Vec<_> = [p, 1, 8]
                    .into_iter()
                    .flat_map(|v| v.to_le_bytes()[..width].to_vec())
                    .collect();
                let (receipt_data, producer) = receipt(&raw);
                history.query(&producer, shake64(&producer)).unwrap();
                Some(receipt_data)
            } else {
                None
            };
            let view = history.query(&input, shake64(&input)).unwrap();
            {
                let proposal = field_proposal::<F>(
                    &history,
                    &view,
                    &input,
                    &request,
                    b"earlier",
                    count,
                    &receipt_data,
                )
                .unwrap();
                assert_eq!(
                    proposal.coefficients,
                    if count == 0 {
                        vec![]
                    } else {
                        vec![F::from(1), F::from(7)]
                    }
                );
                assert_eq!(proposal.request, request);
                assert!(!proposal.request_was_queried);
                assert!(proposal.consistent_with(&raw));
            }
            if let Some(other) = alternative {
                // A valid, already available receipt outside this candidate
                // must not be substituted for the absorbed receipt.
                assert!(
                    field_proposal::<F>(
                        &history, &view, &input, &request, b"earlier", count, &other
                    )
                    .is_none()
                );
            }
            let actual = shake64(&request);
            history.query(&request, actual).unwrap();
            let repeated = history.query(&input, shake64(&input)).unwrap();
            let old = field_proposal::<F>(
                &history,
                &repeated,
                &input,
                &request,
                b"earlier",
                count,
                &receipt_data,
            )
            .unwrap();
            assert!(!old.request_was_queried);
            drop(old);
            let later_input = candidate::<F>(&request, &receipt_data, b"later current");
            let later = history.query(&later_input, shake64(&later_input)).unwrap();
            let proposal = field_proposal::<F>(
                &history,
                &later,
                &later_input,
                &request,
                b"earlier",
                count,
                &receipt_data,
            )
            .unwrap();
            assert!(proposal.request_was_queried);
            if count == 0 {
                assert!(proposal.consistent_with(&[]));
            } else {
                assert!(!proposal.consistent_with(&actual[..raw.len()]));
            }
            drop(proposal);
            assert!(
                field_proposal::<F>(
                    &history,
                    &later,
                    &input,
                    &request,
                    b"earlier",
                    count,
                    &receipt_data
                )
                .is_none()
            );
            assert!(
                field_proposal::<F>(
                    &history,
                    &view,
                    &input,
                    &request,
                    b"wrong label",
                    count,
                    &receipt_data
                )
                .is_none()
            );
            assert!(
                field_proposal::<F>(
                    &history,
                    &view,
                    &input,
                    &request,
                    b"earlier",
                    count + 1,
                    &receipt_data
                )
                .is_none()
            );
            let mut wrong_length = receipt_data.clone();
            wrong_length[0] ^= 1;
            let malformed = candidate::<F>(&request, &wrong_length, b"malformed current");
            let malformed_view = history.query(&malformed, shake64(&malformed)).unwrap();
            assert!(
                field_proposal::<F>(
                    &history,
                    &malformed_view,
                    &malformed,
                    &request,
                    b"earlier",
                    count,
                    &wrong_length
                )
                .is_none()
            );
            let mut foreign = classical_xof_history::History::default();
            let foreign_view = foreign.query(&input, shake64(&input)).unwrap();
            assert!(
                field_proposal::<F>(
                    &history,
                    &foreign_view,
                    &input,
                    &request,
                    b"earlier",
                    count,
                    &receipt_data
                )
                .is_none()
            );
            let huge = make_request::<F, EF>(usize::MAX);
            let huge_input = candidate::<F>(&huge, &receipt_data, b"huge current");
            let huge_view = history.query(&huge_input, shake64(&huge_input)).unwrap();
            assert!(
                field_proposal::<F>(
                    &history,
                    &huge_view,
                    &huge_input,
                    &huge,
                    b"earlier",
                    usize::MAX,
                    &receipt_data
                )
                .is_none()
            );
            let mut late = classical_xof_history::History::default();
            let first = late.query(&input, shake64(&input)).unwrap();
            late.query(&producer, shake64(&producer)).unwrap();
            assert!(
                field_proposal::<F>(
                    &late,
                    &first,
                    &input,
                    &request,
                    b"earlier",
                    count,
                    &receipt_data
                )
                .is_none()
            );
            let repeated = late.query(&input, shake64(&input)).unwrap();
            assert!(
                field_proposal::<F>(
                    &late,
                    &repeated,
                    &input,
                    &request,
                    b"earlier",
                    count,
                    &receipt_data
                )
                .is_none()
            );
        }
    }
    #[test]
    fn proposed_receipts_keep_sampling_consistency_separate_from_first_view() {
        run::<algebra::BabyBear, algebra::BabyBearExtension6>();
        run::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    #[test]
    fn zero_identity_can_be_interpreted_without_its_unused_sampling_query() {
        fn exercise<F: NTTField, EF: AbstractExtensionField<F>>() {
            use helper::FiatShamirTranscript;
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
            let inputs = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let sink = Arc::clone(&inputs);
            let guard = helper::classical_transcript::audit::observe(move |input| {
                sink.lock().unwrap().push(input.to_vec());
            })
            .unwrap();
            let mut parent = profile.parent_transcript::<F>().unwrap();
            let mut child = parent
                .fork_classical_extension::<F, EF>(b"proposal child", b"context")
                .unwrap();
            child.get_challenge_bytes(b"proposal current", &mut [0; 64]);
            drop(guard);
            let inputs = inputs.lock().unwrap();
            let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
            let mut descriptor = p.to_le_bytes().to_vec();
            descriptor.extend(0u64.to_le_bytes());
            let mut identity_tail = Vec::new();
            frame(
                &mut identity_tail,
                4,
                b"typed extension identity",
                &descriptor,
            );
            let mut current_tail = Vec::new();
            frame(
                &mut current_tail,
                2,
                b"proposal current",
                &64u64.to_le_bytes(),
            );
            let mut history = classical_xof_history::History::default();
            let (mut omitted, mut candidate_view) = (None, None);
            let mut candidate_input = None;
            for input in inputs.iter() {
                if input.ends_with(&identity_tail) {
                    assert!(omitted.replace(input).is_none());
                    continue;
                }
                let view = history.query(input, shake64(input)).unwrap();
                if input.ends_with(&current_tail) {
                    candidate_view = Some(view);
                    candidate_input = Some(input);
                }
            }
            let view = candidate_view.unwrap();
            let known = history.producers(&view).unwrap();
            // Existing typed-child prefix interpretation accepts its real seed,
            // trusted basis and empty receipt without the unused zero query.
            assert!(
                typed_child_prefix::<F, EF>(&profile, candidate_input.unwrap(), &known).is_some()
            );
            let receipt = receipt(&[]).0;
            let proposal = field_proposal::<F>(
                &history,
                &view,
                candidate_input.unwrap(),
                omitted.unwrap(),
                b"typed extension identity",
                0,
                &receipt,
            )
            .unwrap();
            assert!(!proposal.request_was_queried);
            assert!(proposal.coefficients.is_empty());
            assert!(proposal.consistent_with(&[]));
            assert_eq!(history.availability_hits(), 0);
            assert_eq!(history.collisions(), 0);
        }
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}

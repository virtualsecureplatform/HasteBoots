//! Brakedown-style matrix-weighted openings (2025/719, §4.1).
//!
//! Both scalar row codes and the paper's block-RS layout are supported. Block
//! queries authenticate every base-field coordinate of each encoded symbol.
//! This is non-hiding; concrete whole-proof security must be budgeted by callers.

use crate::utils::code::BlockReedSolomonCode;
use crate::utils::{
    code::{LinearCode, RowCode, ScalarRowCode},
    hash::Hash,
    merkle_tree::MerkleTree,
};
use algebra::{
    NTTField, PrimeField,
    matrix_weighted::{MatrixPair, PackedTable, matrix_weights},
};
use helper::{FiatShamirTranscript, Transcript};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Experimental multi-root aggregation for one common ordered matrix query.
pub mod aggregate;

/// Invalid parameters or a rejected matrix-weighted opening.
#[derive(Debug, thiserror::Error)]
#[error("matrix-weighted PCS: {0}")]
pub struct Error(pub &'static str);

/// Public commitment; dimensions and code are supplied by trusted parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment<O> {
    /// Merkle root of encoded columns.
    pub root: O,
}

/// One authenticated encoded column, including its leaf and sibling hashes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Column<F, O> {
    /// Block coordinates in row-major, coordinate-minor order.
    pub values: Vec<F>,
    /// Authentication path including the leaf hash.
    pub path: Vec<O>,
}

/// Opening of a structured matrix-weighted query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opening<F, O> {
    /// Random linear test, stored row-major.
    pub test: Vec<F>,
    /// Structured linear aggregation, stored row-major.
    pub evaluation: Vec<F>,
    /// Distinct sampled columns in sorted index order; duplicates are omitted.
    pub columns: Vec<Column<F, O>>,
}

/// Several openings of one canonical commitment, sharing the random linear test
/// and queried columns. Queries with identical left-matrix prefixes share their
/// structured response too; their suffix evaluations remain independently checked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchOpening<F, O> {
    /// One random linear response.
    pub test: Vec<F>,
    /// Responses for distinct left-query prefixes, in first-occurrence order.
    pub evaluations: Vec<Vec<F>>,
    /// One set of authenticated whole-symbol columns for all responses.
    pub columns: Vec<Column<F, O>>,
}

/// Prover-only state. Never serialize this as part of a proof.
pub struct State<F, H: Hash + Send + Sync> {
    table: PackedTable<F>,
    encoded: Vec<F>,
    tree: MerkleTree<H>,
    parameter_digest: H::Output,
}

impl<F, H: Hash + Send + Sync> State<F, H> {
    /// Borrow the immutable original prover word, without exposing encoded state.
    /// This is private witness access for a prover, never a verifier input.
    pub fn table(&self) -> &PackedTable<F> { &self.table }
}


/// Trusted shape and linear-code parameters for one family of tables.
pub struct Parameters<C> {
    num_vars: usize,
    width: usize,
    left_vars: usize,
    queries: usize,
    code: C,
}

impl<C> Parameters<ScalarRowCode<C>> {
    /// Construct parameters for an existing scalar linear encoder.
    pub fn new<F: PrimeField>(
        num_vars: usize,
        width: usize,
        left_vars: usize,
        queries: usize,
        code: C,
    ) -> Result<Self, Error>
    where
        C: LinearCode<F>,
    {
        Self::new_encoded::<F>(
            num_vars,
            width,
            left_vars,
            queries,
            ScalarRowCode::new(code),
        )
    }
}

impl<C> Parameters<C> {
    /// Construct parameters using a code whose message length is `2^(num_vars-left_vars)`.
    /// `queries` is explicit: callers must account for both proximity tests and
    /// the random linear-test error in their complete soundness budget.
    pub fn new_encoded<F: PrimeField>(
        num_vars: usize,
        width: usize,
        left_vars: usize,
        queries: usize,
        code: C,
    ) -> Result<Self, Error>
    where
        C: RowCode<F>,
    {
        if width == 0 || left_vars > num_vars || num_vars >= usize::BITS as usize || queries == 0 {
            return Err(Error("invalid dimensions or query count"));
        }
        let cols = 1usize << (num_vars - left_vars);
        if code.message_len() != cols
            || code
                .codeword_blocks()
                .checked_mul(code.block_width())
                .is_none_or(|n| n < cols)
            || code.codeword_blocks() == 0
            || code.block_width() == 0
        {
            return Err(Error("code dimensions do not match table"));
        }
        (1usize << num_vars)
            .checked_mul(width)
            .ok_or(Error("table size overflow"))?;
        (1usize << left_vars)
            .checked_mul(width)
            .and_then(|rows| {
                rows.checked_mul(code.codeword_blocks())
                    .and_then(|n| n.checked_mul(code.block_width()))
            })
            .ok_or(Error("encoded size overflow"))?;
        (1usize << left_vars)
            .checked_mul(width)
            .and_then(|rows| rows.checked_mul(width))
            .ok_or(Error("linear-test matrix size overflow"))?;
        code.codeword_blocks()
            .checked_next_power_of_two()
            .and_then(|n| n.checked_mul(2))
            .ok_or(Error("Merkle tree size overflow"))?;
        Ok(Self {
            num_vars,
            width,
            left_vars,
            queries,
            code,
        })
    }

    /// Number of sampled columns (sampling is with replacement).
    pub fn queries(&self) -> usize {
        self.queries
    }

    /// Number of Boolean table variables.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
    /// Packing width of the committed table (independent of code block width).
    pub fn width(&self) -> usize {
        self.width
    }
    /// Number of low-index variables assigned to matrix rows.
    pub fn left_vars(&self) -> usize {
        self.left_vars
    }
    /// Trusted row encoder, including its symbol dimensions.
    pub fn code(&self) -> &C {
        &self.code
    }

    /// Commit to all packed lanes, using the existing encoder and Merkle tree.
    pub fn commit<F, H>(
        &self,
        table: &PackedTable<F>,
    ) -> Result<(Commitment<H::Output>, State<F, H>), Error>
    where
        F: PrimeField + Serialize,
        H: Hash + Send + Sync,
        C: RowCode<F> + Serialize,
    {
        table.validate().map_err(|_| Error("invalid table"))?;
        if table.num_vars() != self.num_vars || table.width() != self.width {
            return Err(Error("table shape mismatch"));
        }
        let cols = self.code.message_len();
        let rows = (1usize << self.left_vars) * self.width;
        let length = self.code.codeword_blocks();
        let block = self.code.block_width();
        let stride = length * block;
        let mut encoded = vec![F::zero(); rows * stride];
        encoded
            .par_chunks_exact_mut(stride)
            .enumerate()
            .for_each(|(row, target)| {
                let left = row / self.width;
                let lane = row % self.width;
                let input: Vec<_> = (0..cols)
                    .map(|right| table.at(left + (right << self.left_vars))[lane])
                    .collect();
                self.code.encode_row(&input, target);
            });
        let leaves: Vec<_> = (0..length)
            .into_par_iter()
            .map(|column| {
                let values: Vec<_> = (0..rows)
                    .flat_map(|row| {
                        encoded[row * stride + column * block..row * stride + (column + 1) * block]
                            .iter()
                            .copied()
                    })
                    .collect();
                hash_column::<F, H>(&values)
            })
            .collect();
        let mut tree = MerkleTree::<H>::new();
        tree.generate(&leaves);
        Ok((
            Commitment { root: tree.root },
            State {
                table: table.clone(),
                encoded,
                tree,
                parameter_digest: self.context_digest::<F, H>()?,
            },
        ))
    }

    /// Prove an opening, binding parameters, query, commitment and claimed value.
    pub fn open<F, H>(
        &self,
        trans: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        state: &State<F, H>,
        query: &[MatrixPair<F>],
        value: &[F],
    ) -> Result<Opening<F, H::Output>, Error>
    where
        F: PrimeField + Serialize,
        H: Hash + Send + Sync,
        C: RowCode<F> + Serialize,
    {
        if state.tree.root != commitment.root
            || state.parameter_digest != self.context_digest::<F, H>()?
        {
            return Err(Error("commitment/state mismatch"));
        }
        if state.table.num_vars() != self.num_vars
            || state.table.width() != self.width
            || state.encoded.len()
                != (1usize << self.left_vars)
                    * self.width
                    * self.code.codeword_blocks()
                    * self.code.block_width()
        {
            return Err(Error("state shape mismatch"));
        }
        self.bind::<F, H>(trans, commitment, query, value)?;
        let rows = (1usize << self.left_vars) * self.width;
        let random = trans.get_vec_challenge(b"mw random linear test", self.width * rows);
        let structured = self.structured(query)?;
        let test = self.aggregate(&state.table, &random);
        let evaluation = self.aggregate(&state.table, &structured);
        if self.finish(query, &evaluation)? != value {
            return Err(Error("incorrect claimed value"));
        }
        trans.append_message(b"mw linear responses", &(&test, &evaluation));
        let indices = sample_columns(trans, self.code.codeword_blocks(), self.queries);
        let block = self.code.block_width();
        let stride = self.code.codeword_blocks() * block;
        let columns = indices
            .into_iter()
            .map(|column| Column {
                values: (0..rows)
                    .flat_map(|row| {
                        state.encoded
                            [row * stride + column * block..row * stride + (column + 1) * block]
                            .iter()
                            .copied()
                    })
                    .collect(),
                path: state.tree.query(column),
            })
            .collect();
        Ok(Opening {
            test,
            evaluation,
            columns,
        })
    }

    /// Verify an opening without the table or prover state; malformed shapes reject.
    pub fn verify<F, H>(
        &self,
        trans: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        query: &[MatrixPair<F>],
        value: &[F],
        proof: &Opening<F, H::Output>,
    ) -> Result<(), Error>
    where
        F: PrimeField + Serialize,
        H: Hash + Send + Sync,
        C: RowCode<F> + Serialize,
    {
        let cols = self.code.message_len();
        let length = self.code.codeword_blocks();
        let block = self.code.block_width();
        let stride = length * block;
        let rows = (1usize << self.left_vars) * self.width;
        let path_len = length.next_power_of_two().ilog2() as usize + 1;
        if proof.test.len() != self.width * cols
            || proof.evaluation.len() != self.width * cols
            || proof.columns.is_empty()
            || proof.columns.len() > self.queries.min(length)
            || proof
                .columns
                .iter()
                .any(|column| column.values.len() != rows * block || column.path.len() != path_len)
        {
            return Err(Error("malformed opening dimensions"));
        }
        self.bind::<F, H>(trans, commitment, query, value)?;
        let random = trans.get_vec_challenge(b"mw random linear test", self.width * rows);
        let structured = self.structured(query)?;
        trans.append_message(b"mw linear responses", &(&proof.test, &proof.evaluation));
        let indices = sample_columns(trans, length, self.queries);
        if proof.columns.len() != indices.len() {
            return Err(Error("incorrect distinct column count"));
        }
        let encoded_test = self.encode_responses(&proof.test);
        let encoded_evaluation = self.encode_responses(&proof.evaluation);
        proof
            .columns
            .par_iter()
            .zip(indices.par_iter())
            .try_for_each(|(column, &index)| {
                if column.path[0] != hash_column::<F, H>(&column.values)
                    || !MerkleTree::<H>::check(&commitment.root, index, &column.path)
                {
                    return Err(Error("invalid column authentication"));
                }
                for lane in 0..self.width {
                    for coordinate in 0..block {
                        let dot = |weights: &[F]| {
                            weights[lane * rows..(lane + 1) * rows]
                                .iter()
                                .enumerate()
                                .fold(F::zero(), |acc, (row, &a)| {
                                    acc + a * column.values[row * block + coordinate]
                                })
                        };
                        let at = lane * stride + index * block + coordinate;
                        if dot(&random) != encoded_test[at]
                            || dot(&structured) != encoded_evaluation[at]
                        {
                            return Err(Error("linear response inconsistent with committed block"));
                        }
                    }
                }
                Ok(())
            })?;

        if self.finish(query, &proof.evaluation)? != value {
            return Err(Error("incorrect opening value"));
        }
        Ok(())
    }

    /// Open several points of one committed table. All queries and claimed
    /// values are bound before the shared random test; all responses are bound
    /// before column sampling. Equal left prefixes require only one response.
    pub fn open_many<F, H>(
        &self,
        trans: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        state: &State<F, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<BatchOpening<F, H::Output>, Error>
    where
        F: PrimeField + Serialize,
        H: Hash + Send + Sync,
        C: RowCode<F> + Serialize,
    {
        if state.tree.root != commitment.root
            || state.parameter_digest != self.context_digest::<F, H>()?
        {
            return Err(Error("commitment/state mismatch"));
        }
        if state.table.num_vars() != self.num_vars
            || state.table.width() != self.width
            || state.encoded.len()
                != (1usize << self.left_vars)
                    * self.width
                    * self.code.codeword_blocks()
                    * self.code.block_width()
        {
            return Err(Error("state shape mismatch"));
        }
        self.bind_many::<F, H>(trans, commitment, queries, values)?;
        let (representatives, groups) = self.query_groups(queries);
        let rows = (1usize << self.left_vars) * self.width;
        let random = trans.get_vec_challenge(b"mw batch random linear test", self.width * rows);
        let test = self.aggregate(&state.table, &random);
        let evaluations = representatives
            .iter()
            .map(|&i| {
                self.structured(&queries[i])
                    .map(|weights| self.aggregate(&state.table, &weights))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (i, query) in queries.iter().enumerate() {
            if self.finish(query, &evaluations[groups[i]])? != values[i] {
                return Err(Error("incorrect batch claimed value"));
            }
        }
        trans.append_message(b"mw batch linear responses", &(&test, &evaluations));
        let indices = sample_columns(trans, self.code.codeword_blocks(), self.queries);
        let block = self.code.block_width();
        let stride = self.code.codeword_blocks() * block;
        let columns = indices
            .into_iter()
            .map(|column| Column {
                values: (0..rows)
                    .flat_map(|row| {
                        state.encoded
                            [row * stride + column * block..row * stride + (column + 1) * block]
                            .iter()
                            .copied()
                    })
                    .collect(),
                path: state.tree.query(column),
            })
            .collect();
        Ok(BatchOpening {
            test,
            evaluations,
            columns,
        })
    }

    /// Verify several points with shared columns and prefix responses. The
    /// grouping is recomputed from trusted queries, not supplied by the proof.
    pub fn verify_many<F, H>(
        &self,
        trans: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &BatchOpening<F, H::Output>,
    ) -> Result<(), Error>
    where
        F: PrimeField + Serialize,
        H: Hash + Send + Sync,
        C: RowCode<F> + Serialize,
    {
        self.bind_many::<F, H>(trans, commitment, queries, values)?;
        let (representatives, groups) = self.query_groups(queries);
        let cols = self.code.message_len();
        let blocks = self.code.codeword_blocks();
        let block = self.code.block_width();
        let stride = blocks * block;
        let rows = (1usize << self.left_vars) * self.width;
        let path_len = blocks.next_power_of_two().ilog2() as usize + 1;
        if proof.test.len() != self.width * cols
            || proof.evaluations.len() != representatives.len()
            || proof
                .evaluations
                .iter()
                .any(|v| v.len() != self.width * cols)
            || proof.columns.is_empty()
            || proof.columns.len() > self.queries.min(blocks)
            || proof
                .columns
                .iter()
                .any(|c| c.values.len() != rows * block || c.path.len() != path_len)
        {
            return Err(Error("malformed batch opening dimensions"));
        }
        let random = trans.get_vec_challenge(b"mw batch random linear test", self.width * rows);
        let structured = representatives
            .iter()
            .map(|&i| self.structured(&queries[i]))
            .collect::<Result<Vec<_>, _>>()?;
        trans.append_message(
            b"mw batch linear responses",
            &(&proof.test, &proof.evaluations),
        );
        let indices = sample_columns(trans, blocks, self.queries);
        if indices.len() != proof.columns.len() {
            return Err(Error("incorrect distinct column count"));
        }
        let encoded_test = self.encode_responses(&proof.test);
        let encoded_values: Vec<_> = proof
            .evaluations
            .par_iter()
            .map(|v| self.encode_responses(v))
            .collect();
        proof
            .columns
            .par_iter()
            .zip(indices.par_iter())
            .try_for_each(|(column, &index)| {
                if column.path[0] != hash_column::<F, H>(&column.values)
                    || !MerkleTree::<H>::check(&commitment.root, index, &column.path)
                {
                    return Err(Error("invalid batch column authentication"));
                }
                for lane in 0..self.width {
                    for coordinate in 0..block {
                        let dot = |weights: &[F]| {
                            weights[lane * rows..(lane + 1) * rows]
                                .iter()
                                .enumerate()
                                .fold(F::zero(), |sum, (row, &a)| {
                                    sum + a * column.values[row * block + coordinate]
                                })
                        };
                        let at = lane * stride + index * block + coordinate;
                        if dot(&random) != encoded_test[at] {
                            return Err(Error("batch random test mismatch"));
                        }
                        for (weights, encoded) in structured.iter().zip(&encoded_values) {
                            if dot(weights) != encoded[at] {
                                return Err(Error("batch structured response mismatch"));
                            }
                        }
                    }
                }
                Ok(())
            })?;
        for (i, query) in queries.iter().enumerate() {
            if self.finish(query, &proof.evaluations[groups[i]])? != values[i] {
                return Err(Error("incorrect batch opening value"));
            }
        }
        Ok(())
    }

    fn bind_many<F, H>(
        &self,
        trans: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<(), Error>
    where
        F: PrimeField + Serialize,
        H: Hash,
        C: RowCode<F> + Serialize,
    {
        if queries.is_empty() || queries.len() != values.len() {
            return Err(Error("empty or mismatched batch point count"));
        }
        for (query, value) in queries.iter().zip(values) {
            if query.len() != self.num_vars || value.len() != self.width {
                return Err(Error("batch query/value dimensions"));
            }
            for pair in query {
                pair.validate(self.width)
                    .map_err(|_| Error("invalid batch matrix"))?;
            }
        }
        trans.append_message(
            b"mw batched row-code v1",
            &(self.context_digest::<F, H>()?, commitment, queries, values),
        );
        Ok(())
    }

    fn query_groups<F: PrimeField>(
        &self,
        queries: &[Vec<MatrixPair<F>>],
    ) -> (Vec<usize>, Vec<usize>) {
        let mut representatives: Vec<usize> = Vec::new();
        let mut groups = Vec::with_capacity(queries.len());
        for (i, query) in queries.iter().enumerate() {
            let group = representatives
                .iter()
                .position(|&j| queries[j][..self.left_vars] == query[..self.left_vars]);
            match group {
                Some(group) => groups.push(group),
                None => {
                    groups.push(representatives.len());
                    representatives.push(i);
                }
            }
        }
        (representatives, groups)
    }

    fn bind<F, H>(
        &self,
        trans: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        query: &[MatrixPair<F>],
        value: &[F],
    ) -> Result<(), Error>
    where
        F: PrimeField + Serialize,
        H: Hash,
        C: RowCode<F> + Serialize,
    {
        if query.len() != self.num_vars || value.len() != self.width {
            return Err(Error("query/value shape mismatch"));
        }
        for pair in query {
            pair.validate(self.width)
                .map_err(|_| Error("invalid query matrix"))?;
        }
        trans.append_message(b"mw brakedown row-code v2", &self.context_digest::<F, H>()?);
        trans.append_message(b"mw commitment and query", &(commitment, query, value));
        Ok(())
    }

    /// Digest of the trusted field, layout, repetitions, and complete row-code
    /// description, for binding this oracle into an enclosing protocol.
    pub fn context_digest<F, H>(&self) -> Result<H::Output, Error>
    where
        F: PrimeField + Serialize,
        H: Hash,
        C: RowCode<F> + Serialize,
    {
        let mut hash = H::new();
        hash.update_hash_value(b"HasteBoots/mw-parameters/v2");
        let metadata = (
            F::MODULUS_VALUE.to_string(),
            self.num_vars,
            self.width,
            self.left_vars,
            self.queries,
            self.code.block_width(),
            self.code.codeword_blocks(),
            self.code.domain_separator(),
            &self.code,
        );
        hash.update_hash_value(
            &bincode::serde::encode_to_vec(metadata, bincode::config::standard())
                .map_err(|_| Error("code serialization"))?,
        );
        Ok(hash.output_reset())
    }

    fn structured<F: PrimeField>(&self, query: &[MatrixPair<F>]) -> Result<Vec<F>, Error> {
        let weights = matrix_weights(self.width, &query[..self.left_vars])
            .map_err(|_| Error("invalid left query"))?;
        let rows = weights.len() * self.width;
        let mut result = vec![F::zero(); self.width * rows];
        for (left, weight) in weights.iter().enumerate() {
            for a in 0..self.width {
                for c in 0..self.width {
                    result[a * rows + left * self.width + c] = weight.values()[a * self.width + c];
                }
            }
        }
        Ok(result)
    }

    fn aggregate<F: PrimeField>(&self, table: &PackedTable<F>, weights: &[F]) -> Vec<F>
    where
        C: RowCode<F>,
    {
        let cols = self.code.message_len();
        let rows = (1usize << self.left_vars) * self.width;
        let mut response = vec![F::zero(); self.width * cols];
        response
            .par_iter_mut()
            .enumerate()
            .for_each(|(index, out)| {
                let lane = index / cols;
                let right = index % cols;
                for left in 0..(1usize << self.left_vars) {
                    for c in 0..self.width {
                        *out += weights[lane * rows + left * self.width + c]
                            * table.at(left + (right << self.left_vars))[c];
                    }
                }
            });
        response
    }

    fn encode_responses<F: PrimeField>(&self, responses: &[F]) -> Vec<F>
    where
        C: RowCode<F>,
    {
        let cols = self.code.message_len();
        let stride = self.code.codeword_blocks() * self.code.block_width();
        let mut encoded = vec![F::zero(); self.width * stride];
        encoded
            .par_chunks_exact_mut(stride)
            .zip(responses.par_chunks_exact(cols))
            .for_each(|(target, source)| self.code.encode_row(source, target));
        encoded
    }

    fn finish<F: PrimeField>(
        &self,
        query: &[MatrixPair<F>],
        response: &[F],
    ) -> Result<Vec<F>, Error> {
        let remaining = self.num_vars - self.left_vars;
        let cols = 1usize << remaining;
        let mut values = vec![F::zero(); self.width * cols];
        for (right, out) in values.chunks_exact_mut(self.width).enumerate() {
            for (lane, out) in out.iter_mut().enumerate() {
                *out = response[lane * cols + right];
            }
        }
        // Folding costs O(k^2 * cols). Expanding a full matrix tensor here
        // costs O(k^3 * cols) and allocates one matrix per Boolean index.
        let mut table = PackedTable::new(remaining, self.width, values)
            .map_err(|_| Error("invalid response shape"))?;
        for pair in &query[self.left_vars..] {
            table
                .fold_in_place(pair)
                .map_err(|_| Error("invalid suffix query"))?;
        }
        Ok(table.values().to_vec())
    }
}

impl<F: NTTField> Parameters<BlockReedSolomonCode<F>> {
    /// Choose a row/column split minimizing a conservative opening-size estimate.
    /// The estimate includes both linear responses, whole queried block symbols,
    /// and SHA-256-sized authentication paths. This tunes layout, not soundness;
    /// the caller supplies an independently budgeted repetition count.
    pub fn balanced_block_rs(
        num_vars: usize,
        width: usize,
        queries: usize,
        blowup: usize,
    ) -> Result<Self, Error> {
        if width == 0
            || queries == 0
            || num_vars >= usize::BITS as usize
            || blowup < 2
            || !blowup.is_power_of_two()
        {
            return Err(Error("invalid block RS layout parameters"));
        }
        (1usize << num_vars)
            .checked_mul(width)
            .ok_or(Error("table size overflow"))?;
        let prime = F::MODULUS_VALUE
            .to_string()
            .parse::<u128>()
            .map_err(|_| Error("unsupported field characteristic"))?;
        if prime < 2 {
            return Err(Error("invalid field characteristic"));
        }
        let field_bytes = ((128 - prime.leading_zeros()) as usize).div_ceil(8) + 1;
        let mut best = None;
        for left in 0..=num_vars {
            let columns = 1usize << (num_vars - left);
            let Some(message_blocks) = columns.div_ceil(width).checked_next_power_of_two() else {
                continue;
            };
            let Some(blocks) = message_blocks.checked_mul(blowup).map(|n| n.max(32)) else {
                continue;
            };
            if (prime - 1) % (2 * blocks as u128) != 0 {
                continue;
            }
            let Some(rows) = (1usize << left).checked_mul(width) else {
                continue;
            };
            if rows
                .checked_mul(blocks)
                .and_then(|n| n.checked_mul(width))
                .is_none()
            {
                continue;
            }
            let unique = queries.min(blocks) as u128;
            let fields =
                2 * width as u128 * columns as u128 + unique * rows as u128 * width as u128;
            let score = fields * field_bytes as u128 + unique * (blocks.ilog2() as u128 + 1) * 32;
            if best.is_none_or(|(_, previous)| score < previous) {
                best = Some((left, score));
            }
        }
        let left = best.ok_or(Error("no supported block RS layout"))?.0;
        let code = BlockReedSolomonCode::<F>::new(1usize << (num_vars - left), width, blowup)
            .map_err(Error)?;
        Self::new_encoded::<F>(num_vars, width, left, queries, code)
    }
}

fn hash_column<F: Serialize, H: Hash>(column: &[F]) -> H::Output {
    let mut hash = H::new();
    hash.update_hash_value(b"HasteBoots/mw-column/v1");
    hash.update_hash_value(
        &bincode::serde::encode_to_vec(column, bincode::config::standard()).unwrap(),
    );
    hash.output_reset()
}

fn sample_columns<F: PrimeField>(
    trans: &mut Transcript<F>,
    length: usize,
    count: usize,
) -> Vec<usize> {
    let bound = length as u64;
    let limit = u64::MAX - u64::MAX % bound;
    let mut columns: Vec<_> = (0..count)
        .map(|_| {
            loop {
                let mut bytes = [0u8; 8];
                trans.get_challenge_bytes(b"mw unbiased column", &mut bytes);
                let sample = u64::from_le_bytes(bytes);
                if sample < limit {
                    break (sample % bound) as usize;
                }
            }
        })
        .collect();
    columns.sort_unstable();
    columns.dedup();
    columns
}

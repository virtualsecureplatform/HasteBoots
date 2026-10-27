//! Column-symbol encoders for matrix-weighted commitments.
//!
//! Block RS is Algorithm 2 of 2025/719: transpose consecutive blocks into base
//! field coordinate polynomials, evaluate each by NTT, and repack the symbols.
//! The extension alphabet is represented as vectors; no extension multiplication
//! or choice of an irreducible extension polynomial is needed.

use super::LinearCode;
use algebra::{Field, NTTField, transformation::AbstractNTT};
use serde::{Deserialize, Serialize};

/// A base-linear row encoder whose output columns contain block symbols.
pub trait RowCode<F: Field>: Send + Sync {
    /// Number of base-field input coefficients, before zero padding.
    fn message_len(&self) -> usize;
    /// Number of base-field coordinates in one encoded column symbol.
    fn block_width(&self) -> usize;
    /// Number of encoded column symbols.
    fn codeword_blocks(&self) -> usize;
    /// Lower bound on relative distance in the block-symbol metric.
    fn distance(&self) -> f64;
    /// Proximity gap used for conservative Brakedown parameter accounting.
    fn proximity_gap(&self) -> f64;
    /// Distinguish encoding conventions in the commitment transcript.
    fn domain_separator(&self) -> &'static [u8];
    /// Encode an exact-length input into block-major, coordinate-minor output.
    fn encode_row(&self, input: &[F], output: &mut [F]);
}

/// Adapt an existing scalar linear code to one-coordinate column symbols.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalarRowCode<C> {
    code: C,
}

impl<C> ScalarRowCode<C> {
    /// Wrap a scalar encoder without changing its encoding convention.
    pub fn new(code: C) -> Self {
        Self { code }
    }
}

impl<F: Field, C: LinearCode<F>> RowCode<F> for ScalarRowCode<C> {
    fn message_len(&self) -> usize {
        self.code.message_len()
    }
    fn block_width(&self) -> usize {
        1
    }
    fn codeword_blocks(&self) -> usize {
        self.code.codeword_len()
    }
    fn distance(&self) -> f64 {
        self.code.distance()
    }
    fn proximity_gap(&self) -> f64 {
        self.code.proximity_gap()
    }
    fn domain_separator(&self) -> &'static [u8] {
        b"scalar-row-code/v1"
    }
    fn encode_row(&self, input: &[F], output: &mut [F]) {
        assert_eq!(input.len(), self.code.message_len());
        assert_eq!(output.len(), self.code.codeword_len());
        output.fill(F::zero());
        output[..input.len()].copy_from_slice(input);
        self.code.encode(output);
    }
}

/// NTT-backed block RS over an extension alphabet represented by base vectors.
///
/// The input is zero padded to `block_width * message_blocks`, with a power-of-two
/// `message_blocks`. The domain is the bit-reversed negacyclic NTT coset. Querying
/// a column opens every coordinate of its symbol; scalar-coordinate distance is
/// not substituted for block distance.
#[derive(Clone, Debug, Serialize)]
pub struct BlockReedSolomonCode<F> {
    message_len: usize,
    block_width: usize,
    message_blocks: usize,
    codeword_blocks: usize,
    modulus: String,
    domain_root: F,
}

impl<F: NTTField> BlockReedSolomonCode<F> {
    /// Construct a block code with power-of-two blowup >= 2. Domains smaller
    /// than 32 are enlarged to 32 to support the concrete NTT backend. Unsupported
    /// domains reject here, before any commitment allocation or cache initialization.
    pub fn new(
        message_len: usize,
        block_width: usize,
        blowup: usize,
    ) -> Result<Self, &'static str> {
        if message_len == 0 || block_width == 0 || blowup < 2 || !blowup.is_power_of_two() {
            return Err("invalid block RS dimensions or blowup");
        }
        let message_blocks = message_len
            .div_ceil(block_width)
            .checked_next_power_of_two()
            .ok_or("block RS message size overflow")?;
        let codeword_blocks = message_blocks
            .checked_mul(blowup)
            .ok_or("block RS domain overflow")?
            .max(32);
        codeword_blocks
            .checked_mul(block_width)
            .ok_or("block RS codeword size overflow")?;
        let log_size = codeword_blocks.ilog2();
        // generate_ntt_table returns errors rather than the upstream lazy-cache
        // initializer's unwrap, so invalid field/domain combinations fail cleanly.
        F::generate_ntt_table(log_size).map_err(|_| "unsupported block RS NTT domain")?;
        F::init_ntt_table(log_size).map_err(|_| "cannot initialize block RS NTT domain")?;
        let domain_root = F::get_ntt_table(log_size)
            .map_err(|_| "cannot load block RS domain")?
            .root();
        Ok(Self {
            message_len,
            block_width,
            message_blocks,
            codeword_blocks,
            modulus: F::MODULUS_VALUE.to_string(),
            domain_root,
        })
    }

    /// Number of coefficient blocks after zero padding.
    pub fn message_blocks(&self) -> usize {
        self.message_blocks
    }
}

impl<F: NTTField> RowCode<F> for BlockReedSolomonCode<F> {
    fn message_len(&self) -> usize {
        self.message_len
    }
    fn block_width(&self) -> usize {
        self.block_width
    }
    fn codeword_blocks(&self) -> usize {
        self.codeword_blocks
    }
    fn distance(&self) -> f64 {
        (self.codeword_blocks - self.message_blocks + 1) as f64 / self.codeword_blocks as f64
    }
    fn proximity_gap(&self) -> f64 {
        1.0 / 3.0
    }
    fn domain_separator(&self) -> &'static [u8] {
        b"block-rs/negacyclic-ntt/v1"
    }
    fn encode_row(&self, input: &[F], output: &mut [F]) {
        assert_eq!(input.len(), self.message_len);
        assert_eq!(output.len(), self.codeword_blocks * self.block_width);
        let table =
            F::get_ntt_table(self.codeword_blocks.ilog2()).expect("validated block RS domain");
        assert_eq!(table.root(), self.domain_root, "block RS domain changed");
        // Reuse one base-field buffer for all coordinates. Multiplications in
        // transform_slice are exclusively base-field NTT butterflies.
        let mut coordinate = vec![F::zero(); self.codeword_blocks];
        for lane in 0..self.block_width {
            coordinate.fill(F::zero());
            for (block, input) in input.chunks(self.block_width).enumerate() {
                if lane < input.len() {
                    coordinate[block] = input[lane];
                }
            }
            table.transform_slice(&mut coordinate);
            for (symbol, &value) in output.chunks_exact_mut(self.block_width).zip(&coordinate) {
                symbol[lane] = value;
            }
        }
    }
}

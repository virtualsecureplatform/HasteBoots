use std::marker::PhantomData;

use rand::SeedableRng;
use serde::Serialize;

use algebra::{AbstractExtensionField, AsFrom, AsInto, Field, PrimeField};

use algebra::utils::{Block, Prg};

use crate::FiatShamirTranscript;

/// Direct prime-field sampling protocol identifier.
pub const DIRECT_TRANSCRIPT_ID: &str = "merlin-direct-canonical-rejection-v1";
/// Direct polynomial-basis extension-field sampling protocol identifier.
pub const DIRECT_EXTENSION_TRANSCRIPT_ID: &str = "merlin-direct-extension-canonical-rejection-v1";
const EXTENSION_DOMAIN: &[u8] = b"HasteBoots direct-extension transcript v1";
const DIRECT_DOMAIN: &[u8] = b"HasteBoots direct-field transcript v1";
const STREAM_LABEL: &[u8] = b"direct canonical field stream";
const STREAM_BLOCK: usize = 256;

#[derive(Clone, Copy)]
enum Sampling<F> {
    LegacyPrg128,
    Direct,
    Extension(fn(&mut merlin::Transcript, &'static [u8], usize, &[u8]) -> Vec<F>),
}

/// A Merlin transcript with an explicitly selected field-challenge protocol.
pub struct Transcript<F: Field> {
    transcript: merlin::Transcript,
    sampling: Sampling<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> Transcript<F> {
    /// Create a new IOP transcript.
    #[inline]
    pub fn new() -> Self {
        Self {
            transcript: merlin::Transcript::new(b""),
            sampling: Sampling::LegacyPrg128,
            _marker: PhantomData,
        }
    }
    /// Use versioned, direct transcript bytes with canonical rejection sampling.
    /// The default constructor keeps the legacy AES-seeded protocol unchanged.
    pub fn new_direct() -> Self
    where
        F: PrimeField,
    {
        Self {
            transcript: merlin::Transcript::new(DIRECT_DOMAIN),
            sampling: Sampling::Direct,
            _marker: PhantomData,
        }
    }

    /// Sample every polynomial-basis coefficient independently and uniformly
    /// over a prime base field, directly from Merlin bytes. The constructor
    /// binds the base characteristic, extension degree, and the complete basis
    /// multiplication table; different extension representations are separated.
    /// This is a distinct protocol from both legacy and direct prime sampling.
    /// It assumes the supplied algebra traits describe a valid field extension;
    /// uniform sampling alone does not establish protocol security.
    pub fn new_direct_extension<Base: PrimeField>() -> Self
    where
        F: AbstractExtensionField<Base>,
    {
        assert!(F::D > 0, "extension degree must be positive");
        let mut transcript = merlin::Transcript::new(EXTENSION_DOMAIN);
        let p: u128 = Base::MODULUS_VALUE.as_into();
        transcript.append_message(b"extension characteristic", &p.to_le_bytes());
        transcript.append_message(
            b"extension degree",
            &u64::try_from(F::D).expect("degree fits u64").to_le_bytes(),
        );
        // Canonical fixed-width integers avoid relying on a field's serde or
        // internal Montgomery/lazy representation for its mathematical identity.
        let mut products = Vec::new();
        for i in 0..F::D {
            for j in 0..F::D {
                let product = F::monomial(i) * F::monomial(j);
                let coefficients = product.as_base_slice();
                assert!(
                    coefficients.len() <= F::D,
                    "invalid extension basis representation"
                );
                for k in 0..F::D {
                    let value: u128 = coefficients
                        .get(k)
                        .copied()
                        .unwrap_or_else(Base::zero)
                        .value()
                        .as_into();
                    products.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        transcript.append_message(b"extension basis products", &products);
        Self {
            transcript,
            sampling: Sampling::Extension(extension_values::<Base, F>),
            _marker: PhantomData,
        }
    }

    fn direct_values(&mut self, label: &'static [u8], count: usize, kind: &[u8]) -> Vec<F> {
        let p: u128 = F::MODULUS_VALUE.as_into();
        // Fixed encodings, independent of rand's distribution implementation.
        self.transcript.append_message(b"direct request kind", kind);
        self.transcript
            .append_message(b"direct request label", label);
        self.transcript
            .append_message(b"direct field characteristic", &p.to_le_bytes());
        self.transcript.append_message(
            b"direct field count",
            &u64::try_from(count)
                .expect("challenge count fits u64")
                .to_le_bytes(),
        );
        let sampler = CanonicalSampler::new(p);
        let mut reader = DirectReader {
            transcript: &mut self.transcript,
            bytes: [0; STREAM_BLOCK],
            cursor: STREAM_BLOCK,
        };
        (0..count)
            .map(|_| {
                F::new(F::Value::as_from(
                    sampler.sample(&mut |out| reader.read(out)),
                ))
            })
            .collect()
    }
}

impl<F: Field> FiatShamirTranscript<F> for Transcript<F> {
    /// Append the message to the transcript.
    fn append_message<M: Serialize>(&mut self, label: &'static [u8], msg: &M) {
        self.transcript.append_message(
            label,
            &bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap(),
        );
    }

    /// Generate the challenge bytes from the current transcript
    #[inline]
    fn get_challenge_bytes(&mut self, label: &'static [u8], bytes: &mut [u8]) {
        self.transcript.challenge_bytes(label, bytes);
    }

    /// Generate the challenge from the current transcript
    fn get_challenge(&mut self, label: &'static [u8]) -> F {
        if matches!(self.sampling, Sampling::Direct) {
            return self.direct_values(label, 1, b"scalar")[0];
        }
        if let Sampling::Extension(sample) = self.sampling {
            return sample(&mut self.transcript, label, 1, b"scalar")[0];
        }
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        F::random(&mut prg)
    }

    /// Generate the challenge vector from the current transcript
    fn get_vec_challenge(&mut self, label: &'static [u8], num: usize) -> Vec<F> {
        if matches!(self.sampling, Sampling::Direct) {
            return self.direct_values(label, num, b"vector");
        }
        if let Sampling::Extension(sample) = self.sampling {
            return sample(&mut self.transcript, label, num, b"vector");
        }
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        (0..num).map(|_| F::random(&mut prg)).collect()
    }
}

impl<F: Field> Default for Transcript<F> {
    fn default() -> Self {
        Self::new()
    }
}

fn extension_values<Base: PrimeField, EF: AbstractExtensionField<Base>>(
    transcript: &mut merlin::Transcript,
    label: &'static [u8],
    count: usize,
    kind: &[u8],
) -> Vec<EF> {
    transcript.append_message(b"extension request kind", kind);
    transcript.append_message(b"extension request label", label);
    transcript.append_message(
        b"extension value count",
        &u64::try_from(count)
            .expect("challenge count fits u64")
            .to_le_bytes(),
    );
    let sampler = CanonicalSampler::new(Base::MODULUS_VALUE.as_into());
    let mut reader = DirectReader {
        transcript,
        bytes: [0; STREAM_BLOCK],
        cursor: STREAM_BLOCK,
    };
    // Consume bytes in explicit ascending basis order, independently of how
    // an extension implementation might order calls to from_base_fn.
    let mut coefficients = vec![Base::zero(); EF::D];
    (0..count)
        .map(|_| {
            for coefficient in &mut coefficients {
                *coefficient = Base::new(Base::Value::as_from(
                    sampler.sample(&mut |out| reader.read(out)),
                ));
            }
            EF::from_base_slice(&coefficients)
        })
        .collect()
}

struct CanonicalSampler {
    p: u128,
    mask: u128,
    bytes: usize,
}
impl CanonicalSampler {
    fn new(p: u128) -> Self {
        assert!(p > 1, "field characteristic must exceed one");
        let bits = u128::BITS - (p - 1).leading_zeros();
        Self {
            p,
            mask: if bits == 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            },
            bytes: bits.div_ceil(8) as usize,
        }
    }
    fn sample(&self, read: &mut impl FnMut(&mut [u8])) -> u128 {
        loop {
            let mut bytes = [0u8; 16];
            read(&mut bytes[..self.bytes]);
            let value = u128::from_le_bytes(bytes) & self.mask;
            if value < self.p {
                return value;
            }
        }
    }
}

struct DirectReader<'a> {
    transcript: &'a mut merlin::Transcript,
    bytes: [u8; STREAM_BLOCK],
    cursor: usize,
}
impl DirectReader<'_> {
    fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.cursor == STREAM_BLOCK {
                self.transcript
                    .challenge_bytes(STREAM_LABEL, &mut self.bytes);
                self.cursor = 0;
            }
            let take = out.len().min(STREAM_BLOCK - self.cursor);
            out[..take].copy_from_slice(&self.bytes[self.cursor..self.cursor + take]);
            self.cursor += take;
            out = &mut out[take..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{BabyBear, Goldilocks};

    fn legacy_reference<F: Field>() {
        let mut actual = Transcript::<F>::default();
        let mut reference = merlin::Transcript::new(b"");
        actual.append_message(b"legacy fixture", &17u64);
        reference.append_message(
            b"legacy fixture",
            &bincode::serde::encode_to_vec(17u64, bincode::config::standard()).unwrap(),
        );
        for count in [0, 1, 3, 2048] {
            let mut seed = [0u8; 16];
            reference.challenge_bytes(b"legacy vector", &mut seed);
            let mut prg = Prg::from_seed(Block::from(seed));
            let expected = (0..count).map(|_| F::random(&mut prg)).collect::<Vec<_>>();
            assert_eq!(actual.get_vec_challenge(b"legacy vector", count), expected);
        }
        let mut seed = [0u8; 16];
        reference.challenge_bytes(b"legacy scalar", &mut seed);
        let expected = F::random(&mut Prg::from_seed(Block::from(seed)));
        assert_eq!(actual.get_challenge(b"legacy scalar"), expected);
        let mut a = [0u8; 32];
        let mut b = a;
        actual.get_challenge_bytes(b"after legacy", &mut a);
        reference.challenge_bytes(b"after legacy", &mut b);
        assert_eq!(a, b);
    }
    #[test]
    fn default_legacy_bytes_and_prg_sampling_are_unchanged() {
        legacy_reference::<BabyBear>();
        legacy_reference::<Goldilocks>();
        legacy_reference::<algebra::BabyBearExetension>();
    }
    #[test]
    fn canonical_sampling_rejects_the_modulus_instead_of_reducing_it() {
        for p in [3u128, 257, 2013265921, 18446744069414584321, u128::MAX] {
            let sampler = CanonicalSampler::new(p);
            let mut count = 0;
            let got = sampler.sample(&mut |out| {
                let value = if count < 2 { p } else { p - 1 };
                count += 1;
                out.copy_from_slice(&value.to_le_bytes()[..out.len()]);
            });
            assert_eq!(got, p - 1);
            assert_eq!(count, 3);
        }
        assert_eq!(CanonicalSampler::new(2).sample(&mut |out| out.fill(255)), 1);
    }
    #[test]
    fn stream_reads_preserve_bytes_across_every_buffer_boundary() {
        let mut actual = merlin::Transcript::new(b"reader fixture");
        let mut reference = merlin::Transcript::new(b"reader fixture");
        let mut expected = Vec::new();
        for _ in 0..5 {
            let mut block = [0u8; 256];
            reference.challenge_bytes(b"direct canonical field stream", &mut block);
            expected.extend(block);
        }
        let mut got = Vec::new();
        {
            let mut reader = DirectReader {
                transcript: &mut actual,
                bytes: [0; STREAM_BLOCK],
                cursor: STREAM_BLOCK,
            };
            for len in [1, 3, 253, 8, 511, 251] {
                let mut part = vec![0; len];
                reader.read(&mut part);
                got.extend(part);
            }
        }
        assert_eq!(got, &expected[..1027]);
        let mut a = [0u8; 32];
        let mut b = a;
        actual.challenge_bytes(b"after stream", &mut a);
        reference.challenge_bytes(b"after stream", &mut b);
        assert_eq!(a, b);
    }
    fn direct_reference<F: PrimeField>(bytes_per_value: usize, mask: u128) {
        let p: u128 = F::MODULUS_VALUE.as_into();
        let mut actual = Transcript::<F>::new_direct();
        let mut reference = merlin::Transcript::new(b"HasteBoots direct-field transcript v1");
        // Independently frame the public protocol and decode complete blocks.
        for (kind, count) in [
            (b"vector".as_slice(), 0usize),
            (b"vector", 2000),
            (b"scalar", 1),
        ] {
            reference.append_message(b"direct request kind", kind);
            reference.append_message(b"direct request label", b"reference field challenge");
            reference.append_message(b"direct field characteristic", &p.to_le_bytes());
            reference.append_message(b"direct field count", &(count as u64).to_le_bytes());
            let mut expected = Vec::new();
            let mut block = [0u8; 256];
            let mut cursor = 256;
            while expected.len() < count {
                if cursor == 256 {
                    reference.challenge_bytes(b"direct canonical field stream", &mut block);
                    cursor = 0;
                }
                let mut bytes = [0u8; 16];
                bytes[..bytes_per_value].copy_from_slice(&block[cursor..cursor + bytes_per_value]);
                cursor += bytes_per_value;
                let candidate = u128::from_le_bytes(bytes) & mask;
                if candidate < p {
                    expected.push(F::new(F::Value::as_from(candidate)));
                }
            }
            let got = if kind == b"scalar" {
                vec![actual.get_challenge(b"reference field challenge")]
            } else {
                actual.get_vec_challenge(b"reference field challenge", count)
            };
            assert_eq!(got, expected);
        }
        let mut a = [0u8; 32];
        let mut b = a;
        actual.get_challenge_bytes(b"after direct", &mut a);
        reference.challenge_bytes(b"after direct", &mut b);
        assert_eq!(a, b);
    }
    #[test]
    fn direct_fields_match_explicit_merlin_frames_and_rejection_reference() {
        direct_reference::<BabyBear>(4, (1u128 << 31) - 1);
        direct_reference::<Goldilocks>(8, u64::MAX as u128);
    }
    #[test]
    fn request_kind_label_count_and_empty_vectors_are_domain_separated() {
        let mut outputs = Vec::new();
        for mode in 0..5 {
            let mut transcript = Transcript::<BabyBear>::new_direct();
            match mode {
                0 => {
                    transcript.get_challenge(b"a");
                }
                1 => {
                    transcript.get_vec_challenge(b"a", 1);
                }
                2 => {
                    transcript.get_vec_challenge(b"b", 1);
                }
                3 => {
                    transcript.get_vec_challenge(b"a", 2);
                }
                _ => {
                    transcript.get_vec_challenge(b"a", 0);
                }
            }
            let mut bytes = [0u8; 32];
            transcript.get_challenge_bytes(b"after request", &mut bytes);
            outputs.push(bytes);
        }
        for i in 0..outputs.len() {
            for j in 0..i {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
        let mut bb = Transcript::<BabyBear>::new_direct();
        let mut gold = Transcript::<Goldilocks>::new_direct();
        bb.get_vec_challenge(b"same", 0);
        gold.get_vec_challenge(b"same", 0);
        let mut a = [0u8; 32];
        let mut b = a;
        bb.get_challenge_bytes(b"after field", &mut a);
        gold.get_challenge_bytes(b"after field", &mut b);
        assert_ne!(a, b);
    }
    fn extension_frame(p: u128, degree: usize, w: u128) -> merlin::Transcript {
        let mut reference = merlin::Transcript::new(b"HasteBoots direct-extension transcript v1");
        reference.append_message(b"extension characteristic", &p.to_le_bytes());
        reference.append_message(b"extension degree", &(degree as u64).to_le_bytes());
        // Independently derive multiplication from X^degree=w, without
        // invoking the extension arithmetic used by the production framing.
        let mut products = Vec::new();
        for i in 0..degree {
            for j in 0..degree {
                for k in 0..degree {
                    let value: u128 = if k == (i + j) % degree {
                        if i + j < degree { 1 } else { w }
                    } else {
                        0
                    };
                    products.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        reference.append_message(b"extension basis products", &products);
        reference
    }
    fn extension_reference<Base: PrimeField, EF: AbstractExtensionField<Base>>(
        width: usize,
        mask: u128,
        w: u128,
    ) {
        let p: u128 = Base::MODULUS_VALUE.as_into();
        let mut actual = Transcript::<EF>::new_direct_extension::<Base>();
        let mut reference = extension_frame(p, EF::D, w);
        for (kind, count) in [
            (b"vector".as_slice(), 0usize),
            (b"vector", 1300),
            (b"scalar", 1),
            (b"vector", 17),
        ] {
            reference.append_message(b"extension request kind", kind);
            reference.append_message(b"extension request label", b"reference extension challenge");
            reference.append_message(b"extension value count", &(count as u64).to_le_bytes());
            let mut coefficients = Vec::new();
            let mut block = [0u8; 256];
            let mut cursor = 256;
            while coefficients.len() < count * EF::D {
                if cursor == 256 {
                    reference.challenge_bytes(b"direct canonical field stream", &mut block);
                    cursor = 0;
                }
                let mut bytes = [0u8; 16];
                bytes[..width].copy_from_slice(&block[cursor..cursor + width]);
                cursor += width;
                let value = u128::from_le_bytes(bytes) & mask;
                if value < p {
                    coefficients.push(Base::new(Base::Value::as_from(value)));
                }
            }
            let expected: Vec<EF> = coefficients
                .chunks_exact(EF::D)
                .map(EF::from_base_slice)
                .collect();
            let got = if kind == b"scalar" {
                vec![actual.get_challenge(b"reference extension challenge")]
            } else {
                actual.get_vec_challenge(b"reference extension challenge", count)
            };
            assert_eq!(got, expected);
            if count > 100 {
                for coordinate in 0..EF::D {
                    assert!(
                        got.iter()
                            .any(|x| x.as_base_slice()[coordinate] != Base::zero())
                    );
                }
            }
        }
        let mut a = [0u8; 32];
        let mut b = a;
        actual.get_challenge_bytes(b"after extension", &mut a);
        reference.challenge_bytes(b"after extension", &mut b);
        assert_eq!(a, b);
        for (degree, w) in [(EF::D, w + 1), (EF::D + 1, w)] {
            let mut actual = Transcript::<EF>::new_direct_extension::<Base>();
            let mut wrong = extension_frame(p, degree, w);
            actual.get_challenge_bytes(b"field identity", &mut a);
            wrong.challenge_bytes(b"field identity", &mut b);
            assert_ne!(a, b);
        }
    }
    #[test]
    fn extension_challenges_match_independent_binomial_and_byte_reference() {
        extension_reference::<BabyBear, algebra::BabyBearExetension>(4, (1u128 << 31) - 1, 11);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension>(8, u64::MAX as u128, 7);
    }
    #[test]
    fn larger_extension_challenges_match_independent_polynomial_and_byte_reference() {
        extension_reference::<BabyBear, algebra::BabyBearExtension6>(4, (1u128 << 31) - 1, 31);
        extension_reference::<BabyBear, algebra::BabyBearExtension8>(4, (1u128 << 31) - 1, 11);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension4>(8, u64::MAX as u128, 7);
        extension_reference::<BabyBear, algebra::BabyBearExtension5>(4, (1u128 << 31) - 1, 2);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension5>(8, u64::MAX as u128, 3);
        extension_reference::<Goldilocks, algebra::GoldilocksExtension3>(8, u64::MAX as u128, 7);
    }
    #[test]
    fn extension_request_kinds_labels_counts_and_sampling_modes_are_separated() {
        type EF = algebra::BabyBearExetension;
        let mut outputs = Vec::new();
        for mode in 0..6 {
            let mut t = if mode == 5 {
                Transcript::<EF>::new()
            } else {
                Transcript::<EF>::new_direct_extension::<BabyBear>()
            };
            match mode {
                0 | 5 => {
                    t.get_challenge(b"a");
                }
                1 => {
                    t.get_vec_challenge(b"a", 1);
                }
                2 => {
                    t.get_vec_challenge(b"b", 1);
                }
                3 => {
                    t.get_vec_challenge(b"a", 2);
                }
                _ => {
                    t.get_vec_challenge(b"a", 0);
                }
            }
            let mut bytes = [0u8; 32];
            t.get_challenge_bytes(b"after request", &mut bytes);
            outputs.push(bytes);
        }
        for i in 0..outputs.len() {
            for j in 0..i {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
    }
}

//! Experimental packed ZeroCheck coupled to structured MW-Basefold.
//!
//! Canonical factor roots are fixed before ZeroCheck. Each fresh matrix pair
//! immediately folds/authenticates every factor oracle before the next packed
//! challenge. This is a separate streaming protocol, not a replacement for the
//! generic after-query MW-Brakedown API or a whole-proof security certificate.
use algebra::{PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    mw_basefold::{self as bf, Commitment, Parameters, RoundProof, StartProof, State},
    utils::hash::Hash,
};
use serde::{Deserialize, Serialize};
use sumcheck::{
    packed::PackedShape,
    packed_zero::{self, ZeroProof},
};

/// Invalid trusted parameters, source state or rejected coupled certificate.
#[derive(Debug, thiserror::Error)]
#[error("packed MW-Basefold: {0}")]
pub struct Error(pub String);
/// One complete coupled relation proof. Roots and mathematical shape are public
/// expected inputs, never accepted as prover-selected replacement parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Initialization for each canonical original source.
    pub starts: Vec<StartProof<F>>,
    /// Algebraic ZeroCheck transcript; source values come from the FRI tails.
    pub zero: ZeroProof<F>,
    /// Oracle rounds in time order, each containing one fold per source.
    pub folds: Vec<Vec<RoundProof<F, O>>>,
}
/// Prover-only wall-clock counters, excluded from proof/transcript data.
#[derive(Default, Debug)]
pub struct Statistics {
    /// Total ZeroCheck plus streaming-oracle time.
    pub proving: std::time::Duration,
    /// Time inside source folds, Merkle commitments and query answers.
    pub oracle_folds: std::time::Duration,
}
/// Prove a Boolean row-wise relation from canonical roots and reusable states.
pub fn prove<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    roots: &[Commitment<H::Output>],
    states: &[State<F, H>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    prove_with_statistics::<F, H>(
        trans,
        pp,
        shape,
        factors,
        roots,
        states,
        &mut Statistics::default(),
    )
}
/// Prove with timings of the actual coupled protocol.
pub fn prove_with_statistics<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    roots: &[Commitment<H::Output>],
    states: &[State<F, H>],
    statistics: &mut Statistics,
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    prove_impl::<F, H>(trans, pp, shape, factors, roots, states, statistics, true)
}
fn prove_impl<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    roots: &[Commitment<H::Output>],
    states: &[State<F, H>],
    statistics: &mut Statistics,
    strict: bool,
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    bind::<F, H>(trans, pp, shape, roots)?;
    if states.len() != shape.num_factors || factors.len() != shape.num_factors {
        return Err(Error("source dimensions".into()));
    }
    let (mut sources, starts): (Vec<_>, Vec<_>) = roots
        .iter()
        .zip(states)
        .map(|(root, state)| bf::Prover::begin(trans, pp, root, state).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    let mut folds = vec![Vec::with_capacity(shape.num_factors); pp.rounds()];
    let timer = std::time::Instant::now();
    let (zero, claim, _) =
        packed_zero::prove_with_rounds(trans, shape, factors, |t, round, pair| {
            let timer = std::time::Instant::now();
            for source in &mut sources {
                if let Some(proof) = source.advance(t, pair).map_err(sum_error)? {
                    folds[round].push(proof);
                }
            }
            statistics.oracle_folds += timer.elapsed();
            Ok(())
        })
        .map_err(convert)?;
    let values = sources
        .iter()
        .map(|s| s.finish().map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    if strict {
        claim.check(shape, &values).map_err(convert)?;
    }
    statistics.proving += timer.elapsed();
    Ok(Proof {
        starts,
        zero,
        folds,
    })
}
/// Verify using only expected canonical roots, trusted parameters and shape.
/// No factor values, source state or caller-supplied matrix query is accepted.
pub fn verify<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    shape: &PackedShape<F>,
    roots: &[Commitment<H::Output>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    verify_impl::<F, H>(trans, pp, shape, roots, proof, true)
}
fn verify_impl<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    shape: &PackedShape<F>,
    roots: &[Commitment<H::Output>],
    proof: &Proof<F, H::Output>,
    strict: bool,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    bind::<F, H>(trans, pp, shape, roots)?;
    if proof.starts.len() != shape.num_factors
        || proof.folds.len() != pp.rounds()
        || proof.folds.iter().any(|r| r.len() != shape.num_factors)
    {
        return Err(Error("proof source/round counts".into()));
    }
    let mut sources = roots
        .iter()
        .zip(&proof.starts)
        .map(|(root, p)| bf::Verifier::<F, H>::begin(trans, pp, root, p).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let claim = packed_zero::verify_with_rounds(trans, shape, &proof.zero, |t, round, pair| {
        for (j, source) in sources.iter_mut().enumerate() {
            let p = proof.folds.get(round).map(|r| &r[j]);
            source.advance(t, pair, p).map_err(sum_error)?;
        }
        Ok(())
    })
    .map_err(convert)?;
    let values = sources
        .iter()
        .map(|s| s.finish().map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    if strict {
        claim.check(shape, &values).map_err(convert)?;
    }
    Ok(())
}
fn bind<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    shape: &PackedShape<F>,
    roots: &[Commitment<H::Output>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    shape.validate().map_err(convert)?;
    if shape.num_vars == 0
        || pp.num_vars() != shape.num_vars
        || pp.width() != shape.width
        || roots.len() != shape.num_factors
    {
        return Err(Error("relation/source geometry".into()));
    }
    trans.append_message(
        b"HasteBoots streaming structured packed Basefold relation v1",
        &(pp, shape, roots),
    );
    Ok(())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn sum_error(e: impl std::fmt::Display) -> sumcheck::error::Error {
    sumcheck::error::Error::Reject(Some(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, transformation::AbstractNTT};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    fn exercise<F: NTTField + Serialize + DeserializeOwned + From<usize>>() {
        for (vars, k) in [(1usize, 2usize), (3, 2), (4, 4), (5, 4)] {
            let n = (1 << vars) / k * 2;
            let mut root = F::generate_ntt_table(n.max(64).ilog2()).unwrap().root();
            for _ in n.ilog2()..n.max(64).ilog2() {
                root *= root;
            }
            let pp = Parameters::new(vars, k, 2, 24, root).unwrap();
            let shape = PackedShape {
                num_vars: vars,
                width: k,
                num_factors: 3,
                terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
            };
            let make = |v| PackedTable::new(vars, k, v).unwrap();
            let a: Vec<_> = (0..(1 << vars) * k).map(|i| F::from(i + 1)).collect();
            let b: Vec<_> = a.iter().map(|&v| v + F::from(7)).collect();
            let c: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a * b).collect();
            let factors = vec![make(a), make(b), make(c)];
            for false_source in [false, true] {
                let mut actual = factors.clone();
                if false_source {
                    let mut v = actual[2].values().to_vec();
                    v[0] += F::one();
                    actual[2] = make(v);
                }
                let (roots, states): (Vec<_>, Vec<_>) = actual
                    .iter()
                    .map(|t| bf::commit::<F, Sha256>(&pp, t).unwrap())
                    .unzip();
                let mut prover = Transcript::new_direct();
                let proof = prove_impl::<F, Sha256>(
                    &mut prover,
                    &pp,
                    &shape,
                    &factors,
                    &roots,
                    &states,
                    &mut Statistics::default(),
                    !false_source,
                )
                .unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, used): (Proof<F, [u8; 32]>, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                // Every algebraic child and every streamed PCS opening is
                // genuine under the actual root/header. Only the public
                // terminal relation is omitted in this independent replay.
                let mut reference = Transcript::new_direct();
                verify_impl::<F, Sha256>(&mut reference, &pp, &shape, &roots, &proof, false)
                    .unwrap();
                assert_eq!(
                    prover.get_challenge(b"after coupled proof"),
                    reference.get_challenge(b"after coupled proof")
                );
                let result =
                    verify::<F, Sha256>(&mut Transcript::new_direct(), &pp, &shape, &roots, &proof);
                if false_source {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("packed ZeroCheck terminal identity failed")
                    );
                } else {
                    result.unwrap();
                    if pp.rounds() > 0 {
                        let mut bad = proof.clone();
                        bad.folds[0].swap(0, 1);
                        assert!(
                            verify::<F, Sha256>(
                                &mut Transcript::new_direct(),
                                &pp,
                                &shape,
                                &roots,
                                &bad
                            )
                            .is_err()
                        );
                    }
                    let mut bad = proof.clone();
                    bad.starts.pop();
                    assert!(
                        verify::<F, Sha256>(
                            &mut Transcript::new_direct(),
                            &pp,
                            &shape,
                            &roots,
                            &bad
                        )
                        .is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn babybear_coupled_relation_and_genuine_false_source() {
        exercise::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_coupled_relation_and_genuine_false_source() {
        exercise::<algebra::Goldilocks>();
    }
}

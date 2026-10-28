//! Conditional linear-view audit; excludes hashes and challenge dependence.
use super::*;
use algebra::{NTTField, transformation::AbstractNTT};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;

struct FriTrace<F> {
    alphas: Vec<F>,
    indices: Vec<usize>,
}
struct Trace<F> {
    alpha: F,
    source_weights: Vec<F>,
    source_fri: FriTrace<F>,
    consistency: Vec<usize>,
    weights: Vec<Vec<F>>,
    fri: FriTrace<F>,
}
fn replay_fri<F: Field + Serialize>(
    t: &mut Transcript<F>,
    pp: &rolling_fri::Parameters<F>,
    ids: &[[u8; 32]],
    proof: &rolling_fri::Proof<F, [u8; 32]>,
) -> FriTrace<F> {
    let roots: Vec<_> = ids
        .iter()
        .map(|&root| rolling_fri::Commitment { root })
        .collect();
    t.append_message(
        b"HasteBoots rolling batch FRI virtual all v2",
        &(pp.context::<Sha256>(), roots),
    );
    let mut alphas = Vec::new();
    for layer in 0..pp.rounds() {
        alphas.push(t.get_challenge(b"rolling FRI fold challenge"));
        if layer + 1 == pp.rounds() {
            t.append_message(b"rolling FRI terminal", &proof.terminal);
        } else {
            t.append_message(
                b"rolling FRI derived root",
                &(layer + 1, &proof.derived[layer]),
            );
        }
    }
    let indices = (0..pp.queries())
        .map(|_| {
            let mut bytes = [0u8; 8];
            t.get_challenge_bytes(b"rolling FRI unbiased domain index", &mut bytes);
            (u64::from_le_bytes(bytes) & (pp.encoded_len() as u64 - 1)) as usize
        })
        .collect();
    FriTrace { alphas, indices }
}
fn trace<F: Field + Serialize>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &[u8; 32],
    query: &[MatrixPair<F>],
    claim: &[F],
    proof: &Proof<F, [u8; 32]>,
) -> Trace<F> {
    let alpha = bind(t, pp, root, proof.index, query, claim, &proof.mask_claim);
    let (source_weights, ids) = source_projection::<F, Sha256>(t, pp, root, proof.index);
    let fri_pp =
        rolling_fri::Parameters::new(2 * pp.message, pp.blowup, pp.queries, pp.root).unwrap();
    let source_fri = replay_fri(t, &fri_pp, &ids, &proof.source_proximity);
    let oracle = pp.oracle(false);
    let id = identifier::<F, Sha256>(pp, root, proof.index, alpha);
    let padded = padded_query(pp, query, claim).unwrap();
    let combined: Vec<_> = claim
        .iter()
        .zip(&proof.mask_claim)
        .map(|(&p, &s)| (p + alpha * s).canonicalized())
        .collect();
    t.append_message(b"packed PolyFRIM virtual source v2", &());
    super::super::bind(
        t,
        &oracle,
        &id,
        &proof.inner.consistency.roots,
        &padded,
        &combined,
    );
    let consistency = (0..pp.queries)
        .map(|_| {
            let mut bytes = [0u8; 8];
            t.get_challenge_bytes(b"packed PolyFRIM domain index v2", &mut bytes);
            (u64::from_le_bytes(bytes) & (oracle.len(0) as u64 - 1)) as usize
        })
        .collect();
    let roots: Vec<_> = std::iter::once(id)
        .chain(proof.inner.consistency.roots.iter().copied())
        .collect();
    t.append_message(
        b"packed PolyFRIM same-root proximity v2",
        &(&oracle, &roots),
    );
    let weights: Vec<_> = (0..oracle.rounds())
        .map(|_| t.get_vec_challenge(b"packed PolyFRIM lane projection v2", pp.width))
        .collect();
    let ids: Vec<_> = roots
        .iter()
        .zip(&weights)
        .enumerate()
        .map(|(layer, (root, row))| {
            hash::<Sha256, _>(&(
                b"packed PolyFRIM virtual layer v2",
                &oracle,
                layer,
                root,
                row,
            ))
        })
        .collect();
    let fri = replay_fri(t, &fri_pp, &ids, &proof.inner.proximity);
    Trace {
        alpha,
        source_weights,
        source_fri,
        consistency,
        weights,
        fri,
    }
}

// Independent coefficient algebra: no production table/Polynomial/FFT folds.
fn matrix_fold<F: Field>(coefficients: &[F], width: usize, pair: &MatrixPair<F>) -> Vec<F> {
    let mut out = vec![F::zero(); coefficients.len() / 2];
    for (cell, values) in coefficients.chunks_exact(2 * width).enumerate() {
        for row in 0..width {
            for column in 0..width {
                out[cell * width + row] += (pair.zero.values()[row * width + column]
                    + pair.one.values()[row * width + column])
                    * values[column]
                    + pair.one.values()[row * width + column] * values[width + column];
            }
        }
    }
    out
}
fn scalar_fold<F: Field>(coefficients: &[F], alpha: F) -> Vec<F> {
    coefficients
        .chunks_exact(2)
        .map(|p| p[0] + alpha * p[1])
        .collect()
}
fn projection<F: Field>(coefficients: &[F], width: usize, weights: &[F]) -> Vec<F> {
    coefficients
        .chunks_exact(width)
        .map(|v| {
            v.iter()
                .zip(weights)
                .fold(F::zero(), |a, (&x, &w)| a + x * w)
        })
        .collect()
}
fn evaluate<F: Field>(coefficients: &[F], width: usize, point: F) -> Vec<F> {
    let mut out = vec![F::zero(); width];
    for vector in coefficients.chunks_exact(width).rev() {
        for (y, &c) in out.iter_mut().zip(vector) {
            *y = *y * point + c;
        }
    }
    out
}
fn pair<F: Field + Serialize>(
    pp: &Parameters<F>,
    coefficients: &[F],
    width: usize,
    layer: usize,
    index: usize,
) -> Vec<F> {
    let oracle = pp.oracle(false);
    let n = oracle.len(layer);
    let index = (index >> layer) & !1;
    let reversed = index.reverse_bits() >> (usize::BITS - n.ilog2());
    let x = power(oracle.shift(layer), 2 * reversed + 1);
    let mut out = evaluate(coefficients, width, x);
    out.extend(evaluate(coefficients, width, -x));
    out
}
fn rolling_polynomials<F: Field>(originals: &[Vec<F>], trace: &FriTrace<F>) -> (Vec<Vec<F>>, F) {
    let mut combined = originals[0].clone();
    let mut derived = Vec::new();
    for (layer, &alpha) in trace.alphas.iter().enumerate() {
        let folded = scalar_fold(&combined, alpha);
        if layer + 1 == originals.len() {
            return (derived, folded[0]);
        }
        combined = folded
            .iter()
            .zip(&originals[layer + 1])
            .map(|(&p, &s)| p + alpha * alpha * s)
            .collect();
        derived.push(folded);
    }
    unreachable!()
}
fn fri_view<F: Field + Serialize>(
    pp: &Parameters<F>,
    originals: &[Vec<F>],
    derived: &[Vec<F>],
    terminal: F,
    trace: &FriTrace<F>,
) -> Vec<F> {
    let mut out = vec![terminal];
    for &index in &trace.indices {
        for (layer, polynomial) in originals.iter().enumerate() {
            out.extend(pair(pp, polynomial, 1, layer, index));
        }
        for (i, polynomial) in derived.iter().enumerate() {
            out.extend(pair(pp, polynomial, 1, i + 1, index));
        }
    }
    out
}
// Coordinates: original low coefficients, private high coefficients, full S.
fn numerical_view<F: Field + Serialize>(
    pp: &Parameters<F>,
    c: &[F],
    query: &[MatrixPair<F>],
    trace: &Trace<F>,
) -> Vec<F> {
    let k = pp.width;
    let m = pp.message;
    let r = (2 * m).ilog2() as usize;
    let data = &c[..2 * m * k];
    let mask = &c[2 * m * k..];
    let padded = padded_query(pp, query, &vec![F::zero(); k]).unwrap();
    let mut mask_value = mask.to_vec();
    for q in &padded {
        mask_value = matrix_fold(&mask_value, k, q);
    }
    let mut out = mask_value;
    let paired: Vec<F> = data
        .chunks_exact(k)
        .zip(mask.chunks_exact(k))
        .flat_map(|(p, s)| p.iter().chain(s).copied())
        .collect();
    let mut source_originals = vec![projection(&paired, 2 * k, &trace.source_weights)];
    source_originals.extend((1..r).map(|i| vec![F::zero(); 2 * m >> i]));
    let (source_derived, source_terminal) =
        rolling_polynomials(&source_originals, &trace.source_fri);
    out.extend(fri_view(
        pp,
        &source_originals,
        &source_derived,
        source_terminal,
        &trace.source_fri,
    ));
    for &index in &trace.source_fri.indices {
        out.extend(pair(pp, &paired, 2 * k, 0, index));
    }
    let mut ladder = vec![
        data.iter()
            .zip(mask)
            .map(|(&p, &s)| p + trace.alpha * s)
            .collect::<Vec<_>>(),
    ];
    for q in padded.iter().take(r - 1) {
        ladder.push(matrix_fold(ladder.last().unwrap(), k, q));
    }
    for &index in &trace.consistency {
        for (layer, polynomial) in ladder.iter().enumerate() {
            out.extend(pair(pp, polynomial, k, layer, index));
        }
    }
    let originals: Vec<_> = ladder
        .iter()
        .zip(&trace.weights)
        .map(|(p, w)| projection(p, k, w))
        .collect();
    let (derived, terminal) = rolling_polynomials(&originals, &trace.fri);
    out.extend(fri_view(pp, &originals, &derived, terminal, &trace.fri));
    for &index in &trace.fri.indices {
        for (layer, polynomial) in ladder.iter().enumerate() {
            out.extend(pair(pp, polynomial, k, layer, index));
        }
    }
    for &index in trace.consistency.iter().chain(&trace.fri.indices) {
        out.extend(pair(pp, &paired, 2 * k, 0, index));
    }
    out
}
fn revealed<F: Field>(proof: &Proof<F, [u8; 32]>) -> Vec<F> {
    fn fri<F: Field>(p: &rolling_fri::Proof<F, [u8; 32]>) -> Vec<F> {
        let mut out = vec![p.terminal];
        for q in &p.queries {
            for pair in q.originals.iter().chain(&q.derived) {
                out.extend(pair.values);
            }
        }
        out
    }
    let mut out = proof.mask_claim.clone();
    out.extend(fri(&proof.source_proximity));
    for pair in &proof.source_pairs {
        out.extend(&pair.values);
    }
    for query in &proof.inner.consistency.queries {
        for pair in query {
            out.extend(&pair.values);
        }
    }
    out.extend(fri(&proof.inner.proximity));
    for query in &proof.inner.packed {
        for pair in query {
            out.extend(&pair.values);
        }
    }
    for pair in &proof.sources {
        out.extend(&pair.values);
    }
    out
}
fn rank<F: Field>(mut a: Vec<Vec<F>>) -> usize {
    if a.is_empty() {
        return 0;
    }
    let mut row = 0;
    for col in 0..a[0].len() {
        let Some(pivot) = (row..a.len()).find(|&i| a[i][col] != F::zero()) else {
            continue;
        };
        a.swap(row, pivot);
        let inverse = F::one() / a[row][col];
        for v in &mut a[row][col..] {
            *v *= inverse;
        }
        let normalized = a[row].clone();
        for lower in a.iter_mut().skip(row + 1) {
            let scale = lower[col];
            if scale != F::zero() {
                for i in col..lower.len() {
                    lower[i] -= scale * normalized[i];
                }
            }
        }
        row += 1;
        if row == a.len() {
            break;
        }
    }
    row
}
fn audit<F: NTTField + Serialize + DeserializeOwned>() {
    for width in [1, 2] {
        for singular in [false, true] {
            let m: usize = if width == 1 { 512 } else { 1024 };
            let variables = m.ilog2() as usize;
            let root = F::generate_ntt_table((4 * m).ilog2()).unwrap().root();
            let pp = Parameters::new(m, width, 2, 1, 2, root).unwrap();
            let mut rng =
                StdRng::seed_from_u64(7201 + width as u64 + if singular { 100 } else { 0 });
            let table = PackedTable::new(
                variables,
                width,
                (0..m * width).map(|_| F::random(&mut rng)).collect(),
            )
            .unwrap();
            let mut session = commit::<F, Sha256, _>(&pp, &table, &mut rng).unwrap();
            let mut c = vec![F::zero(); 4 * m * width];
            for (cell, v) in session
                .source
                .polynomial
                .coefficients
                .chunks_exact(2 * width)
                .enumerate()
            {
                c[cell * width..(cell + 1) * width].copy_from_slice(&v[..width]);
                c[2 * m * width + cell * width..2 * m * width + (cell + 1) * width]
                    .copy_from_slice(&v[width..]);
            }
            let mut queries = Vec::new();
            let mut traces = Vec::new();
            for opening in 0..2 {
                let mut query: Vec<_> = (0..variables)
                    .map(|i| MatrixPair {
                        zero: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| F::from(i + 2 * j + opening + 1))
                                .collect(),
                        )
                        .unwrap(),
                        one: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| F::from(j * j + 3 * i + 2 * opening + 3))
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect();
                if width == 2 && opening == 0 {
                    assert_ne!(
                        query[0].zero.mul(&query[1].one).unwrap(),
                        query[1].one.mul(&query[0].zero).unwrap()
                    );
                }
                if singular && opening == 1 {
                    let mut projector = vec![F::zero(); width * width];
                    if width > 1 {
                        projector[0] = F::one();
                    }
                    query[variables - 1] = MatrixPair {
                        zero: Matrix::new(width, projector).unwrap(),
                        one: Matrix::new(width, vec![F::zero(); width * width]).unwrap(),
                    };
                }
                let claim = table.evaluate(&query).unwrap();
                let mut prover = Transcript::new_direct();
                let proof = prove(&mut prover, &pp, &mut session, &query, &claim).unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, used): (Proof<F, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());

                verify::<F, Sha256>(
                    &mut Transcript::new_direct(),
                    &pp,
                    &session.root(),
                    &query,
                    &claim,
                    &proof,
                )
                .unwrap();
                let mut replay = Transcript::new_direct();
                let trace = trace(&mut replay, &pp, &session.root(), &query, &claim, &proof);
                assert_eq!(
                    prover.get_challenge(b"after direct packed disclosure"),
                    replay.get_challenge(b"after direct packed disclosure")
                );
                assert_eq!(numerical_view(&pp, &c, &query, &trace), revealed(&proof));
                queries.push(query);
                traces.push(trace);
            }
            let view = |c: &[F]| {
                queries
                    .iter()
                    .zip(&traces)
                    .flat_map(|(q, t)| numerical_view(&pp, c, q, t))
                    .collect::<Vec<_>>()
            };
            let columns = c.len();
            let witness = m * width;
            let zero = vec![F::zero(); columns];
            let rows = view(&zero).len();
            let mut a = vec![vec![F::zero(); columns]; rows];
            let mut allowed = vec![vec![F::zero(); columns]; 2 * width];
            for col in 0..columns {
                let mut basis = zero.clone();
                basis[col] = F::one();
                for (row, value) in view(&basis).into_iter().enumerate() {
                    a[row][col] = value;
                }
                if col < witness {
                    for (opening, query) in queries.iter().enumerate() {
                        let mut value = basis[..witness].to_vec();
                        for pair in query {
                            value = matrix_fold(&value, width, pair);
                        }
                        for lane in 0..width {
                            allowed[opening * width + lane][col] = value[lane];
                        }
                    }
                }
            }
            let random_rank = rank(a.iter().map(|row| row[witness..].to_vec()).collect());
            let allowed_rank = rank(allowed.clone());
            assert_eq!(
                allowed_rank,
                if singular { 2 * width - 1 } else { 2 * width },
                "rank audit fixture must exercise the intended response rank"
            );

            let mut joined = a;
            joined.extend(allowed);
            let full_rank = rank(joined.clone());
            assert_eq!(
                full_rank,
                random_rank + allowed_rank,
                "masked direct packed numerical disclosure exceeds allowed responses"
            );
            // Deliberately reveal an original coefficient beyond the permitted view.
            let mut detected = false;
            let mut negative_rank = full_rank;
            for coordinate in 0..witness {
                let mut candidate = joined.clone();
                let mut leak = vec![F::zero(); columns];
                leak[coordinate] = F::one();
                candidate.push(leak);
                negative_rank = rank(candidate);
                if negative_rank > full_rank {
                    detected = true;
                    break;
                }
            }
            assert!(detected);
            println!(
                "HB_PACKED_MASK_RANK {{\"field\":\"{}\",\"schedule\":\"{}\",\"width\":{},\"m\":{},\"openings\":2,\"rows\":{},\"columns\":{},\"random_rank\":{},\"allowed_rank\":{},\"full_rank\":{},\"negative_control_rank\":{}}}",
                std::any::type_name::<F>(),
                if singular {
                    "dense-singular"
                } else {
                    "dense-dense"
                },
                width,
                m,
                rows,
                columns,
                random_rank,
                allowed_rank,
                full_rank,
                negative_rank
            );
        }
    }
}

#[test]
fn babybear_cumulative_linear_view() {
    audit::<algebra::BabyBear>();
}
#[test]
fn goldilocks_cumulative_linear_view() {
    audit::<algebra::Goldilocks>();
}

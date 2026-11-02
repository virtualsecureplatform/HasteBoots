//! Isolated monomial NTT row requests, not an accepted prior-prefix theorem.
use super::*;

pub(super) fn exercise<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    plan: &crate::packed_monomial::Plan,
    coefficients: &[Commitment<Digest512>],
    monomial_binding: &[u8],
) where
    F: NTTField + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let evaluations = vec![
        Commitment {
            root: Digest512([19; 64]),
        },
        Commitment {
            root: Digest512([23; 64]),
        },
    ];
    let sources = pp.accumulators[..2]
        .iter()
        .zip(coefficients)
        .map(|(parameters, commitment)| CanonicalVerifierOracle {
            parameters: *parameters,
            commitment,
        })
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 2);
    let shape =
        ntt::Shape::new_canonical::<F, Sha512, P>(pp.monomial, plan.polynomial_size()).unwrap();
    let count = shape.width() * shape.row_variables();
    let root = F::get_ntt_table(plan.polynomial_size().ilog2())
        .unwrap()
        .root();
    for component in 0..2 {
        let mut production = profile.parent_transcript::<F>().unwrap();
        crate::packed_monomial::canonical::audit::bind_for_test::<F, Sha512, P>(
            &mut production,
            plan,
            pp.monomial,
            &sources,
        )
        .unwrap();
        production.append_message(b"public canonical monomial NTT roots", &evaluations);
        let evaluation = CanonicalVerifierOracle {
            parameters: pp.monomial,
            commitment: &evaluations[component],
        };
        let points = ntt::audit_binding_row_points::<F, Sha512, P>(
            &mut production,
            &shape,
            &sources[component],
            &evaluation,
        )
        .unwrap();
        let mut bytes = initial_header::<F>(profile).unwrap();
        bytes.extend(monomial_binding);
        frame(
            &mut bytes,
            1,
            b"public canonical monomial NTT roots",
            &encoded(&evaluations),
        );
        let request_start = bytes.len();
        let contexts = (
            sources[component].parameters.context().ok().unwrap(),
            pp.monomial.context().ok().unwrap(),
        );
        frame(
            &mut bytes,
            1,
            P::NTT_DOMAIN,
            &encoded(&(
                F::MODULUS_VALUE.to_string(),
                &shape,
                root,
                contexts,
                &coefficients[component],
                &evaluations[component],
            )),
        );
        frame(&mut bytes, 1, b"typed request kind", b"vector");
        frame(&mut bytes, 1, b"field challenge kind", b"prime vector");
        let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((count as u64).to_le_bytes());
        frame(
            &mut bytes,
            4,
            b"packed NTT atomic row points v2",
            &descriptor,
        );
        let (row, request) = super::monomial_ntt_prefix_audit::request::<F, P>(
            pp,
            plan.polynomial_size(),
            component,
            coefficients,
            &evaluations,
        )
        .unwrap();
        assert_eq!(&bytes[request_start..], request.as_slice());
        let body_start = bytes.len();
        let (coins, raw) = raw_prime_phase::<F>(&bytes, count);
        let coins: Vec<F> = coins
            .into_iter()
            .map(|v| F::from(usize::try_from(v).unwrap()))
            .collect();
        let expected = if shape.row_variables() == 0 {
            vec![vec![]; shape.width()]
        } else {
            coins
                .chunks_exact(shape.row_variables())
                .map(<[F]>::to_vec)
                .collect()
        };
        assert_eq!(encoded(&points), encoded(&expected));
        let (phase, producer) = receipt(&raw);
        let mut known = Producers::new();
        let row_digest = phase[16..].try_into().unwrap();
        known.insert(row_digest, producer);
        frame(&mut bytes, 5, b"packed NTT atomic row points v2", &phase);
        let folded_start = bytes.len();
        let (co, ev) = super::monomial_ntt_prefix_audit::polynomials::<F, P>(pp, &row);
        frame(
            &mut bytes,
            1,
            b"packed NTT folded polynomials",
            &encoded(&(&co, &ev)),
        );
        let compression = ntt::audit_folded_compression(&mut production, &shape, &co, &ev).unwrap();
        for (round, pair) in compression.iter().enumerate() {
            bytes.extend(ntt_compression_tail::<F>(shape.width()));
            let (parsed, rest) =
                ntt_compression_body::<F, P>(pp, row.clone(), &bytes[body_start..], &known, round)
                    .unwrap();
            assert!(rest.is_empty());
            assert_eq!(parsed.compression.len(), round);
            assert_eq!(encoded(&parsed.points), encoded(&points));
            assert_eq!(encoded(&parsed.coefficients), encoded(&co));
            assert_eq!(encoded(&parsed.evaluations), encoded(&ev));
            let mut missing = known.clone();
            missing.remove(&row_digest);
            assert!(
                ntt_compression_body::<F, P>(
                    pp,
                    row.clone(),
                    &bytes[body_start..],
                    &missing,
                    round
                )
                .is_none()
            );
            let (coins, raw) = raw_prime_phase::<F>(&bytes, shape.width());
            let coins = coins
                .into_iter()
                .map(|v| F::from(usize::try_from(v).unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(
                encoded(pair),
                encoded(&sumcheck::packed::challenge_pair(&coins).unwrap())
            );
            let (phase, producer) = receipt(&raw);
            known.insert(phase[16..].try_into().unwrap(), producer);
            frame(&mut bytes, 5, b"packed NTT coefficient compression", &phase);
        }
        if let Some(last) = compression.len().checked_sub(1) {
            let (parsed, rest) =
                ntt_compression_body::<F, P>(pp, row.clone(), &bytes[body_start..], &known, last)
                    .unwrap();
            let (batch, rest) = ntt_batch_body(parsed, rest, &known).unwrap();
            assert!(rest.is_empty());
            let (queries, co_values, ev_values) =
                ntt::audit_source_obligations(&shape, &compression, &points, &co, &ev).unwrap();
            assert_eq!(encoded(&batch.queries), encoded(&queries));
            assert_eq!(encoded(&batch.coefficient_values), encoded(&co_values));
            assert_eq!(encoded(&batch.evaluation_values), encoded(&ev_values));
            assert_eq!(batch.queries.len(), shape.width());
            assert!(
                batch
                    .queries
                    .iter()
                    .all(|q| q.len() == pp.monomial.num_vars())
            );
        }
        let mut bad = ev.clone();
        bad[0][0] += F::one();
        assert!(
            ntt::audit_folded_compression(
                &mut profile.parent_transcript::<F>().unwrap(),
                &shape,
                &co,
                &bad
            )
            .is_err()
        );
        let mut wrong = bytes[..folded_start].to_vec();
        frame(
            &mut wrong,
            1,
            b"packed NTT folded polynomials",
            &encoded(&(&co, &bad)),
        );
        wrong.extend(ntt_compression_tail::<F>(shape.width()));
        if !compression.is_empty() {
            assert!(
                ntt_compression_body::<F, P>(pp, row.clone(), &wrong[body_start..], &known, 0)
                    .is_none()
            );
        }
        frame(
            &mut bytes,
            2,
            b"monomial NTT row replay",
            &64u64.to_le_bytes(),
        );
        let mut output = [0; 64];
        production.get_challenge_bytes(b"monomial NTT row replay", &mut output);
        assert_eq!(output, shake64(&bytes));
        println!(
            "HB_MONOMIAL_NTT_COMPRESSION prime={} n={} version={} backend={:?} component={} rounds={} source_openings_authenticated=false",
            F::MODULUS_VALUE,
            plan.polynomial_size(),
            profile.version(),
            profile.specification().backend,
            component,
            compression.len()
        );
    }
    println!(
        "HB_MONOMIAL_NTT_ROWS prime={} n={} version={} backend={:?} requests=2",
        F::MODULUS_VALUE,
        plan.polynomial_size(),
        profile.version(),
        profile.specification().backend
    );
}

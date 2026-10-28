use algebra::{
    Goldilocks as F, GoldilocksExtension3 as E,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, aggregated},
};
use rand::{SeedableRng, rngs::StdRng};
use sha2::Sha256;

#[test]
fn identical_roots_have_distinct_bound_backend_contexts() {
    let independent = Parameters::<F, E>::new(1, 1, 10, 2, 1, 2).unwrap();
    let canonical = aggregated::Parameters::from_independent(independent.clone());
    let previous = pcs::matrix_weighted::masked_polyfrim::joint::Parameters::from_independent(
        independent.clone(),
    );
    assert_ne!(
        CanonicalPcs::<F, Sha256>::context(&previous).unwrap(),
        CanonicalPcs::<F, Sha256>::context(&canonical).unwrap()
    );
    assert_ne!(
        CanonicalPcs::<F, Sha256>::context(&independent).unwrap(),
        CanonicalPcs::<F, Sha256>::context(&canonical).unwrap()
    );
    let table = PackedTable::new(1, 1, vec![F::from(5usize), F::from(8usize)]).unwrap();
    let (root, state) = canonical
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(991))
        .unwrap();
    let (other, _) = independent
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(991))
        .unwrap();
    assert_eq!(root.root, other.root);
    let queries = vec![vec![MatrixPair {
        zero: Matrix::identity(1).unwrap(),
        one: Matrix::identity(1).unwrap(),
    }]];
    let values = vec![table.evaluate(&queries[0]).unwrap()];
    let mut pt = Transcript::new_direct();
    let proof =
        CanonicalPcs::<F, Sha256>::open_many(&canonical, &mut pt, &root, &state, &queries, &values)
            .unwrap();
    let mut vt = Transcript::new_direct();
    CanonicalPcs::<F, Sha256>::verify_many(&canonical, &mut vt, &root, &queries, &values, &proof)
        .unwrap();
    assert_eq!(
        pt.get_challenge(b"canonical aggregated after"),
        vt.get_challenge(b"canonical aggregated after")
    );
    // Exact same proof type, source geometry and root; only the trusted canonical
    // backend context differs. A structurally valid packet cannot bridge it.
    assert!(
        independent
            .verify_many_aggregated::<Sha256>(
                &mut Transcript::new_direct(),
                &root,
                &queries,
                &values,
                &proof
            )
            .is_err()
    );
    let mut pt = Transcript::new_direct();
    let direct = independent
        .open_many_aggregated::<Sha256>(&mut pt, &root, &state, &queries, &values)
        .unwrap();
    let mut vt = Transcript::new_direct();
    independent
        .verify_many_aggregated::<Sha256>(&mut vt, &root, &queries, &values, &direct)
        .unwrap();
    assert_eq!(
        pt.get_challenge(b"direct aggregated after"),
        vt.get_challenge(b"direct aggregated after")
    );
    assert!(
        canonical
            .verify_many::<Sha256>(
                &mut Transcript::new_direct(),
                &root,
                &queries,
                &values,
                &direct
            )
            .is_err()
    );
    assert_eq!(state.spent().unwrap(), 2);
    let mut attempted = Transcript::new_direct();
    let mut untouched = Transcript::<F>::new_direct();
    assert!(
        CanonicalPcs::<F, Sha256>::open_many(
            &canonical,
            &mut attempted,
            &root,
            &state,
            &queries,
            &values
        )
        .is_err()
    );
    assert_eq!(
        attempted.get_challenge(b"exhausted"),
        untouched.get_challenge(b"exhausted")
    );
    assert_eq!(state.spent().unwrap(), 2);
}

#[test]
fn transient_cache_preserves_canonical_context_and_packet() {
    let retained = aggregated::Parameters::<F, E>::new(1, 1, 10, 2, 1, 2).unwrap();
    let transient = retained.clone().with_transient_source_values();
    assert_eq!(
        CanonicalPcs::<F, Sha256>::context(&retained).unwrap(),
        CanonicalPcs::<F, Sha256>::context(&transient).unwrap()
    );
    let table = PackedTable::new(1, 1, vec![F::from(5usize), F::from(8usize)]).unwrap();
    let (root, state) = retained
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(993))
        .unwrap();
    let (other, transient_state) = transient
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(993))
        .unwrap();
    assert_eq!(root.root, other.root);
    assert!(state.cached_codeword_elements().unwrap() > 0);
    assert_eq!(transient_state.cached_codeword_elements().unwrap(), 0);
    let queries = vec![vec![MatrixPair {
        zero: Matrix::identity(1).unwrap(),
        one: Matrix::identity(1).unwrap(),
    }]];
    let claims = vec![table.evaluate(&queries[0]).unwrap()];
    let mut a = Transcript::new_direct();
    let mut b = Transcript::new_direct();
    let proof =
        CanonicalPcs::<F, Sha256>::open_many(&retained, &mut a, &root, &state, &queries, &claims)
            .unwrap();
    let regenerated = CanonicalPcs::<F, Sha256>::open_many(
        &retained,
        &mut b,
        &other,
        &transient_state,
        &queries,
        &claims,
    )
    .unwrap();
    assert_eq!(
        bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap(),
        bincode::serde::encode_to_vec(&regenerated, bincode::config::standard()).unwrap()
    );
    assert_eq!(
        a.get_challenge(b"transient canonical after"),
        b.get_challenge(b"transient canonical after")
    );
    assert_eq!(transient_state.cached_codeword_elements().unwrap(), 0);
    CanonicalPcs::<F, Sha256>::verify_many(
        &transient,
        &mut Transcript::new_direct(),
        &root,
        &queries,
        &claims,
        &regenerated,
    )
    .unwrap();
}

#[test]
fn canonical_backend_domains_are_disjoint() {
    type A = aggregated::Parameters<F, E>;
    type J = pcs::matrix_weighted::masked_polyfrim::joint::Parameters<F, E>;
    type I = Parameters<F, E>;
    macro_rules! domains {
        ($p:ty) => {
            [
                <$p as CanonicalPcs<F, Sha256>>::LINEAR_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::NTT_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::RELATION_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::ACCUMULATOR_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::REGISTRY_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::CLAIM_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::SEAL_DOMAIN,
            ]
        };
    }
    let all: std::collections::HashSet<_> = domains!(A)
        .into_iter()
        .chain(domains!(J))
        .chain(domains!(I))
        .collect();
    assert_eq!(all.len(), 21);
}

use algebra::{BabyBear as F, Basis, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use lattice::NTTRGSW;
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use sha2::Sha256;
use snarks::{packed_bootstrap_key as public, packed_relation};
use sumcheck::packed::PackedShape;
fn fixture() -> Vec<NTTRGSW<F>> {
    (0..3)
        .map(|row| {
            let mut r = NTTRGSW::zero(32, Basis::new(8));
            for (component, g) in [r.c_neg_s_m_mut()].into_iter().enumerate() {
                for (digit, p) in g.iter_mut().enumerate() {
                    for i in 0..32 {
                        p.a_mut_slice()[i] = F::from(1000 * row + 100 * component + 20 * digit + i);
                        p.b_mut_slice()[i] = F::from(5000 + 1000 * row + 20 * digit + i);
                    }
                }
            }
            for (digit, p) in r.c_m_mut().iter_mut().enumerate() {
                for i in 0..32 {
                    p.a_mut_slice()[i] = F::from(10000 + 1000 * row + 20 * digit + i);
                    p.b_mut_slice()[i] = F::from(15000 + 1000 * row + 20 * digit + i);
                }
            }
            r
        })
        .collect()
}
#[test]
fn public_layout_matches_every_native_key_half_and_zero_padding() {
    let key = fixture();
    let tables = public::tables(4, 32, &key).unwrap();
    let d = key[0].c_m().data().len();
    assert_eq!(tables.len(), 2 * d);
    for c in 0..2 * d {
        for row in 0..4 {
            for h in 0..2 {
                for i in 0..32 {
                    let expected = if row == 3 {
                        F::from(0)
                    } else {
                        let g = if c < d {
                            key[row].c_neg_s_m()
                        } else {
                            key[row].c_m()
                        };
                        let p = &g.data()[c % d];
                        if h == 0 {
                            p.a_slice()[i]
                        } else {
                            p.b_slice()[i]
                        }
                    };
                    assert_eq!(tables[c].values()[h * 128 + row * 32 + i], expected);
                }
            }
        }
    }
    assert!(public::tables::<F>(4, 32, &[]).is_err());
    assert!(public::tables(3, 32, &key).is_err());
    assert!(public::tables(4, 64, &key).is_err());
    let bad = vec![key[0].clone(), NTTRGSW::zero(32, Basis::new(4))];
    assert!(public::tables(4, 32, &bad).is_err());
}
#[test]
fn valid_foreign_key_relation_cannot_replace_expected_key_roots() {
    let key = fixture();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(6, 4, 32, 2).unwrap();
    let expected = public::preprocess::<F, Sha256, _>(&pp, 32, &key).unwrap();
    assert_eq!(expected.rounds(), 3);
    assert_eq!(expected.basis_bits(), 8);
    let foreign = vec![NTTRGSW::zero(32, Basis::new(8)); 3];
    for actual in [&key, &foreign] {
        let columns = public::tables(4, 32, actual).unwrap();
        let count = columns.len();
        let mut factors = Vec::new();
        let mut sum = vec![F::from(0); 256];
        for (i, c) in columns.into_iter().enumerate() {
            let digit = F::from(i + 1);
            for (s, &v) in sum.iter_mut().zip(c.values()) {
                *s += digit * v;
            }
            factors.push(PackedTable::new(6, 4, vec![digit; 256]).unwrap());
            factors.push(c);
        }
        factors.push(PackedTable::new(6, 4, sum).unwrap());
        let (roots, states): (Vec<_>, Vec<_>) = factors
            .iter()
            .map(|t| pp.commit::<F, Sha256>(t).unwrap())
            .unzip();
        let private: Vec<_> = roots.iter().step_by(2).cloned().collect();
        let mut terms = (0..count)
            .map(|i| (F::from(1), vec![2 * i, 2 * i + 1]))
            .collect::<Vec<_>>();
        terms.push((-F::from(1), vec![2 * count]));
        let shape = PackedShape {
            num_vars: 6,
            width: 4,
            num_factors: 2 * count + 1,
            terms,
        };
        // A valid whole relation for the foreign key, even under the requested parent context.
        let prefix =
            |t: &mut Transcript<F>| t.append_message(b"requested public key", &expected.roots());
        let mut prover = Transcript::new();
        prefix(&mut prover);
        let proof = packed_relation::prove::<F, Sha256, _>(
            &mut prover,
            &shape,
            &pp,
            &factors,
            &roots,
            &states,
        )
        .unwrap();
        let mut own = Transcript::new();
        prefix(&mut own);
        packed_relation::verify::<F, Sha256, _>(&mut own, &shape, &pp, &roots, &proof).unwrap();
        let mut verifier = Transcript::new();
        prefix(&mut verifier);
        let result =
            public::verify::<F, Sha256, _>(&mut verifier, &pp, &expected, &private, &proof);
        if std::ptr::eq(actual, &key) {
            result.unwrap();
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
        } else {
            assert!(result.is_err());
        }
        assert!(public::commitments::<F, Sha256, _>(&pp, &expected, &private[..count]).is_err());
        let other = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(6, 4, 33, 2).unwrap();
        assert!(public::commitments::<F, Sha256, _>(&other, &expected, &private).is_err());
    }
}

//! Per-owner resource allowances; no security level is inferred from these counts.
use super::*;

/// Required allowances for each fresh owner in one complete canonical PBS.
/// Native key owners spend one per proof; callers may provision longer lifetimes.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OpeningBudget {
    /// Per coefficient digit/sum-product owner.
    pub coefficients: usize,
    /// Per evaluation owner.
    pub evaluations: usize,
    /// Per retained bootstrapping-key owner.
    pub key: usize,
    /// Per decomposition input owner.
    pub inputs: usize,
    /// Per borrow-column owner.
    pub borrows: usize,
    /// Per reciprocal helper owner.
    pub helper: usize,
    /// Input accumulator, monomial product, external input, output accumulator.
    pub accumulators: [usize; 4],
    /// Per monomial-evaluation owner.
    pub monomial: usize,
    /// Per final-stage coefficient owner.
    pub final_coefficients: usize,
    /// Per final-stage evaluation owner.
    pub final_evaluations: usize,
    /// Per retained switching-key owner.
    pub final_key: usize,
    /// Public final input and its decomposition authentication.
    pub final_input: usize,
    /// Per final-stage borrow owner.
    pub final_borrows: usize,
    /// Per final-stage reciprocal helper.
    pub final_helper: usize,
}
impl Config {
    /// Derive per-source v10/v11 allowances from the actual public query schedule.
    /// This does not select physical masking capacity or certify proof security.
    pub fn canonical_opening_budget(&self, width: usize) -> Result<OpeningBudget, Error> {
        self.variables(width)?;
        let linkage = acc::Shape::new(self.n, self.lwe)
            .map_err(convert)?
            .opening_counts(width)
            .map_err(convert)?;
        let add = |a: usize, b: usize| {
            a.checked_add(b)
                .ok_or_else(|| error("opening schedule overflow"))
        };
        let co = add(width, 2)?;
        let ev = add(width, 1)?;
        Ok(OpeningBudget {
            coefficients: co,
            evaluations: ev,
            key: 1,
            inputs: add(1, linkage[acc::DECOMPOSITION_A])?,
            borrows: 3,
            helper: 2,
            accumulators: [
                add(linkage[acc::INPUT_ACC], width)?,
                add(linkage[acc::MONOMIAL_PRODUCT], width)?,
                linkage[acc::EXTERNAL_INPUT],
                linkage[acc::OUTPUT_ACC],
            ],
            monomial: ev,
            final_coefficients: co,
            final_evaluations: ev,
            final_key: 1,
            final_input: 2,
            final_borrows: 3,
            final_helper: 2,
        })
    }
}
impl<P> Parameters<'_, P> {
    /// Reject an exposed finite lifetime below the complete per-source schedule.
    /// Logical geometry and expected roots are validated separately.
    pub fn check_opening_limits<F, H>(&self, config: &Config) -> Result<(), Error>
    where
        F: NTTField + Serialize,
        H: Hash + Send + Sync,
        P: CanonicalPcs<F, H>,
    {
        let b = config.canonical_opening_budget(self.coefficients.width())?;
        for (role, pp, needed) in [
            ("coefficients", self.coefficients, b.coefficients),
            ("evaluations", self.evaluations, b.evaluations),
            ("native key", self.key, b.key),
            ("inputs", self.inputs, b.inputs),
            ("borrows", self.borrows, b.borrows),
            ("helper", self.helper, b.helper),
            ("accumulator input", self.accumulators[0], b.accumulators[0]),
            ("monomial product", self.accumulators[1], b.accumulators[1]),
            ("external input", self.accumulators[2], b.accumulators[2]),
            (
                "accumulator output",
                self.accumulators[3],
                b.accumulators[3],
            ),
            ("monomial", self.monomial, b.monomial),
            (
                "final coefficients",
                self.final_stage.coefficients,
                b.final_coefficients,
            ),
            (
                "final evaluations",
                self.final_stage.evaluations,
                b.final_evaluations,
            ),
            ("final key", self.final_stage.key, b.final_key),
            ("final input", self.final_stage.input, b.final_input),
            ("final borrows", self.final_stage.borrows, b.final_borrows),
            ("final helper", self.final_stage.helper, b.final_helper),
        ] {
            if let Some(limit) = pp.opening_limit() {
                if limit < needed {
                    return Err(convert(format!(
                        "canonical opening allowance for {role}: required {needed}, configured {limit}"
                    )));
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_schedule_includes_shift_and_monomial_queries() {
        for width in [4, 8] {
            let cfg = Config::new::<algebra::Goldilocks>(1024, 728, 8, 5, 1, 1).unwrap();
            let b = cfg.canonical_opening_budget(width).unwrap();
            assert_eq!(b.accumulators, [width + 13, width + 1, 3, 2]);
            assert_eq!(
                (
                    b.coefficients,
                    b.evaluations,
                    b.key,
                    b.inputs,
                    b.borrows,
                    b.helper
                ),
                (width + 2, width + 1, 1, 2, 3, 2)
            );
            assert_eq!(
                (
                    b.final_coefficients,
                    b.final_evaluations,
                    b.final_key,
                    b.final_input,
                    b.final_borrows,
                    b.final_helper
                ),
                (width + 2, width + 1, 1, 2, 3, 2)
            );
            let small = Config::new::<algebra::Goldilocks>(32, 21, 8, 5, 1, 1)
                .unwrap()
                .canonical_opening_budget(width)
                .unwrap();
            assert_eq!(small.accumulators[0], width + 8);
        }
    }
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    type P = pcs::matrix_weighted::masked_polyfrim::joint::Parameters<F, E>;
    fn parameters(p: &[P]) -> Parameters<'_, P> {
        Parameters {
            coefficients: &p[0],
            evaluations: &p[1],
            key: &p[2],
            inputs: &p[3],
            borrows: &p[4],
            helper: &p[5],
            accumulators: [&p[6], &p[7], &p[8], &p[9]],
            monomial: &p[10],
            final_stage: final_stage::Parameters {
                coefficients: &p[11],
                evaluations: &p[12],
                key: &p[13],
                input: &p[14],
                borrows: &p[15],
                helper: &p[16],
            },
        }
    }
    #[test]
    fn each_finite_role_rejects_an_insufficient_declared_allowance() {
        let cfg = Config::new::<F>(1024, 728, 8, 5, 1, 1).unwrap();
        let b = cfg.canonical_opening_budget(4).unwrap();
        let required = [
            b.coefficients,
            b.evaluations,
            b.key,
            b.inputs,
            b.borrows,
            b.helper,
            b.accumulators[0],
            b.accumulators[1],
            b.accumulators[2],
            b.accumulators[3],
            b.monomial,
            b.final_coefficients,
            b.final_evaluations,
            b.final_key,
            b.final_input,
            b.final_borrows,
            b.final_helper,
        ];
        // Resource checking is intentionally separate from logical geometry and
        // native key setup. Small real masked parameters avoid any commitments.
        let exact: Vec<_> = required
            .iter()
            .map(|&n| P::new(1, 4, 14, 2, 1, n).unwrap())
            .collect();
        parameters(&exact)
            .check_opening_limits::<F, sha2::Sha256>(&cfg)
            .unwrap();
        for (index, &needed) in required.iter().enumerate().filter(|(_, n)| **n > 1) {
            let mut inadequate = exact.clone();
            inadequate[index] = P::new(1, 4, 14, 2, 1, needed - 1).unwrap();
            let e = parameters(&inadequate)
                .check_opening_limits::<F, sha2::Sha256>(&cfg)
                .unwrap_err();
            assert!(
                e.to_string()
                    .contains(&format!("required {needed}, configured {}", needed - 1))
            );
        }
        let mut copied_small_fixture = exact.clone();
        copied_small_fixture[6] = P::new(1, 4, 14, 2, 1, 12).unwrap();
        assert!(
            parameters(&copied_small_fixture)
                .check_opening_limits::<F, sha2::Sha256>(&cfg)
                .unwrap_err()
                .to_string()
                .contains("accumulator input: required 17, configured 12")
        );
    }
    #[test]
    fn canonical_resource_metadata_tracks_the_same_retained_owner() {
        use algebra::matrix_weighted::{Matrix, MatrixPair, PackedTable};
        use rand::{SeedableRng, rngs::StdRng};
        use sha2::Sha256;
        let pp = P::new(1, 4, 10, 2, 1, 2).unwrap();
        let table = PackedTable::new(1, 4, (0..8).map(F::from).collect()).unwrap();
        let (root, state) = pp
            .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(925))
            .unwrap();
        assert_eq!(CanonicalPcs::<F, Sha256>::opening_limit(&pp), Some(2));
        assert_eq!(
            CanonicalPcs::<F, Sha256>::remaining_openings(&pp, &state).unwrap(),
            Some(2)
        );
        let query = vec![MatrixPair {
            zero: Matrix::identity(4).unwrap(),
            one: Matrix::identity(4).unwrap(),
        }];
        let value = table.evaluate(&query).unwrap();
        let queries = vec![query.clone(), query];
        let values = vec![value.clone(), value];
        pp.open_many::<Sha256>(
            &mut Transcript::new_direct(),
            &root,
            &state,
            &queries,
            &values,
        )
        .unwrap();
        assert_eq!(
            CanonicalPcs::<F, Sha256>::remaining_openings(&pp, &state).unwrap(),
            Some(0)
        );
        assert_eq!(
            CanonicalPcs::<F, Sha256>::remaining_openings(pp.independent_parameters(), &state)
                .unwrap(),
            Some(0)
        );
    }
}

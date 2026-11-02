from fractions import Fraction as F
import unittest

from classical_hazard_work import affine_hazard_work_bound, field_sampler_hazard, native_sampler_hazard, joint_oracle_hazard, joint_hazard_work_report
from classical_work_cost import exact_rational


class HazardWorkTests(unittest.TestCase):
    def test_joint_native_sampler_uses_disjoint_opportunities_and_never_lookup(self):
        from classical_candidate_terms import candidate_terms
        from test_classical_candidate_terms import native
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for version in (4, 5):
                for backend in range(5):
                    candidate = candidate_terms(native(backend, prime, degree, width, version))
                    sampler = native_sampler_hazard(candidate, fresh_xof_inputs_per_step=17)
                    field, column = map(exact_rational, (sampler['field_local_bound'], sampler['column_local_bound']))
                    if version == 4 and backend == 0:
                        geometry = sampler['column_geometry']
                        n = geometry['domain']
                        q = geometry['ordered_draws']
                        retries = geometry['rejected_candidate_limit']
                        maximum = 2**64-1
                        cutoff = maximum-maximum % n
                        self.assertEqual(column, min(F(1), q*F(2**64-cutoff, 2**64)**retries))
                        self.assertGreater(column, 0)
                    else:
                        self.assertEqual(column, 0)
                    self.assertEqual(exact_rational(sampler['constant']), 17*max(field, column))
                    self.assertFalse(sampler['automatic_lookup_stop_charge'])
                    result = joint_hazard_work_report(oracle_hazard=self.oracle(),
                        sampler_hazard=sampler, remaining_constant=1, remaining_slope=0)
                    self.assertEqual(result['automatic_column_stop_charge'], version == 4 and backend == 0)
                    self.assertEqual(exact_rational(result['expected_work_per_success_bound']), 1)
                    with self.assertRaises(ValueError):
                        joint_hazard_work_report(oracle_hazard=self.oracle(),
                            sampler_hazard=sampler, field_hazard=sampler,
                            remaining_constant=0, remaining_slope=0)
        with self.assertRaises(ValueError):
            native_sampler_hazard(candidate, fresh_xof_inputs_per_step=True)

    def test_native_field_first_input_hazard_across_twenty_profiles(self):
        from classical_candidate_terms import candidate_terms
        from test_classical_candidate_terms import native
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for version in (4, 5):
                for backend in range(5):
                    candidate = candidate_terms(native(backend, prime, degree, width, version))
                    envelope = candidate['sampler_resource_envelope']
                    count = envelope['coefficient_count_ceiling']
                    retries = envelope['candidate_limit_per_coefficient']
                    p = int(prime)
                    support = 1 << (p-1).bit_length()
                    expected = min(F(1), count*F(support-p, support)**retries)
                    for batch in (0, 1, 17):
                        row = field_sampler_hazard(prime=p, coefficient_ceiling=count,
                            rejected_candidate_limit=retries, fresh_xof_inputs_per_step=batch)
                        self.assertEqual(exact_rational(row['constant']), batch*expected)
                        self.assertEqual(F(row['slope']), 0)
                        self.assertFalse(row['automatic_column_stop_charge'])
                        self.assertFalse(row['automatic_lookup_stop_charge'])
                        self.assertFalse(row['conditional_hazard_established'])
                        oracle = self.oracle()
                        report = joint_hazard_work_report(oracle_hazard=oracle,
                            field_hazard=row, remaining_constant=1, remaining_slope=0)
                        self.assertEqual(exact_rational(report['hazard_constant']),
                            exact_rational(oracle['constant'])+batch*expected+1)
                        self.assertEqual(exact_rational(report['expected_work_per_success_bound']), 1)
                        self.assertTrue(report['automatic_field_stop_charge'])
                        self.assertFalse(report['automatic_column_stop_charge'])

    def test_field_hazard_rejects_unreviewed_or_inexact_geometry(self):
        args = dict(prime=2013265921, coefficient_ceiling=16,
                    rejected_candidate_limit=8, fresh_xof_inputs_per_step=1)
        for key, value in [('prime', 17), ('prime', True), ('coefficient_ceiling', 2**64),
                ('coefficient_ceiling', -1), ('rejected_candidate_limit', 0),
                ('fresh_xof_inputs_per_step', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                field_sampler_hazard(**dict(args, **{key: value}))
        self.assertEqual(F(field_sampler_hazard(**dict(args, coefficient_ceiling=0))['constant']), 0)

    def oracle(self, **changes):
        caps = dict(hash_answers_per_step=3, xof_answers_per_step=2,
            hash_prior_answers_per_work=4, hash_prior_answer_offset=7,
            xof_prior_answers_per_work=5, xof_prior_answer_offset=11,
            target_windows_per_work=63, target_window_offset=17)
        caps.update(changes)
        return joint_oracle_hazard(**caps)

    def test_batch_hazard_counts_prior_and_internal_pairs_once(self):
        row = self.oracle()
        for j in (1, 2, 19, 2**128):
            windows = 63*j+17
            exposed = 0
            for prior, batch in [(4*j+7, 3), (5*j+11, 2)]:
                for k in range(batch):
                    exposed += windows+prior+k
            self.assertEqual(F(row['constant'])+F(row['slope'])*j, F(exposed, 2**512))
        for key in ('constant', 'slope'):
            self.assertEqual(F(row[key]), sum(F(part[key]) for part in row['components'].values()))

    def test_separate_oracles_and_no_fresh_answers(self):
        row = self.oracle(hash_answers_per_step=1, xof_answers_per_step=1,
            hash_prior_answers_per_work=0, hash_prior_answer_offset=0,
            xof_prior_answers_per_work=0, xof_prior_answer_offset=0,
            target_windows_per_work=0, target_window_offset=0)
        # One answer from each oracle does not create a within-oracle pair.
        self.assertEqual(F(row['constant'])+F(row['slope']), 0)
        row = self.oracle(hash_answers_per_step=0, xof_answers_per_step=0)
        self.assertEqual(F(row['constant'])+F(row['slope']), 0)
        with self.assertRaises(ValueError):
            self.oracle(hash_answers_per_step=True)
        with self.assertRaises(ValueError):
            self.oracle(target_window_offset=-1)

    def test_remaining_hazard_is_mandatory_and_composed_before_work(self):
        oracle = self.oracle()
        with self.assertRaises(TypeError):
            joint_hazard_work_report(oracle_hazard=oracle)
        result = joint_hazard_work_report(oracle_hazard=oracle,
            remaining_constant=F(1, 2**150), remaining_slope=0)
        self.assertEqual(F(result['hazard_constant']), F(oracle['constant'])+F(1, 2**150))
        unknown = joint_hazard_work_report(oracle_hazard=oracle,
            remaining_constant=1, remaining_slope=0)
        self.assertEqual(F(unknown['expected_work_per_success_bound']), 1)
        self.assertFalse(result['remaining_conditional_hazard_established'])
        self.assertFalse(result['security_qualified'])
        with self.assertRaises(ValueError):
            joint_hazard_work_report(oracle_hazard=oracle, remaining_constant=-1, remaining_slope=0)

    def test_monotone_hazard_against_exact_survival_and_stopping_bellman(self):
        for a, b in [(0, F(1, 16)), (F(1, 20), F(1, 40)), (F(2), F(1, 3))]:
            row = affine_hazard_work_bound(constant=a, slope=b)
            bound = F(row['expected_work_per_success_bound'])
            hazards, survival, mean = [], F(1), F(0)
            j = 1
            while survival:
                hazard = min(F(1), a+b*j)
                hazards.append(hazard)
                mean += survival
                survival *= 1-hazard
                j += 1
            self.assertLessEqual(bound, mean)
            # Exact backward induction permits stopping at every history.
            # Choosing a smaller success hazard is also allowed; the objective
            # is affine in it, so checking both endpoints covers that choice.
            value = F(0)
            for hazard in reversed(hazards):
                value = max(F(0), -1+value, -1+hazard*bound+(1-hazard)*value)
            self.assertEqual(value, 0)
            self.assertFalse(row['success_probability_lower_bound_required'])

    def test_rare_randomized_retry_branches_do_not_require_a_success_floor(self):
        row = affine_hazard_work_bound(constant=0, slope=F(1, 8))
        bound = F(row['expected_work_per_success_bound'])
        for cutoff in range(1, 9):
            survival, cost = F(1), F(0)
            for j in range(1, cutoff+1):
                cost += survival
                survival *= 1-F(j, 8)
            for participate in (F(1), F(1, 7), F(1, 2**256)):
                self.assertGreaterEqual(participate*cost/(participate*(1-survival)), bound)

    def test_large_security_scale_is_exact_without_enumerating_steps(self):
        n = 2**256
        row = affine_hazard_work_bound(constant='0', slope=F(1, n))
        self.assertGreater(F(row['expected_work_per_success_bound']), 2**127)
        self.assertFalse(row['conditional_hazard_established'])
        self.assertFalse(row['security_qualified'])

    def test_constant_hazard_and_invalid_inputs(self):
        self.assertEqual(F(affine_hazard_work_bound(constant=F(1, 17), slope=0)[
            'expected_work_per_success_bound']), 17)
        self.assertEqual(F(affine_hazard_work_bound(constant=2, slope=0)[
            'expected_work_per_success_bound']), 1)
        for a, b in [(0, 0), (-1, 1), (1, -1), (True, 1), (0.1, 1)]:
            with self.assertRaises(ValueError):
                affine_hazard_work_bound(constant=a, slope=b)


if __name__ == '__main__':
    unittest.main()

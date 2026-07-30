#!/usr/bin/env python3

import fractions
import json
import math
import pathlib
import statistics
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import paired_stats


class PairedStatsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_path = pathlib.Path(__file__).parent / "fixtures" / "paired-stats-v1.json"
        cls.fixture = json.loads(fixture_path.read_text())

    def test_splitmix64_contract_prefix(self):
        state = paired_stats.BOOTSTRAP_SEED
        actual = []
        for _ in range(8):
            state, value = paired_stats.splitmix64(state)
            actual.append(f"0x{value:016x}")
        self.assertEqual(actual, self.fixture["splitmix64_prefix"])

    def test_golden_bootstrap_bits(self):
        result = paired_stats.paired_bootstrap(self.fixture["ratios"])
        self.assertEqual(result.first_indices, tuple(self.fixture["first_indices"]))
        self.assertEqual(result.accepted_indices, self.fixture["draws"] * len(self.fixture["ratios"]))
        self.assertEqual(result.rejected_outputs, 0)
        self.assertEqual(result.prng_id, "splitmix64-v1")
        self.assertEqual(result.sampler_id, "u64-rejection-mod-v1")
        self.assertEqual(result.seed_hex, self.fixture["seed"])
        self.assertEqual(result.median_rule, "sorted-binary64-middle-or-middle-mean-v1")
        self.assertEqual(result.quantile_rule, "nearest-rank-v1")
        self.assertEqual(
            [
                struct.pack(">d", value).hex()
                for value in (
                    result.two_sided_lower,
                    result.two_sided_upper,
                    result.one_sided_upper,
                )
            ],
            self.fixture["bound_binary64_be"],
        )

    def test_sign_test_removes_ties(self):
        self.assertEqual(
            paired_stats.exact_one_sided_sign_probability(7, 8),
            fractions.Fraction(9, 256),
        )

    def test_exact_probability_json_preserves_the_rational_authority(self):
        self.assertEqual(
            paired_stats.exact_probability_json(fractions.Fraction(9, 256)),
            {"numerator": 9, "denominator": 256, "probability": 9 / 256},
        )

    def test_resolution_preserves_controller_formula(self):
        result = paired_stats.ratio_resolution([0.91, 0.93, 0.94, 0.96])
        expected = 1.6448536269514722 * statistics.stdev(
            [0.91, 0.93, 0.94, 0.96]
        ) / math.sqrt(4)
        self.assertEqual(result["formula"], "normal-one-sided-ratio-sd-v1")
        self.assertEqual(result["resolution_fraction"], expected)
        self.assertEqual(result["smallest_resolvable_improvement_ratio"], 1 - expected)

    def test_rejection_index_rejects_zero_population(self):
        with self.assertRaisesRegex(ValueError, "population must be positive"):
            paired_stats.rejection_index(paired_stats.BOOTSTRAP_SEED, 0)

    def test_paired_bootstrap_rejects_empty_population(self):
        with self.assertRaisesRegex(ValueError, "ratios must not be empty"):
            paired_stats.paired_bootstrap([])

    def test_binary64_median_handles_odd_and_even_populations(self):
        self.assertEqual(paired_stats.median_binary64([3.0, 1.0, 2.0]), 2.0)
        self.assertEqual(paired_stats.median_binary64([4.0, 1.0, 3.0, 2.0]), 2.5)
        with self.assertRaisesRegex(ValueError, "values must not be empty"):
            paired_stats.median_binary64([])

    def test_nearest_rank_includes_endpoints(self):
        values = [3.0, 1.0, 2.0]
        self.assertEqual(paired_stats.nearest_rank(values, 0.0), 1.0)
        self.assertEqual(paired_stats.nearest_rank(values, 1.0), 3.0)

    def test_nearest_rank_rejects_invalid_probability(self):
        for probability in (-0.01, 1.01, math.nan):
            with self.subTest(probability=probability):
                with self.assertRaisesRegex(ValueError, "probability"):
                    paired_stats.nearest_rank([1.0], probability)

    def test_paired_bootstrap_rejects_seed_outside_u64(self):
        for seed in (-1, paired_stats.MASK64 + 1):
            with self.subTest(seed=seed):
                with self.assertRaisesRegex(ValueError, "unsigned 64-bit"):
                    paired_stats.paired_bootstrap([1.0], seed=seed)

    def test_sign_test_rejects_invalid_or_oversized_counts(self):
        for wins, trials in ((2, 1), (0, 128)):
            with self.subTest(wins=wins, trials=trials):
                with self.assertRaisesRegex(ValueError, "sign-test counts are invalid"):
                    paired_stats.exact_one_sided_sign_probability(wins, trials)


if __name__ == "__main__":
    unittest.main()

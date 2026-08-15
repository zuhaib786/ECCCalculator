from __future__ import annotations

import json
import unittest

from crypto_lab.metrics import TraceCollector
from crypto_lab.number_theory import mod_pow
from ecc_factor import factorize


class TraceMetricsTests(unittest.TestCase):
    def test_collects_both_trace_event_families(self) -> None:
        collector = TraceCollector()
        mod_pow(4, 13, 497, trace=collector)
        factorize(91, progress=collector)
        self.assertGreater(collector.total_operations, 2)
        self.assertIn("modpow.bit", collector.counts)
        self.assertIn("factor.complete", collector.counts)
        records = [json.loads(line) for line in collector.to_jsonl().splitlines()]
        self.assertEqual(records[0]["code"], "modpow.bit")

    def test_level_filter_still_counts_hidden_events(self) -> None:
        collector = TraceCollector(max_level=1)
        mod_pow(4, 13, 497, trace=collector)
        self.assertEqual(collector.counts["modpow.bit"], 4)
        self.assertNotIn("modpow.bit", [event.code for event in collector.events])


if __name__ == "__main__":
    unittest.main()


from __future__ import annotations

import unittest

from tooling.gpt_guardrails.cost import (
    actual_chat_request_cost,
    estimate_chat_request_cost,
    resolve_chat_pricing_model,
    safe_actual_chat_request_cost,
    safe_estimate_chat_request_cost,
)


class CostPricingResolutionTests(unittest.TestCase):
    def test_current_gpt54_mini_pricing_is_resolved_exactly(self) -> None:
        self.assertEqual(resolve_chat_pricing_model("gpt-5.4-mini"), "gpt-5.4-mini")
        self.assertAlmostEqual(
            estimate_chat_request_cost("gpt-5.4-mini", 1000, 2000),
            0.00075 + (2 * 0.0045),
        )
        self.assertAlmostEqual(
            actual_chat_request_cost("gpt-5.4-mini", 1200, 800),
            (1.2 * 0.00075) + (0.8 * 0.0045),
        )

    def test_safe_cost_helpers_return_none_for_unknown_model(self) -> None:
        self.assertIsNone(safe_estimate_chat_request_cost("totally-unknown-model", 1000, 1000))
        self.assertIsNone(safe_actual_chat_request_cost("totally-unknown-model", 1000, 1000))

    def test_dated_model_ids_map_to_current_table_keys(self) -> None:
        self.assertEqual(resolve_chat_pricing_model("gpt-4o-mini-2024-07-18"), "gpt-4o-mini")
        self.assertEqual(resolve_chat_pricing_model("chat-latest"), "chat-latest")


if __name__ == "__main__":
    unittest.main()

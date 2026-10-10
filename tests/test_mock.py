import unittest
from threading import Event
from adf_runtime_worker.adapters import MockAdapter, Request

class MockContractTests(unittest.TestCase):
    def test_cancel_prevents_start_and_usage_is_unknown(self) -> None:
        cancellation = Event()
        cancellation.set()
        events: list[str] = []
        adapter = MockAdapter()
        result = adapter.execute(Request("e", "r", 1), lambda kind, payload: events.append(kind), cancellation)
        self.assertEqual(result, "cancelled")
        self.assertEqual(events, ["cancelled"])
        self.assertIsNone(adapter.collect_usage().cost)
    def test_normalized_sequence(self) -> None:
        events: list[str] = []
        MockAdapter().execute(Request("e", "r", 1), lambda kind, payload: events.append(kind), Event())
        self.assertEqual(events, ["started", "completed"])

from threading import Event
import unittest
from adf_runtime_worker.adapters import MockAdapter, Request

class MockTests(unittest.TestCase):
    def test_unknown_usage_and_completion(self):
        events = []
        adapter = MockAdapter()
        result = adapter.execute(Request("execution", "run", 1), lambda kind, payload: events.append(kind), Event())
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(events, ["started", "completed"])
        self.assertIsNone(adapter.collect_usage().cost)

    def test_precancelled_has_no_start(self):
        cancellation = Event()
        cancellation.set()
        events = []
        result = MockAdapter().execute(Request("execution", "run", 1), lambda kind, payload: events.append(kind), cancellation)
        self.assertEqual(result.status, "cancelled")
        self.assertEqual(events, ["cancelled"])

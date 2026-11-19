import time
import unittest
from unittest.mock import patch
from packetlens.capture import Worker
from .fixtures import frame


class FakeCapture:
    linktype = 1
    warning = ""

    def __init__(self, *args, **kwargs):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def read(self):
        return None

    def statistics(self):
        return {"kernel_dropped": 0}


class BusyCapture(FakeCapture):
    def read(self):
        return (1, frame(), 54)


class LifecycleTests(unittest.TestCase):
    @patch("packetlens.capture.ProcessMap.refresh")
    def test_idle_stop_closes_handle(self, _):
        cap = FakeCapture()
        with patch("packetlens.capture.Capture", return_value=cap):
            w = Worker("fake")
            w.start()
            self.assertTrue(w.ready.wait(1))
            w.stop()
            w.thread.join(1)
        self.assertFalse(w.thread.is_alive())
        self.assertTrue(cap.closed)

    @patch("packetlens.capture.ProcessMap.refresh")
    def test_full_queue_still_stops(self, _):
        cap = BusyCapture()
        with patch("packetlens.capture.Capture", return_value=cap):
            w = Worker("fake")
            w.start()
            w.ready.wait(1)
            deadline = time.monotonic() + 2
            while not w.queue_dropped and time.monotonic() < deadline:
                time.sleep(0.01)
            w.stop()
            w.thread.join(1)
        self.assertGreater(w.queue_dropped, 0)
        self.assertLessEqual(w.queue.qsize(), 256)
        self.assertTrue(cap.closed)
        self.assertFalse(w.thread.is_alive())

    def test_permission_failure_is_reported(self):
        with patch(
            "packetlens.capture.Capture", side_effect=PermissionError("capture denied")
        ):
            w = Worker("fake")
            w.start()
            w.thread.join(1)
        self.assertIn("capture denied", w.error)
        self.assertTrue(w.ready.is_set())

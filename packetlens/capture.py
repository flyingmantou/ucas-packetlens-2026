"""Capture worker owns native handle; GUI consumes a bounded queue."""

import queue
import threading
import time
from .pcap import Capture
from .decode import decode
from .processes import ProcessMap


class Worker:
    def __init__(self, interface, bpf="", promiscuous=False):
        self.interface = interface
        self.bpf = bpf
        self.promiscuous = promiscuous
        self.queue = queue.Queue(maxsize=256)
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.stats = {}
        self.error = ""
        self.status = "准备抓包"
        self.queue_dropped = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def run(self):
        processes = ProcessMap()
        try:
            with Capture(self.interface, self.bpf, self.promiscuous) as cap:
                self.status = "正在实时抓包"
                self.ready.set()
                while not self.stop_event.is_set():
                    if time.monotonic() - processes.updated > processes.refresh_interval:
                        processes.refresh()
                    item = cap.read()
                    if item is None:
                        self.stop_event.wait(0.01)
                        continue
                    ts, raw, wire = item
                    p = decode(ts, raw, wire, cap.linktype)
                    processes.attach(p)
                    try:
                        self.queue.put_nowait(p)
                    except queue.Full:
                        self.queue_dropped += 1
                self.stats = cap.statistics()
                self.stats["process_status"] = processes.status
        except Exception as e:
            self.error = str(e)
            self.status = "抓包失败"
        finally:
            self.stats["queue_dropped"] = self.queue_dropped
            self.ready.set()
            if not self.error:
                self.status = "已停止"

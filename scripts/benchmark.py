"""Fixed-seed offline workload; reports actual local measurements, not wire rate."""

import json, platform, statistics, sys, time, tracemalloc
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from tests.fixtures import demo_frames
from packetlens.decode import decode
from packetlens.filters import compile_filter
from packetlens.streams import StreamTable

frames = demo_frames()
count = 5000
times = []
for trial in range(5):
    start = time.perf_counter()
    table = StreamTable()
    fn = compile_filter("tcp and not tls")
    matches = 0
    for i in range(count):
        p = decode(i * 0.001, frames[i % len(frames)])
        table.add(p)
        matches += bool(fn(p))
    times.append(time.perf_counter() - start)
record = {
    "platform": platform.platform(),
    "kind": "offline decode + display filter + stream indexing; excludes GUI and reassembly rendering",
    "packets_per_trial": count,
    "trials_seconds": times,
    "median_seconds": statistics.median(times),
    "median_packets_per_second": round(count / statistics.median(times)),
    "matched": matches,
    "fixture": f"{len(frames)} deterministic course-demo frames repeated in fixed order",
}
(root / "evidence/benchmark.json").write_text(
    json.dumps(record, indent=2), encoding="utf-8"
)
print(json.dumps(record, indent=2))

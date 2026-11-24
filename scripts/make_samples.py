import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.fixtures import demo_frames
from packetlens.decode import decode
from packetlens.files import write_pcap

root = Path(__file__).resolve().parents[1]
frames = demo_frames()
write_pcap(
    root / "samples/course-demo.pcap",
    [decode(1795046400 + i * 0.05, b) for i, b in enumerate(frames)],
)
print(f"Generated {len(frames)} synthetic packets (HTTP/DNS/ICMP/IPv6/TLS); no third-party traffic.")

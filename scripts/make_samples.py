import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tests.fixtures import demo_frames
from packetlens.decode import decode
from packetlens.files import write_pcap
root=Path(__file__).resolve().parents[1]
write_pcap(root/'samples/course-demo.pcap',[decode(1795046400+i*.05,b) for i,b in enumerate(demo_frames())])
print('Generated 16 synthetic packets; no third-party traffic.')

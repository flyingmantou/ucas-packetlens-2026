"""Classic PCAP I/O with size and record bounds."""

import struct
from .decode import decode

MAX_BYTES = 64 * 1024 * 1024
MAX_PACKETS = 5000


def read_pcap(path):
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("PCAP 文件头截断")
        modes = {
            b"\xd4\xc3\xb2\xa1": ("<", 1e6),
            b"\xa1\xb2\xc3\xd4": (">", 1e6),
            b"\x4d\x3c\xb2\xa1": ("<", 1e9),
            b"\xa1\xb2\x3c\x4d": (">", 1e9),
        }
        if header[:4] not in modes:
            raise ValueError("仅支持经典 PCAP，请将 pcapng 转换为 pcap")
        endian, scale = modes[header[:4]]
        major, minor, zone, sig, snap, link = struct.unpack(
            endian + "HHiIII", header[4:]
        )
        if (major, minor) != (2, 4) or not 0 < snap <= 65535:
            raise ValueError("不支持的 PCAP 版本或快照长度")
        packets = []
        size = 0
        while True:
            hdr = f.read(16)
            if not hdr:
                break
            if len(hdr) != 16:
                raise ValueError("PCAP 记录头截断")
            sec, frac, cap, wire = struct.unpack(endian + "IIII", hdr)
            if cap > snap or cap > wire or frac >= scale:
                raise ValueError("PCAP 记录长度或时间非法")
            size += cap
            if size > MAX_BYTES or len(packets) >= MAX_PACKETS:
                raise ValueError("文件超过 5000 包或 64 MiB 限制")
            raw = f.read(cap)
            if len(raw) != cap:
                raise ValueError("PCAP 记录数据截断")
            packets.append(
                decode(sec + frac / scale, raw, wire, link, len(packets) + 1)
            )
        return packets


def write_pcap(path, packets, linktype=None):
    packets = list(packets)
    link = linktype if linktype is not None else packets[0].linktype if packets else 1
    if any(p.linktype != link for p in packets):
        raise ValueError("PCAP 不能混合链路类型")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link))
        for p in packets:
            sec = int(p.timestamp)
            micro = int((p.timestamp - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, micro, len(p.raw), p.wirelen))
            f.write(p.raw)

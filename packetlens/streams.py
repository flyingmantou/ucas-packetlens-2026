"""Directional TCP sequence reconstruction, flow timelines, and TLS metadata."""

from dataclasses import dataclass, field
from .decode import format_tcp_flags


@dataclass
class Direction:
    anchor: object = None
    segments: list = field(default_factory=list)
    stored: int = 0
    omitted: int = 0

    def add(self, p):
        start = (p.seq + (1 if p.flags & 2 else 0)) & 0xFFFFFFFF
        if self.anchor is None:
            self.anchor = start
        if not p.payload:
            return
        if self.stored + len(p.payload) > 262144:
            self.omitted += len(p.payload)
            return
        offset = ((start - self.anchor + 2**31) % 2**32) - 2**31
        self.segments.append((offset, p.payload))
        self.stored += len(p.payload)

    def reconstruct(self):
        cells = {}
        duplicates = 0
        conflicts = 0
        # First observation wins. Sorting only after resolving overlaps preserves policy.
        for offset, data in self.segments:
            for j, b in enumerate(data):
                pos = offset + j
                if pos in cells:
                    duplicates += 1
                    conflicts += cells[pos] != b
                else:
                    cells[pos] = b
        chunks = []
        gaps = []
        start = None
        last = None
        buf = bytearray()
        for pos in sorted(cells):
            if last is not None and pos != last + 1:
                chunks.append((start, bytes(buf)))
                buf.clear()
                gaps.append((last + 1, pos))
                start = None
            if start is None:
                start = pos
            buf.append(cells[pos])
            last = pos
        if buf:
            chunks.append((start, bytes(buf)))
        return {
            "chunks": chunks,
            "gaps": gaps,
            "duplicate_bytes": duplicates,
            "conflict_bytes": conflicts,
            "omitted_bytes": self.omitted,
        }


@dataclass
class Stream:
    id: int
    key: tuple
    directions: dict = field(default_factory=dict)
    packets: int = 0
    wire_bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    first_packet_no: int = 0
    syn: object = None
    client_endpoint: object = None
    server_endpoint: object = None
    pids: set = field(default_factory=set)
    process_names: dict = field(default_factory=dict)
    has_http: bool = False
    has_tls: bool = False
    tls_sni: str = ""
    tls_alpn: list = field(default_factory=list)
    tls_ja3: str = ""
    tls_version: str = ""
    timeline: list = field(default_factory=list)

    def add(self, p):
        p.stream = self.id
        self.packets += 1
        self.wire_bytes += p.wirelen
        if self.packets == 1:
            self.first = p.timestamp
            self.first_packet_no = p.number
            self.client_endpoint = (p.src, p.sport)
            self.server_endpoint = (p.dst, p.dport)
        self.last = p.timestamp
        if p.pid is not None:
            self.pids.add(p.pid)
            if p.process:
                self.process_names[p.pid] = p.process
        if p.flags & 2 and not p.flags & 16:
            self.syn = (p.src, p.sport, p.seq)
            self.client_endpoint = (p.src, p.sport)
            self.server_endpoint = (p.dst, p.dport)
        if "http" in p.layers:
            self.has_http = True

        dir_idx = 0 if (p.src, p.sport) == self.client_endpoint else 1
        if "tls" in p.layers:
            self.has_tls = True
            if p.sni:
                self.tls_sni = p.sni
            if p.alpn:
                self.tls_alpn = list(p.alpn)
            if p.ja3:
                self.tls_ja3 = p.ja3
            if p.tls_version:
                self.tls_version = p.tls_version
            tls_det = p.details.get("TLS", {})
            if "ClientHello" in str(tls_det.get("handshake", "")):
                self.client_endpoint = (p.src, p.sport)
                self.server_endpoint = (p.dst, p.dport)
                dir_idx = 0

        direction = (p.src, p.sport, p.dst, p.dport)
        self.directions.setdefault(direction, Direction()).add(p)

        if len(self.timeline) < 120:
            self.timeline.append(
                {
                    "no": p.number,
                    "rel_time": p.timestamp - self.first,
                    "dir": dir_idx,
                    "protocol": p.protocol,
                    "flags": format_tcp_flags(p.flags),
                    "payload_len": len(p.payload),
                    "info": p.info,
                }
            )

    @property
    def protocol_label(self):
        if self.has_tls:
            version = self.tls_version or "TLS"
            return f"{version} ({self.tls_sni})" if self.tls_sni else version
        return "HTTP/1.x" if self.has_http else "TCP"

    def process_label(self):
        if not self.pids:
            return "未知"
        items = []
        for pid in sorted(self.pids):
            name = self.process_names.get(pid, "")
            items.append(f"{name}({pid})" if name else str(pid))
        return ", ".join(items)

    def text(self):
        parts = [
            f"TCP stream {self.id} | packets={self.packets} bytes={self.wire_bytes} | protocol={self.protocol_label} | process={self.process_label()}"
        ]
        if self.tls_sni or self.tls_ja3:
            parts.append(
                f"TLS Meta: version={self.tls_version or '未知'}, SNI={self.tls_sni or '无'}, ALPN={','.join(self.tls_alpn) or '无'}, JA3={self.tls_ja3 or '无'}"
            )
        for direction, d in self.directions.items():
            r = d.reconstruct()
            parts.append(
                f"\n{direction[0]}:{direction[1]} → {direction[2]}:{direction[3]}"
            )
            parts.append(
                f'duplicate_bytes={r["duplicate_bytes"]}, conflict_bytes={r["conflict_bytes"]}, omitted_bytes={r["omitted_bytes"]}'
            )
            previous = None
            for start, data in r["chunks"]:
                if previous is not None:
                    parts.append(f"\n[缺失 {start-previous} 字节，未拼接]\n")
                parts.append(data.decode("utf-8", "replace"))
                previous = start + len(data)
        return "\n".join(parts)


class StreamTable:
    def __init__(self):
        self.streams = []
        self.current = {}

    def add(self, p):
        if "tcp" not in p.layers:
            return
        s = self.current.get(p.key)
        syn = (p.src, p.sport, p.seq)
        if s is None or (
            p.flags & 2 and not p.flags & 16 and s.syn is not None and s.syn != syn
        ):
            s = Stream(len(self.streams), p.key)
            self.streams.append(s)
            self.current[p.key] = s
        s.add(p)

    def process_summary(self):
        """Aggregate all TCP streams by PID for OS Process Tracing view."""
        groups = {}
        for s in self.streams:
            pids = sorted(s.pids) if s.pids else [None]
            for pid in pids:
                name = s.process_names.get(pid, "未知进程") if pid is not None else "未知 / 离线 PCAP"
                entry = groups.setdefault(
                    pid,
                    {
                        "pid": pid,
                        "name": name,
                        "stream_ids": [],
                        "packets": 0,
                        "bytes": 0,
                        "protocols": set(),
                    },
                )
                entry["stream_ids"].append(s.id)
                entry["packets"] += s.packets
                entry["bytes"] += s.wire_bytes
                entry["protocols"].add(s.protocol_label)
        return sorted(
            groups.values(),
            key=lambda x: (x["pid"] is None, -(x["bytes"])),
        )

"""Bounded, defensive decoding. No native dissector is used."""

from dataclasses import dataclass, field
import ipaddress
import re
import struct


@dataclass
class Packet:
    timestamp: float
    raw: bytes
    wirelen: int
    linktype: int = 1
    number: int = 0
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    protocol: str = "UNKNOWN"
    layers: set = field(default_factory=set)
    details: dict = field(default_factory=dict)
    payload: bytes = b""
    seq: int = 0
    flags: int = 0
    stream: int = -1
    pid: object = None
    process: str = ""
    warning: str = ""
    info: str = ""

    @property
    def key(self):
        return tuple(sorted(((self.src, self.sport), (self.dst, self.dport))))


def dns_name(data, pos):
    labels = []
    seen = set()
    end = None
    for _ in range(128):
        if pos >= len(data) or pos in seen:
            raise ValueError("DNS 名称越界或压缩指针循环")
        seen.add(pos)
        n = data[pos]
        pos += 1
        if n == 0:
            return ".".join(labels), end if end is not None else pos
        if n & 0xC0 == 0xC0:
            if pos >= len(data):
                raise ValueError("DNS 指针截断")
            if end is None:
                end = pos + 1
            pos = ((n & 63) << 8) | data[pos]
            continue
        if n > 63 or pos + n > len(data):
            raise ValueError("DNS 标签非法")
        labels.append(data[pos : pos + n].decode("ascii", "replace"))
        pos += n
    raise ValueError("DNS 名称过深")


def application(p):
    data = p.payload
    if "tcp" in p.layers and re.match(
        rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n]{1,2048} HTTP/1\.[01]\r\n|HTTP/1\.[01] [0-9]{3} ",
        data,
    ):
        p.layers.add("http")
        p.protocol = "HTTP"
        head = data.split(b"\r\n\r\n", 1)[0][:8192].decode("utf-8", "replace")
        p.details["HTTP"] = head
        p.info = head.split("\r\n")[0]
    elif "udp" in p.layers and 53 in (p.sport, p.dport) and len(data) >= 12:
        ident, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
        if qd > 64 or an + ns + ar > 256:
            raise ValueError("DNS 记录数量超限")
        pos = 12
        questions = []
        for _ in range(qd):
            name, pos = dns_name(data, pos)
            if pos + 4 > len(data):
                raise ValueError("DNS 问题截断")
            typ, cls = struct.unpack_from("!HH", data, pos)
            pos += 4
            questions.append({"name": name, "type": typ, "class": cls})
        answers = []
        for i in range(an + ns + ar):
            name, pos = dns_name(data, pos)
            if pos + 10 > len(data):
                raise ValueError("DNS 资源记录截断")
            typ, cls, ttl, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if pos + size > len(data):
                raise ValueError("DNS 资源数据截断")
            value = data[pos : pos + size].hex()
            if (typ, size) in ((1, 4), (28, 16)):
                value = str(ipaddress.ip_address(data[pos : pos + size]))
            elif typ in (2, 5, 12):
                value = dns_name(data, pos)[0]
            if i < an:
                answers.append({"name": name, "type": typ, "ttl": ttl, "value": value})
            pos += size
        p.protocol = "DNS"
        p.layers.add("dns")
        p.details["DNS"] = {
            "id": ident,
            "response": bool(flags & 0x8000),
            "rcode": flags & 15,
            "questions": questions,
            "answers": answers,
        }
        p.info = ("response " if flags & 0x8000 else "query ") + ", ".join(
            q["name"] for q in questions
        )
    elif (
        "tcp" in p.layers
        and len(data) >= 5
        and data[0] in (20, 21, 22, 23)
        and data[1] == 3
        and data[2] <= 4
    ):
        length = int.from_bytes(data[3:5], "big")
        if length > 18432:
            return
        p.layers.add("tls")
        p.protocol = "TLS"
        p.details["TLS"] = {
            "record_type": data[0],
            "legacy_version": data[1:3].hex(),
            "record_length": length,
            "complete_record": len(data) >= length + 5,
            "note": "仅显示密文记录元数据，不解密 HTTPS",
        }
        p.info = f"TLS record type={data[0]}, length={length}"


def decode(timestamp, raw, wirelen=None, linktype=1, number=0):
    p = Packet(
        timestamp, raw, len(raw) if wirelen is None else wirelen, linktype, number
    )
    try:
        if len(raw) > 65535:
            raise ValueError("捕获长度超过 65535")

        def need(n, off=0):
            if off + n > len(raw):
                raise ValueError("报文截断")

        off = 0
        etype = 0
        if linktype == 1:
            need(14)
            off = 14
            etype = int.from_bytes(raw[12:14], "big")
            p.layers.add("ethernet")
            p.details["Ethernet"] = {"src": raw[6:12].hex(":"), "dst": raw[:6].hex(":")}
            vlans = []
            while etype in (0x8100, 0x88A8):
                if len(vlans) >= 2:
                    raise ValueError("超过两层 VLAN")
                need(4, off)
                vlans.append(int.from_bytes(raw[off : off + 2], "big") & 4095)
                etype = int.from_bytes(raw[off + 2 : off + 4], "big")
                off += 4
            if vlans:
                p.details["VLAN"] = vlans
        elif linktype in (0, 108):
            need(4)
            fam = int.from_bytes(raw[:4], "big" if linktype == 108 else "little")
            off = 4
            if fam not in (2, 24, 28, 30):
                fam = int.from_bytes(raw[:4], "big")
            etype = 0x800 if fam == 2 else 0x86DD if fam in (24, 28, 30) else 0
            p.details["Loopback"] = {"family": fam}
        elif linktype in (12, 101):
            need(1)
            etype = 0x800 if raw[0] >> 4 == 4 else 0x86DD if raw[0] >> 4 == 6 else 0
        elif linktype == 113:
            need(16)
            etype = int.from_bytes(raw[14:16], "big")
            off = 16
        elif linktype == 276:
            need(20)
            etype = int.from_bytes(raw[:2], "big")
            off = 20
        else:
            raise ValueError(f"不支持链路类型 {linktype}")
        if etype == 0x806:
            need(28, off)
            p.layers.add("arp")
            p.protocol = "ARP"
            hw, pt, hl, pl, op = struct.unpack_from("!HHBBH", raw, off)
            if (hw, pt, hl, pl) != (1, 0x800, 6, 4):
                raise ValueError("暂不支持该 ARP 地址格式")
            p.src = str(ipaddress.ip_address(raw[off + 14 : off + 18]))
            p.dst = str(ipaddress.ip_address(raw[off + 24 : off + 28]))
            p.details["ARP"] = {"operation": op}
            p.info = f"{op}: {p.src} → {p.dst}"
            return p
        if etype == 0x800:
            need(20, off)
            ihl = (raw[off] & 15) * 4
            total = int.from_bytes(raw[off + 2 : off + 4], "big")
            if raw[off] >> 4 != 4 or ihl < 20 or total < ihl:
                raise ValueError("IPv4 首部长度非法")
            need(ihl, off)
            end = min(len(raw), off + total)
            if len(raw) < off + total:
                p.warning = "IPv4 数据被截断"
            p.src = str(ipaddress.ip_address(raw[off + 12 : off + 16]))
            p.dst = str(ipaddress.ip_address(raw[off + 16 : off + 20]))
            proto = raw[off + 9]
            frag = int.from_bytes(raw[off + 6 : off + 8], "big")
            p.layers.update(("ip", "ipv4"))
            p.protocol = "IPv4"
            p.details["IPv4"] = {
                "header_length": ihl,
                "total_length": total,
                "ttl": raw[off + 8],
                "protocol": proto,
                "fragment_offset": (frag & 8191) * 8,
                "more_fragments": bool(frag & 8192),
            }
            off += ihl
            if frag & 8191:
                p.info = "非首片，未重组 IP 分片"
                return p
            fragmented = bool(frag & 8192)
        elif etype == 0x86DD:
            need(40, off)
            if raw[off] >> 4 != 6:
                raise ValueError("IPv6 版本错误")
            length = int.from_bytes(raw[off + 4 : off + 6], "big")
            proto = raw[off + 6]
            end = min(len(raw), off + 40 + length)
            if len(raw) < off + 40 + length:
                p.warning = "IPv6 数据被截断"
            p.src = str(ipaddress.ip_address(raw[off + 8 : off + 24]))
            p.dst = str(ipaddress.ip_address(raw[off + 24 : off + 40]))
            p.layers.update(("ip", "ipv6"))
            p.protocol = "IPv6"
            p.details["IPv6"] = {"payload_length": length, "hop_limit": raw[off + 7]}
            off += 40
            ext = []
            fragmented = False
            while proto in (0, 43, 44, 51, 60):
                if len(ext) >= 8:
                    raise ValueError("IPv6 扩展首部过多")
                if off + 2 > end:
                    raise ValueError("IPv6 扩展首部截断")
                old = proto
                proto = raw[off]
                size = (
                    8
                    if old == 44
                    else (raw[off + 1] + 2) * 4 if old == 51 else (raw[off + 1] + 1) * 8
                )
                if off + size > end:
                    raise ValueError("IPv6 扩展首部长度非法")
                ext.append(old)
                if old == 44:
                    fr = int.from_bytes(raw[off + 2 : off + 4], "big")
                    fragmented = bool(fr & 1)
                    if fr & 0xFFF8:
                        p.info = "非首片，未重组 IPv6 分片"
                        return p
                off += size
            p.details["IPv6"]["extensions"] = ext
        else:
            p.info = f"未知 EtherType 0x{etype:04x}"
            return p
        data = raw[off:end]
        if proto == 6:
            if len(data) < 20:
                raise ValueError("TCP 首部截断")
            p.sport, p.dport, p.seq, ack, offset, p.flags, win, checksum, urgent = (
                struct.unpack("!HHIIBBHHH", data[:20])
            )
            size = (offset >> 4) * 4
            if size < 20 or size > len(data):
                raise ValueError("TCP 数据偏移非法")
            p.protocol = "TCP"
            p.layers.add("tcp")
            p.payload = data[size:]
            p.details["TCP"] = {
                "src_port": p.sport,
                "dst_port": p.dport,
                "seq": p.seq,
                "ack": ack,
                "flags": p.flags,
                "window": win,
                "header_length": size,
                "options_hex": data[20:size].hex(),
            }
            p.info = f"{p.sport} → {p.dport} seq={p.seq} ack={ack} flags=0x{p.flags:02x} data={len(p.payload)}"
        elif proto == 17:
            if len(data) < 8:
                raise ValueError("UDP 首部截断")
            p.sport, p.dport, length, checksum = struct.unpack("!HHHH", data[:8])
            if length < 8:
                raise ValueError("UDP 长度非法")
            if length > len(data) and not fragmented:
                p.warning = "UDP 数据被截断"
            p.protocol = "UDP"
            p.layers.add("udp")
            p.payload = data[8 : min(length, len(data))]
            p.details["UDP"] = {
                "src_port": p.sport,
                "dst_port": p.dport,
                "length": length,
            }
            p.info = f"{p.sport} → {p.dport} data={len(p.payload)}"
        elif proto in (1, 58):
            if len(data) < 4:
                raise ValueError("ICMP 首部截断")
            p.protocol = "ICMPv6" if proto == 58 else "ICMP"
            p.layers.add(p.protocol.lower())
            p.details[p.protocol] = {
                "type": data[0],
                "code": data[1],
                "checksum": data[2:4].hex(),
            }
            p.payload = data[4:]
            p.info = f"type={data[0]} code={data[1]}"
        else:
            p.payload = data
            p.info = f"IP protocol={proto}"
        if fragmented:
            p.warning = "IP 首片，应用解析需要完整报文"
            return p
        application(p)
    except (ValueError, struct.error, IndexError) as e:
        p.warning = str(e)
    return p

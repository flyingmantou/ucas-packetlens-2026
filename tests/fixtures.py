import ipaddress
import struct


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s & 65535) + (s >> 16)
    s = (s & 65535) + (s >> 16)
    return (~s) & 65535


def frame(
    payload=b"",
    proto=6,
    src="10.0.0.1",
    dst="10.0.0.2",
    sport=50000,
    dport=8080,
    seq=100,
    ack=1,
    flags=24,
    ipv6=False,
    fragment=0,
    vlan=False,
):
    a = ipaddress.ip_address(src).packed
    b = ipaddress.ip_address(dst).packed
    if proto == 6:
        body = (
            struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 4096, 0, 0)
            + payload
        )
        pos = 16
    elif proto == 17:
        body = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload
        pos = 6
    else:
        body = payload
        pos = None
    if pos is not None:
        pseudo = (
            a
            + b
            + (
                struct.pack("!I3xB", len(body), proto)
                if ipv6
                else struct.pack("!BBH", 0, proto, len(body))
            )
        )
        c = checksum(pseudo + body)
        body = body[:pos] + struct.pack("!H", c or 65535) + body[pos + 2 :]
    if ipv6:
        header = struct.pack("!IHBB", 6 << 28, len(body), proto, 64) + a + b
        etype = 0x86DD
    else:
        header = (
            struct.pack("!BBHHHBBH", 0x45, 0, len(body) + 20, 1, fragment, 64, proto, 0)
            + a
            + b
        )
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        etype = 0x800
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" + struct.pack(
        "!H", 0x8100 if vlan else etype
    )
    if vlan:
        eth += struct.pack("!HH", 42, etype)
    return eth + header + body


def dns():
    return (
        struct.pack("!6H", 0x1234, 0x100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )


def demo_frames():
    request = b"GET /course HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nPacketLens"
    return [
        frame(flags=2, seq=99, payload=b""),
        frame(request[:9], seq=100),
        frame(request[25:], seq=125),
        frame(request[9:25], seq=109),
        frame(request[9:25], seq=109),
        frame(
            response, src="10.0.0.2", dst="10.0.0.1", sport=8080, dport=50000, seq=900
        ),
        frame(
            b"GET /other HTTP/1.1\r\nHost: example.test\r\n\r\n",
            sport=51000,
            dport=8888,
            seq=1,
        ),
        frame(dns(), proto=17, dport=53),
        frame(b"\x08\x00\x00\x00ping", proto=1),
        frame(
            b"\x80\x00\x00\x00v6",
            proto=58,
            ipv6=True,
            src="2001:db8::1",
            dst="2001:db8::2",
        ),
        frame(b"\x17\x03\x03\x00\x05abcde", dport=443, sport=52000),
        frame(b"vlan packet", proto=17, vlan=True),
        frame(b"this is not HTTP", dport=80, sport=53000),
        frame(b"abc", sport=54000, seq=10),
        frame(b"xyz", sport=54000, seq=20),
        frame(b"damaged")[:25],
    ]

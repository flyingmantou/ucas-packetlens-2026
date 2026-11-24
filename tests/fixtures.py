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


def tls_client_hello(
    sni="www.ucas.ac.cn",
    alpn=("h2", "http/1.1"),
    ciphers=(0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014),
    tls13=True,
):
    exts = bytearray()
    if sni:
        sni_b = sni.encode("ascii")
        sni_entry = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
        sni_ext = struct.pack("!H", len(sni_entry)) + sni_entry
        exts += struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext
    if alpn:
        alpn_body = b"".join(bytes([len(p)]) + p.encode("ascii") for p in alpn)
        alpn_ext = struct.pack("!H", len(alpn_body)) + alpn_body
        exts += struct.pack("!HH", 0x0010, len(alpn_ext)) + alpn_ext
    # Supported groups (x25519, secp256r1)
    grp_body = struct.pack("!HHH", 4, 0x001D, 0x0017)
    exts += struct.pack("!HH", 0x000A, len(grp_body)) + grp_body
    # EC point formats (uncompressed)
    exts += struct.pack("!HHBB", 0x000B, 2, 1, 0)
    if tls13:
        sv = struct.pack("!BHH", 4, 0x0304, 0x0303)
        exts += struct.pack("!HH", 0x002B, len(sv)) + sv

    cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", len(cs_bytes))
        + cs_bytes
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + bytes(exts)
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_server_hello(cipher=0x1301, tls13=True):
    exts = b""
    if tls13:
        exts = struct.pack("!HHH", 0x002B, 2, 0x0304)
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32, 64))
        + b"\x00"
        + struct.pack("!HB", cipher, 0)
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tls_app_record(length):
    return b"\x17\x03\x03" + struct.pack("!H", length) + (b"\xaa" * length)


def demo_frames():
    request = b"GET /course HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nPacketLens"
    frames = [
        # Stream 0: Reordered + retransmitted HTTP/1.1
        frame(flags=2, seq=99, payload=b""),
        frame(request[:9], seq=100),
        frame(request[25:], seq=125),
        frame(request[9:25], seq=109),
        frame(request[9:25], seq=109),
        frame(
            response, src="10.0.0.2", dst="10.0.0.1", sport=8080, dport=50000, seq=900
        ),
        # Stream 1: HTTP/1.1 on non-standard port 8888 (with cleartext Authorization header)
        frame(
            b"GET /other HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic dWNhczpkZW1v\r\n\r\n",
            sport=51000,
            dport=8888,
            seq=1,
        ),
        # DNS / ICMP / ICMPv6 / TLS / VLAN / non-HTTP on port 80 / Gap / Malformed
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
        # Normal HTTPS TLS 1.3 flow with SNI + ALPN
        frame(
            tls_client_hello(sni="www.ucas.ac.cn", alpn=("h2", "http/1.1")),
            src="10.0.0.1",
            dst="202.122.32.10",
            sport=55000,
            dport=443,
            seq=1000,
        ),
        frame(
            tls_server_hello(),
            src="202.122.32.10",
            dst="10.0.0.1",
            sport=443,
            dport=55000,
            seq=2000,
        ),
        frame(
            tls_app_record(180),
            src="10.0.0.1",
            dst="202.122.32.10",
            sport=55000,
            dport=443,
            seq=1300,
        ),
    ]
    return frames

import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from packetlens.decode import decode, dns_name
from packetlens.files import read_pcap, write_pcap
from packetlens.filters import compile_filter
from packetlens.intel import analyze_security
from packetlens.streams import StreamTable
from packetlens.pcap import Library, CaptureError, Timeval
from packetlens.processes import ProcessMap
from .fixtures import (
    frame,
    dns,
    demo_frames,
    tls_client_hello,
    tls_app_record,
)


def packet(payload=b"", **kw):
    return decode(1, frame(payload, **kw))


class DecodeTests(unittest.TestCase):
    def test_http_nonstandard_port(self):
        self.assertEqual(packet(b"GET / HTTP/1.1\r\n\r\n", dport=8888).protocol, "HTTP")

    def test_port_is_not_protocol(self):
        self.assertEqual(packet(b"garbage", dport=80).protocol, "TCP")

    def test_tcp_fields(self):
        p = packet(b"abc", seq=123, ack=456)
        self.assertEqual(
            (p.seq, p.details["TCP"]["ack"], p.payload), (123, 456, b"abc")
        )

    def test_udp(self):
        self.assertEqual(packet(b"abc", proto=17).payload, b"abc")

    def test_dns(self):
        self.assertEqual(
            packet(dns(), proto=17, dport=53).details["DNS"]["questions"][0]["name"],
            "example.com",
        )

    def test_dns_pointer_loop(self):
        with self.assertRaises(ValueError):
            dns_name(b"\xc0\x00", 0)

    def test_dns_truncated(self):
        self.assertTrue(packet(dns()[:-3], proto=17, dport=53).warning)

    def test_tls_metadata(self):
        self.assertEqual(packet(b"\x17\x03\x03\x00\x03abc").protocol, "TLS")

    def test_icmp(self):
        self.assertEqual(
            packet(b"\x08\x00\x00\x00", proto=1).details["ICMP"]["type"], 8
        )

    def test_ipv6(self):
        self.assertEqual(packet(b"abc", ipv6=True, src="::1", dst="::2").src, "::1")

    def test_ipv6_extension(self):
        raw = bytearray(frame(b"abc", ipv6=True, src="::1", dst="::2"))
        raw[20] = 0
        raw[18:20] = struct.pack("!H", 31)
        raw[54:54] = bytes([6, 0]) + bytes(6)
        p = decode(1, bytes(raw))
        self.assertEqual(p.payload, b"abc")
        self.assertEqual(p.details["IPv6"]["extensions"], [0])

    def test_ipv6_fragment_noninitial(self):
        raw = bytearray(frame(b"x", ipv6=True, src="::1", dst="::2"))
        raw[20] = 44
        raw[18:20] = struct.pack("!H", 29)
        raw[54:54] = bytes([6, 0, 0, 8]) + bytes(4)
        self.assertNotIn("tcp", decode(1, bytes(raw)).layers)

    def test_ipv4_fragment_noninitial(self):
        self.assertNotIn("tcp", packet(b"abc", fragment=1).layers)

    def test_vlan(self):
        self.assertEqual(packet(vlan=True).details["VLAN"], [42])

    def test_null_link(self):
        self.assertEqual(
            decode(1, struct.pack("<I", 2) + frame()[14:], linktype=0).protocol, "TCP"
        )

    def test_loop_link(self):
        self.assertEqual(
            decode(1, struct.pack(">I", 2) + frame()[14:], linktype=108).protocol, "TCP"
        )

    def test_raw_link(self):
        self.assertEqual(decode(1, frame()[14:], linktype=101).protocol, "TCP")

    def test_linux_cooked(self):
        self.assertEqual(
            decode(1, bytes(14) + b"\x08\x00" + frame()[14:], linktype=113).protocol,
            "TCP",
        )

    def test_linux_cooked_v2(self):
        self.assertEqual(
            decode(1, b"\x08\x00" + bytes(18) + frame()[14:], linktype=276).protocol,
            "TCP",
        )

    def test_arp(self):
        raw = (
            bytes(12)
            + b"\x08\x06"
            + struct.pack("!HHBBH", 1, 0x800, 6, 4, 1)
            + bytes(6)
            + b"\x0a\0\0\x01"
            + bytes(6)
            + b"\x0a\0\0\x02"
        )
        self.assertEqual(
            (decode(1, raw).protocol, decode(1, raw).dst), ("ARP", "10.0.0.2")
        )

    def test_tcp_bad_offset(self):
        raw = bytearray(frame())
        raw[46] = 0x10
        self.assertIn("偏移", decode(1, bytes(raw)).warning)

    def test_all_truncations(self):
        raw = frame(b"GET / HTTP/1.1\r\n\r\n")
        for i in range(len(raw)):
            self.assertIsInstance(decode(1, raw[:i]).warning, str)

    def test_seeded_malformed(self):
        rng = random.Random(2026)
        for _ in range(1000):
            raw = rng.randbytes(rng.randrange(256))
            p = decode(1, raw, linktype=rng.choice([0, 1, 12, 101, 108, 113, 276]))
            self.assertIsInstance(p.warning, str)


class FilterTests(unittest.TestCase):
    def test_precedence(self):
        self.assertTrue(compile_filter("udp or tcp and not ipv6")(packet()))

    def test_parentheses(self):
        self.assertFalse(compile_filter("(udp or tcp) and ipv6")(packet()))

    def test_ports(self):
        self.assertTrue(compile_filter("tcp.port == 8080")(packet()))

    def test_wrong_transport(self):
        self.assertFalse(compile_filter("udp.port == 8080")(packet()))

    def test_ip(self):
        self.assertTrue(compile_filter("ip.addr == 10.0.0.1")(packet()))

    def test_ip_not_equal(self):
        self.assertFalse(compile_filter("ip.addr != 10.0.0.1")(packet()))

    def test_contains(self):
        self.assertTrue(compile_filter('contains "hello"')(packet(b"hello")))

    def test_length(self):
        self.assertTrue(compile_filter("len >= 54")(packet()))

    def test_missing_pid(self):
        self.assertFalse(compile_filter("pid != 1")(packet()))

    def test_invalid(self):
        for expr in [
            "tcp or",
            "(tcp",
            "ip.addr == abc",
            "port == 65536",
            "len == x",
            "tcp; import os",
            "tcp and ()",
            "len = 1",
        ]:
            with self.subTest(expr=expr), self.assertRaises(ValueError):
                compile_filter(expr)

    def test_deep(self):
        with self.assertRaises(ValueError):
            compile_filter("not " * 30 + "tcp")

    def test_bpf_native(self):
        try:
            lib = Library()
        except CaptureError as e:
            self.skipTest(str(e))
        self.assertTrue(lib.matches("tcp and port 8080", frame()))
        self.assertFalse(lib.matches("udp", frame()))
        with self.assertRaises(CaptureError):
            lib.matches("tcp and )", frame())


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "t.pcap"

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        ps = [decode(1 + i, raw) for i, raw in enumerate(demo_frames())]
        write_pcap(self.path, ps)
        got = read_pcap(self.path)
        self.assertEqual([p.raw for p in got], [p.raw for p in ps])

    def test_big_endian_nano(self):
        raw = frame()
        self.path.write_bytes(
            struct.pack(">IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
            + struct.pack(">IIII", 1, 500000000, len(raw), len(raw))
            + raw
        )
        self.assertEqual(read_pcap(self.path)[0].timestamp, 1.5)

    def test_truncated_record(self):
        write_pcap(self.path, [packet()])
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            read_pcap(self.path)

    def test_invalid_length(self):
        self.path.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF)
        )
        with self.assertRaises(ValueError):
            read_pcap(self.path)

    def test_mixed_link(self):
        a = packet()
        b = packet()
        b.linktype = 0
        with self.assertRaises(ValueError):
            write_pcap(self.path, [a, b])

    def test_pcapng_rejected(self):
        self.path.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(20))
        with self.assertRaises(ValueError):
            read_pcap(self.path)


class StreamTests(unittest.TestCase):
    def make(self, seqs):
        t = StreamTable()
        for seq, data in seqs:
            t.add(packet(data, seq=seq))
        return (
            t.streams[0].directions[("10.0.0.1", 50000, "10.0.0.2", 8080)].reconstruct()
        )

    def test_reorder(self):
        self.assertEqual(
            self.make([(13, b"def"), (10, b"abc")])["chunks"], [(-3, b"abcdef")]
        )

    def test_duplicate(self):
        self.assertEqual(self.make([(1, b"abc"), (1, b"abc")])["duplicate_bytes"], 3)

    def test_conflict(self):
        r = self.make([(1, b"abc"), (2, b"XX")])
        self.assertEqual(r["conflict_bytes"], 2)
        self.assertEqual(r["chunks"][0][1], b"abc")

    def test_gap(self):
        self.assertEqual(self.make([(1, b"abc"), (10, b"x")])["gaps"], [(3, 9)])

    def test_wrap(self):
        self.assertEqual(
            self.make([(0xFFFFFFFE, b"ab"), (0, b"cd")])["chunks"][0][1], b"abcd"
        )

    def test_bidirectional(self):
        t = StreamTable()
        a = packet()
        b = packet(src="10.0.0.2", dst="10.0.0.1", sport=8080, dport=50000)
        t.add(a)
        t.add(b)
        self.assertEqual(a.stream, b.stream)
        self.assertEqual(len(t.streams[0].directions), 2)

    def test_new_syn(self):
        t = StreamTable()
        t.add(packet(flags=2, seq=1))
        t.add(packet(flags=2, seq=1))
        t.add(packet(flags=2, seq=2))
        self.assertEqual(len(t.streams), 2)

    def test_reconstructed_http(self):
        t = StreamTable()
        for raw in demo_frames():
            t.add(decode(1, raw))
        self.assertIn("GET /course HTTP/1.1", t.streams[0].text())
        self.assertIn("duplicate_bytes=16", t.streams[0].text())

    def test_stream_bound(self):
        r = self.make([(i * 60000, b"x" * 60000) for i in range(5)])
        self.assertEqual(r["omitted_bytes"], 60000)


class ProcessTests(unittest.TestCase):
    def test_exact_tuple(self):
        from types import SimpleNamespace

        mapper = ProcessMap(
            lambda: [
                SimpleNamespace(
                    laddr=("10.0.0.1", 50000), raddr=("10.0.0.2", 8080), pid=os.getpid()
                )
            ]
        )
        mapper.refresh()
        p = packet()
        mapper.attach(p)
        self.assertEqual(p.pid, os.getpid())
        q = packet(dst="10.0.0.3")
        mapper.attach(q)
        self.assertIsNone(q.pid)

    def test_ambiguous(self):
        from types import SimpleNamespace

        mapper = ProcessMap(
            lambda: [
                SimpleNamespace(
                    laddr=("10.0.0.1", 50000), raddr=("10.0.0.2", 8080), pid=n
                )
                for n in (1, 2)
            ]
        )
        mapper.refresh()
        p = packet()
        mapper.attach(p)
        self.assertIsNone(p.pid)

    def test_permission_denied(self):
        def fail():
            raise PermissionError()

        m = ProcessMap(fail)
        m.refresh()
        self.assertIn("不可用", m.status)


class TlsAndSecurityTests(unittest.TestCase):
    def test_tls_client_hello_sni_alpn_ja3(self):
        p = packet(
            tls_client_hello(sni="github.com", alpn=("h2", "http/1.1")), dport=443
        )
        self.assertEqual(p.protocol, "TLS")
        self.assertEqual(p.sni, "github.com")
        self.assertEqual(p.alpn, ["h2", "http/1.1"])
        self.assertEqual(len(p.ja3), 32)
        self.assertEqual(p.tls_version, "TLS 1.3")
        self.assertIn("SNI=github.com", p.info)

    def test_tls_multi_record_parsing(self):
        p = packet(tls_app_record(40) + tls_app_record(450) + tls_app_record(620), dport=443)
        self.assertEqual(p.protocol, "TLS")
        self.assertEqual([r["length"] for r in p.tls_records], [40, 450, 620])

    def test_https_through_local_connect(self):
        table = StreamTable()
        payloads = [
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
            tls_client_hello(sni="example.test", alpn=("h2", "http/1.1")),
            b"".join(tls_app_record(n) for n in (63, 87, 429, 651, 26, 34)),
        ]
        packets = []
        seq = 1
        for payload in payloads:
            p = packet(payload, src="127.0.0.1", dst="127.0.0.1", dport=7897, seq=seq)
            table.add(p)
            packets.append(p)
            seq += len(payload)
        self.assertEqual([p.protocol for p in packets], ["HTTP", "TLS", "TLS"])
        self.assertEqual(table.streams[0].protocol_label, "TLS 1.3 (example.test)")
        self.assertEqual(analyze_security(packets, table), [])

    def test_display_filters_and_process_summary(self):
        table = StreamTable()
        pkts = []
        for i, raw in enumerate(demo_frames(), 1):
            p = decode(1000.0 + i * 0.05, raw, number=i)
            if p.dport == 443 and p.sni == "www.ucas.ac.cn":
                p.pid = 4242
                p.process = "curl"
            table.add(p)
            pkts.append(p)

        self.assertTrue(any(compile_filter('tls.sni == "www.ucas.ac.cn"')(p) for p in pkts))
        self.assertTrue(any(compile_filter('tls.sni contains "ucas"')(p) for p in pkts))
        self.assertTrue(any(compile_filter('process == "curl"')(p) for p in pkts))

        summary = table.process_summary()
        self.assertTrue(any(g["pid"] == 4242 and g["name"] == "curl" for g in summary))

    def test_security_alerts(self):
        pkts = []
        table = StreamTable()
        # Cleartext HTTP Basic Auth + SYN port scan (5 ports) + ARP spoofing + TCP conflict
        scan_frames = [
            frame(
                b"GET /login HTTP/1.1\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\r\n",
                dport=80,
                sport=40000,
                seq=1,
            ),
            frame(b"abc", sport=41000, dport=8080, seq=10),
            frame(b"aXc", sport=41000, dport=8080, seq=10),
        ] + [
            frame(b"", src="10.0.0.99", dst="10.0.0.2", sport=42000 + i, dport=20 + i, flags=2, seq=1)
            for i in range(6)
        ]
        arp1 = (
            bytes(12) + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x800, 6, 4, 2)
            + b"\xaa\xaa\xaa\xaa\xaa\x01" + b"\x0a\x00\x00\x05"
            + bytes(6) + b"\x0a\x00\x00\x01"
        )
        arp2 = (
            bytes(12) + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x800, 6, 4, 2)
            + b"\xbb\xbb\xbb\xbb\xbb\x02" + b"\x0a\x00\x00\x05"
            + bytes(6) + b"\x0a\x00\x00\x01"
        )
        for i, raw in enumerate(scan_frames + [arp1, arp2], 1):
            p = decode(1.0 + i * 0.01, raw, number=i)
            table.add(p)
            pkts.append(p)
        alerts = analyze_security(pkts, table)
        cats = {a["category"] for a in alerts}
        self.assertIn("明文凭据泄露", cats)
        self.assertIn("疑似端口扫描", cats)
        self.assertIn("疑似 ARP 欺骗", cats)
        self.assertIn("TCP 重叠冲突", cats)

    def test_macos_timeval_abi(self):
        import ctypes, sys
        if sys.platform == "darwin":
            self.assertEqual(ctypes.sizeof(Timeval), 16)
            self.assertEqual(Timeval.usec.size, 4)


if __name__ == "__main__":
    unittest.main()

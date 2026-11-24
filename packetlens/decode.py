"""Bounded, defensive decoding with TLS SNI/JA3, Trojan, and AnyTLS dissection."""

from dataclasses import dataclass, field
import hashlib
import ipaddress
import re
import struct

HEX56_RE = re.compile(rb"^[0-9a-f]{56}$")
HTTP_RE = re.compile(
    rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n]{1,2048} HTTP/1\.[01]\r\n|HTTP/1\.[01] [0-9]{3} "
)

TCP_FLAG_NAMES = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}

ICMPV6_TYPES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
}

TLS_RECORD_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
}

TLS_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

ANYTLS_COMMANDS = {
    0: "cmdWaste",
    1: "cmdSYN",
    2: "cmdPSH",
    3: "cmdFIN",
    4: "cmdSettings",
    5: "cmdAlert",
    6: "cmdUpdatePaddingScheme",
    7: "cmdSYNACK",
    8: "cmdHeartRequest",
    9: "cmdHeartResponse",
    10: "cmdServerSettings",
}

ANYTLS_SETTING_KEYS = {"v", "client", "padding-md5", "stop", "0", "1", "2"}


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
    sni: str = ""
    alpn: list = field(default_factory=list)
    ja3: str = ""
    tls_version: str = ""
    tls_records: list = field(default_factory=list)

    @property
    def key(self):
        return tuple(sorted(((self.src, self.sport), (self.dst, self.dport))))


def format_tcp_flags(flags):
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return ",".join(names) if names else "NONE"


def ipv4_checksum_valid(header_bytes):
    if len(header_bytes) < 20 or len(header_bytes) % 2 != 0:
        return False
    total = sum(struct.unpack(f"!{len(header_bytes) // 2}H", header_bytes))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def parse_tcp_options(opt_bytes):
    options = []
    pos = 0
    end = len(opt_bytes)
    steps = 0
    while pos < end and steps < 20:
        steps += 1
        kind = opt_bytes[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 2 > end:
            break
        length = opt_bytes[pos + 1]
        if length < 2 or pos + length > end:
            break
        val = opt_bytes[pos + 2 : pos + length]
        if kind == 2 and len(val) == 2:
            options.append(f"MSS={int.from_bytes(val, 'big')}")
        elif kind == 3 and len(val) == 1:
            options.append(f"WScale={val[0]}")
        elif kind == 4 and len(val) == 0:
            options.append("SACK_PERM")
        elif kind == 8 and len(val) == 8:
            tsval, tsecr = struct.unpack("!II", val)
            options.append(f"TS={tsval}/{tsecr}")
        else:
            options.append(f"Opt({kind},len={length})")
        pos += length
    return options


def _is_grease(val):
    return (val & 0x0F0F) == 0x0A0A and (val >> 8) == (val & 0xFF)


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


def _parse_tls_client_hello(body):
    # body starts right after the 4-byte handshake header (type + uint24 len)
    if len(body) < 38:
        return {}
    client_ver = int.from_bytes(body[:2], "big")
    pos = 34  # 2B version + 32B random
    if pos >= len(body):
        return {}
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return {}
    cs_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if cs_len % 2 != 0 or pos + cs_len > len(body):
        return {}
    ciphers = [
        int.from_bytes(body[pos + i : pos + i + 2], "big")
        for i in range(0, cs_len, 2)
    ]
    pos += cs_len
    if pos >= len(body):
        return {}
    comp_len = body[pos]
    pos += 1 + comp_len
    if pos > len(body):
        return {}

    sni = ""
    alpn = []
    exts = []
    groups = []
    ec_formats = []
    supported_versions = []

    if pos + 2 <= len(body):
        ext_total = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        ext_end = min(len(body), pos + ext_total)
        ext_count = 0
        while pos + 4 <= ext_end and ext_count < 64:
            ext_count += 1
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
            pos += 4
            if pos + ext_len > ext_end:
                break
            edata = body[pos : pos + ext_len]
            pos += ext_len
            exts.append(ext_type)

            if ext_type == 0x0000 and len(edata) >= 5:
                # Server Name Indication
                list_len = int.from_bytes(edata[:2], "big")
                epos = 2
                while epos + 3 <= min(len(edata), 2 + list_len):
                    name_type = edata[epos]
                    name_len = int.from_bytes(edata[epos + 1 : epos + 3], "big")
                    epos += 3
                    if epos + name_len > len(edata):
                        break
                    if name_type == 0:
                        sni = edata[epos : epos + name_len].decode("ascii", "replace")
                        break
                    epos += name_len
            elif ext_type == 0x0010 and len(edata) >= 3:
                # ALPN
                list_len = int.from_bytes(edata[:2], "big")
                epos = 2
                limit = min(len(edata), 2 + list_len)
                while epos < limit and len(alpn) < 16:
                    plen = edata[epos]
                    epos += 1
                    if plen == 0 or epos + plen > limit:
                        break
                    alpn.append(edata[epos : epos + plen].decode("ascii", "replace"))
                    epos += plen
            elif ext_type == 0x000A and len(edata) >= 4:
                # Supported Groups
                glen = int.from_bytes(edata[:2], "big")
                for i in range(2, min(len(edata), 2 + glen) - 1, 2):
                    groups.append(int.from_bytes(edata[i : i + 2], "big"))
            elif ext_type == 0x000B and len(edata) >= 2:
                # EC Point Formats
                flen = edata[0]
                ec_formats.extend(edata[1 : 1 + flen])
            elif ext_type == 0x002B and len(edata) >= 3:
                # Supported Versions
                vlen = edata[0]
                for i in range(1, min(len(edata), 1 + vlen) - 1, 2):
                    v = int.from_bytes(edata[i : i + 2], "big")
                    if not _is_grease(v):
                        supported_versions.append(v)

    ja3_ciphers = "-".join(str(c) for c in ciphers if not _is_grease(c))
    ja3_exts = "-".join(str(e) for e in exts if not _is_grease(e))
    ja3_groups = "-".join(str(g) for g in groups if not _is_grease(g))
    ja3_ec = "-".join(str(f) for f in ec_formats)
    ja3_str = f"{client_ver},{ja3_ciphers},{ja3_exts},{ja3_groups},{ja3_ec}"
    ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

    effective_ver = (
        max(supported_versions) if supported_versions else client_ver
    )
    return {
        "client_version": TLS_VERSIONS.get(client_ver, f"0x{client_ver:04x}"),
        "effective_version": TLS_VERSIONS.get(
            effective_ver, f"0x{effective_ver:04x}"
        ),
        "sni": sni,
        "alpn": alpn,
        "cipher_count": len(ciphers),
        "extension_count": len(exts),
        "ja3": ja3_hash,
        "ja3_raw": ja3_str,
    }


def _parse_tls_server_hello(body):
    if len(body) < 38:
        return {}
    server_ver = int.from_bytes(body[:2], "big")
    pos = 34
    if pos >= len(body):
        return {}
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 3 > len(body):
        return {}
    cipher = int.from_bytes(body[pos : pos + 2], "big")
    pos += 3  # 2B cipher + 1B compression
    effective_ver = server_ver
    if pos + 2 <= len(body):
        ext_total = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        ext_end = min(len(body), pos + ext_total)
        ext_count = 0
        while pos + 4 <= ext_end and ext_count < 32:
            ext_count += 1
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
            pos += 4
            if pos + ext_len > ext_end:
                break
            edata = body[pos : pos + ext_len]
            pos += ext_len
            if ext_type == 0x002B and len(edata) == 2:
                effective_ver = int.from_bytes(edata, "big")
    return {
        "effective_version": TLS_VERSIONS.get(
            effective_ver, f"0x{effective_ver:04x}"
        ),
        "cipher_suite": f"0x{cipher:04x}",
    }


def parse_tls(p):
    data = p.payload
    if (
        "tcp" not in p.layers
        or len(data) < 5
        or data[0] not in TLS_RECORD_TYPES
        or data[1] != 3
        or data[2] > 4
    ):
        return False
    first_len = int.from_bytes(data[3:5], "big")
    if first_len > 18432:
        return False

    pos = 0
    records = []
    handshake_info = {}
    handshake_names = []
    while pos + 5 <= len(data) and len(records) < 32:
        rtype = data[pos]
        if rtype not in TLS_RECORD_TYPES or data[pos + 1] != 3 or data[pos + 2] > 4:
            break
        rlen = int.from_bytes(data[pos + 3 : pos + 5], "big")
        if rlen > 18432:
            break
        complete = pos + 5 + rlen <= len(data)
        rver = int.from_bytes(data[pos + 1 : pos + 3], "big")
        rec = {
            "type": rtype,
            "type_name": TLS_RECORD_TYPES[rtype],
            "legacy_version": TLS_VERSIONS.get(rver, f"0x{rver:04x}"),
            "length": rlen,
            "complete": complete,
        }
        rec_payload = data[pos + 5 : pos + 5 + min(rlen, len(data) - pos - 5)]
        if rtype == 22 and len(rec_payload) >= 4:
            hs_type = rec_payload[0]
            hs_len = int.from_bytes(rec_payload[1:4], "big")
            hs_name = TLS_HANDSHAKE_TYPES.get(hs_type)
            if hs_name and hs_len <= 16384:
                rec["handshake_type"] = hs_name
                handshake_names.append(hs_name)
                hs_body = rec_payload[4 : 4 + hs_len]
                if hs_type == 1:
                    ch = _parse_tls_client_hello(hs_body)
                    if ch:
                        handshake_info = ch
                        p.sni = ch.get("sni", "")
                        p.alpn = ch.get("alpn", [])
                        p.ja3 = ch.get("ja3", "")
                        p.tls_version = ch.get("effective_version", "")
                elif hs_type == 2:
                    sh = _parse_tls_server_hello(hs_body)
                    if sh:
                        handshake_info = sh
                        p.tls_version = sh.get("effective_version", "")
        records.append(rec)
        if not complete:
            break
        pos += 5 + rlen

    if not records:
        return False

    p.layers.add("tls")
    p.protocol = "TLS"
    p.tls_records = records
    first = records[0]
    tls_detail = {
        "record_type": first["type"],
        "record_type_name": first["type_name"],
        "legacy_version": data[1:3].hex(),
        "version": p.tls_version or first["legacy_version"],
        "record_length": first["length"],
        "complete_record": first["complete"],
        "record_count": len(records),
        "records": records,
        "note": "仅解析明文握手元数据与密文记录边界，不解密 HTTPS 载荷",
    }
    if handshake_names:
        tls_detail["handshake"] = ", ".join(handshake_names)
    if handshake_info:
        tls_detail.update(handshake_info)
    p.details["TLS"] = tls_detail

    if p.sni:
        alpn_tag = f" ALPN={','.join(p.alpn)}" if p.alpn else ""
        ja3_tag = f" JA3={p.ja3[:10]}..." if p.ja3 else ""
        p.info = f"{tls_detail['version']} ClientHello SNI={p.sni}{alpn_tag}{ja3_tag}"
    elif handshake_names:
        extra = (
            f" cipher={handshake_info['cipher_suite']}"
            if "cipher_suite" in handshake_info
            else ""
        )
        p.info = f"{tls_detail['version']} {'/'.join(handshake_names)}{extra}"
    elif len(records) > 1:
        sizes = "+".join(str(r["length"]) for r in records[:6])
        if len(records) > 6:
            sizes += "+..."
        p.info = f"TLS {first['type_name']} ({len(records)} records: {sizes} B)"
    else:
        p.info = f"TLS {first['type_name']} (type={first['type']}, len={first['length']})"
    return True


def parse_trojan(p):
    """Exact dissector for plaintext/decrypted Trojan protocol request header."""
    data = p.payload
    if "tcp" not in p.layers or len(data) < 64:
        return False
    if data[56:58] != b"\r\n" or not HEX56_RE.match(data[:56]):
        return False
    cmd = data[58]
    if cmd not in (1, 3):
        return False
    atyp = data[59]
    pos = 60
    if atyp == 1:
        if pos + 8 > len(data):
            return False
        target_host = str(ipaddress.IPv4Address(data[pos : pos + 4]))
        pos += 4
        atyp_name = "IPv4"
    elif atyp == 3:
        if pos + 1 > len(data):
            return False
        dlen = data[pos]
        pos += 1
        if dlen == 0 or pos + dlen + 4 > len(data):
            return False
        domain_bytes = data[pos : pos + dlen]
        if any(b < 33 or b > 126 for b in domain_bytes):
            return False
        target_host = domain_bytes.decode("ascii")
        pos += dlen
        atyp_name = "Domain"
    elif atyp == 4:
        if pos + 20 > len(data):
            return False
        target_host = str(ipaddress.IPv6Address(data[pos : pos + 16]))
        pos += 16
        atyp_name = "IPv6"
    else:
        return False
    target_port = int.from_bytes(data[pos : pos + 2], "big")
    if data[pos + 2 : pos + 4] != b"\r\n":
        return False
    pos += 4
    pwd_hash = data[:56].decode("ascii")
    inner_len = len(data) - pos
    cmd_name = "CONNECT" if cmd == 1 else "UDP_ASSOCIATE"

    p.layers.update(("trojan", "proxy"))
    p.protocol = "Trojan"
    p.details["Trojan"] = {
        "mode": "明文/解密后协议帧精确匹配",
        "sha224_prefix": f"{pwd_hash[:8]}...{pwd_hash[-4:]}",
        "command": cmd_name,
        "address_type": atyp_name,
        "target_host": target_host,
        "target_port": target_port,
        "inner_payload_bytes": inner_len,
    }
    p.info = f"Trojan {cmd_name} → {target_host}:{target_port} (inner={inner_len} B)"
    return True


def _parse_anytls_frames(buf):
    pos = 0
    frames = []
    settings = {}
    has_signature_frame = False
    while pos + 7 <= len(buf) and len(frames) < 64:
        cmd = buf[pos]
        if cmd not in ANYTLS_COMMANDS:
            return None
        sid = int.from_bytes(buf[pos + 1 : pos + 5], "big")
        flen = int.from_bytes(buf[pos + 5 : pos + 7], "big")
        pos += 7
        if pos + flen > len(buf):
            return None
        body = buf[pos : pos + flen]
        pos += flen

        # Structural sanity checks per AnyTLS specification
        if cmd in (1, 7, 8, 9) and flen != 0:
            return None
        if cmd in (0, 4, 6, 10) and sid != 0:
            return None

        entry = {
            "cmd": cmd,
            "cmd_name": ANYTLS_COMMANDS[cmd],
            "sid": sid,
            "length": flen,
        }
        if cmd in (4, 6, 10) and flen > 0:
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                return None
            parsed_kv = {}
            for line in text.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    parsed_kv[k.strip()] = v.strip()
            if parsed_kv and (set(parsed_kv) & ANYTLS_SETTING_KEYS):
                has_signature_frame = True
                settings.update(parsed_kv)
                entry["fields"] = parsed_kv
            elif cmd == 4:
                return None
        frames.append(entry)
    if pos != len(buf) or not frames:
        return None
    if not has_signature_frame:
        # Require at least 2 coherent frames with plausible stream IDs & control command
        if len(frames) < 2:
            return None
        cmds = {f["cmd"] for f in frames}
        if not (cmds & {0, 1, 7, 8, 9}):
            return None
        if any(f["sid"] > 1_000_000 for f in frames):
            return None
    return frames, settings


def parse_anytls(p):
    """Exact dissector for plaintext/decrypted AnyTLS auth prologue and frame sequence."""
    data = p.payload
    if "tcp" not in p.layers or len(data) < 7:
        return False

    auth_present = False
    padding_len = 0
    sha256_prefix = ""
    result = None

    # Pattern A: 32-byte SHA256(password) + 2-byte padding_len + padding + AnyTLS frames
    if len(data) >= 41:
        pad_len = int.from_bytes(data[32:34], "big")
        offset = 34 + pad_len
        if pad_len <= 4096 and offset + 7 <= len(data):
            candidate = _parse_anytls_frames(data[offset:])
            if candidate is not None:
                frames, settings = candidate
                # Require settings or explicit control command after auth prologue
                if settings or any(f["cmd"] in (1, 4, 6, 10) for f in frames):
                    auth_present = True
                    padding_len = pad_len
                    sha256_prefix = data[:4].hex() + "..." + data[30:32].hex()
                    result = candidate

    # Pattern B: Standalone AnyTLS control/data frame sequence
    if result is None:
        result = _parse_anytls_frames(data)

    if result is None:
        return False

    frames, settings = result
    p.layers.update(("anytls", "proxy"))
    p.protocol = "AnyTLS"
    detail = {
        "mode": "明文/解密后协议帧精确匹配",
        "auth_prologue": auth_present,
        "frame_count": len(frames),
        "frames": frames,
    }
    if auth_present:
        detail["sha256_prefix"] = sha256_prefix
        detail["initial_padding_bytes"] = padding_len
    if settings:
        detail["settings"] = settings
    p.details["AnyTLS"] = detail

    cmds_summary = ", ".join(f"{f['cmd_name']}(sid={f['sid']},len={f['length']})" for f in frames[:3])
    if len(frames) > 3:
        cmds_summary += f" +{len(frames) - 3}"
    prefix = f"Auth(pad={padding_len}B) + " if auth_present else ""
    p.info = f"AnyTLS {prefix}{cmds_summary}"
    return True


def application(p):
    data = p.payload
    if "tcp" in p.layers and HTTP_RE.match(data):
        p.layers.add("http")
        p.protocol = "HTTP"
        head = data.split(b"\r\n\r\n", 1)[0][:8192].decode("utf-8", "replace")
        lines = head.split("\r\n")
        start_line = lines[0] if lines else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        http_detail = {"start_line": start_line, "headers": headers, "raw_head": head}
        parts = start_line.split(" ", 2)
        if start_line.startswith("HTTP/") and len(parts) >= 2:
            http_detail["version"] = parts[0]
            http_detail["status_code"] = parts[1]
            http_detail["reason"] = parts[2] if len(parts) > 2 else ""
        elif len(parts) >= 3:
            http_detail["method"] = parts[0]
            http_detail["path"] = parts[1]
            http_detail["version"] = parts[2]
        p.details["HTTP"] = http_detail
        p.info = start_line
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
    elif parse_tls(p):
        return
    elif parse_trojan(p):
        return
    elif parse_anytls(p):
        return


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
            sender_mac = raw[off + 8 : off + 14].hex(":")
            p.src = str(ipaddress.ip_address(raw[off + 14 : off + 18]))
            target_mac = raw[off + 18 : off + 24].hex(":")
            p.dst = str(ipaddress.ip_address(raw[off + 24 : off + 28]))
            op_name = {1: "Request", 2: "Reply"}.get(op, f"Op({op})")
            p.details["ARP"] = {
                "operation": op,
                "operation_name": op_name,
                "sender_mac": sender_mac,
                "sender_ip": p.src,
                "target_mac": target_mac,
                "target_ip": p.dst,
            }
            p.info = f"ARP {op_name}: {p.src} ({sender_mac}) → {p.dst}"
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
            cksum_ok = ipv4_checksum_valid(raw[off : off + ihl])
            p.layers.update(("ip", "ipv4"))
            p.protocol = "IPv4"
            p.details["IPv4"] = {
                "header_length": ihl,
                "total_length": total,
                "ttl": raw[off + 8],
                "protocol": proto,
                "checksum_valid": cksum_ok,
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
            flags_str = format_tcp_flags(p.flags)
            opts = parse_tcp_options(data[20:size]) if size > 20 else []
            p.details["TCP"] = {
                "src_port": p.sport,
                "dst_port": p.dport,
                "seq": p.seq,
                "ack": ack,
                "flags": p.flags,
                "flags_str": flags_str,
                "window": win,
                "header_length": size,
                "options": opts,
                "options_hex": data[20:size].hex(),
            }
            p.info = f"{p.sport} → {p.dport} [{flags_str}] seq={p.seq} ack={ack} len={len(p.payload)}"
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
            type_table = ICMPV6_TYPES if proto == 58 else ICMP_TYPES
            tname = type_table.get(data[0], f"Type {data[0]}")
            p.details[p.protocol] = {
                "type": data[0],
                "type_name": tname,
                "code": data[1],
                "checksum": data[2:4].hex(),
            }
            p.payload = data[4:]
            p.info = f"{tname} (type={data[0]}, code={data[1]})"
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

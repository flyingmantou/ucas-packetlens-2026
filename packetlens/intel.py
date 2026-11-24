"""Encrypted traffic analysis (Trojan / AnyTLS) and network security alerts."""

import re

CRED_RE = re.compile(
    rb"(?i)(authorization:\s*(?:basic|bearer)\s+\S+|(?:password|passwd|pwd|secret|access_token)=[^&\s\r\n]{2,})"
)


def _group_record_bursts(events):
    """Collapse consecutive TLS ApplicationData events in the same direction into bursts."""
    bursts = []
    for direction, lengths in events:
        if bursts and bursts[-1][0] == direction:
            bursts[-1][1].extend(lengths)
        else:
            bursts.append([direction, list(lengths)])
    return bursts


def analyze_stream(stream):
    """Classify a TCP stream for Trojan / AnyTLS (deterministic + encrypted ETA)."""
    if stream.deterministic_proxy == "Trojan":
        return {
            "protocol_label": "Trojan (协议帧确认)",
            "proxy_family": "Trojan",
            "detection_mode": "deterministic",
            "confidence": 100,
            "confidence_level": "确定",
            "reasons": [
                "命中 Trojan 明文/解密后协议头（56 字节 SHA224 十六进制 + CRLF + CMD/SOCKS5 地址 + CRLF）"
            ],
            "record_sequence": [],
        }

    if stream.deterministic_proxy == "AnyTLS":
        return {
            "protocol_label": "AnyTLS (协议帧确认)",
            "proxy_family": "AnyTLS",
            "detection_mode": "deterministic",
            "confidence": 100,
            "confidence_level": "确定",
            "reasons": [
                "命中 AnyTLS 明文/解密后控制帧或认证头（cmd + sid + len 结构及 settings/padding 字段合法）"
            ],
            "record_sequence": [],
        }

    # Format human-readable TLS AppData record sequence for explainability
    rec_seq = []
    for direction, lengths in stream.tls_app_events[:12]:
        arrow = "C→S" if direction == 0 else "S→C"
        rec_seq.append(f"{arrow}:{'+'.join(str(x) for x in lengths)}B")

    if not stream.has_tls:
        if stream.has_http:
            label = "HTTP/1.x"
        else:
            label = "TCP"
        return {
            "protocol_label": label,
            "proxy_family": "",
            "detection_mode": "none",
            "confidence": 0,
            "confidence_level": "无",
            "reasons": [],
            "record_sequence": [],
        }

    # Encrypted TLS Traffic Analysis (ETA)
    bursts = _group_record_bursts(stream.tls_app_events)
    client_bursts = [b[1] for b in bursts if b[0] == 0]
    server_bursts = [b[1] for b in bursts if b[0] == 1]

    trojan_score = 0
    trojan_reasons = []
    anytls_score = 0
    anytls_reasons = []

    # Check AnyTLS encrypted padding-scheme heuristics first:
    # AnyTLS splits/pads early client AppData records into multiple records (often 30-1000B).
    if client_bursts:
        first_c = client_bursts[0]
        early_c_records = sum((b for b in client_bursts[:2]), [])
        padded_band = [n for n in early_c_records if 350 <= n <= 1100]
        small_ctrl = [n for n in early_c_records if 18 <= n <= 160]

        if len(first_c) >= 3 and len(padded_band) >= 2:
            anytls_score += 48
            anytls_reasons.append(
                f"外层 TLS 握手后首个客户端突发即拆分为 {len(first_c)} 个连续密文记录（{first_c[:6]} B），高度符合 AnyTLS padding_scheme 分片填充特征"
            )
        elif len(early_c_records) >= 4 and len(padded_band) >= 3:
            anytls_score += 42
            anytls_reasons.append(
                f"前两轮客户端密文包含 {len(padded_band)} 个 350~1100 B 填充区间记录，呈现明显 AnyTLS 抗指纹填充分布"
            )

        if small_ctrl and len(padded_band) >= 2:
            anytls_score += 18
            anytls_reasons.append(
                f"早期密文同时出现小尺寸控制/认证记录（{small_ctrl[:3]} B）与多段中等填充记录"
            )

        # Check symmetric tiny heartbeat / multiplex control records (7B header + 17B TLS1.3 AEAD = 24B)
        all_app_lens = [n for _, lens in stream.tls_app_events for n in lens]
        tiny_recs = [n for n in all_app_lens if 20 <= n <= 48]
        if len(tiny_recs) >= 2:
            anytls_score += 14
            anytls_reasons.append(
                f"流内出现 {len(tiny_recs)} 次 20~48 B 极短双向密文记录（疑似 AnyTLS cmdHeart/cmdSYN/cmdFIN 多路复用控制帧）"
            )

        # Check Trojan unpadded TLS-in-TLS double-handshake heuristic:
        # Single/compact client AppData (Trojan hdr ~58-80B + inner ClientHello ~200-700B),
        # immediately followed by large server AppData burst (inner ServerHello + Certificate >= 1300B),
        # followed by compact client AppData (inner Finished/KeyExchange <= 450B).
        if (
            len(first_c) <= 2
            and 220 <= sum(first_c) <= 950
            and len(bursts) >= 2
            and bursts[0][0] == 0
            and bursts[1][0] == 1
        ):
            s1_sum = sum(bursts[1][1])
            if s1_sum >= 1300:
                trojan_score += 45
                trojan_reasons.append(
                    f"检出典型未填充 TLS-in-TLS 双握手突发：外层握手后 C→S 发送 {sum(first_c)} B，S→C 立即回传 {s1_sum} B（疑似内层 ServerHello+证书链）"
                )
                if (
                    len(bursts) >= 3
                    and bursts[2][0] == 0
                    and 32 <= sum(bursts[2][1]) <= 480
                ):
                    trojan_score += 15
                    trojan_reasons.append(
                        f"随后 C→S 发送 {sum(bursts[2][1])} B 短密文（疑似内层 Client Finished/密钥交换）"
                    )

    # Shared TLS ClientHello anomaly signals
    if stream.saw_client_hello:
        if not stream.tls_alpn:
            trojan_score += 18
            anytls_score += 18
            msg = "TLS ClientHello 未携带 ALPN（缺少 h2/http/1.1 协商，常见于代理隧道客户端）"
            trojan_reasons.append(msg)
            anytls_reasons.append(msg)
        if stream.client_cipher_count and stream.client_cipher_count <= 8:
            trojan_score += 10
            anytls_score += 10
            msg = f"ClientHello 仅提供 {stream.client_cipher_count} 个加密套件（偏离常见浏览器指纹）"
            trojan_reasons.append(msg)
            anytls_reasons.append(msg)

    if stream.server_port and stream.server_port not in (443, 8443, 993, 995, 465, 853):
        trojan_score += 10
        anytls_score += 10
        msg = f"TLS 流量运行在非常规端口 {stream.server_port}"
        trojan_reasons.append(msg)
        anytls_reasons.append(msg)

    # Decide classification cleanly without false positives on normal HTTPS
    if anytls_score >= 55 and anytls_score >= trojan_score:
        conf = min(92, anytls_score)
        return {
            "protocol_label": f"疑似 AnyTLS ({conf}%)",
            "proxy_family": "AnyTLS",
            "detection_mode": "heuristic",
            "confidence": conf,
            "confidence_level": "高" if conf >= 75 else "中",
            "reasons": anytls_reasons,
            "record_sequence": rec_seq,
        }

    if trojan_score >= 55 and trojan_score > anytls_score:
        conf = min(92, trojan_score)
        return {
            "protocol_label": f"疑似 Trojan ({conf}%)",
            "proxy_family": "Trojan",
            "detection_mode": "heuristic",
            "confidence": conf,
            "confidence_level": "高" if conf >= 75 else "中",
            "reasons": trojan_reasons,
            "record_sequence": rec_seq,
        }

    ver = stream.tls_version or "TLS"
    sni_part = f" ({stream.tls_sni})" if stream.tls_sni else ""
    return {
        "protocol_label": f"{ver}{sni_part}",
        "proxy_family": "",
        "detection_mode": "none",
        "confidence": 0,
        "confidence_level": "无",
        "reasons": [],
        "record_sequence": rec_seq,
    }


def analyze_security(packets, stream_table):
    """Run security & protocol intelligence checks across packets and TCP streams."""
    alerts = []

    # 1. Proxy / Encrypted Protocol Findings (Trojan & AnyTLS)
    for s in stream_table.streams:
        info = s.intel
        if info["proxy_family"]:
            sev = "高" if info["confidence"] >= 75 else "中"
            mode_cn = "明文帧确认" if info["detection_mode"] == "deterministic" else "加密流特征启发式"
            seq_txt = (
                " | 密文序列: " + " → ".join(info["record_sequence"][:6])
                if info["record_sequence"]
                else ""
            )
            alerts.append(
                {
                    "severity": sev,
                    "category": f"代理协议识别 ({info['proxy_family']})",
                    "title": f"流 #{s.id} 检出 {info['protocol_label']} [{mode_cn}]",
                    "detail": "；".join(info["reasons"]) + seq_txt,
                    "packet_no": s.first_packet_no,
                    "stream_id": s.id,
                }
            )

        # 2. TCP reassembly byte conflict (potential IDS/evasion overlap)
        conflict_total = 0
        for d in s.directions.values():
            conflict_total += d.reconstruct()["conflict_bytes"]
        if conflict_total > 0:
            alerts.append(
                {
                    "severity": "高",
                    "category": "TCP 重叠冲突",
                    "title": f"流 #{s.id} 存在 {conflict_total} 字节重传内容冲突",
                    "detail": "同一 TCP 序列号区间出现不一致载荷字节，可能存在网络异常或 TCP 分段重叠逃逸（IDS Evasion）行为",
                    "packet_no": s.first_packet_no,
                    "stream_id": s.id,
                }
            )

    # 3. Cleartext HTTP credentials
    for p in packets:
        if "http" in p.layers and CRED_RE.search(p.payload):
            alerts.append(
                {
                    "severity": "高",
                    "category": "明文凭据泄露",
                    "title": f"报文 #{p.number} 检测到明文 HTTP 认证凭据或敏感参数",
                    "detail": f"{p.src}:{p.sport} → {p.dst}:{p.dport} ({p.info})，明文传输易被嗅探窃取",
                    "packet_no": p.number,
                    "stream_id": p.stream,
                }
            )

    # 4. SYN Port Scan detection (>=5 distinct dst ports from same src->dst)
    syn_targets = {}
    for p in packets:
        if "tcp" in p.layers and (p.flags & 0x02) and not (p.flags & 0x10):
            pair = (p.src, p.dst)
            entry = syn_targets.setdefault(pair, {"ports": set(), "first_no": p.number})
            entry["ports"].add(p.dport)
    for (src, dst), entry in syn_targets.items():
        if len(entry["ports"]) >= 5:
            sample_ports = sorted(entry["ports"])[:8]
            alerts.append(
                {
                    "severity": "中",
                    "category": "疑似端口扫描",
                    "title": f"{src} → {dst} 发起 {len(entry['ports'])} 个不同端口的 TCP SYN 探测",
                    "detail": f"目标端口示例：{sample_ports}",
                    "packet_no": entry["first_no"],
                    "stream_id": -1,
                }
            )

    # 5. ARP spoofing / IP-to-multiple-MAC conflict
    arp_ip_macs = {}
    for p in packets:
        if "arp" in p.layers and "ARP" in p.details:
            ip = p.details["ARP"].get("sender_ip")
            mac = p.details["ARP"].get("sender_mac")
            if ip and mac:
                entry = arp_ip_macs.setdefault(ip, {"macs": set(), "first_no": p.number})
                entry["macs"].add(mac)
    for ip, entry in arp_ip_macs.items():
        if len(entry["macs"]) >= 2:
            alerts.append(
                {
                    "severity": "高",
                    "category": "疑似 ARP 欺骗",
                    "title": f"IP {ip} 对应多个不同 MAC 地址",
                    "detail": f"观测到的 MAC 列表：{sorted(entry['macs'])}",
                    "packet_no": entry["first_no"],
                    "stream_id": -1,
                }
            )

    return alerts

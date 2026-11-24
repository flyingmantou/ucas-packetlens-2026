"""Security alerts from decoded packets and reassembled TCP streams."""

import re

CRED_RE = re.compile(
    rb"(?i)(authorization:\s*(?:basic|bearer)\s+\S+|(?:password|passwd|pwd|secret|access_token)=[^&\s\r\n]{2,})"
)


def analyze_security(packets, stream_table):
    """Collect security alerts for a capture."""
    alerts = []

    for s in stream_table.streams:
        # TCP reassembly byte conflict (potential IDS/evasion overlap)
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

    # Cleartext HTTP credentials
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

    # SYN Port Scan detection (>=5 distinct dst ports from same src->dst)
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

    # ARP spoofing / IP-to-multiple-MAC conflict
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

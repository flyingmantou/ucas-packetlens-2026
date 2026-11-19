"""Capture only this script's loopback traffic. Run with capture privileges."""

import base64, json, os, platform, queue, socket, sys, threading, time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from packetlens.capture import Worker
from packetlens.pcap import Library
from packetlens.files import write_pcap
from packetlens.streams import StreamTable


def main():
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(1)
    port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    uport = udp.getsockname()[1]
    iface = next(d["name"] for d in Library().devices() if d["loopback"])
    worker = Worker(iface, f"tcp port {port} or udp port {uport}")
    worker.start()
    worker.ready.wait(5)
    if worker.error:
        raise RuntimeError(worker.error)
    request = (
        b"GET /live-proof HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    reply = b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nPacketLens-live-OK!"
    client = socket.create_connection(("127.0.0.1", port))
    server, _ = tcp.accept()
    # Keep endpoints alive across a process snapshot interval.
    time.sleep(1.3)
    client.sendall(request)
    server.recv(4096)
    server.sendall(reply)
    client.recv(4096)
    uclient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uclient.sendto(b"PacketLens-udp-proof", ("127.0.0.1", uport))
    data, addr = udp.recvfrom(4096)
    udp.sendto(data, addr)
    uclient.recvfrom(4096)
    client.close()
    server.close()
    tcp.close()
    udp.close()
    uclient.close()
    time.sleep(0.4)
    worker.stop()
    worker.thread.join(5)
    if worker.thread.is_alive():
        raise RuntimeError("capture worker failed to stop")
    packets = []
    while not worker.queue.empty():
        packets.append(worker.queue.get_nowait())
    streams = StreamTable()
    for p in packets:
        streams.add(p)
    text = "\n".join(s.text() for s in streams.streams)
    checks = {
        "actual_packets": len(packets) > 0,
        "http_request": b"/live-proof" in b"".join(p.payload for p in packets),
        "http_response": "PacketLens-live-OK!" in text,
        "udp_roundtrip": any(
            "udp" in p.layers and p.payload == b"PacketLens-udp-proof" for p in packets
        ),
        "process_attribution": any(p.pid == os.getpid() for p in packets),
        "stopped_cleanly": not worker.error,
    }
    evidence = root / "evidence"
    evidence.mkdir(exist_ok=True)
    write_pcap(evidence / "live-loopback.pcap", packets)
    record = {
        "kind": "real libpcap capture of self-generated loopback traffic",
        "platform": platform.platform(),
        "python": sys.version,
        "libpcap": Library().version().decode("utf-8", "replace"),
        "interface": iface,
        "bpf": worker.bpf,
        "pid": os.getpid(),
        "packet_count": len(packets),
        "tcp_streams": len(streams.streams),
        "protocols": {
            name: sum(p.protocol == name for p in packets)
            for name in sorted({p.protocol for p in packets})
        },
        "checks": checks,
        "statistics": worker.stats,
        "stream_text": text,
    }
    (evidence / "live-results.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("LIVE_RESULT_JSON=" + json.dumps(record, ensure_ascii=False))
    print(
        "LIVE_PCAP_BASE64="
        + base64.b64encode((evidence / "live-loopback.pcap").read_bytes()).decode()
    )
    if not all(checks.values()):
        raise RuntimeError("live integration check failed")


if __name__ == "__main__":
    main()

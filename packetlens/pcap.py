"""Direct ctypes bindings to libpcap/Npcap; no tcpdump subprocess is used."""

import ctypes as C
import ctypes.util
import os
from pathlib import Path
import sys
import time


class CaptureError(RuntimeError):
    pass


class Timeval(C.Structure):
    # macOS 64-bit defines __darwin_suseconds_t as 32-bit int32 with 4-byte tail padding;
    # Linux (LP64) uses 64-bit long and Windows (LLP64) uses 32-bit long for both fields.
    _fields_ = [
        ("sec", C.c_long),
        ("usec", C.c_int32 if sys.platform == "darwin" else C.c_long),
    ]


def _decode_cstr(raw):
    if not raw:
        return ""
    for enc in ("utf-8", "gbk" if sys.platform == "win32" else "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class Header(C.Structure):
    _fields_ = [("ts", Timeval), ("caplen", C.c_uint32), ("length", C.c_uint32)]


class Device(C.Structure):
    pass


Device._fields_ = [
    ("next", C.POINTER(Device)),
    ("name", C.c_char_p),
    ("description", C.c_char_p),
    ("addresses", C.c_void_p),
    ("flags", C.c_uint),
]


class Bpf(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


class Stats(C.Structure):
    # Extra space accommodates platform-specific pcap_stat extensions.
    _fields_ = [
        ("received", C.c_uint),
        ("dropped", C.c_uint),
        ("interface_dropped", C.c_uint),
        ("extra", C.c_uint * 13),
    ]


class Library:
    def __init__(self):
        self.dll_directory = None
        if sys.platform == "win32":
            directory = (
                Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/Npcap"
            )
            if not (directory / "wpcap.dll").exists():
                raise CaptureError(
                    "未找到 Npcap。请从 npcap.com 安装；离线 PCAP 查看仍可使用。"
                )
            self.dll_directory = os.add_dll_directory(str(directory))
            name = str(directory / "wpcap.dll")
        else:
            name = ctypes.util.find_library("pcap")
        if not name:
            raise CaptureError("未找到 libpcap；Linux 请安装 libpcap0.8。")
        self.lib = C.CDLL(name)

        def bind(name, result, args):
            f = getattr(self.lib, name)
            f.restype = result
            f.argtypes = args
            return f

        ptr = C.c_void_p
        char = C.c_char_p
        integer = C.c_int
        self.version = bind("pcap_lib_version", char, [])
        self.find = bind(
            "pcap_findalldevs", integer, [C.POINTER(C.POINTER(Device)), char]
        )
        self.free = bind("pcap_freealldevs", None, [C.POINTER(Device)])
        self.create = bind("pcap_create", ptr, [char, char])
        self.close = bind("pcap_close", None, [ptr])
        self.activate = bind("pcap_activate", integer, [ptr])
        self.error = bind("pcap_geterr", char, [ptr])
        self.dlt = bind("pcap_datalink", integer, [ptr])
        self.next = bind(
            "pcap_next_ex",
            integer,
            [ptr, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))],
        )
        self.nonblock = bind("pcap_setnonblock", integer, [ptr, integer, char])
        self.compile = bind(
            "pcap_compile", integer, [ptr, C.POINTER(Bpf), char, integer, C.c_uint32]
        )
        self.setfilter = bind("pcap_setfilter", integer, [ptr, C.POINTER(Bpf)])
        self.freecode = bind("pcap_freecode", None, [C.POINTER(Bpf)])
        self.stats = bind("pcap_stats", integer, [ptr, C.POINTER(Stats)])
        self.dead = bind("pcap_open_dead", ptr, [integer, integer])
        self.offline_filter = bind(
            "pcap_offline_filter",
            C.c_uint,
            [C.POINTER(Bpf), C.POINTER(Header), C.POINTER(C.c_ubyte)],
        )
        for setting in [
            "snaplen",
            "promisc",
            "timeout",
            "buffer_size",
            "immediate_mode",
        ]:
            name = "pcap_set_" + setting
            if hasattr(self.lib, name):
                bind(name, integer, [ptr, integer])

    def devices(self):
        head = C.POINTER(Device)()
        err = C.create_string_buffer(256)
        if self.find(C.byref(head), err) < 0:
            raise CaptureError(_decode_cstr(err.value))
        result = []
        try:
            p = head
            while p:
                d = p.contents
                result.append(
                    {
                        "name": _decode_cstr(d.name),
                        "description": _decode_cstr(d.description),
                        "loopback": bool(d.flags & 1),
                    }
                )
                p = d.next
        finally:
            self.free(head)
        return result

    def matches(self, expression, raw, linktype=1):
        """Use actual libpcap BPF compiler against an offline packet (no privilege)."""
        handle = self.dead(linktype, 65535)
        if not handle:
            raise CaptureError("pcap_open_dead failed")
        program = Bpf()
        try:
            if (
                self.compile(
                    handle, C.byref(program), expression.encode(), 1, 0xFFFFFFFF
                )
                < 0
            ):
                raise CaptureError(self.error(handle).decode(errors="replace"))
            header = Header(Timeval(0, 0), len(raw), len(raw))
            buf = (C.c_ubyte * len(raw)).from_buffer_copy(raw)
            return bool(self.offline_filter(C.byref(program), C.byref(header), buf))
        finally:
            if program.instructions:
                self.freecode(C.byref(program))
            self.close(handle)


class Capture:
    def __init__(self, interface, bpf="", promiscuous=False, snaplen=65535):
        self.api = Library()
        self.handle = None
        self.warning = ""
        err = C.create_string_buffer(256)
        handle = self.api.create(interface.encode(), err)
        if not handle:
            raise CaptureError(err.value.decode(errors="replace"))
        self.handle = handle
        try:
            for key, value in [
                ("snaplen", snaplen),
                ("promisc", int(promiscuous)),
                ("timeout", 100),
                ("buffer_size", 4 * 1024 * 1024),
                ("immediate_mode", 1),
            ]:
                f = getattr(self.api.lib, "pcap_set_" + key, None)
                if f and f(handle, value) != 0:
                    raise CaptureError(f"pcap_set_{key} failed")
            result = self.api.activate(handle)
            if result < 0:
                raise CaptureError(self.api.error(handle).decode(errors="replace"))
            if result > 0:
                self.warning = self.api.error(handle).decode(errors="replace")
            self.linktype = self.api.dlt(handle)
            if bpf:
                program = Bpf()
                try:
                    if (
                        self.api.compile(
                            handle, C.byref(program), bpf.encode(), 1, 0xFFFFFFFF
                        )
                        < 0
                    ):
                        raise CaptureError(
                            self.api.error(handle).decode(errors="replace")
                        )
                    if self.api.setfilter(handle, C.byref(program)) < 0:
                        raise CaptureError(
                            self.api.error(handle).decode(errors="replace")
                        )
                finally:
                    if program.instructions:
                        self.api.freecode(C.byref(program))
            if self.api.nonblock(handle, 1, err) < 0:
                raise CaptureError(err.value.decode(errors="replace"))
        except Exception:
            self.close()
            raise

    def read(self):
        header = C.POINTER(Header)()
        payload = C.POINTER(C.c_ubyte)()
        result = self.api.next(self.handle, C.byref(header), C.byref(payload))
        if result == 0:
            return None
        if result != 1:
            raise CaptureError(self.api.error(self.handle).decode(errors="replace"))
        h = header.contents
        if h.caplen > 65535:
            raise CaptureError("Captured packet exceeds configured snaplen")
        return h.ts.sec + h.ts.usec / 1e6, C.string_at(payload, h.caplen), h.length

    def statistics(self):
        stats = Stats()
        if self.api.stats(self.handle, C.byref(stats)) < 0:
            return {"available": False}
        return {
            "available": True,
            "received": stats.received,
            "kernel_dropped": stats.dropped,
            "interface_dropped": stats.interface_dropped,
        }

    def close(self):
        if self.handle:
            self.api.close(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

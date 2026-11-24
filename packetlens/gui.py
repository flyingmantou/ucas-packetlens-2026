"""Native desktop GUI for real capture, deep NPA, process tracing, and security analysis."""

from collections import Counter
import csv
import json
from pathlib import Path
import queue
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .capture import Worker
from .files import read_pcap, write_pcap, MAX_BYTES, MAX_PACKETS
from .filters import compile_filter
from .intel import analyze_security
from .pcap import Library
from .streams import StreamTable

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"


def _mono_font(size):
    family = "Menlo" if IS_MAC else ("Consolas" if IS_WIN else "DejaVu Sans Mono")
    return (family, size)


def _ui_font(size, weight="normal"):
    family = "Helvetica" if IS_MAC else ("Segoe UI" if IS_WIN else "DejaVu Sans")
    return (family, size, weight) if weight != "normal" else (family, size)


def _accel(key):
    return f"⌘{key}" if IS_MAC else f"Ctrl+{key}"


class App:
    def __init__(self, root, path=None):
        self.root = root
        root.title("PacketLens · 严喆瀚 · 网络报文分析与协议识别")
        root.geometry("1260x840")
        root.minsize(1020, 700)
        self.packets = []
        self.streams = StreamTable()
        self.alerts = []
        self.worker = None
        self.bytes = 0
        self.fn = lambda p: True
        self.shown = 0
        self.last_error = ""
        self.device_map = {}
        self.selected_process_pid = "ALL"
        self.status = tk.StringVar(
            value="就绪 · 可打开示例 PCAP 或选择网卡开始抓包"
        )
        self.iface = tk.StringVar()
        self.bpf = tk.StringVar(value="tcp or udp or icmp or icmp6 or arp")
        self.expr = tk.StringVar()
        self.promisc = tk.BooleanVar(value=False)
        self.diagram_stream_var = tk.StringVar()

        self._build_menu()
        self._build_layout()
        self._bind_shortcuts()

        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()
        self.update_summary()
        root.after(50, self.poll)
        if path:
            self.load(path)

    def _build_menu(self):
        menu = tk.Menu(self.root)
        file_m = tk.Menu(menu, tearoff=False)
        file_m.add_command(
            label="打开 PCAP…", command=self.open, accelerator=_accel("O")
        )
        file_m.add_command(
            label="打开课程示例", command=self.sample, accelerator=_accel("D")
        )
        file_m.add_command(
            label="打开 Linux 实测 PCAP",
            command=lambda: self.load(
                Path(__file__).resolve().parents[1] / "evidence" / "live-loopback.pcap"
            ),
            accelerator=_accel("L"),
        )
        file_m.add_command(label="保存全部 PCAP…", command=self.save)
        file_m.add_command(label="导出显示结果 CSV…", command=self.export)
        file_m.add_separator()
        file_m.add_command(label="退出", command=self.close)
        menu.add_cascade(label="文件", menu=file_m)

        actions = tk.Menu(menu, tearoff=False)
        actions.add_command(label="应用显示过滤", command=self.apply_filter)
        actions.add_command(
            label="查看选中 TCP 流", command=self.follow, accelerator=_accel("T")
        )
        actions.add_separator()
        actions.add_command(
            label="快捷过滤：HTTP",
            command=lambda: self.preset("http"),
            accelerator=_accel("Shift+F"),
        )
        actions.add_command(
            label="快捷过滤：TLS / HTTPS",
            command=lambda: self.preset("tls"),
        )
        actions.add_command(label="显示全部", command=lambda: self.preset(""))
        menu.add_cascade(label="分析", menu=actions)
        self.root.config(menu=menu)

    def _build_layout(self):
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="PacketLens", font=_ui_font(22, "bold")).pack(
            side="left"
        )
        ttk.Label(
            header,
            text="  实时捕获  /  协议分层  /  TLS SNI & JA3  /  进程与流时序追踪",
            foreground="#52606d",
            font=_ui_font(10),
        ).pack(side="left", pady=(8, 0))

        # Capture control bar
        bar = ttk.Frame(outer)
        bar.pack(fill="x")
        ttk.Label(bar, text="网卡").pack(side="left")
        self.interfaces = ttk.Combobox(bar, textvariable=self.iface, width=42)
        self.interfaces.pack(side="left", padx=6)
        ttk.Button(bar, text="刷新", command=self.refresh).pack(side="left")
        ttk.Checkbutton(bar, text="混杂模式", variable=self.promisc).pack(
            side="left", padx=8
        )
        self.start_btn = ttk.Button(bar, text="开始抓包", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(
            bar, text="停止", command=self.stop, state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5)
        ttk.Button(bar, text="示例", command=self.sample).pack(side="right")
        ttk.Button(bar, text="打开 PCAP", command=self.open).pack(side="right", padx=5)

        # BPF capture filter
        row = ttk.Frame(outer)
        row.pack(fill="x", pady=5)
        ttk.Label(row, text="捕获过滤 BPF").pack(side="left")
        ttk.Entry(row, textvariable=self.bpf).pack(
            side="left", fill="x", expand=True, padx=8
        )

        # Display filter
        row = ttk.Frame(outer)
        row.pack(fill="x")
        ttk.Label(row, text="显示过滤").pack(side="left")
        self.filter_entry = ttk.Entry(row, textvariable=self.expr)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=8)
        self.filter_entry.bind("<Return>", lambda e: self.apply_filter())
        ttk.Button(row, text="应用", command=self.apply_filter).pack(side="left")
        ttk.Button(row, text="清除", command=lambda: self.preset("")).pack(
            side="left", padx=(4, 0)
        )
        ttk.Button(row, text="追踪 TCP 流", command=self.follow).pack(
            side="left", padx=5
        )
        ttk.Label(
            outer,
            text='例：http  |  tls.sni contains "ucas"  |  tcp and (port == 8080 or port == 443)  |  contains "GET"',
            foreground="#596575",
            font=_ui_font(9),
        ).pack(anchor="w", pady=(3, 4))

        self.summary = tk.StringVar()
        ttk.Label(
            outer, textvariable=self.summary, font=_ui_font(11, "bold")
        ).pack(anchor="w", pady=(0, 6))

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        self._build_packets_tab()
        self._build_flows_process_tab()
        self._build_sequence_tab()
        self._build_charts_tab()
        self._build_security_tab()

        ttk.Label(
            outer, textvariable=self.status, wraplength=1200, foreground="#384b62"
        ).pack(fill="x", pady=(6, 0))

    def _build_packets_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="报文与解析")

        vsplit = ttk.Panedwindow(frame, orient="vertical")
        vsplit.pack(fill="both", expand=True)

        top = ttk.Frame(vsplit)
        columns = (
            "no",
            "time",
            "src",
            "dst",
            "protocol",
            "length",
            "stream",
            "pid",
            "info",
        )
        self.tree = ttk.Treeview(top, columns=columns, show="headings", height=12)
        widths = (48, 92, 130, 130, 76, 58, 48, 96, 360)
        for c, title, w in zip(
            columns,
            (
                "序号",
                "相对时间",
                "源地址",
                "目的地址",
                "协议",
                "长度",
                "流",
                "进程 / PID",
                "摘要",
            ),
            widths,
        ):
            self.tree.heading(c, text=title)
            self.tree.column(
                c, width=w, minwidth=38, stretch=c in ("src", "dst", "info")
            )
        # Wireshark-style soft protocol tinting
        self.tree.tag_configure("http", background="#e8f7ec")
        self.tree.tag_configure("dns", background="#e8f3fc")
        self.tree.tag_configure("tls", background="#f2ecfa")
        self.tree.tag_configure("icmp", background="#fef4e8")
        self.tree.tag_configure("arp", background="#e8f8f7")
        self.tree.tag_configure("warn", background="#fdeaea")

        scroll = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.select)
        self.tree.bind("<Double-1>", lambda e: self.follow())
        vsplit.add(top, weight=3)

        lower = ttk.Panedwindow(vsplit, orient="horizontal")
        # Collapsible protocol detail tree (left)
        detail_wrap = ttk.Frame(lower)
        self.detail_tree = ttk.Treeview(
            detail_wrap, columns=("val",), show="tree headings", height=11
        )
        self.detail_tree.heading("#0", text="协议层级 / 字段")
        self.detail_tree.heading("val", text="解析值")
        self.detail_tree.column("#0", width=210, minwidth=140)
        self.detail_tree.column("val", width=340, minwidth=180, stretch=True)
        dscroll = ttk.Scrollbar(
            detail_wrap, orient="vertical", command=self.detail_tree.yview
        )
        self.detail_tree.configure(yscrollcommand=dscroll.set)
        dscroll.pack(side="right", fill="y")
        self.detail_tree.pack(fill="both", expand=True)
        lower.add(detail_wrap, weight=1)

        # Hex / ASCII view (right)
        hex_wrap = ttk.Frame(lower)
        self.hex = tk.Text(
            hex_wrap,
            height=11,
            width=58,
            font=_mono_font(10),
            wrap="none",
            state="disabled",
        )
        hscroll = ttk.Scrollbar(hex_wrap, orient="vertical", command=self.hex.yview)
        self.hex.configure(yscrollcommand=hscroll.set)
        hscroll.pack(side="right", fill="y")
        self.hex.pack(fill="both", expand=True)
        lower.add(hex_wrap, weight=1)

        vsplit.add(lower, weight=2)

    def _build_flows_process_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="TCP 流与进程追踪")

        split = ttk.Panedwindow(tab, orient="vertical")
        split.pack(fill="both", expand=True, padx=4, pady=4)

        # Top: OS Process Aggregation (commview-style bonus feature)
        proc_box = ttk.LabelFrame(split, text="按进程聚合追踪（点击进程筛选其全部 TCP 流）")
        pbar = ttk.Frame(proc_box)
        pbar.pack(fill="x", padx=4, pady=3)
        ttk.Button(
            pbar, text="显示全部进程流", command=self._show_all_process_streams
        ).pack(side="left")
        ttk.Button(
            pbar, text="在报文页按选中进程过滤", command=self._filter_by_selected_process
        ).pack(side="left", padx=6)

        pcols = ("pid", "name", "streams", "packets", "bytes", "protocols")
        self.proc_tree = ttk.Treeview(
            proc_box, columns=pcols, show="headings", height=6
        )
        for c, t, w in zip(
            pcols,
            ("PID", "进程名", "TCP 流数", "总报文数", "总字节数", "涉及协议 / 识别结果"),
            (80, 160, 80, 85, 100, 380),
        ):
            self.proc_tree.heading(c, text=t)
            self.proc_tree.column(c, width=w, stretch=c in ("name", "protocols"))
        ps = ttk.Scrollbar(proc_box, orient="vertical", command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=ps.set)
        ps.pack(side="right", fill="y")
        self.proc_tree.pack(fill="both", expand=True)
        self.proc_tree.bind("<<TreeviewSelect>>", self._on_process_select)
        split.add(proc_box, weight=2)

        # Bottom: TCP Stream table
        stream_box = ttk.LabelFrame(
            split, text="TCP 流列表（双击查看双向重组，单击更新时序图）"
        )
        sbar = ttk.Frame(stream_box)
        sbar.pack(fill="x", padx=4, pady=3)
        ttk.Button(
            sbar, text="打开选中流重组", command=self._follow_selected_stream
        ).pack(side="left")
        ttk.Button(
            sbar, text="查看选中流时序图", command=self._view_selected_stream_diagram
        ).pack(side="left", padx=6)
        ttk.Button(
            sbar, text="在报文页过滤该流", command=self._filter_selected_stream
        ).pack(side="left")

        scols = (
            "id",
            "client",
            "server",
            "packets",
            "bytes",
            "duration",
            "process",
            "sni",
            "protocol",
        )
        self.stream_tree = ttk.Treeview(
            stream_box, columns=scols, show="headings", height=10
        )
        for c, t, w in zip(
            scols,
            (
                "流号",
                "客户端",
                "服务端",
                "报文数",
                "字节数",
                "持续时间",
                "进程",
                "TLS SNI",
                "协议",
            ),
            (52, 165, 165, 65, 80, 88, 120, 150, 195),
        ):
            self.stream_tree.heading(c, text=t)
            self.stream_tree.column(
                c, width=w, stretch=c in ("client", "server", "sni", "protocol")
            )
        ss = ttk.Scrollbar(
            stream_box, orient="vertical", command=self.stream_tree.yview
        )
        self.stream_tree.configure(yscrollcommand=ss.set)
        ss.pack(side="right", fill="y")
        self.stream_tree.pack(fill="both", expand=True)
        self.stream_tree.bind("<Double-1>", lambda e: self._follow_selected_stream())
        self.stream_tree.bind("<<TreeviewSelect>>", self._on_stream_select)
        split.add(stream_box, weight=3)

    def _build_sequence_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="流时序图")
        ctrl = ttk.Frame(tab, padding=6)
        ctrl.pack(fill="x")
        ttk.Label(ctrl, text="选择 TCP 流：").pack(side="left")
        self.diagram_combo = ttk.Combobox(
            ctrl, textvariable=self.diagram_stream_var, state="readonly", width=65
        )
        self.diagram_combo.pack(side="left", padx=6)
        self.diagram_combo.bind("<<ComboboxSelected>>", lambda e: self._draw_sequence())
        ttk.Button(ctrl, text="刷新时序图", command=self._draw_sequence).pack(
            side="left", padx=4
        )

        wrap = ttk.Frame(tab)
        wrap.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.seq_canvas = tk.Canvas(wrap, bg="#fbfdff", highlightthickness=1, highlightbackground="#d0dce6")
        vbar = ttk.Scrollbar(wrap, orient="vertical", command=self.seq_canvas.yview)
        self.seq_canvas.configure(yscrollcommand=vbar.set)
        vbar.pack(side="right", fill="y")
        self.seq_canvas.pack(fill="both", expand=True)
        self.seq_canvas.bind("<Configure>", lambda e: self._draw_sequence())

    def _build_charts_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="流量统计与图表")
        self.chart_canvas = tk.Canvas(
            tab, bg="#ffffff", highlightthickness=0
        )
        self.chart_canvas.pack(fill="both", expand=True, padx=8, pady=8)
        self.chart_canvas.bind("<Configure>", lambda e: self._draw_charts())

    def _build_security_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="安全告警")
        split = ttk.Panedwindow(tab, orient="vertical")
        split.pack(fill="both", expand=True, padx=6, pady=6)

        top = ttk.Frame(split)
        bar = ttk.Frame(top)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Label(
            bar,
            text="明文凭据、端口扫描、ARP 地址冲突与 TCP 重叠冲突（双击告警可定位）",
            foreground="#465868",
        ).pack(side="left")

        acols = ("severity", "category", "title", "target")
        self.alert_tree = ttk.Treeview(top, columns=acols, show="headings", height=11)
        for c, t, w in zip(
            acols,
            ("级别", "类别", "检出摘要", "关联报文 / 流"),
            (65, 175, 480, 140),
        ):
            self.alert_tree.heading(c, text=t)
            self.alert_tree.column(c, width=w, stretch=c == "title")
        self.alert_tree.tag_configure("高", background="#fdeaea")
        self.alert_tree.tag_configure("中", background="#fff4dc")
        self.alert_tree.tag_configure("低", background="#eef5fc")
        asc = ttk.Scrollbar(top, orient="vertical", command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=asc.set)
        asc.pack(side="right", fill="y")
        self.alert_tree.pack(fill="both", expand=True)
        self.alert_tree.bind("<<TreeviewSelect>>", self._on_alert_select)
        self.alert_tree.bind("<Double-1>", self._on_alert_jump)
        split.add(top, weight=3)

        self.alert_detail = tk.Text(
            split, height=8, font=_mono_font(10), wrap="word", state="disabled"
        )
        split.add(self.alert_detail, weight=2)

    def _bind_shortcuts(self):
        for mod in ("Command", "Control"):
            self.root.bind(f"<{mod}-o>", lambda e: self.open())
            self.root.bind(f"<{mod}-d>", lambda e: self.sample())
            self.root.bind(f"<{mod}-t>", lambda e: self.follow())
            self.root.bind(f"<{mod}-Shift-F>", lambda e: self.preset("http"))
            self.root.bind(
                f"<{mod}-l>",
                lambda e: self.load(
                    Path(__file__).resolve().parents[1]
                    / "evidence"
                    / "live-loopback.pcap"
                ),
            )

    def settext(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text.replace("\r\n", "\n").replace("\r", "\\r"))
        widget.config(state="disabled")

    def active(self):
        return self.worker and self.worker.thread.is_alive()

    def refresh(self):
        try:
            devices = Library().devices()
            self.device_map = {}
            labels = []
            default_label = ""
            for d in devices:
                desc = d.get("description", "").strip()
                label = f"{desc} ({d['name']})" if desc and desc != d["name"] else d["name"]
                self.device_map[label] = d["name"]
                labels.append(label)
                if d.get("loopback") and not default_label:
                    default_label = label
            self.interfaces["values"] = labels
            if labels:
                self.iface.set(default_label or labels[0])
        except Exception as e:
            self.status.set(str(e))

    def _selected_interface_name(self):
        raw = self.iface.get().strip()
        return self.device_map.get(raw, raw)

    def reset(self):
        self.packets = []
        self.streams = StreamTable()
        self.alerts = []
        self.bytes = 0
        self.selected_process_pid = "ALL"
        self.tree.delete(*self.tree.get_children())
        self.shown = 0
        self.detail_tree.delete(*self.detail_tree.get_children())
        self.settext(self.hex, "")
        self.settext(self.alert_detail, "")

    def start(self):
        if self.active():
            return
        if self.packets and not messagebox.askyesno(
            "开始新的捕获", "开始后将清空当前内存中的报文。需要保留时请先保存 PCAP。"
        ):
            return
        self.reset()
        iface_name = self._selected_interface_name()
        self.worker = Worker(iface_name, self.bpf.get(), self.promisc.get())
        self.worker.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.set(f"正在打开捕获设备 {iface_name}…")

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.status.set("正在停止并保存统计…")

    def append(self, p):
        if len(self.packets) >= MAX_PACKETS or self.bytes + len(p.raw) > MAX_BYTES:
            self.stop()
            self.status.set("达到 5000 包或 64 MiB 上限，已请求停止")
            return
        p.number = len(self.packets) + 1
        self.packets.append(p)
        self.bytes += len(p.raw)
        self.streams.add(p)
        if self.fn(p):
            self.row(p)

    def _row_tag(self, p):
        if p.warning or ("tcp" in p.layers and (p.flags & 0x04)):
            return ("warn",)
        proto = p.protocol.lower()
        if proto in ("http", "dns", "tls", "icmp", "icmpv6", "arp"):
            return ("icmp" if proto == "icmpv6" else proto,)
        return ()

    def row(self, p):
        proc_col = (
            f"{p.process}({p.pid})"
            if p.pid is not None and p.process
            else (str(p.pid) if p.pid is not None else "—")
        )
        self.tree.insert(
            "",
            "end",
            iid=str(p.number),
            tags=self._row_tag(p),
            values=(
                p.number,
                f"{p.timestamp - self.packets[0].timestamp:.6f}",
                p.src,
                p.dst,
                p.protocol,
                p.wirelen,
                p.stream if p.stream >= 0 else "—",
                proc_col,
                p.info + (" ⚠ " + p.warning if p.warning else ""),
            ),
        )
        self.shown += 1

    def update_summary(self):
        self.alerts = analyze_security(self.packets, self.streams)

        counts = Counter(p.protocol for p in self.packets)
        self.summary.set(
            f"已捕获 / 导入 {len(self.packets)} 包   显示 {self.shown} 包   TCP 流 {len(self.streams.streams)}   "
            f"安全告警 {len(self.alerts)}   原始数据 {self.bytes:,} B   |  "
            + "  ".join(f"{k} {v}" for k, v in counts.most_common(8))
        )
        self._update_process_and_streams_views()
        self._update_security_view()
        self._draw_sequence()
        self._draw_charts()

    def _update_process_and_streams_views(self):
        self.proc_tree.delete(*self.proc_tree.get_children())
        for g in self.streams.process_summary():
            iid = "NONE" if g["pid"] is None else str(g["pid"])
            self.proc_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    g["pid"] if g["pid"] is not None else "—",
                    g["name"],
                    len(g["stream_ids"]),
                    g["packets"],
                    f"{g['bytes']:,}",
                    ", ".join(sorted(g["protocols"]))[:80],
                ),
            )
        self._populate_stream_table()

        choices = [
            f"流 #{s.id} | {s.client_endpoint[0]}:{s.client_endpoint[1]} ↔ {s.server_endpoint[0]}:{s.server_endpoint[1]} ({s.protocol_label})"
            for s in self.streams.streams
            if s.client_endpoint and s.server_endpoint
        ]
        self.diagram_combo["values"] = choices
        if choices and self.diagram_stream_var.get() not in choices:
            self.diagram_stream_var.set(choices[0])
        elif not choices:
            self.diagram_stream_var.set("")

    def _populate_stream_table(self):
        self.stream_tree.delete(*self.stream_tree.get_children())
        for s in self.streams.streams:
            if self.selected_process_pid != "ALL":
                if self.selected_process_pid is None and s.pids:
                    continue
                if (
                    self.selected_process_pid is not None
                    and self.selected_process_pid not in s.pids
                ):
                    continue
            ce = (
                f"{s.client_endpoint[0]}:{s.client_endpoint[1]}"
                if s.client_endpoint
                else "—"
            )
            se = (
                f"{s.server_endpoint[0]}:{s.server_endpoint[1]}"
                if s.server_endpoint
                else "—"
            )
            self.stream_tree.insert(
                "",
                "end",
                iid=str(s.id),
                values=(
                    s.id,
                    ce,
                    se,
                    s.packets,
                    f"{s.wire_bytes:,}",
                    f"{s.last - s.first:.4f}s",
                    s.process_label(),
                    s.tls_sni or "—",
                    s.protocol_label,
                ),
            )

    def _update_security_view(self):
        self.alert_tree.delete(*self.alert_tree.get_children())
        for idx, a in enumerate(self.alerts):
            target = (
                f"流 #{a['stream_id']} / 包 #{a['packet_no']}"
                if a["stream_id"] >= 0
                else f"包 #{a['packet_no']}"
            )
            self.alert_tree.insert(
                "",
                "end",
                iid=str(idx),
                tags=(a["severity"],),
                values=(a["severity"], a["category"], a["title"], target),
            )
        if not self.alerts:
            self.settext(self.alert_detail, "当前会话暂无安全告警。")

    def _draw_sequence(self):
        c = self.seq_canvas
        c.delete("all")
        sel = self.diagram_stream_var.get()
        if not sel or not self.streams.streams:
            c.create_text(
                360,
                140,
                text="暂无可绘制的 TCP 流（请先打开示例 PCAP 或开始抓包）",
                fill="#607080",
                font=_ui_font(12),
            )
            return
        try:
            sid = int(sel.split("|")[0].replace("流 #", "").strip())
            s = self.streams.streams[sid]
        except Exception:
            return

        w = max(840, c.winfo_width() - 20)
        left_x = 180
        right_x = w - 180
        top_y = 58
        row_h = 40
        total_h = max(360, top_y + len(s.timeline) * row_h + 70)
        c.configure(scrollregion=(0, 0, w, total_h))

        ce = f"{s.client_endpoint[0]}:{s.client_endpoint[1]}"
        se = f"{s.server_endpoint[0]}:{s.server_endpoint[1]}"
        c.create_text(
            w // 2,
            18,
            text=f"TCP 流 #{s.id} 时序图 · {s.protocol_label} · 进程：{s.process_label()}",
            font=_ui_font(11, "bold"),
            fill="#16334a",
        )
        c.create_rectangle(left_x - 110, 34, left_x + 110, 62, fill="#e3effa", outline="#4a80b5")
        c.create_text(left_x, 48, text=f"Client {ce}", font=_ui_font(9, "bold"), fill="#16334a")
        c.create_rectangle(right_x - 110, 34, right_x + 110, 62, fill="#e6f4ea", outline="#438d5b")
        c.create_text(right_x, 48, text=f"Server {se}", font=_ui_font(9, "bold"), fill="#1a472a")

        c.create_line(left_x, 62, left_x, total_h - 24, fill="#9eb0c0", dash=(4, 3), width=2)
        c.create_line(right_x, 62, right_x, total_h - 24, fill="#9eb0c0", dash=(4, 3), width=2)

        for i, ev in enumerate(s.timeline):
            y = top_y + 34 + i * row_h
            c.create_text(
                52,
                y,
                text=f"#{ev['no']} +{ev['rel_time']:.3f}s",
                font=_mono_font(9),
                fill="#5a6b7a",
            )
            is_c2s = ev["dir"] == 0
            x1, x2 = (left_x, right_x) if is_c2s else (right_x, left_x)
            color = "#1f6f9f" if is_c2s else "#2d7d46"
            if "RST" in ev["flags"]:
                color = "#c0392b"
            elif ev["protocol"] == "TLS":
                color = "#6b46c1" if is_c2s else "#4c51bf"
            c.create_line(x1, y, x2, y, arrow=tk.LAST, width=2, fill=color)
            label = ev["info"]
            if len(label) > 68:
                label = label[:65] + "..."
            c.create_text(
                (left_x + right_x) // 2,
                y - 12,
                text=f"[{ev['protocol']}] {label}",
                font=_mono_font(9),
                fill=color,
            )

    def _draw_charts(self):
        c = self.chart_canvas
        c.delete("all")
        w = max(860, c.winfo_width())
        h = max(420, c.winfo_height())
        if not self.packets:
            c.create_text(
                w // 2,
                h // 2,
                text="暂无流量统计数据（请先打开示例 PCAP 或开始实时抓包）",
                fill="#607080",
                font=_ui_font(12),
            )
            return

        # Left half: Protocol distribution horizontal bar chart
        mid = w // 2
        c.create_text(
            24, 24, anchor="w", text="协议分布统计（按报文数）", font=_ui_font(12, "bold"), fill="#16334a"
        )
        counts = Counter(p.protocol for p in self.packets).most_common(10)
        palette = {
            "HTTP": "#2e8b57",
            "TLS": "#6b46c1",
            "DNS": "#2563eb",
            "TCP": "#3b82f6",
            "UDP": "#0ea5e9",
            "ICMP": "#ea580c",
            "ICMPv6": "#f97316",
            "ARP": "#0d9488",
        }
        max_cnt = max(v for _, v in counts) or 1
        bar_max_w = max(140, mid - 210)
        total_pkts = len(self.packets)
        for i, (proto, cnt) in enumerate(counts):
            y = 64 + i * 34
            bw = max(6, int(bar_max_w * cnt / max_cnt))
            color = palette.get(proto, "#64748b")
            c.create_text(24, y + 10, anchor="w", text=proto, font=_mono_font(10), fill="#1e293b")
            c.create_rectangle(105, y, 105 + bw, y + 20, fill=color, outline="")
            pct = cnt * 100.0 / total_pkts
            c.create_text(
                113 + bw,
                y + 10,
                anchor="w",
                text=f"{cnt} ({pct:.1f}%)",
                font=_mono_font(9),
                fill="#334155",
            )

        # Right half: Timeline packet volume bar chart
        rx0 = mid + 24
        rw = max(240, w - rx0 - 36)
        ry0 = 64
        rh = min(260, h - 130)
        c.create_text(
            rx0, 24, anchor="w", text="时间线吞吐分布（报文数 / 时间片）", font=_ui_font(12, "bold"), fill="#16334a"
        )
        t0 = self.packets[0].timestamp
        t1 = self.packets[-1].timestamp
        span = max(t1 - t0, 1e-6)
        buckets = 16
        counts_b = [0] * buckets
        bytes_b = [0] * buckets
        for p in self.packets:
            bi = min(buckets - 1, int((p.timestamp - t0) / span * buckets))
            counts_b[bi] += 1
            bytes_b[bi] += p.wirelen
        max_b = max(counts_b) or 1
        c.create_rectangle(rx0, ry0, rx0 + rw, ry0 + rh, outline="#cbd5e1", fill="#f8fafc")
        col_w = rw / buckets
        for bi, val in enumerate(counts_b):
            bh = int((rh - 24) * val / max_b) if val else 0
            x1 = rx0 + bi * col_w + 4
            x2 = rx0 + (bi + 1) * col_w - 4
            y2 = ry0 + rh
            y1 = y2 - bh
            if bh:
                c.create_rectangle(x1, y1, x2, y2, fill="#0284c7", outline="")
                c.create_text((x1 + x2) / 2, y1 - 8, text=str(val), font=_mono_font(8), fill="#0f172a")
        c.create_text(rx0, ry0 + rh + 14, anchor="w", text="0.00s", font=_mono_font(9), fill="#64748b")
        c.create_text(
            rx0 + rw, ry0 + rh + 14, anchor="e", text=f"{t1 - t0:.2f}s (总字节 {self.bytes:,} B)", font=_mono_font(9), fill="#64748b"
        )

    def _on_process_select(self, event=None):
        sel = self.proc_tree.selection()
        if not sel:
            return
        iid = sel[0]
        self.selected_process_pid = None if iid == "NONE" else int(iid)
        self._populate_stream_table()

    def _show_all_process_streams(self):
        self.selected_process_pid = "ALL"
        self.proc_tree.selection_remove(self.proc_tree.selection())
        self._populate_stream_table()

    def _filter_by_selected_process(self):
        sel = self.proc_tree.selection()
        if not sel or sel[0] == "NONE":
            messagebox.showinfo("按进程过滤", "请先选择一个带有具体 PID 的进程")
            return
        self._jump_filter(f"pid == {sel[0]}")

    def _on_stream_select(self, event=None):
        sel = self.stream_tree.selection()
        if not sel:
            return
        sid = int(sel[0])
        for item in self.diagram_combo["values"]:
            if item.startswith(f"流 #{sid} "):
                self.diagram_stream_var.set(item)
                self._draw_sequence()
                break

    def _follow_selected_stream(self):
        sel = self.stream_tree.selection()
        if not sel:
            messagebox.showinfo("TCP 流", "请先在下方列表选择一条 TCP 流")
            return
        self._open_stream_window(int(sel[0]))

    def _view_selected_stream_diagram(self):
        self._on_stream_select()
        self.notebook.select(2)

    def _filter_selected_stream(self):
        sel = self.stream_tree.selection()
        if not sel:
            return
        self._jump_filter(f"stream == {sel[0]}")

    def _jump_filter(self, expr):
        self.notebook.select(0)
        self.preset(expr)

    def _on_alert_select(self, event=None):
        sel = self.alert_tree.selection()
        if not sel:
            return
        a = self.alerts[int(sel[0])]
        text = (
            f"【{a['severity']}风险 · {a['category']}】\n"
            f"标题：{a['title']}\n"
            f"详情：{a['detail']}\n"
            f"定位：报文 #{a['packet_no']}"
            + (f"，TCP 流 #{a['stream_id']}" if a["stream_id"] >= 0 else "")
        )
        self.settext(self.alert_detail, text)

    def _on_alert_jump(self, event=None):
        sel = self.alert_tree.selection()
        if not sel:
            return
        a = self.alerts[int(sel[0])]
        if a["stream_id"] >= 0:
            self._open_stream_window(a["stream_id"])
        elif a["packet_no"] > 0:
            self.notebook.select(0)
            iid = str(a["packet_no"])
            if self.tree.exists(iid):
                self.tree.selection_set(iid)
                self.tree.see(iid)
                self.select()

    def poll(self):
        changed = False
        if self.worker:
            for _ in range(200):
                try:
                    self.append(self.worker.queue.get_nowait())
                    changed = True
                except queue.Empty:
                    break
            if not self.worker.thread.is_alive() and self.worker.queue.empty():
                w = self.worker
                self.worker = None
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
                self.status.set(
                    (w.error or w.status)
                    + " | "
                    + json.dumps(w.stats, ensure_ascii=False)
                )
                self.last_error = w.error
                self.update_summary()
            elif self.worker:
                self.status.set(
                    f"{self.worker.status} · 应用队列丢包 {self.worker.queue_dropped}"
                )
        if changed:
            self.update_summary()
        self.root.after(50, self.poll)

    def open(self):
        path = filedialog.askopenfilename(
            filetypes=[("PCAP", "*.pcap"), ("所有文件", "*")]
        )
        if path:
            self.load(path)

    def sample(self):
        self.load(Path(__file__).resolve().parents[1] / "samples" / "course-demo.pcap")

    def load(self, path):
        if self.active():
            messagebox.showinfo("正在捕获", "请先停止抓包")
            return
        try:
            packets = read_pcap(path)
        except Exception as e:
            messagebox.showerror("无法打开", str(e))
            return
        self.reset()
        for p in packets:
            self.append(p)
        self.update_summary()
        self.status.set(
            f"离线 PCAP · {Path(path).name} · PID 不包含在 PCAP 中，无法追溯历史进程"
        )
        if self.tree.get_children():
            self.tree.selection_set(self.tree.get_children()[0])
            self.select()

    def preset(self, text):
        self.expr.set(text)
        self.apply_filter()

    def apply_filter(self):
        try:
            fn = compile_filter(self.expr.get())
        except ValueError as e:
            messagebox.showerror("过滤表达式无效", str(e))
            return
        self.fn = fn
        self.tree.delete(*self.tree.get_children())
        self.shown = 0
        for p in self.packets:
            if fn(p):
                self.row(p)
        self.update_summary()
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.select()
        else:
            self.detail_tree.delete(*self.detail_tree.get_children())
            self.settext(self.hex, "")

    def _insert_tree_nodes(self, parent, value):
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, (dict, list)):
                    node = self.detail_tree.insert(
                        parent,
                        "end",
                        text=str(k),
                        values=(f"({len(v)} 项)",),
                        open=len(v) <= 6,
                    )
                    self._insert_tree_nodes(node, v)
                else:
                    disp = str(v).replace("\r\n", " | ").replace("\n", " | ")
                    self.detail_tree.insert(parent, "end", text=str(k), values=(disp,))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, (dict, list)):
                    node = self.detail_tree.insert(
                        parent, "end", text=f"[{i}]", values=("",), open=i < 3
                    )
                    self._insert_tree_nodes(node, item)
                else:
                    self.detail_tree.insert(
                        parent, "end", text=f"[{i}]", values=(str(item),)
                    )

    def select(self, event=None):
        ids = self.tree.selection()
        if not ids:
            return
        p = self.packets[int(ids[0]) - 1]
        self.detail_tree.delete(*self.detail_tree.get_children())

        frame_node = self.detail_tree.insert(
            "",
            "end",
            text=f"Frame #{p.number}",
            values=(f"{p.wirelen} bytes on wire, captured {len(p.raw)} B, DLT={p.linktype}",),
            open=True,
        )
        self.detail_tree.insert(frame_node, "end", text="警告", values=(p.warning or "无",))
        self.detail_tree.insert(
            frame_node,
            "end",
            text="进程归属",
            values=(
                f"{p.process} (PID={p.pid})" if p.pid is not None else (p.process or "未知"),
            ),
        )

        for layer_name, layer_val in p.details.items():
            summary = ""
            if layer_name == "TCP" and isinstance(layer_val, dict):
                summary = f"{layer_val.get('src_port')} → {layer_val.get('dst_port')} [{layer_val.get('flags_str', '')}]"
            elif layer_name == "TLS" and isinstance(layer_val, dict):
                summary = f"{layer_val.get('version', '')} {layer_val.get('handshake', layer_val.get('record_type_name', ''))}"
            elif layer_name == "IPv4" and isinstance(layer_val, dict):
                summary = f"{p.src} → {p.dst} (TTL={layer_val.get('ttl')}, Cksum={'OK' if layer_val.get('checksum_valid') else 'ERR'})"
            node = self.detail_tree.insert(
                "", "end", text=layer_name, values=(summary,), open=True
            )
            self._insert_tree_nodes(node, layer_val)

        self.settext(
            self.hex,
            "\n".join(
                f'{i:04x}  {p.raw[i:i+16].hex(" "):<47}  '
                + "".join(chr(b) if 32 <= b < 127 else "." for b in p.raw[i : i + 16])
                for i in range(0, len(p.raw), 16)
            ),
        )

    def _open_stream_window(self, stream_id):
        if stream_id < 0 or stream_id >= len(self.streams.streams):
            return
        win = tk.Toplevel(self.root)
        win.title(f"TCP 流 {stream_id} · 双向重组与协议详情")
        win.geometry("920x620")
        text = tk.Text(win, font=_mono_font(11), wrap="word")
        text.pack(fill="both", expand=True, padx=12, pady=12)
        self.settext(text, self.streams.streams[stream_id].text())

    def follow(self):
        ids = self.tree.selection()
        if not ids:
            messagebox.showinfo("追踪 TCP 流", "先选择一个 TCP 报文")
            return
        p = self.packets[int(ids[0]) - 1]
        if p.stream < 0:
            messagebox.showinfo("追踪 TCP 流", "当前报文不是 TCP")
            return
        self._open_stream_window(p.stream)

    def save(self):
        path = filedialog.asksaveasfilename(defaultextension=".pcap")
        if path:
            try:
                write_pcap(path, self.packets)
                self.status.set("已保存全部报文：" + path)
            except Exception as e:
                messagebox.showerror("保存失败", str(e))

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(
                    [
                        "number",
                        "time",
                        "source",
                        "destination",
                        "protocol",
                        "length",
                        "stream",
                        "pid",
                        "process",
                        "sni",
                        "info",
                    ]
                )
                for p in self.packets:
                    if self.fn(p):
                        w.writerow(
                            [
                                p.number,
                                p.timestamp,
                                p.src,
                                p.dst,
                                p.protocol,
                                p.wirelen,
                                p.stream,
                                p.pid,
                                p.process,
                                p.sni,
                                (
                                    "'" + p.info
                                    if p.info.startswith(("=", "+", "-", "@"))
                                    else p.info
                                ),
                            ]
                        )
            self.status.set("已导出当前显示结果")

    def close(self):
        if self.worker:
            self.worker.stop()
            self.worker.thread.join(3)
        self.root.destroy()


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--open")
    args = parser.parse_args()
    root = tk.Tk()
    App(root, args.open)
    root.mainloop()


if __name__ == "__main__":
    main()

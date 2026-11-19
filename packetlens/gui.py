"""Native desktop GUI for real capture and reproducible offline analysis."""
import csv
import json
from pathlib import Path
import queue
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from .capture import Worker
from .files import read_pcap,write_pcap,MAX_BYTES,MAX_PACKETS
from .filters import compile_filter
from .pcap import Library
from .streams import StreamTable

class App:
    def __init__(self,root,path=None):
        self.root=root;root.title('PacketLens · 严喆瀚 · 网络报文分析');root.geometry('1180x800');root.minsize(980,680)
        self.packets=[];self.streams=StreamTable();self.worker=None;self.bytes=0;self.fn=lambda p:True;self.shown=0;self.last_error=''
        self.status=tk.StringVar(value='就绪 · 可打开示例 PCAP 或选择网卡开始抓包')
        self.iface=tk.StringVar();self.bpf=tk.StringVar(value='tcp or udp or icmp or icmp6 or arp');self.expr=tk.StringVar();self.promisc=tk.BooleanVar(value=False)
        menu=tk.Menu(root);file=tk.Menu(menu,tearoff=False);file.add_command(label='打开 PCAP…',command=self.open,accelerator='⌘O');file.add_command(label='打开课程示例',command=self.sample,accelerator='⌘D');file.add_command(label='打开 Linux 实测 PCAP',command=lambda:self.load(Path(__file__).resolve().parents[1]/'evidence'/'live-loopback.pcap'),accelerator='⌘L');file.add_command(label='保存全部 PCAP…',command=self.save);file.add_command(label='导出显示结果 CSV…',command=self.export);file.add_separator();file.add_command(label='退出',command=self.close);menu.add_cascade(label='文件',menu=file)
        actions=tk.Menu(menu,tearoff=False);actions.add_command(label='应用显示过滤',command=self.apply_filter);actions.add_command(label='查看选中 TCP 流',command=self.follow,accelerator='⌘T');actions.add_command(label='示例 HTTP 过滤',command=lambda:self.preset('http'),accelerator='⌘⇧F');actions.add_command(label='显示全部',command=lambda:self.preset(''));menu.add_cascade(label='分析',menu=actions);root.config(menu=menu)
        outer=ttk.Frame(root,padding=14);outer.pack(fill='both',expand=True)
        ttk.Label(outer,text='PacketLens',font=('Helvetica',25,'bold')).pack(anchor='w')
        ttk.Label(outer,text='实时捕获  /  协议分层  /  TCP 流重组',foreground='#596575').pack(anchor='w',pady=(0,10))
        bar=ttk.Frame(outer);bar.pack(fill='x');ttk.Label(bar,text='网卡').pack(side='left');self.interfaces=ttk.Combobox(bar,textvariable=self.iface,width=37);self.interfaces.pack(side='left',padx=7);ttk.Button(bar,text='刷新',command=self.refresh).pack(side='left');ttk.Checkbutton(bar,text='混杂模式',variable=self.promisc).pack(side='left',padx=8);self.start_btn=ttk.Button(bar,text='开始抓包',command=self.start);self.start_btn.pack(side='left');self.stop_btn=ttk.Button(bar,text='停止',command=self.stop,state='disabled');self.stop_btn.pack(side='left',padx=5);ttk.Button(bar,text='示例',command=self.sample).pack(side='right');ttk.Button(bar,text='打开 PCAP',command=self.open).pack(side='right',padx=5)
        row=ttk.Frame(outer);row.pack(fill='x',pady=6);ttk.Label(row,text='捕获过滤 BPF').pack(side='left');ttk.Entry(row,textvariable=self.bpf).pack(side='left',fill='x',expand=True,padx=8)
        row=ttk.Frame(outer);row.pack(fill='x');ttk.Label(row,text='显示过滤').pack(side='left');self.filter_entry=ttk.Entry(row,textvariable=self.expr);self.filter_entry.pack(side='left',fill='x',expand=True,padx=8);self.filter_entry.bind('<Return>',lambda e:self.apply_filter());ttk.Button(row,text='应用',command=self.apply_filter).pack(side='left');ttk.Button(row,text='追踪 TCP 流',command=self.follow).pack(side='left',padx=5)
        ttk.Label(outer,text='例：tcp and (port == 8080 or port == 443)    |    http    |    ipv6    |    contains "GET"',foreground='#596575').pack(anchor='w',pady=5)
        self.summary=tk.StringVar();ttk.Label(outer,textvariable=self.summary,font=('Helvetica',12,'bold')).pack(anchor='w',pady=(0,7))
        notebook=ttk.Notebook(outer);notebook.pack(fill='both',expand=True)
        frame=ttk.Frame(notebook);notebook.add(frame,text='报文与解析')
        columns=('no','time','src','dst','protocol','length','stream','pid','info');self.tree=ttk.Treeview(frame,columns=columns,show='headings',height=10)
        widths=(45,95,125,125,70,60,55,55,300)
        for c,title,w in zip(columns,('序号','相对时间','源地址','目的地址','协议','长度','流','PID','摘要'),widths):self.tree.heading(c,text=title);self.tree.column(c,width=w,minwidth=35,stretch=c in ('src','dst','info'))
        scroll=ttk.Scrollbar(frame,orient='vertical',command=self.tree.yview);self.tree.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');self.tree.pack(fill='both',expand=True);self.tree.bind('<<TreeviewSelect>>',self.select)
        lower=ttk.Panedwindow(frame,orient='horizontal');lower.pack(fill='both',expand=True,pady=6)
        self.details=tk.Text(lower,height=11,width=55,font=('Menlo',10),wrap='word',state='disabled');self.hex=tk.Text(lower,height=11,width=55,font=('Menlo',10),wrap='none',state='disabled');lower.add(self.details,weight=1);lower.add(self.hex,weight=1)
        flow=ttk.Frame(notebook);notebook.add(flow,text='TCP 流统计');self.flowtext=tk.Text(flow,font=('Menlo',11),state='disabled',wrap='word');self.flowtext.pack(fill='both',expand=True)
        ttk.Label(outer,textvariable=self.status,wraplength=1120,foreground='#384b62').pack(fill='x',pady=(7,0))
        root.bind('<Command-o>',lambda e:self.open());root.bind('<Control-o>',lambda e:self.open());root.bind('<Command-d>',lambda e:self.sample());root.bind('<Control-d>',lambda e:self.sample());root.bind('<Command-t>',lambda e:self.follow());root.bind('<Command-Shift-F>',lambda e:self.preset('http'));root.bind('<Command-l>',lambda e:self.load(Path(__file__).resolve().parents[1]/'evidence'/'live-loopback.pcap'));root.protocol('WM_DELETE_WINDOW',self.close)
        self.refresh();self.update_summary();root.after(50,self.poll)
        if path:self.load(path)
    def settext(self,widget,text):widget.config(state='normal');widget.delete('1.0','end');widget.insert('1.0',text.replace('\r\n','\n').replace('\r','\\r'));widget.config(state='disabled')
    def active(self):return self.worker and self.worker.thread.is_alive()
    def refresh(self):
        try:
            devices=Library().devices();self.interfaces['values']=[d['name'] for d in devices]
            if devices:self.iface.set(next((d['name'] for d in devices if d['loopback']),devices[0]['name']))
        except Exception as e:self.status.set(str(e))
    def reset(self):
        self.packets=[];self.streams=StreamTable();self.bytes=0;self.tree.delete(*self.tree.get_children());self.shown=0;self.settext(self.details,'');self.settext(self.hex,'')
    def start(self):
        if self.active():return
        if self.packets and not messagebox.askyesno('开始新的捕获','开始后将清空当前内存中的报文。需要保留时请先保存 PCAP。'):return
        self.reset();self.worker=Worker(self.iface.get(),self.bpf.get(),self.promisc.get());self.worker.start();self.start_btn.config(state='disabled');self.stop_btn.config(state='normal');self.status.set('正在打开捕获设备…')
    def stop(self):
        if self.worker:self.worker.stop();self.status.set('正在停止并保存统计…')
    def append(self,p):
        if len(self.packets)>=MAX_PACKETS or self.bytes+len(p.raw)>MAX_BYTES:
            self.stop();self.status.set('达到 5000 包或 64 MiB 上限，已请求停止');return
        p.number=len(self.packets)+1;self.packets.append(p);self.bytes+=len(p.raw);self.streams.add(p)
        if self.fn(p):self.row(p)
    def row(self,p):
        self.tree.insert('', 'end',iid=str(p.number),values=(p.number,f'{p.timestamp-self.packets[0].timestamp:.6f}',p.src,p.dst,p.protocol,p.wirelen,p.stream if p.stream>=0 else '—',p.pid or '—',p.info+(' ⚠ '+p.warning if p.warning else '')));self.shown+=1
    def update_summary(self):
        from collections import Counter
        counts=Counter(p.protocol for p in self.packets)
        self.summary.set(f'已捕获 / 导入 {len(self.packets)} 包     显示 {self.shown} 包     TCP 流 {len(self.streams.streams)}     原始数据 {self.bytes:,} B     '+ '  '.join(f'{k} {v}' for k,v in counts.items()))
        lines=['流号   报文数   字节数   持续时间   端点 / 进程']
        for s in self.streams.streams:lines.append(f'{s.id:<6} {s.packets:<8} {s.wire_bytes:<9} {s.last-s.first:.6f}s   {s.key}   PID={sorted(s.pids) or "未知"}')
        self.settext(self.flowtext,'\n\n'.join(lines))
    def poll(self):
        changed=False
        if self.worker:
            for _ in range(200):
                try:self.append(self.worker.queue.get_nowait());changed=True
                except queue.Empty:break
            if not self.worker.thread.is_alive() and self.worker.queue.empty():
                w=self.worker;self.worker=None;self.start_btn.config(state='normal');self.stop_btn.config(state='disabled');self.status.set((w.error or w.status)+' | '+json.dumps(w.stats,ensure_ascii=False));self.last_error=w.error
            elif self.worker:self.status.set(f'{self.worker.status} · 应用队列丢包 {self.worker.queue_dropped}')
        if changed:self.update_summary()
        self.root.after(50,self.poll)
    def open(self):
        path=filedialog.askopenfilename(filetypes=[('PCAP','*.pcap'),('所有文件','*')])
        if path:self.load(path)
    def sample(self):self.load(Path(__file__).resolve().parents[1]/'samples'/'course-demo.pcap')
    def load(self,path):
        if self.active():messagebox.showinfo('正在捕获','请先停止抓包');return
        try:packets=read_pcap(path)
        except Exception as e:messagebox.showerror('无法打开',str(e));return
        self.reset()
        for p in packets:self.append(p)
        self.update_summary();self.status.set(f'离线 PCAP · {Path(path).name} · PID 不包含在 PCAP 中，无法追溯历史进程')
        if self.tree.get_children():self.tree.selection_set(self.tree.get_children()[0]);self.select()
    def preset(self,text):self.expr.set(text);self.apply_filter()
    def apply_filter(self):
        try:fn=compile_filter(self.expr.get())
        except ValueError as e:messagebox.showerror('过滤表达式无效',str(e));return
        self.fn=fn;self.tree.delete(*self.tree.get_children());self.shown=0
        for p in self.packets:
            if fn(p):self.row(p)
        self.update_summary()
    def select(self,event=None):
        ids=self.tree.selection()
        if not ids:return
        p=self.packets[int(ids[0])-1];self.settext(self.details,json.dumps(p.details,ensure_ascii=False,indent=2)+'\n\n警告：'+(p.warning or '无')+'\n进程：'+(p.process or '未知'))
        self.settext(self.hex,'\n'.join(f'{i:04x}  {p.raw[i:i+16].hex(" "):<47}  '+''.join(chr(b) if 32<=b<127 else '.' for b in p.raw[i:i+16]) for i in range(0,len(p.raw),16)))
    def follow(self):
        ids=self.tree.selection()
        if not ids:messagebox.showinfo('追踪 TCP 流','先选择一个 TCP 报文');return
        p=self.packets[int(ids[0])-1]
        if p.stream<0:messagebox.showinfo('追踪 TCP 流','当前报文不是 TCP');return
        win=tk.Toplevel(self.root);win.title(f'TCP 流 {p.stream} · 双向重组');win.geometry('900x600');text=tk.Text(win,font=('Menlo',12),wrap='word');text.pack(fill='both',expand=True,padx=12,pady=12);self.settext(text,self.streams.streams[p.stream].text())
    def save(self):
        path=filedialog.asksaveasfilename(defaultextension='.pcap')
        if path:
            try:write_pcap(path,self.packets);self.status.set('已保存全部报文：'+path)
            except Exception as e:messagebox.showerror('保存失败',str(e))
    def export(self):
        path=filedialog.asksaveasfilename(defaultextension='.csv')
        if path:
            with open(path,'w',encoding='utf-8-sig',newline='') as f:
                w=csv.writer(f);w.writerow(['number','time','source','destination','protocol','length','stream','pid','info'])
                for p in self.packets:
                    if self.fn(p):w.writerow([p.number,p.timestamp,p.src,p.dst,p.protocol,p.wirelen,p.stream,p.pid,"'"+p.info if p.info.startswith(('=','+','-','@')) else p.info])
            self.status.set('已导出当前显示结果')
    def close(self):
        if self.worker:self.worker.stop();self.worker.thread.join(3)
        self.root.destroy()

def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--open');args=parser.parse_args();root=tk.Tk();App(root,args.open);root.mainloop()
if __name__=='__main__':main()

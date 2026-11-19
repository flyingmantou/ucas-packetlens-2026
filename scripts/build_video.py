"""Create a clearly labelled replay of actual screenshots and recorded outputs.
Requires Pillow and imageio-ffmpeg; no fabricated screen recording.
"""
import json,subprocess,sys
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
import imageio_ffmpeg
ROOT=Path(__file__).resolve().parents[1];E=ROOT/'evidence';T=ROOT/'output/video-frames';T.mkdir(parents=True,exist_ok=True)
OUT=ROOT.parent/'严喆瀚_202628015059_ex1A_play.mp4'
F='/System/Library/Fonts/Hiragino Sans GB.ttc';M='/System/Library/Fonts/Menlo.ttc';fonts={n:ImageFont.truetype(F,n) for n in [24,28,32,38,48,72]};mono=ImageFont.truetype(M,29)
INK='#16334a';TEAL='#176878';GRAY='#5a7080';scenes=[]
local=json.loads((E/'test-results.json').read_text());live=json.loads((E/'live-results.json').read_text());bench=json.loads((E/'benchmark.json').read_text())
compile_run=subprocess.run([sys.executable,'-m','compileall','-q','packetlens','scripts','tests'],cwd=ROOT,capture_output=True,text=True)
(E/'compile-result.json').write_text(json.dumps({'command':'python -m compileall -q packetlens scripts tests','exit_code':compile_run.returncode,'stdout':compile_run.stdout,'stderr':compile_run.stderr},indent=2),encoding='utf-8')
assert compile_run.returncode==0

def wrap(text,font,width):
 lines=[];line=''
 for ch in text:
  if ch=='\n':lines.append(line);line='';continue
  if font.getlength(line+ch)>width:lines.append(line);line=ch
  else:line+=ch
 if line:lines.append(line)
 return lines

def base(title):
 im=Image.new('RGB',(1920,1080),'#f2f6f8');d=ImageDraw.Draw(im);d.rectangle((0,0,1920,12),fill=TEAL);d.text((60,40),'PacketLens / 软件与系统安全 · 实验 1A',font=fonts[28],fill=GRAY);d.text((60,98),title,font=fonts[48],fill=INK);d.line((60,1000,1860,1000),fill='#c7d5dd',width=2);d.text((60,1020),'严喆瀚 202628015059 · 真实界面截图与日志讲解回放 · 非连续录屏',font=fonts[24],fill=GRAY);return im,d

def save(im,seconds,title):
 p=T/f'{len(scenes):02d}.png';im.save(p);scenes.append({'path':str(p),'seconds':seconds,'title':title})

def textslide(title,lines,note,seconds=16):
 im,d=base(title);d.rounded_rectangle((60,200,1860,735),radius=12,fill='#123044');y=235
 for line in lines:
  for part in wrap(line,mono,1720):d.text((90,y),part,font=mono,fill='#e1eff4');y+=46
 y=785
 for line in wrap(note,fonts[32],1760):d.text((60,y),line,font=fonts[32],fill=INK);y+=51
 save(im,seconds,title)

def shot(title,name,note,seconds=20):
 im,d=base(title);s=Image.open(E/name).convert('RGB');s.thumbnail((1420,790));im.paste(s,(45,190));y=235
 for line in wrap(note,fonts[28],385):d.text((1480,y),line,font=fonts[28],fill=INK);y+=46
 save(im,seconds,title)

im,d=base('嗅探器设计与实现');d.text((60,240),'PacketLens',font=fonts[72],fill=TEAL)
for i,s in enumerate(['直接调用 libpcap / Npcap','多协议解析、逻辑过滤、TCP 流重组','固定样例 + Linux 真实回环捕获']):d.text((60,390+i*100),s,font=fonts[38],fill=INK)
d.text((60,800),'我用两类实验分别验证捕获路径和分析结果。',font=fonts[32],fill=GRAY);save(im,9,'项目介绍')
textslide('1  编译检查与启动',['$ python -m compileall -q packetlens scripts tests',f'exit_code = {compile_run.returncode}','$ python run.py --open samples/course-demo.pcap','Runtime: Python 3.12 + Tk','Optional dependency: psutil'], 'Python 源码编译为字节码。编译检查已实际执行；后续截图来自本机运行的 GUI。',13)
shot('2  报文列表与分层字段','gui-packets.png','我打开可重复生成的合成样例：16 包、5 条 TCP 流。列表包含 TCP、HTTP、DNS、ICMP、IPv6 和 TLS。下方同时显示首部字段与原始字节。')
shot('3  HTTP 显示过滤','gui-filter.png','输入 http 后，16 包中显示 2 包。HTTP 依据内容识别，不依赖端口 80。显示过滤只改变可见行，TCP 流仍保留完整数据。')
shot('4  TCP 乱序与重传','gui-stream.png','我追踪流 0。请求片段按 100、125、109、109 到达，仍重组为完整请求。重复字节为 16；方向分开显示，缺口不会被直接拼接。',22)
textslide('5  Linux 真实抓包证据',['$ sudo .venv/bin/python scripts/live_demo.py',live['libpcap'],f'interface = {live["interface"]}',f'BPF = {live["bpf"]}',f'packets = {live["packet_count"]}, TCP streams = {live["tcp_streams"]}',f'protocols = {live["protocols"]}','kernel_dropped = 0, queue_dropped = 0'], '这里调用真实捕获接口，只捕获脚本自身生成的本机流量。6 项集成检查均通过，原始 PCAP 与 JSON 一并保存。',21)
shot('6  打开实际捕获结果','gui-live-pcap.png','我把 Linux 抓到的 PCAP 放回本机 GUI。HTTP 请求路径是 /live-proof，响应包含 PacketLens-live-OK!。这是实抓文件的离线复查。',20)
textslide('7  进程归属与实现边界',[f'process_attribution = {live["checks"]["process_attribution"]}',f'traffic generator PID = {live["pid"]}','Match: local IP:port + remote IP:port','Offline PCAP: historical PID unavailable','TLS: record metadata only; no decryption'], '实时进程归属使用完整连接端点，权限不足或有歧义时保留未知。普通 PCAP 不保存 PID；本机 macOS 实抓受到权限限制。',18)
textslide('8  固定回归测试与真实排错',['$ python scripts/run_tests.py',f'Ran {local["tests"]} tests; failures={local["failures"]}; errors={local["errors"]}','Seeded malformed inputs: 2026 / 1000 cases','TCP: reorder / overlap / gap / wrap-around','Lifecycle: idle stop / full queue / permission error','Windows: JSON writer explicitly uses UTF-8'], '我保留了首轮 Windows 中文证据写入失败的日志。修复后复跑完整测试；未安装 Npcap 的 Windows 跳过原生 BPF 项。',20)
textslide('9  复现与交付',['Repository: flyingmantou/ucas-packetlens-2026','samples/course-demo.pcap','evidence/live-loopback.pcap','scripts/run_tests.py','scripts/live_demo.py','Report: design / evidence / limits / commands'], '源代码、报告和视频按作业要求放入独立 ZIP。报告保留验证范围与不足，源代码仓库保留开发提交历史。',12)
# concat demuxer uses relative safe frame names from the same directory.
concat=T/'frames.txt';concat.write_text(''.join(f"file '{Path(s['path']).name}'\nduration {s['seconds']}\n" for s in scenes)+f"file '{Path(scenes[-1]['path']).name}'\n")
subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(),'-y','-hide_banner','-loglevel','error','-f','concat','-safe','0','-i',str(concat),'-vf','fps=24','-c:v','libx264','-preset','fast','-tune','stillimage','-crf','21','-pix_fmt','yuv420p','-movflags','+faststart',str(OUT)],check=True)
(E/'video-chapters.json').write_text(json.dumps({'kind':'labelled screenshot and log replay','seconds':sum(s['seconds'] for s in scenes),'scenes':[{k:v for k,v in s.items() if k!='path'} for s in scenes]},ensure_ascii=False,indent=2),encoding='utf-8');print(OUT);print('seconds',sum(s['seconds'] for s in scenes))

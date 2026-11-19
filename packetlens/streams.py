"""Directional TCP sequence reconstruction, with explicit gaps and conflicts."""
from dataclasses import dataclass,field

@dataclass
class Direction:
    anchor: object=None
    segments:list=field(default_factory=list)
    stored:int=0
    omitted:int=0
    def add(self,p):
        start=(p.seq+(1 if p.flags&2 else 0))&0xffffffff
        if self.anchor is None:self.anchor=start
        if not p.payload:return
        if self.stored+len(p.payload)>262144:self.omitted+=len(p.payload);return
        offset=((start-self.anchor+2**31)%2**32)-2**31
        self.segments.append((offset,p.payload));self.stored+=len(p.payload)
    def reconstruct(self):
        cells={};duplicates=0;conflicts=0
        # First observation wins. Sorting only after resolving overlaps preserves policy.
        for offset,data in self.segments:
            for j,b in enumerate(data):
                pos=offset+j
                if pos in cells:
                    duplicates+=1;conflicts+=cells[pos]!=b
                else:cells[pos]=b
        chunks=[];gaps=[];start=None;last=None;buf=bytearray()
        for pos in sorted(cells):
            if last is not None and pos!=last+1:
                chunks.append((start,bytes(buf)));buf.clear();gaps.append((last+1,pos));start=None
            if start is None:start=pos
            buf.append(cells[pos]);last=pos
        if buf:chunks.append((start,bytes(buf)))
        return {'chunks':chunks,'gaps':gaps,'duplicate_bytes':duplicates,'conflict_bytes':conflicts,'omitted_bytes':self.omitted}

@dataclass
class Stream:
    id:int
    key:tuple
    directions:dict=field(default_factory=dict)
    packets:int=0
    wire_bytes:int=0
    first:float=0
    last:float=0
    syn:object=None
    pids:set=field(default_factory=set)
    def add(self,p):
        p.stream=self.id;self.packets+=1;self.wire_bytes+=p.wirelen
        if self.packets==1:self.first=p.timestamp
        self.last=p.timestamp
        if p.pid is not None:self.pids.add(p.pid)
        if p.flags&2 and not p.flags&16:self.syn=(p.src,p.sport,p.seq)
        direction=(p.src,p.sport,p.dst,p.dport)
        self.directions.setdefault(direction,Direction()).add(p)
    def text(self):
        parts=[f'TCP stream {self.id} | packets={self.packets} bytes={self.wire_bytes}']
        for direction,d in self.directions.items():
            r=d.reconstruct();parts.append(f'\n{direction[0]}:{direction[1]} → {direction[2]}:{direction[3]}')
            parts.append(f'duplicate_bytes={r["duplicate_bytes"]}, conflict_bytes={r["conflict_bytes"]}, omitted_bytes={r["omitted_bytes"]}')
            previous=None
            for start,data in r['chunks']:
                if previous is not None:parts.append(f'\n[缺失 {start-previous} 字节，未拼接]\n')
                parts.append(data.decode('utf-8','replace'));previous=start+len(data)
        return '\n'.join(parts)

class StreamTable:
    def __init__(self):self.streams=[];self.current={}
    def add(self,p):
        if 'tcp' not in p.layers:return
        s=self.current.get(p.key)
        syn=(p.src,p.sport,p.seq)
        if s is None or (p.flags&2 and not p.flags&16 and s.syn is not None and s.syn!=syn):
            s=Stream(len(self.streams),p.key);self.streams.append(s);self.current[p.key]=s
        s.add(p)

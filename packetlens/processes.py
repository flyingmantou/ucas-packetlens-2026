"""Best-effort exact connected-socket mapping; never infer a PID by port alone."""
import time
class ProcessMap:
    def __init__(self,provider=None):
        self.provider=provider;self.mapping={};self.status='尚未查询';self.updated=0
    def refresh(self):
        try:
            if self.provider:
                records=self.provider()
            else:
                import psutil
                records=psutil.net_connections(kind='tcp')
            mapping={}
            for c in records:
                if not c.laddr or not c.raddr or c.pid is None:continue
                key=tuple(sorted(((str(c.laddr[0]),c.laddr[1]),(str(c.raddr[0]),c.raddr[1]))))
                mapping.setdefault(key,set()).add(c.pid)
            self.mapping=mapping;self.status='连接快照可用'
        except Exception as e:self.mapping={};self.status=f'进程归属不可用：{type(e).__name__}'
        self.updated=time.monotonic()
    def attach(self,p):
        if 'tcp' not in p.layers:return
        pids=self.mapping.get(p.key,set())
        if len(pids)==1:
            p.pid=next(iter(pids))
            try:
                import psutil
                p.process=psutil.Process(p.pid).name()
            except Exception:p.process='未知名称'
        elif len(pids)>1:p.process='多进程共享此连接，未唯一归属'

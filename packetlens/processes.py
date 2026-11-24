"""Best-effort exact connected-socket mapping with cached process names."""

import time


class ProcessMap:
    def __init__(self, provider=None, refresh_interval=0.25, miss_cooldown=0.12):
        self.provider = provider
        self.refresh_interval = refresh_interval
        self.miss_cooldown = miss_cooldown
        self.mapping = {}
        self.name_cache = {}
        self.status = "尚未查询"
        self.updated = 0.0

    def refresh(self):
        try:
            if self.provider:
                records = self.provider()
            else:
                import psutil

                records = psutil.net_connections(kind="tcp")
            mapping = {}
            for c in records:
                if not c.laddr or not c.raddr or c.pid is None:
                    continue
                key = tuple(
                    sorted(
                        ((str(c.laddr[0]), c.laddr[1]), (str(c.raddr[0]), c.raddr[1]))
                    )
                )
                mapping.setdefault(key, set()).add(c.pid)
            self.mapping = mapping
            self.status = "连接快照可用"
        except Exception as e:
            self.mapping = {}
            self.status = f"进程归属不可用：{type(e).__name__}"
        self.updated = time.monotonic()

    def _resolve_name(self, pid):
        now = time.monotonic()
        cached = self.name_cache.get(pid)
        if cached and now - cached[1] < 10.0:
            return cached[0]
        try:
            import psutil

            name = psutil.Process(pid).name()
        except Exception:
            name = "未知名称"
        self.name_cache[pid] = (name, now)
        return name

    def attach(self, p):
        if "tcp" not in p.layers:
            return
        pids = self.mapping.get(p.key)
        if pids is None and self.provider is None:
            if time.monotonic() - self.updated >= self.miss_cooldown:
                self.refresh()
                pids = self.mapping.get(p.key)
        if not pids:
            return
        if len(pids) == 1:
            p.pid = next(iter(pids))
            p.process = self._resolve_name(p.pid)
        elif len(pids) > 1:
            p.process = "多进程共享此连接，未唯一归属"

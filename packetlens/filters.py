"""Small typed recursive-descent display-filter language, never eval."""

import ipaddress
import re

TOKEN = re.compile(r'\s*(>=|<=|==|!=|>|<|\(|\)|"[^"\r\n]*"|[^\s()=!<>]+)')
PROTOCOLS = set("ethernet arp ip ipv4 ipv6 tcp udp icmp icmpv6 http dns tls".split())
FIELDS = set("ip.addr ip.src ip.dst tcp.port udp.port port len stream pid".split())


def compile_filter(source):
    if len(source) > 2048:
        raise ValueError("过滤表达式过长")
    source = source.strip()
    if not source:
        return lambda p: True
    tokens = []
    pos = 0
    while pos < len(source):
        m = TOKEN.match(source, pos)
        if not m:
            raise ValueError(f"无法识别字符 {pos}")
        tokens.append(m.group(1))
        pos = m.end()
    if len(tokens) > 256:
        raise ValueError("过滤表达式过于复杂")
    idx = 0

    def peek():
        return tokens[idx] if idx < len(tokens) else None

    def take():
        nonlocal idx
        if peek() is None:
            raise ValueError("过滤表达式不完整")
        t = tokens[idx]
        idx += 1
        return t

    def atom(depth):
        if depth > 24:
            raise ValueError("括号或 not 嵌套过深")
        t = take()
        if t == "not":
            f = atom(depth + 1)
            return lambda p: not f(p)
        if t == "(":
            f = expr(depth + 1)
            if take() != ")":
                raise ValueError("缺少右括号")
            return f
        if t in PROTOCOLS:
            return lambda p: t in p.layers
        if t == "contains":
            v = take()
            if not (v.startswith('"') and v.endswith('"')):
                raise ValueError("contains 后需要双引号文本")
            b = v[1:-1].encode()
            return lambda p: b in p.payload
        if t not in FIELDS:
            raise ValueError(f"未知字段 {t}")
        op = take()
        v = take()
        if op not in ("==", "!=", ">", "<", ">=", "<="):
            raise ValueError("需要比较运算符")
        if t.startswith("ip."):
            if op not in ("==", "!="):
                raise ValueError("IP 地址只支持 == 或 !=")
            try:
                v = str(ipaddress.ip_address(v))
            except ValueError:
                raise ValueError("IP 地址格式错误")
        else:
            try:
                v = int(v)
            except ValueError:
                raise ValueError("需要整数")
            if v < 0 or (t.endswith("port") and v > 65535):
                raise ValueError("数值超出范围")

        def test(p):
            if t.startswith("tcp.") and "tcp" not in p.layers:
                return False
            if t.startswith("udp.") and "udp" not in p.layers:
                return False
            vals = {
                "ip.addr": (p.src, p.dst),
                "ip.src": (p.src,),
                "ip.dst": (p.dst,),
                "port": (p.sport, p.dport),
                "tcp.port": (p.sport, p.dport),
                "udp.port": (p.sport, p.dport),
                "len": (p.wirelen,),
                "stream": (p.stream,),
                "pid": (p.pid,),
            }[t]
            vals = tuple(x for x in vals if x is not None and x != "")
            if not vals:
                return False
            if op == "!=":
                return all(x != v for x in vals)
            return any(
                {
                    "==": lambda: x == v,
                    ">": lambda: x > v,
                    "<": lambda: x < v,
                    ">=": lambda: x >= v,
                    "<=": lambda: x <= v,
                }[op]()
                for x in vals
            )

        return test

    def conj(depth):
        f = atom(depth)
        while peek() == "and":
            take()
            g = atom(depth)
            f = (lambda a, b: lambda p: a(p) and b(p))(f, g)
        return f

    def expr(depth):
        f = conj(depth)
        while peek() == "or":
            take()
            g = conj(depth)
            f = (lambda a, b: lambda p: a(p) or b(p))(f, g)
        return f

    result = expr(0)
    if peek() is not None:
        raise ValueError(f"多余内容 {peek()}")
    return result

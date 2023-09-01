import json
import os
import re
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import reduce, wraps
from inspect import Parameter, signature
from ipaddress import ip_network
from itertools import chain
from math import log
from operator import getitem
from random import choices, randint
from string import ascii_lowercase
from threading import RLock
from typing import AnyStr, Callable, Hashable, Iterable, Iterator, TypeVar
from urllib.parse import (parse_qs, parse_qsl, quote, unquote_plus, urlencode,
                          urlsplit, urlunsplit)

T = TypeVar('T')

re_non_empty_base64 = re.compile(rb'^(?=[\da-z+/]+={0,2}$)(?:.{4})+$', re.I)
re_cfg_item_or_k = re.compile(r'^\s*((?:(?: {2,})?[^#;\s](?: ?\S)*)+)', re.M)
re_cfg_item_v_sep = re.compile(r' {2,}')
re_cfg_k = re.compile(r'\[(.+?)\]')
re_cfg_illegal = re.compile(r'[\r\n ]+')
re_sort_key = re.compile(r'(\D+)(\d+)')
re_time = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)([-+]\d{2}:\d{2})?')
re_traffic = re.compile(r'([-+]?\d+(?:\.\d+)?)\s*([BKMGTPE])?', re.I)


# 文件读写删


def read(path, b=False, reader=None):
    if os.path.isfile(path):
        with (open(path, 'rb') if b or reader else open(path, 'r', encoding='utf8')) as f:
            return reader(f) if reader else f.read()
    return None if reader else b'' if b else ''


def write(path, first, *rest):
    os.makedirs(os.path.normpath(os.path.dirname(path)), exist_ok=True)
    if hasattr(first, '__call__'):
        with open(path, 'wb') as f:
            first(f)
    else:
        with (open(path, 'w', newline='', encoding='utf8') if isinstance(first, str) else open(path, 'wb')) as f:
            f.write(first)
            f.writelines(rest)


def remove(path):
    if os.path.isfile(path):
        os.remove(path)
    elif os.path.isdir(path):
        os.rmdir(path)


def clear_files(dir_path):
    for path in list_file_paths(dir_path):
        os.remove(path)


def list_paths(dir_path):
    if os.path.exists(dir_path):
        return (os.path.join(dir_path, name) for name in os.listdir(dir_path))
    else:
        return []


def list_file_paths(dir_path):
    return filter(os.path.isfile, list_paths(dir_path))


def list_folder_paths(dir_path):
    return filter(os.path.isdir, list_paths(dir_path))


# 自定义配置文件读写


def read_cfg(path=None, text=None, dict_items=False):
    cfg = defaultdict((lambda: defaultdict(list)) if dict_items else list)
    g = cfg['default']
    for m in re_cfg_item_or_k.finditer(text or read(path)):
        vs = re_cfg_item_v_sep.split(m[1])
        m = re_cfg_k.fullmatch(vs[0])
        if m:
            g = cfg[m[1]]
        elif dict_items:
            g[vs[0]] = vs[1:]
        else:
            g.append(vs)
    return cfg


def write_cfg(path, cfg):
    def lines(items):
        if isinstance(items, list):
            for item in items:
                line = '  '.join(map(_remove_illegal, item)) if isinstance(item, list) else _remove_illegal(item)
                if line:
                    yield line
        elif isinstance(items, dict):
            for k, v in _sort_items(items.items()):
                line = '  '.join(chain([_remove_illegal(k)], map(_remove_illegal, v)
                                 if isinstance(v, list) else [_remove_illegal(v)]))
                if line:
                    yield line
        elif items is not None and item != '':
            yield _remove_illegal(items)

    gs = []
    if isinstance(cfg, dict):
        default = cfg.get('default')
        if default:
            gs.append('\n'.join(lines(default)))
        for k, items in cfg.items():
            if k == 'default':
                continue
            gs.append('\n'.join(chain([f'[{k}]'], lines(items))))
    else:
        gs.append('\n'.join(lines(cfg)))
    write(path, '\n\n'.join(gs), '\n')


def _remove_illegal(v):
    return re_cfg_illegal.sub(' ', str(v).strip())


def _sort_items(items):
    return sorted(items, key=lambda kv: [(s, int(n)) for s, n in re_sort_key.findall(f'a{kv[0]}0')])


################


_NOT_FOUND = object()


def cached(func):
    """双重检查锁装饰器, 支持参数个数为 0 或 1 个 (如 cls 或 self) 的函数"""
    params = signature(func).parameters
    if len(params) > 1:
        raise TypeError('参数个数超过 1 个')
    if params and next(iter(params.values())).kind in (Parameter.VAR_KEYWORD, Parameter.VAR_POSITIONAL):
        raise TypeError('不支持可变参数')

    locks = defaultdict(RLock)
    results = {}

    @wraps(func)
    def wrapper(*args, **kwargs):
        k = _make_key(*args, **kwargs)
        result = results.get(k, _NOT_FOUND)
        if result is _NOT_FOUND:
            try:
                with locks[k]:
                    result = results.get(k, _NOT_FOUND)
                    if result is _NOT_FOUND:
                        result = results[k] = func(*args, **kwargs)
            finally:
                locks.pop(k, None)
        return result

    return wrapper


def _make_key(*args, **kwargs):
    if args:
        k = args[0]
    elif kwargs:
        k = next(iter(kwargs.values()))
    else:
        return _NOT_FOUND
    return k if isinstance(k, Hashable) else id(k)


def rand_id():
    return f'{"".join(choices(ascii_lowercase, k=randint(7, 9)))}{randint(0, 999)}'


def str2timestamp(s):
    if not isinstance(s, str):
        return float(s)
    if not s:
        return 0
    m = re_time.fullmatch(s)
    if not m:
        return float(s)
    try:
        return datetime.fromisoformat(m[1] + (m[2] or '+08:00')).timestamp()
    except ValueError:
        return float(s)


def timestamp2str(t: float):
    return str(datetime.fromtimestamp(t, timezone(timedelta(hours=8))))


def to_zero(t: float):
    return (t - 16 * 3600) // (24 * 3600) * (24 * 3600) + 16 * 3600


def get_name(url: AnyStr) -> str:
    if isinstance(url, bytes):
        url = url.decode()
    split = urlsplit(url)
    match split.scheme:
        case 'vmess':
            return json.loads(b64decode(url[8:]).decode())['ps']
        case 'ssr':
            for k, v in parse_qsl(urlsplit('ssr://' + _decode_ssr(url[6:])).query):
                if k == 'remarks':
                    return _decode_ssr(v)
        case _:
            return unquote_plus(split.fragment)
    return ''


def rename(url: AnyStr, name: str) -> AnyStr:
    is_bytes = isinstance(url, bytes)
    if is_bytes:
        url = url.decode()
    split = urlsplit(url)
    match split.scheme:
        case 'vmess':
            j = json.loads(b64decode(url[8:]).decode())
            j['ps'] = name
            url = url[:8] + b64encode(json.dumps(j, ensure_ascii=False, separators=(',', ':')).encode()).decode()
        case 'ssr':
            split = urlsplit(url[:6] + _decode_ssr(url[6:]))
            q = parse_qs(split.query)
            q['remarks'] = [_encode_ssr(name)]
            split = list(split)
            split[3] = urlencode(q, doseq=True, quote_via=quote)
            url = urlunsplit(split)
            url = url[:6] + _encode_ssr(url[6:])
        case _:
            split = list(split)
            split[-1] = quote(name)
            url = urlunsplit(split)
    return url.encode() if is_bytes else url


def _decode_ssr(en: str):
    return urlsafe_b64decode(en + '=' * (3 - (len(en) - 1) % 4)).decode()


def _encode_ssr(de: str):
    return urlsafe_b64encode(de.encode()).decode().rstrip('=')


def size2str(size):
    size = float(size)
    n = int(size and log(abs(size), 1024))
    return f'{size / 1024 ** n:.4g}{"BKMGTPE"[n]}'


def str2size(s):
    m = re_traffic.match(str(s))
    if not m:
        return 0
    return float(m[1]) * 1024 ** next((i for i, u in enumerate('BKMGTPE') if u == m[2]), 0)


def parallel_map(fn: Callable[..., T], *iterables: Iterable) -> Iterator[T]:
    lists = [[*it] for it in iterables]
    n = min(len(li) for li in lists)
    if n:
        with ThreadPoolExecutor(n) as executor:
            yield from executor.map(fn, *lists)


def get(data, *keys, default=None):
    try:
        return reduce(getitem, keys, data)
    except (KeyError, IndexError, TypeError):
        return default


def g0(cfg: dict, k, default=None):
    item = cfg.get(k)
    if item is None:
        return default
    if not isinstance(item, list):
        return item
    return get(item, 0, default=default)


def keep(d: dict, *ks, getitem=getitem):
    return {k: getitem(d, k) for k in ks if k in d}


################


class IP_CIDR_SegmentTree:
    def __init__(self):
        self.__root = IP_CIDR_SegmentTree._Segment()
        self.__version = -1

    def add(self, address: str) -> bool:
        network = ip_network(address, False)
        if network.version != self.__version:
            if self.__version != -1:
                raise TypeError(f"{address} 的版本 (IPv{network.version}) 与内部的 (IPv{self.__version}) 不一致")
            self.__version = network.version
        prefix = int(network.network_address) >> (network.max_prefixlen - network.prefixlen)
        return self.__root.add(prefix, network.prefixlen)

    class _Segment:
        def __init__(self):
            self.cover = False
            self.children: list[IP_CIDR_SegmentTree._Segment | None] = [None, None]

        def __cover(self):
            self.cover = True
            del self.children

        def add(self, prefix: int, i: int) -> bool:
            if self.cover:
                return False
            if i == 0:
                self.__cover()
                return True
            i -= 1
            b = (prefix >> i) & 1
            child = self.children[b]
            if not child:
                child = self.children[b] = IP_CIDR_SegmentTree._Segment()
            if not child.add(prefix, i):
                return False
            if child.cover:
                child = self.children[b ^ 1]
                if child and child.cover:
                    self.__cover()
            return True


class DOMAIN_SUFFIX_Tree:
    FLAG_DOMAIN = 1
    FLAG_DOMAIN_SUFFIX = 2

    def __init__(self):
        self.__root = DOMAIN_SUFFIX_Tree._Node()

    def add(self, domain: str, suffix=True) -> bool:
        flag = self.FLAG_DOMAIN_SUFFIX if suffix else self.FLAG_DOMAIN
        node = self.__root
        for part in reversed(domain.split('.')):
            node = node.next[part]
            if node.flag == self.FLAG_DOMAIN_SUFFIX:
                return False
        if flag > node.flag:
            node.flag = flag
            if flag == self.FLAG_DOMAIN_SUFFIX:
                del node.next
            return True
        return False

    class _Node:
        def __init__(self):
            self.flag = 0
            self.next = defaultdict(DOMAIN_SUFFIX_Tree._Node)


class AC:
    def __init__(self):
        self.__root = AC._Node()
        self.__size = 0

    def __len__(self):
        return self.__size

    def __next(self, node: 'AC._Node', c) -> 'AC._Node':
        edge = node.edges.get(c)
        return edge.v if edge else self.__root

    def build(self):
        q: deque[AC._Node] = deque()
        for edge in self.__root.edges.values():
            edge.v.fail = self.__root
            q.append(edge.v)
        while q:
            node = q.popleft()
            for c, edge in node.edges.items():
                if not edge.failed:
                    edge.v.fail = self.__next(node.fail, c)
                    q.append(edge.v)
            for c, f_edge in node.fail.edges.items():
                edge = node.edges.get(c)
                if edge:
                    if edge.failed:
                        edge.v = f_edge.v
                else:
                    node.edges[c] = AC._Edge(f_edge.v)

    def add(self, word: str):
        node = self.__root
        for c in word:
            edge = node.edges[c]
            if edge.failed:
                edge.failed = False
                edge.v = AC._Node()
            node = edge.v
        node.end = True
        node.edges.clear()
        self.__size += 1

    def match(self, s: str) -> bool:
        node = self.__root
        for c in s:
            if node.end:
                return True
            node = self.__next(node, c)
        return node.end

    def _eat(self, o: 'AC'):
        self.__root._eat(o.__root)
        self.__size += o.__size

    class _Node:
        def __init__(self):
            self.end = False
            self.fail: AC._Node | None = None
            self.edges = defaultdict(AC._Edge)

        def _eat(self, o: 'AC._Node'):
            for c, o_edge in o.edges.items():
                if not o_edge.failed:
                    edge = self.edges.get(c)
                    if edge and not edge.failed:
                        edge.v._eat(o_edge.v)
                    else:
                        self.edges[c] = o_edge

    class _Edge:
        def __init__(self, fail=None):
            if fail:
                self.failed = True
                self.v = fail
            else:
                self.failed = False
                self.v = AC._Node()


class AC_Online:
    def __init__(self):
        self.__acs: list[AC] = []

    def add(self, word: str):
        acs = self.__acs
        i = len(acs)
        if i == 0 or len(acs[-1]) > 1:
            ac = AC()
            ac.add(word)
            ac.build()
            acs.append(ac)
        else:
            i -= 2
            b = 2
            while i >= 0 and len(acs[i]) == b:
                i -= 1
                b <<= 1
            i += 1
            ac = acs[i]
            for j in range(i + 1, len(acs)):
                ac._eat(acs[j])
            del acs[i + 1:]
            ac.add(word)
            ac.build()

    def match(self, s: str) -> bool:
        return any(ac.match(s) for ac in self.__acs)

"""Synthetic suite (vendored from the 4-hour torture harness, same generators and hidden tests - see docs/arena/EVIDENCE.md).
Seeded generator of graded coding tasks. Each task: starting files (given to the agent), a prompt, a HIDDEN pytest file (never shipped to nodes),
and a reference solution used in preflight to prove the hidden tests pass on a correct solution and fail on the starting files.
Tiers: 1 bugfix, 2 implement-from-spec, 3 multi-file, 4 class/algorithm."""
import random, textwrap

def D(s): return textwrap.dedent(s).lstrip("\n")

def t_median_bug(r):
    m = r.choice(["stats", "agg", "numlib"]); f = r.choice(["median", "mid_value", "center"])
    bad = D(f'''
        def {f}(xs):
            """Return the median of a non-empty list of numbers (mean of the two middle values for even length)."""
            s = sorted(xs)
            return s[len(s) // 2]
        ''')
    good = bad.replace("return s[len(s) // 2]", "n = len(s)\n    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2")
    test = D(f'''
        from {m} import {f}
        def test_odd(): assert {f}([5, 1, 3]) == 3
        def test_even(): assert {f}([4, 1, 3, 2]) == 2.5
        def test_one(): assert {f}([7]) == 7
        def test_unsorted_even(): assert {f}([10, -2, 8, 0]) == 4
        ''')
    return dict(tier=1, files={f"{m}.py": bad}, ref={f"{m}.py": good}, test=test,
                prompt=f"`{m}.py` has a bug in `{f}`: it gives wrong answers for even-length lists. Fix it in place so it returns the true median (mean of the two middle values when the length is even). Keep the name and signature.")

def t_paginate_bug(r):
    m = r.choice(["pager", "paging"]); n = r.choice([10, 20, 25])
    bad = D(f'''
        PAGE_SIZE = {n}
        def page_count(total):
            """Number of pages needed for `total` items."""
            return total // PAGE_SIZE
        def page_slice(items, page):
            """1-based page -> the items on it (empty list when page is out of range)."""
            start = page * PAGE_SIZE
            return items[start:start + PAGE_SIZE]
        ''')
    good = D(f'''
        PAGE_SIZE = {n}
        def page_count(total):
            return (total + PAGE_SIZE - 1) // PAGE_SIZE
        def page_slice(items, page):
            if page < 1: return []
            start = (page - 1) * PAGE_SIZE
            return items[start:start + PAGE_SIZE]
        ''')
    test = D(f'''
        from {m} import page_count, page_slice, PAGE_SIZE
        def test_counts():
            assert page_count(0) == 0 and page_count(1) == 1 and page_count(PAGE_SIZE) == 1 and page_count(PAGE_SIZE + 1) == 2
        def test_slices():
            items = list(range(PAGE_SIZE * 2 + 3))
            assert page_slice(items, 1) == items[:PAGE_SIZE]
            assert page_slice(items, 3) == items[2 * PAGE_SIZE:]
            assert page_slice(items, 4) == [] and page_slice(items, 0) == []
        ''')
    return dict(tier=1, files={f"{m}.py": bad}, ref={f"{m}.py": good}, test=test,
                prompt=f"`{m}.py` has two bugs: `page_count` must round UP, and `page_slice` is documented as 1-based (page 0 or below -> empty list, page 1 -> first PAGE_SIZE items). Fix both in place.")

def t_duration(r):
    m = r.choice(["durations", "timeparse"]); w = r.choice([("w", 604800), ("d", 86400)]);
    stub = D('''
        def parse_duration(text):
            """TODO"""
            raise NotImplementedError
        ''')
    good = D(f'''
        import re
        UNITS = {{"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}}
        def parse_duration(text):
            text = text.strip().lower().replace(" ", "")
            if not text or not re.fullmatch(r"(\\d+[smhdw])+", text): raise ValueError(text)
            return sum(int(n) * UNITS[u] for n, u in re.findall(r"(\\d+)([smhdw])", text))
        ''')
    test = D(f'''
        import pytest
        from {m} import parse_duration
        def test_basic(): assert parse_duration("90s") == 90 and parse_duration("2h") == 7200
        def test_combo(): assert parse_duration("1h30m15s") == 5415
        def test_days_weeks(): assert parse_duration("1w2d") == 604800 + 172800
        def test_spaces_case(): assert parse_duration(" 1H 5M ") == 3900
        @pytest.mark.parametrize("bad", ["", "abc", "10", "5x", "h5", "1.5h"])
        def test_bad(bad):
            with pytest.raises(ValueError): parse_duration(bad)
        ''')
    return dict(tier=2, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `parse_duration(text)` in `{m}.py`. Text is one or more `<integer><unit>` parts, unit in s,m,h,d,w (seconds, minutes, hours, days, weeks). Return total seconds as int. Spaces and upper case are allowed ('1H 5M' -> 3900). Anything else (empty, no unit, unknown unit, decimals, unit before number) raises ValueError. Examples: '1h30m15s' -> 5415, '1w2d' -> 777600.")

def t_rle(r):
    m = r.choice(["rle", "squash"]); sep = r.choice(["#", "~", "|"])
    stub = D('''
        def encode(s):
            raise NotImplementedError
        def decode(s):
            raise NotImplementedError
        ''')
    good = D(f'''
        import re
        def encode(s):
            out = []; i = 0
            while i < len(s):
                j = i
                while j < len(s) and s[j] == s[i]: j += 1
                n = j - i
                out.append(s[i] if n == 1 else f"{{n}}{sep}{{s[i]}}"); i = j
            return "".join(out)
        def decode(s):
            return re.sub(r"(\\d+)[{sep}](.)", lambda m: m.group(2) * int(m.group(1)), s, flags=re.S)
        ''')
    test = D(f'''
        from {m} import encode, decode
        def test_enc(): assert encode("aaabcc") == "3{sep}ab2{sep}c"
        def test_single(): assert encode("abc") == "abc" and encode("") == ""
        def test_dec(): assert decode("3{sep}ab2{sep}c") == "aaabcc"
        def test_long(): assert encode("x" * 12) == "12{sep}x" and decode("12{sep}x") == "x" * 12
        def test_round():
            for s in ["", "a", "aab", "zzzzzzzzzzzzq", "abcabc", "ppppqqqqrrrr"]: assert decode(encode(s)) == s
        ''')
    return dict(tier=2, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement run-length `encode(s)` and `decode(s)` in `{m}.py`. A run of n>=2 identical characters becomes `<n>{sep}<char>` (e.g. 'aaabcc' -> '3{sep}ab2{sep}c'); single characters stay as-is. Input strings contain no digits and no '{sep}'. decode reverses encode exactly.")

def t_intervals(r):
    m = r.choice(["spans", "ranges"]); gap = r.choice([0, 1, 2])
    stub = D('''
        def merge(intervals, gap=0):
            raise NotImplementedError
        ''')
    good = D('''
        def merge(intervals, gap=0):
            out = []
            for a, b in sorted(intervals):
                if out and a <= out[-1][1] + gap: out[-1] = (out[-1][0], max(out[-1][1], b))
                else: out.append((a, b))
            return out
        ''')
    test = D(f'''
        from {m} import merge
        def test_basic(): assert merge([(1, 3), (2, 6), (8, 10)]) == [(1, 6), (8, 10)]
        def test_touch(): assert merge([(1, 2), (2, 3)]) == [(1, 3)]
        def test_unsorted(): assert merge([(5, 7), (1, 2), (2, 4)]) == [(1, 4), (5, 7)]
        def test_contained(): assert merge([(1, 10), (2, 3), (4, 5)]) == [(1, 10)]
        def test_gap(): assert merge([(1, 2), (4, 5)], gap=2) == [(1, 5)] and merge([(1, 2), (4, 5)], gap=1) == [(1, 2), (4, 5)]
        def test_empty(): assert merge([]) == []
        ''')
    return dict(tier=2, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `merge(intervals, gap=0)` in `{m}.py`. `intervals` is a list of (start, end) integer tuples, any order. Merge intervals that overlap or whose distance is <= gap (touching intervals merge even with gap=0, i.e. next.start <= current.end + gap). Return a sorted list of tuples. merge([(1,3),(2,6),(8,10)]) == [(1,6),(8,10)].")

def t_wrap(r):
    m = r.choice(["wrapper", "textfmt"])
    stub = D('''
        def wrap(text, width):
            raise NotImplementedError
        ''')
    good = D('''
        def wrap(text, width):
            lines, cur = [], ""
            for w in text.split():
                while len(w) > width:
                    if cur: lines.append(cur); cur = ""
                    lines.append(w[:width]); w = w[width:]
                if not cur: cur = w
                elif len(cur) + 1 + len(w) <= width: cur += " " + w
                else: lines.append(cur); cur = w
            if cur: lines.append(cur)
            return lines
        ''')
    test = D(f'''
        from {m} import wrap
        def test_basic(): assert wrap("the quick brown fox", 10) == ["the quick", "brown fox"]
        def test_exact(): assert wrap("aaa bbb", 7) == ["aaa bbb"]
        def test_long_word(): assert wrap("abcdefghij kl", 4) == ["abcd", "efgh", "ij", "kl"]
        def test_spaces(): assert wrap("  a   b  ", 5) == ["a b"]
        def test_empty(): assert wrap("", 5) == [] and wrap("   ", 5) == []
        ''')
    return dict(tier=2, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `wrap(text, width)` in `{m}.py`: greedy word wrap returning a list of lines, each at most `width` chars. Words are separated by any whitespace and joined by a single space; extra whitespace is dropped. A word longer than width is split into width-sized chunks (the remainder starts a new line and can be joined with following words). Empty/blank text -> [].")

def t_unit_convert(r):
    base = r.choice([("m", {"km": 1000, "cm": 0.01, "mm": 0.001, "m": 1}), ("g", {"kg": 1000, "mg": 0.001, "g": 1, "t": 1e6})])
    tbl = D(f'''
        FACTORS = {base[1]!r}
        BASE = {base[0]!r}
        ''')
    stub = D('''
        from table import FACTORS
        def convert(value, src, dst):
            raise NotImplementedError
        ''')
    good = D('''
        from table import FACTORS
        def convert(value, src, dst):
            if src not in FACTORS or dst not in FACTORS: raise KeyError(src if src not in FACTORS else dst)
            return value * FACTORS[src] / FACTORS[dst]
        ''')
    u = list(base[1])
    test = D(f'''
        import pytest
        from convert import convert
        from table import FACTORS
        def test_roundtrip():
            for a in FACTORS:
                for b in FACTORS: assert abs(convert(convert(3.5, a, b), b, a) - 3.5) < 1e-9
        def test_known(): assert abs(convert(2, {u[0]!r}, {u[1]!r}) - 2 * FACTORS[{u[0]!r}] / FACTORS[{u[1]!r}]) < 1e-12
        def test_same(): assert convert(7, {u[0]!r}, {u[0]!r}) == 7
        def test_unknown():
            with pytest.raises(KeyError): convert(1, "parsec", {u[0]!r})
            with pytest.raises(KeyError): convert(1, {u[0]!r}, "furlong")
        ''')
    return dict(tier=3, files={"table.py": tbl, "convert.py": stub}, ref={"table.py": tbl, "convert.py": good}, test=test,
                prompt="Implement `convert(value, src, dst)` in `convert.py` using the FACTORS table (unit -> size in the base unit) from `table.py`. Return value expressed in dst. Unknown src or dst unit raises KeyError. Read table.py first; do not change it.")

def t_toposort(r):
    m = r.choice(["deps", "order"])
    stub = D('''
        def toposort(graph):
            raise NotImplementedError
        ''')
    good = D('''
        import heapq
        def toposort(graph):
            nodes = set(graph) | {d for ds in graph.values() for d in ds}
            indeg = {n: 0 for n in nodes}; rev = {n: [] for n in nodes}
            for n, ds in graph.items():
                for d in set(ds): indeg[n] += 1; rev[d].append(n)
            h = [n for n in nodes if indeg[n] == 0]; heapq.heapify(h); out = []
            while h:
                n = heapq.heappop(h); out.append(n)
                for x in rev[n]:
                    indeg[x] -= 1
                    if indeg[x] == 0: heapq.heappush(h, x)
            if len(out) != len(nodes): raise ValueError("cycle")
            return out
        ''')
    test = D(f'''
        import pytest
        from {m} import toposort
        def test_chain(): assert toposort({{"c": ["b"], "b": ["a"], "a": []}}) == ["a", "b", "c"]
        def test_tiebreak(): assert toposort({{"x": [], "b": [], "a": [], "z": ["b"]}}) == ["a", "b", "x", "z"]
        def test_implicit(): assert toposort({{"a": ["b"]}}) == ["b", "a"]
        def test_diamond(): assert toposort({{"d": ["b", "c"], "b": ["a"], "c": ["a"]}}) == ["a", "b", "c", "d"]
        def test_cycle():
            with pytest.raises(ValueError): toposort({{"a": ["b"], "b": ["a"]}})
        def test_empty(): assert toposort({{}}) == []
        ''')
    return dict(tier=3, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `toposort(graph)` in `{m}.py`. `graph` maps node -> list of nodes it depends on (dependencies come first in the output). Nodes that appear only as dependencies are included. Among ready nodes always pick the alphabetically smallest (deterministic). Cycle -> raise ValueError. {{}} -> [].")

def t_lru(r):
    m = r.choice(["lrucache", "cachelib"]); cap = r.choice([2, 3])
    stub = D('''
        class LRUCache:
            def __init__(self, capacity): raise NotImplementedError
            def get(self, key, default=None): raise NotImplementedError
            def put(self, key, value): raise NotImplementedError
            def __len__(self): raise NotImplementedError
            def keys(self): raise NotImplementedError
        ''')
    good = D('''
        from collections import OrderedDict
        class LRUCache:
            def __init__(self, capacity):
                if capacity < 1: raise ValueError("capacity")
                self.cap = capacity; self.d = OrderedDict()
            def get(self, key, default=None):
                if key not in self.d: return default
                self.d.move_to_end(key); return self.d[key]
            def put(self, key, value):
                self.d[key] = value; self.d.move_to_end(key)
                if len(self.d) > self.cap: self.d.popitem(last=False)
            def __len__(self): return len(self.d)
            def keys(self): return list(reversed(self.d))
        ''')
    test = D(f'''
        import pytest
        from {m} import LRUCache
        def test_evict():
            c = LRUCache(2); c.put("a", 1); c.put("b", 2); c.put("c", 3)
            assert c.get("a") is None and c.get("b") == 2 and c.get("c") == 3 and len(c) == 2
        def test_get_refreshes():
            c = LRUCache(2); c.put("a", 1); c.put("b", 2); c.get("a"); c.put("c", 3)
            assert c.get("b") is None and c.get("a") == 1
        def test_update_refreshes():
            c = LRUCache(2); c.put("a", 1); c.put("b", 2); c.put("a", 9); c.put("c", 3)
            assert c.get("a") == 9 and c.get("b") is None
        def test_keys_mru_first():
            c = LRUCache(3); c.put(1, 1); c.put(2, 2); c.put(3, 3); c.get(1)
            assert c.keys() == [1, 3, 2]
        def test_default(): assert LRUCache(1).get("x", 42) == 42
        def test_bad_cap():
            with pytest.raises(ValueError): LRUCache(0)
        ''')
    return dict(tier=4, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement class `LRUCache` in `{m}.py` (stubs are there): capacity>=1 else ValueError; get(key, default=None) returns the value (and marks it most-recently-used) or default; put(key, value) inserts/updates (marks MRU) and evicts the least-recently-used entry when over capacity; __len__; keys() lists keys from most- to least-recently-used.")

def t_calc(r):
    m = r.choice(["calc", "exprs"])
    stub = D('''
        def evaluate(expr):
            raise NotImplementedError
        ''')
    good = D('''
        import re
        def evaluate(expr):
            toks = re.findall(r"\\d+\\.?\\d*|[-+*/()^]|\\S", expr); pos = [0]
            def peek(): return toks[pos[0]] if pos[0] < len(toks) else None
            def eat(): t = peek(); pos[0] += 1; return t
            def prim():
                t = eat()
                if t is None: raise ValueError("eof")
                if t == "(":
                    v = add()
                    if eat() != ")": raise ValueError("paren")
                    return v
                if t == "-": return -unary()
                if re.fullmatch(r"\\d+\\.?\\d*", t): return float(t)
                raise ValueError(t)
            def unary():
                return prim()
            def pw():
                b = unary()
                if peek() == "^": eat(); return b ** pw()
                return b
            def mul():
                v = pw()
                while peek() in ("*", "/"):
                    o = eat(); x = pw()
                    if o == "/" and x == 0: raise ZeroDivisionError
                    v = v * x if o == "*" else v / x
                return v
            def add():
                v = mul()
                while peek() in ("+", "-"):
                    o = eat(); x = mul(); v = v + x if o == "+" else v - x
                return v
            v = add()
            if pos[0] != len(toks): raise ValueError("trailing")
            return v
        ''')
    test = D(f'''
        import pytest
        from {m} import evaluate
        def test_prec(): assert evaluate("2+3*4") == 14
        def test_paren(): assert evaluate("(2+3)*4") == 20
        def test_unary(): assert evaluate("-3+5") == 2 and evaluate("2*-3") == -6
        def test_pow_right(): assert evaluate("2^3^2") == 512
        def test_div(): assert evaluate("7/2") == 3.5
        def test_ws(): assert evaluate(" 1 +  2 ") == 3
        def test_left_assoc(): assert evaluate("10-4-3") == 3 and evaluate("100/10/5") == 2
        def test_zero():
            with pytest.raises(ZeroDivisionError): evaluate("1/0")
        @pytest.mark.parametrize("bad", ["", "2+", "(1", "1 2", "a+1", "1+)"])
        def test_bad(bad):
            with pytest.raises(ValueError): evaluate(bad)
        ''')
    return dict(tier=4, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `evaluate(expr)` in `{m}.py`: a safe arithmetic evaluator (do NOT use eval/exec). Numbers (ints/decimals), + - * / ^ , parentheses, unary minus, whitespace. Precedence: ^ (right-assoc) > * / > + - (left-assoc). Returns a number equal to the math result (7/2 == 3.5). Division by zero -> ZeroDivisionError; any malformed input (empty, dangling operator, unbalanced parens, stray tokens/letters) -> ValueError.")

def t_ledger(r):
    m = r.choice(["ledger", "account"]); od = r.choice([0, 50, 100])
    stub = D(f'''
        class InsufficientFunds(Exception): pass
        class Account:
            OVERDRAFT = {od}
            def __init__(self, owner, balance=0): raise NotImplementedError
            def deposit(self, amount): raise NotImplementedError
            def withdraw(self, amount): raise NotImplementedError
            def transfer(self, other, amount): raise NotImplementedError
            def history(self): raise NotImplementedError
        ''')
    good = D(f'''
        class InsufficientFunds(Exception): pass
        class Account:
            OVERDRAFT = {od}
            def __init__(self, owner, balance=0):
                self.owner = owner; self.balance = balance; self._h = []
            def _chk(self, a):
                if a <= 0: raise ValueError("amount")
            def deposit(self, amount):
                self._chk(amount); self.balance += amount; self._h.append(("deposit", amount)); return self.balance
            def withdraw(self, amount):
                self._chk(amount)
                if self.balance - amount < -self.OVERDRAFT: raise InsufficientFunds(amount)
                self.balance -= amount; self._h.append(("withdraw", amount)); return self.balance
            def transfer(self, other, amount):
                self.withdraw(amount); other.deposit(amount)
                self._h[-1] = ("transfer_out", amount); other._h[-1] = ("transfer_in", amount)
            def history(self): return list(self._h)
        ''')
    test = D(f'''
        import pytest
        from {m} import Account, InsufficientFunds
        OD = Account.OVERDRAFT
        def test_basic():
            a = Account("x", 10); assert a.deposit(5) == 15 and a.withdraw(3) == 12 and a.balance == 12
        def test_overdraft_limit():
            a = Account("x", 0); a.withdraw(OD) if OD else None
            with pytest.raises(InsufficientFunds): a.withdraw(1)
            assert a.balance == -OD
        @pytest.mark.parametrize("amt", [0, -5])
        def test_bad_amount(amt):
            a = Account("x", 10)
            with pytest.raises(ValueError): a.deposit(amt)
            with pytest.raises(ValueError): a.withdraw(amt)
        def test_transfer():
            a, b = Account("a", 100), Account("b", 0); a.transfer(b, 40)
            assert (a.balance, b.balance) == (60, 40)
            assert a.history() == [("transfer_out", 40)] and b.history() == [("transfer_in", 40)]
        def test_failed_transfer_atomic():
            a, b = Account("a", 10), Account("b", 0)
            with pytest.raises(InsufficientFunds): a.transfer(b, 10 + OD + 1)
            assert (a.balance, b.balance) == (10, 0) and a.history() == [] and b.history() == []
        def test_history_order_and_copy():
            a = Account("a", 0); a.deposit(5); a.withdraw(2); h = a.history()
            assert h == [("deposit", 5), ("withdraw", 2)]; h.append(1); assert len(a.history()) == 2
        ''')
    return dict(tier=4, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `Account` in `{m}.py` (stubs given; keep OVERDRAFT={od} and InsufficientFunds). deposit/withdraw require amount>0 (else ValueError) and return the new balance. withdraw may take balance down to -OVERDRAFT but no further (else InsufficientFunds, balance unchanged). transfer(other, amount) = withdraw here + deposit there, atomic on failure. history() returns a COPY of a list of (kind, amount) tuples: 'deposit', 'withdraw', and for transfers 'transfer_out' on the sender / 'transfer_in' on the receiver (a transfer must not also log plain deposit/withdraw).")

def t_csvsplit(r):
    m = r.choice(["csvline", "splitter"]); d = r.choice([",", ";", "|"])
    stub = D('''
        def split_line(line, delim=","):
            raise NotImplementedError
        ''')
    good = D('''
        def split_line(line, delim=","):
            out, cur, q, i = [], [], False, 0
            while i < len(line):
                c = line[i]
                if q:
                    if c == '"':
                        if i + 1 < len(line) and line[i + 1] == '"': cur.append('"'); i += 1
                        else: q = False
                    else: cur.append(c)
                elif c == '"': q = True
                elif c == delim: out.append("".join(cur)); cur = []
                else: cur.append(c)
                i += 1
            if q: raise ValueError("unterminated quote")
            out.append("".join(cur)); return out
        ''')
    test = D(f'''
        import pytest
        from {m} import split_line
        D = {d!r}
        def test_plain(): assert split_line(D.join(["a", "b", "c"]), D) == ["a", "b", "c"]
        def test_empty_fields(): assert split_line(D + D, D) == ["", "", ""]
        def test_quoted_delim(): assert split_line('a' + D + '"b' + D + 'c"' + D + 'd', D) == ["a", "b" + D + "c", "d"]
        def test_escaped_quote(): assert split_line('"say ""hi"""' + D + 'x', D) == ['say "hi"', "x"]
        def test_empty_line(): assert split_line("", D) == [""]
        def test_unterminated():
            with pytest.raises(ValueError): split_line('"abc', D)
        def test_default_delim(): assert split_line("a,b") == ["a", "b"]
        ''')
    return dict(tier=3, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `split_line(line, delim=',')` in `{m}.py`: split one CSV line. Fields may be wrapped in double quotes, inside which the delimiter is literal and a doubled quote (\"\") is one literal quote; quotes are removed from the result. Empty fields are kept ('' -> ['']; ',,' -> ['','','']). An unterminated quote raises ValueError. The test suite uses delimiter '{d}' as well as the default.")

def t_matrix_bug(r):
    m = r.choice(["matrix", "grid"])
    bad = D('''
        def transpose(mat):
            """Transpose a rectangular list-of-lists matrix."""
            return [[mat[i][j] for j in range(len(mat))] for i in range(len(mat[0]))]
        def rotate_cw(mat):
            """Rotate 90 degrees clockwise."""
            return [list(row) for row in zip(*mat)]
        def trace(mat):
            """Sum of the main diagonal (square matrices only; else ValueError)."""
            return sum(mat[i][i] for i in range(len(mat)))
        ''')
    good = D('''
        def transpose(mat):
            return [[mat[i][j] for i in range(len(mat))] for j in range(len(mat[0]))] if mat else []
        def rotate_cw(mat):
            return [list(row)[::-1] for row in zip(*mat)]
        def trace(mat):
            if any(len(r) != len(mat) for r in mat): raise ValueError("square")
            return sum(mat[i][i] for i in range(len(mat)))
        ''')
    test = D(f'''
        import pytest
        from {m} import transpose, rotate_cw, trace
        def test_t_rect(): assert transpose([[1, 2, 3], [4, 5, 6]]) == [[1, 4], [2, 5], [3, 6]]
        def test_t_sq(): assert transpose([[1, 2], [3, 4]]) == [[1, 3], [2, 4]]
        def test_rot(): assert rotate_cw([[1, 2, 3], [4, 5, 6]]) == [[4, 1], [5, 2], [6, 3]]
        def test_rot_sq(): assert rotate_cw([[1, 2], [3, 4]]) == [[3, 1], [4, 2]]
        def test_trace(): assert trace([[1, 2], [3, 4]]) == 5
        def test_trace_bad():
            with pytest.raises(ValueError): trace([[1, 2, 3], [4, 5, 6]])
        ''')
    return dict(tier=1, files={f"{m}.py": bad}, ref={f"{m}.py": good}, test=test,
                prompt=f"`{m}.py` has three bugs, one per function (transpose breaks on non-square input, rotate_cw rotates the wrong way/doesn't reverse rows, trace doesn't enforce its documented ValueError). Fix all three in place; docstrings are the spec.")

def t_kv(r):
    m = r.choice(["kvparse", "config"]); sep = r.choice([";", "&"])
    stub = D('''
        def parse_kv(text):
            raise NotImplementedError
        def dump_kv(d):
            raise NotImplementedError
        ''')
    good = D(f'''
        def parse_kv(text):
            out = {{}}; cur = ""; parts = []; i = 0
            while i < len(text):
                c = text[i]
                if c == "\\\\" and i + 1 < len(text): cur += text[i:i + 2]; i += 2; continue
                if c == {sep!r}: parts.append(cur); cur = ""
                else: cur += c
                i += 1
            parts.append(cur)
            def un(s):
                o = ""; j = 0
                while j < len(s):
                    if s[j] == "\\\\" and j + 1 < len(s): o += s[j + 1]; j += 2
                    else: o += s[j]; j += 1
                return o
            for p in parts:
                if not p: continue
                k = 0
                while k < len(p):
                    if p[k] == "\\\\": k += 2; continue
                    if p[k] == "=": break
                    k += 1
                else: raise ValueError(p)
                out[un(p[:k])] = un(p[k + 1:])
            return out
        def dump_kv(d):
            esc = lambda s: s.replace("\\\\", "\\\\\\\\").replace({sep!r}, "\\\\" + {sep!r}).replace("=", "\\\\=")
            return {sep!r}.join(esc(k) + "=" + esc(v) for k, v in d.items())
        ''')
    test = D(f'''
        import pytest
        from {m} import parse_kv, dump_kv
        S = {sep!r}
        def test_basic(): assert parse_kv("a=1" + S + "b=2") == {{"a": "1", "b": "2"}}
        def test_empty_value(): assert parse_kv("a=") == {{"a": ""}}
        def test_skip_empty_parts(): assert parse_kv(S + "a=1" + S + S) == {{"a": "1"}}
        def test_escape_sep(): assert parse_kv("a=x\\\\" + S + "y") == {{"a": "x" + S + "y"}}
        def test_escape_eq(): assert parse_kv("a\\\\=b=c") == {{"a=b": "c"}}
        def test_value_with_eq(): assert parse_kv("a=b=c") == {{"a": "b=c"}}
        def test_missing_eq():
            with pytest.raises(ValueError): parse_kv("abc")
        def test_roundtrip():
            for d in [{{"k": "v"}}, {{"a=b": "c" + S + "d"}}, {{"x": "back\\\\slash", "y": ""}}]: assert parse_kv(dump_kv(d)) == d
        ''')
    return dict(tier=3, files={f"{m}.py": stub}, ref={f"{m}.py": good}, test=test,
                prompt=f"Implement `parse_kv(text)` and `dump_kv(d)` in `{m}.py`. Format: pairs `key=value` joined by '{sep}'. Backslash escapes the next char (so '\\\\{sep}', '\\\\=' and '\\\\\\\\' are literal). The first unescaped '=' splits key from value (later '=' belong to the value). Empty parts between separators are ignored; a non-empty part without an unescaped '=' raises ValueError. dump_kv escapes backslash, '{sep}' and '=' (in keys and values) so that parse_kv(dump_kv(d)) == d. All values are strings.")

TEMPLATES = [t_median_bug, t_paginate_bug, t_matrix_bug, t_duration, t_rle, t_intervals, t_wrap, t_unit_convert, t_toposort, t_csvsplit, t_kv, t_lru, t_calc, t_ledger]
SYSTEM = "You are a coding agent with file tools (list_files, read_file, write_file). Never describe what you are about to do - do it by calling tools. Step 1: read_file every file named in the task. Step 2: call write_file with the COMPLETE finished file contents (you cannot run code, so reason carefully about edge cases and the exact spec). Step 3: reply with one short sentence. A task is only complete once write_file has been called."

def make(seed):
    r = random.Random(seed); t = TEMPLATES[seed % len(TEMPLATES)](r); t["id"] = f"t{seed:05d}"; t["template"] = TEMPLATES[seed % len(TEMPLATES)].__name__[2:]
    t["prompt"] += " Only edit the files named; do not create other files. Your very first reply must be a tool call (read_file on the file(s) above) - do not write any introduction. After reading, your next reply must be a write_file call containing the complete finished file."
    return t

if __name__ == "__main__":     # preflight: reference passes, starting files fail (proves the hidden tests are valid + non-trivial)
    import os, subprocess, sys, tempfile, hashlib
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 56; bad = 0
    for s in range(n):
        t = make(s)
        for label, files, want in (("ref", t["ref"], True), ("start", t["files"], False)):
            d = tempfile.mkdtemp()
            for k, v in files.items(): open(f"{d}/{k}", "w").write(v)
            open(f"{d}/test_hidden.py", "w").write(t["test"])
            p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", d], capture_output=True, text=True, cwd=d)
            if (p.returncode == 0) != want: bad += 1; print("PREFLIGHT FAIL", t["id"], t["template"], label, p.stdout[-400:])
    print("preflight", "OK" if not bad else f"{bad} FAILURES", f"({n} tasks)")
    sys.exit(1 if bad else 0)

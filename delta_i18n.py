#!/usr/bin/env python3
"""Delta (Zed Industries) 简体中文汉化补丁工具。

Delta 是闭源的 Rust/GPUI 应用，界面文字被直接编译进主程序二进制，没有任何
语言包机制。本工具的做法：

1. 解析 Mach-O（arm64），找出所有对 `__TEXT,__const` 里字符串字面量的引用：
   - 代码里的 `adrp + add`（取地址）以及附近给出长度的 `movz`；
   - 代码里的 `adrp + ldr`（把字面量拷进堆，长度隐含在指令里）；
   - 数据段里经 chained fixups 重定位的 `(ptr, len)` 胖指针。
   由此得到每条字面量精确的起点和长度。
2. 对词典里的每一条：
   - 译文字节数 ≤ 原文：**原位替换**，不足部分用零宽字符补齐；
   - 译文更长：把译文写到二进制里未使用的填充区（Mach-O 头页余量、各段尾部
     的对齐空洞），然后改写所有引用它的指针和长度（**搬迁**）。只有在每一处
     引用都能被安全改写时才搬迁，否则该条保持英文。
3. 用 ad-hoc 签名重新签名（原签名在修改后必然失效）。

用法：
    python3 delta_i18n.py apply   [--app /Applications/Delta.app] [--dict translations.json]
    python3 delta_i18n.py check   [--app ...] [--dict ...]    # 只报告，不改动
    python3 delta_i18n.py restore [--app ...]                 # 还原成原版程序
    python3 delta_i18n.py dump    [--app ...] > strings.tsv   # 导出可翻译的字符串
    python3 delta_i18n.py make-cert                           # 创建固定的自签名证书，避免钥匙串反复询问
"""
import argparse, json, os, re, shutil, struct, subprocess, sys, tempfile
from collections import defaultdict

try:
    import numpy as np
except ImportError:
    sys.exit("需要 numpy：pip3 install numpy")

BACKUP_DIR = os.path.expanduser("~/Library/Application Support/delta-zh-cn")
IMAGE_BASE = 0x100000000

# ---------- 零宽填充 ----------
PAD4 = "\U000E0001".encode()  # 4 字节：Unicode TAG 字符，默认可忽略（不显示）
PAD3 = "​".encode()      # 3 字节：零宽空格
PAD2 = "͏".encode()      # 2 字节：组合字形连接符（零宽）
PAD1 = b" "                   # 1 字节：只在凑不出别的组合时用普通空格


def pad_to(b: bytes, n: int) -> bytes:
    gap = n - len(b)
    assert gap >= 0
    out = b
    while gap > 0:
        if gap % 3 == 0:
            out += PAD3; gap -= 3
        elif gap % 3 == 1:
            if gap >= 4: out += PAD4; gap -= 4
            else: out += PAD1; gap -= 1
        else:
            out += PAD2; gap -= 2
    assert len(out) == n
    return out


# ---------- Mach-O ----------
class MachO:
    def __init__(self, data: bytes):
        self.data = data
        magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from('<IiiIIIII', data, 0)
        if magic != 0xfeedfacf:
            sys.exit("只支持 arm64 单架构 Mach-O（Delta 的官方发行版就是这种）")
        self.header_end = 32 + sizeofcmds
        self.sections = {}   # (seg, sect) -> (addr, size, fileoff)
        self.segments = []   # (name, vmaddr, vmsize, fileoff, filesize)
        self.chained_fixups = None
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', data, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                name = data[off+8:off+24].rstrip(b'\0').decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off+24)
                self.segments.append((name, vmaddr, vmsize, fileoff, filesize))
                nsects = struct.unpack_from('<I', data, off+64)[0]
                so = off + 72
                for _ in range(nsects):
                    sect = data[so:so+16].rstrip(b'\0').decode()
                    seg = data[so+16:so+32].rstrip(b'\0').decode()
                    addr, size, foff = struct.unpack_from('<QQI', data, so+32)
                    self.sections[(seg, sect)] = (addr, size, foff)
                    so += 80
            elif cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
                self.chained_fixups = struct.unpack_from('<II', data, off+8)
            off += cmdsize

    def sect(self, seg, name):
        return self.sections[(seg, name)]

    def fileoff_to_addr(self, fo):
        for name, vmaddr, vmsize, fileoff, filesize in self.segments:
            if fileoff <= fo < fileoff + filesize:
                return vmaddr + (fo - fileoff)
        raise ValueError(hex(fo))

    def rebase_locations(self):
        """遍历 chained fixups，返回所有 rebase 指针所在的文件偏移。"""
        if not self.chained_fixups:
            return set()
        d = self.data
        dataoff, _ = self.chained_fixups
        starts_offset = struct.unpack_from('<I', d, dataoff + 4)[0]
        starts = dataoff + starts_offset
        seg_count = struct.unpack_from('<I', d, starts)[0]
        seg_info_offsets = struct.unpack_from(f'<{seg_count}I', d, starts + 4)
        locs = set()
        for sio in seg_info_offsets:
            if sio == 0: continue
            si = starts + sio
            size, page_size, ptr_format, seg_off, max_valid, page_count = struct.unpack_from('<IHHQIH', d, si)
            page_starts = struct.unpack_from(f'<{page_count}H', d, si + 22)
            if ptr_format not in (2, 6):  # DYLD_CHAINED_PTR_64 / DYLD_CHAINED_PTR_64_OFFSET
                continue
            for pi, ps in enumerate(page_starts):
                if ps == 0xFFFF: continue
                fo = seg_off + pi * page_size + ps
                while True:
                    raw = struct.unpack_from('<Q', d, fo)[0]
                    if (raw >> 63) == 0:
                        locs.add(fo)
                    nxt = (raw >> 51) & 0xFFF
                    if nxt == 0: break
                    fo += nxt * 4
        return locs


# ---------- arm64 指令辅助 ----------
def is_adrp(w): return (w & 0x9F000000) == 0x90000000
def is_add_imm64(w): return (w & 0xFFC00000) == 0x91000000  # add xd, xn, #imm12（无移位）
def is_movz(w): return ((w & 0xFF800000) == 0x52800000 or (w & 0xFF800000) == 0xD2800000) and ((w >> 21) & 3) == 0
def is_ldr_uimm(w): return (w & 0x3B400000) == 0x39400000 or (w & 0x3FC00000) == 0x3DC00000
def is_ldur(w): return (w & 0x3B600C00) == 0x38400000 or (w & 0x3F600C00) == 0x3C400000 or (w & 0x3FE00C00) == 0x3CC00000
def is_ldp(w): return (w & 0xFFC00000) in (0xA9400000, 0xAD400000, 0x29400000)
def is_bl(w): return (w & 0xFC000000) == 0x94000000
def is_b(w): return (w & 0xFC000000) == 0x14000000
def is_ret_or_br(w): return (w & 0xFFFFFC1F) == 0xD65F0000 or (w & 0xFFFFFC1F) == 0xD61F0000
def is_bcond(w): return (w & 0xFF000010) == 0x54000000 or (w & 0x7E000000) == 0x34000000 or (w & 0x7E000000) == 0x36000000


def adrp_page(w, pc):
    imm = ((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3))
    if imm & (1 << 20): imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def load_offset(w):
    if is_ldr_uimm(w):
        size = (w >> 30) & 3; V = (w >> 26) & 1; opc = (w >> 22) & 3
        scale = 4 if (V and opc == 3 and size == 0) else size
        return ((w >> 10) & 0xFFF) << scale
    if is_ldur(w):
        o9 = (w >> 12) & 0x1FF
        return o9 - 0x200 if o9 & 0x100 else o9
    if is_ldp(w):
        i7 = (w >> 15) & 0x7F
        if i7 & 0x40: i7 -= 0x80
        sc = 4 if (w & 0xFFC00000) == 0xAD400000 else (3 if (w >> 30) == 2 else 2)
        return i7 << sc
    return None


def reg_written(w, reg):
    """粗略判断指令是否写入通用寄存器 reg（作为目的寄存器）。"""
    if is_b(w) or is_bl(w) or is_bcond(w) or is_ret_or_br(w): return False
    if (w & 0x3B000000) == 0x39000000 or (w & 0x3A000000) == 0x28000000 or (w & 0x3B200C00) == 0x38000000:
        return ((w >> 22) & 1) == 1 and (w & 0x1F) == reg  # 只有 load 才写 Rt
    if (w & 0x7F000000) == 0x71000000 or (w & 0x7F200000) == 0x6B000000:  # subs/cmp
        return (w & 0x1F) == reg and reg != 31
    return (w & 0x1F) == reg


def reg_consumed(w, reg):
    """指令是否把 reg 作为数据来源消费（存储、mov、作为 add 源）。"""
    if (w & 0x3B000000) == 0x39000000 and ((w >> 22) & 1) == 0: return (w & 0x1F) == reg      # str Rt
    if (w & 0x3B200C00) == 0x38000000 and ((w >> 22) & 1) == 0: return (w & 0x1F) == reg      # stur Rt
    if (w & 0x3A000000) == 0x28000000 and ((w >> 22) & 1) == 0:                                # stp Rt/Rt2
        return (w & 0x1F) == reg or ((w >> 10) & 0x1F) == reg
    if (w & 0x7FE0FFE0) == 0x2A0003E0: return ((w >> 16) & 0x1F) == reg                        # mov (orr) 源
    if (w & 0x7F000000) == 0x11000000: return ((w >> 5) & 0x1F) == reg                         # add imm 源
    return False


def load_size(w):
    """返回 load 指令的访问宽度（字节）。"""
    if is_ldr_uimm(w) or is_ldur(w):
        size = (w >> 30) & 3; V = (w >> 26) & 1; opc = (w >> 22) & 3
        if V and opc == 3 and size == 0: return 16
        return 1 << size
    if is_ldp(w):
        return 32 if (w & 0xFFC00000) == 0xAD400000 else (16 if (w >> 30) == 2 else 8)
    return None


def collect_loads(ins, start, base, base_rel, N):
    """从 start 起扫描，收集以 base 寄存器为基址的加载：[(相对字面量起点的偏移, 宽度)]。
    base_rel 是 base 寄存器相对字面量起点的偏移（页寄存器时为负）。遇到 base 被改写、
    分支或调用即停止。"""
    out = []
    for q in range(start, min(start + 16, N)):
        w = ins[q]
        if ((w >> 5) & 0x1F) == base and (is_ldr_uimm(w) or is_ldur(w) or is_ldp(w)):
            off = load_offset(w); sz = load_size(w)
            if off is not None and sz:
                out.append((off - base_rel, sz))
                continue
        if reg_written(w, base) or is_b(w) or is_bl(w) or is_ret_or_br(w) or is_bcond(w): break
    return out


def copy_gap(loads, n):
    """加载覆盖 [0, n) 后剩下的未覆盖区间列表。"""
    covered = [False] * n
    for off, sz in loads:
        for b in range(max(0, off), min(n, off + sz)): covered[b] = True
    gaps, k = [], 0
    while k < n:
        if covered[k]: k += 1; continue
        e = k
        while e < n and not covered[e]: e += 1
        gaps.append((k, e)); k = e
    return gaps


def find_imm_tail(ins, i, j, orig: bytes, gap):
    """未被加载覆盖的尾部若由 movz(+movk) 立即数给出，返回 [(指令下标, 'z'|'k')]。"""
    lo, hi = gap
    n = hi - lo
    if n not in (1, 2, 4): return None
    val = int.from_bytes(orig[lo:hi], 'little')
    N = len(ins)
    for q in range(max(0, i - 6), min(j + 24, N)):
        w = ins[q]
        if is_movz(w) and ((w >> 5) & 0xFFFF) == (val & 0xFFFF):
            if n <= 2: return [(q, 'z')]
            reg = w & 0x1F
            for q2 in range(q + 1, min(q + 6, N)):
                w2 = ins[q2]
                if (w2 & 0xFF800000) == 0x72800000 and ((w2 >> 21) & 3) == 1 and (w2 & 0x1F) == reg \
                   and ((w2 >> 5) & 0xFFFF) == (val >> 16):                       # movk wN, #hi, lsl #16
                    return [(q, 'z'), (q2, 'k')]
            return None
    return None


# ---------- 分析 ----------
class Literal:
    __slots__ = ('addr', 'off', 'len', 'text', 'exact', 'refs', 'cands')
    def __init__(self, addr, off, ln, text, exact):
        self.addr, self.off, self.len, self.text, self.exact = addr, off, ln, text, exact
        self.refs = []   # ('fat', fileoff) | ('code', i, j, k_or_None) | ('load', i, j)


def analyze(m: MachO):
    data = m.data
    text_addr, text_size, text_off = m.sect('__TEXT', '__text')
    const_addr, const_size, const_off = m.sect('__TEXT', '__const')
    const_end = const_addr + const_size
    lens = defaultdict(set)          # addr -> 候选长度
    refs = defaultdict(list)         # addr -> 引用

    # A) 数据段中的胖指针（只认 chained fixups 里真实存在的 rebase 位置）
    for fo in m.rebase_locations():
        raw, ln = struct.unpack_from('<QQ', data, fo)
        low = raw & ((1 << 36) - 1)
        ptr = low if low >= IMAGE_BASE else low + IMAGE_BASE
        if const_addr <= ptr < const_end:
            lens[ptr]  # 任何指向 __const 的指针都是一个起点（长度可能存放在别处）
            if 0 < ln < 8192 and ptr + ln <= const_end:
                lens[ptr].add(int(ln))
                refs[ptr].append(('fat', fo))
            else:
                refs[ptr].append(('ptr', fo))

    # B) 代码引用
    ins = np.frombuffer(data[text_off:text_off + text_size // 4 * 4], dtype='<u4')
    N = len(ins)
    ins_list = ins.tolist()
    for i in np.nonzero((ins & 0x9F000000) == 0x90000000)[0]:
        i = int(i); w = ins_list[i]; rd = w & 0x1F
        page = adrp_page(w, text_addr + i * 4)
        if not (const_addr - 0x1000 <= page <= const_end): continue
        for j in range(i + 1, min(i + 13, N)):
            w2 = ins_list[j]
            if ((w2 >> 5) & 0x1F) != rd:
                if reg_written(w2, rd) or is_b(w2) or is_bl(w2) or is_ret_or_br(w2): break
                continue
            if is_add_imm64(w2):
                target = page + ((w2 >> 10) & 0xFFF)
                if const_addr <= target < const_end:
                    cands = []
                    for k in range(max(0, i - 4), min(j + 8, N)):
                        w3 = ins_list[k]
                        if is_movz(w3):
                            imm16 = (w3 >> 5) & 0xFFFF
                            if 0 < imm16 < 8192 and target + imm16 <= const_end:
                                lens[target].add(imm16); cands.append((k, imm16))
                    # 拷贝型引用：add 之后紧接着用 rd 作基址加载（把字面量拷进内联缓冲区）
                    loads = collect_loads(ins_list, j + 1, rd, 0, N)
                    if loads:
                        refs[target].append(('copy', i, j, cands, loads))
                    else:
                        refs[target].append(('code', i, j, cands))
                    # 派生引用：`add xd, x<base>, #imm` 从同一基址算出相邻字面量
                    for q in range(j + 1, min(j + 48, N)):
                        w4 = ins_list[q]
                        if is_add_imm64(w4) and ((w4 >> 5) & 0x1F) == rd:
                            t2 = target + ((w4 >> 10) & 0xFFF)
                            if const_addr <= t2 < const_end:
                                for k in range(max(0, q - 4), min(q + 8, N)):
                                    w3 = ins_list[k]
                                    if is_movz(w3):
                                        imm16 = (w3 >> 5) & 0xFFFF
                                        if 0 < imm16 < 8192 and t2 + imm16 <= const_end:
                                            lens[t2].add(imm16)
                                refs[t2].append(('derived', q))
                            if (w4 & 0x1F) == rd: break
                            continue
                        if reg_written(w4, rd) or is_b(w4) or is_bl(w4) or is_ret_or_br(w4): break
            else:
                off = load_offset(w2)
                if off is not None:
                    target = page + off
                    if const_addr <= target < const_end:
                        loads = collect_loads(ins_list, j, rd, off, N)   # 以页寄存器为基址的一组加载
                        refs[target].append(('load', i, j, loads))
            break

    # C) 解析每个起点的长度
    starts = sorted(set(lens) | set(refs))
    lits = []
    for idx, a in enumerate(starts):
        nxt = starts[idx + 1] if idx + 1 < len(starts) else const_end
        fo = const_off + (a - const_addr)
        cand = set(lens[a])
        def text_at(l):
            try:
                t = data[fo:fo + l].decode('utf-8')
            except UnicodeDecodeError:
                return None
            return t if all(c.isprintable() or c in '\n\t' for c in t) else None
        blen = nxt - a if 0 < nxt - a <= 512 and text_at(nxt - a) is not None else None
        chosen = None
        if blen and blen in cand:
            chosen, exact = blen, True                        # 边界与某个长度候选吻合：最可靠
        else:
            adjacent = []                                    # 紧跟在 add 后 1-2 条的 movz
            for r in refs.get(a, []):
                if r[0] == 'code':
                    for k, imm in r[3]:
                        if r[2] < k <= r[2] + 2 and (blen is None or imm <= blen):
                            adjacent.append((k - r[2], imm))
            for _, imm in sorted(adjacent):
                if text_at(imm) is not None:
                    chosen, exact = imm, (a + imm == nxt); break
            if chosen is None and blen:
                chosen, exact = blen, True                    # 只有边界可用（如长度存放在别处）
            if chosen is None:
                for l in sorted(cand, reverse=True):
                    if text_at(l) is not None:
                        chosen, exact = l, (a + l == nxt); break
        if chosen is None: continue
        l, t = chosen, text_at(chosen)
        lit = Literal(a, fo, l, t, exact)
        lit.refs = refs.get(a, [])
        strong = set()
        for r in lit.refs:
            if r[0] == 'fat':
                strong.add(struct.unpack_from('<Q', data, r[1] + 8)[0])
            elif r[0] in ('code', 'copy'):
                for k, imm in r[3]:
                    if movz_tied_to_ptr(ins_list, r[2], k):
                        strong.add(imm)
        lit.cands = sorted(strong)
        lits.append(lit)
    return lits, ins_list, (text_addr, text_off)


def movz_tied_to_ptr(ins, j, k):
    """movz(k) 给出的长度是否与 add(j) 得到的指针成对使用：
    `stp xptr, xlen` / `str xptr,[xb,#o]` + `str xlen,[xb,#o+8]` / 指针 x0 + 长度 x1 后紧接 `bl`。
    同时要求长度寄存器在被覆盖前只被消费这一次。"""
    lreg = ins[k] & 0x1F; preg = ins[j] & 0x1F
    N = len(ins)
    uses = []
    for q in range(k + 1, min(k + 48, N)):
        w = ins[q]
        if is_bl(w):
            if lreg <= 7: uses.append(('bl', q)); break
            if lreg <= 18: break
            continue
        if reg_consumed(w, lreg): uses.append(('ins', q))
        if reg_written(w, lreg): break
        if is_b(w) or is_ret_or_br(w): break
    if len(uses) != 1: return False
    kind, q = uses[0]
    if q <= j: return False
    for t in range(j + 1, q):                # add 之后到消费点之间，指针寄存器不能被改写
        if reg_written(ins[t], preg): return False
    w = ins[q]
    if kind == 'bl':
        return preg == 0 and lreg == 1
    if (w & 0x3A000000) == 0x28000000 and ((w >> 22) & 1) == 0:          # stp
        return (w & 0x1F) == preg and ((w >> 10) & 0x1F) == lreg
    if (w & 0x3B000000) == 0x39000000 and ((w >> 22) & 1) == 0 and (w >> 30) == 3:   # str xlen,[xb,#o+8]
        base = (w >> 5) & 0x1F; off = ((w >> 10) & 0xFFF) << 3
        for q2 in range(max(0, q - 12), min(q + 12, N)):
            w2 = ins[q2]
            if (w2 & 0xFFC00000) == 0xF9000000 and (w2 & 0x1F) == preg and ((w2 >> 5) & 0x1F) == base \
               and (((w2 >> 10) & 0xFFF) << 3) + 8 == off:
                return True
        return False
    if (w & 0x3B200C00) == 0x38000000 and ((w >> 22) & 1) == 0 and (w >> 30) == 3:   # stur
        base = (w >> 5) & 0x1F; o9 = (w >> 12) & 0x1FF; off = o9 - 0x200 if o9 & 0x100 else o9
        for q2 in range(max(0, q - 12), min(q + 12, N)):
            w2 = ins[q2]
            if (w2 & 0xFFE00C00) == 0xF8000000 and (w2 & 0x1F) == preg and ((w2 >> 5) & 0x1F) == base:
                o9b = (w2 >> 12) & 0x1FF; offb = o9b - 0x200 if o9b & 0x100 else o9b
                if offb + 8 == off: return True
        return False
    return False


def dedicated_movz(ins, i, j, cands, n):
    ks = [k for k, imm in cands if imm == n]
    if len(ks) != 1: return None
    return ks[0] if movz_tied_to_ptr(ins, j, ks[0]) else None


# ---------- 空闲空间 ----------
def free_regions(m: MachO):
    """返回 [(fileoff, size)]：文件里已映射、只读、全零且无人使用的填充区。"""
    data = m.data
    regions = []
    text_off = m.sect('__TEXT', '__text')[2]
    regions.append((m.header_end, text_off - m.header_end))                      # Mach-O 头页余量
    for name, vmaddr, vmsize, fileoff, filesize in m.segments:
        if name not in ('__TEXT', '__DATA_CONST'): continue
        ends = [fo + s for (sg, _), (a, s, fo) in m.sections.items() if sg == name]
        e = max(ends)
        regions.append((e, fileoff + filesize - e))                                  # 段尾
    out = []
    for fo, size in regions:
        size -= 16; fo += 8  # 两端留一点余量
        if size > 32 and not any(data[fo:fo + size]):
            out.append((fo, size))
    return out


class Allocator:
    def __init__(self, regions):
        self.regions = [[fo, fo + size] for fo, size in regions]
    def alloc(self, n):
        for r in self.regions:
            if r[1] - r[0] >= n:
                fo = r[0]; r[0] += n
                return fo
        return None
    def remaining(self):
        return sum(r[1] - r[0] for r in self.regions)


# ---------- 编码 ----------
def encode_adrp(w, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= imm < (1 << 20)
    imm &= (1 << 21) - 1
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | (w & 0x1F)

def encode_add(w, target):
    return (w & ~(0xFFF << 10)) | ((target & 0xFFF) << 10)

def encode_movz(w, n):
    assert 0 < n < 0x10000
    return (w & ~(0xFFFF << 5)) | (n << 5)


# ---------- 计划与打补丁 ----------
def load_dict(path):
    d = json.load(open(path, encoding='utf-8'))
    return {k: (v['zh'] if isinstance(v, dict) else v) for k, v in d.items()
            if not k.startswith('_') and v}


def make_plan(m: MachO, table, verbose=False):
    lits, ins, (text_addr, text_off) = analyze(m)
    by_text = defaultdict(list)
    for lit in lits: by_text[lit.text].append(lit)
    alloc = Allocator(free_regions(m))
    inplace, relocs, skipped, partial, missing, unsafe = [], [], [], [], [], []
    relocated_text = {}   # zh bytes -> fileoff（相同译文共用一份）

    def utf8_consistent(lit, nb):
        """任何一个候选长度去读替换后的字节都必须是合法 UTF-8。"""
        for l in lit.cands:
            if l < lit.len:
                try: nb[:l].decode('utf-8')
                except UnicodeDecodeError: return False
        return True

    def copy_patches(lit, nb):
        """拷贝型引用：加载必须覆盖整个字面量，未覆盖的尾部必须是可改写的立即数。
        返回需要改写的立即数指令列表，或 None 表示不安全。"""
        orig = lit.text.encode('utf-8')
        out = []
        for r in lit.refs:
            if r[0] not in ('copy', 'load'): continue
            loads = r[4] if r[0] == 'copy' else r[3]
            for gap in copy_gap(loads, lit.len):
                imm = find_imm_tail(ins, r[1], r[2], orig, gap)
                if imm is None: return None
                for q, kind in imm:
                    out.append((q, kind, nb[gap[0]:gap[1]]))
        return out

    def inplace_safe(lit):
        code = [r for r in lit.refs if r[0] in ('code', 'copy')]
        if lit.exact: return True
        if any(r[0] == 'load' for r in lit.refs): return False
        if any(r[0] in ('derived', 'ptr') for r in lit.refs) and not code: return False
        return bool(code) and all(any(imm == lit.len for _, imm in r[3]) for r in code)

    for en, zh in table.items():
        hits = [l for l in by_text.get(en, []) if inplace_safe(l)]
        if not hits:
            (missing if en not in by_text else unsafe).append(en); continue
        zb = zh.encode('utf-8')
        if len(zb) <= min(l.len for l in hits):
            for lit in hits:
                nb = pad_to(zb, lit.len)
                cp = copy_patches(lit, nb)
                if utf8_consistent(lit, nb) and cp is not None: inplace.append((lit, nb, cp))
                else: unsafe.append(en)
            continue
        # 需要搬迁：逐处检查引用是否都可改写
        done = 0
        for lit in hits:
            if len(zb) <= lit.len:
                nb = pad_to(zb, lit.len)
                cp = copy_patches(lit, nb)
                if utf8_consistent(lit, nb) and cp is not None: inplace.append((lit, nb, cp)); done += 1
                continue
            patches = []
            ok = bool(lit.refs)
            for r in lit.refs:
                if r[0] == 'fat':
                    patches.append(r)
                elif r[0] == 'code':
                    k = dedicated_movz(ins, r[1], r[2], r[3], lit.len)
                    if k is None: ok = False; break
                    patches.append(('code', r[1], r[2], k))
                elif r[0] == 'copy':
                    ok = False; break   # 内联拷贝的长度隐含在指令里，无法搬迁
                else:  # load / derived / ptr（长度另存）：无法改写
                    ok = False; break
            if not ok:
                continue
            if zb in relocated_text:
                fo = relocated_text[zb]
            else:
                fo = alloc.alloc(len(zb))
                if fo is None:
                    skipped.append((en, zh, lit.len, len(zb), '空闲空间不足')); break
                relocated_text[zb] = fo
            relocs.append((lit, zb, fo, patches)); done += 1
        if done == 0:
            skipped.append((en, zh, hits[0].len, len(zb), '引用方式无法安全改写'))
        elif done < len(hits):
            partial.append((en, done, len(hits)))
    return dict(inplace=inplace, relocs=relocs, skipped=skipped, partial=partial,
                missing=missing, unsafe=unsafe, alloc=alloc, text_addr=text_addr, text_off=text_off, ins=ins)


def report(plan, table):
    n_ok = len({l.text for l, *_ in plan['inplace']} | {l.text for l, *_ in plan['relocs']})
    print(f"词条 {len(table)} 条：原位替换 {len(plan['inplace'])} 处，搬迁 {len(plan['relocs'])} 处，"
          f"覆盖 {n_ok} 条；跳过 {len(plan['skipped'])} 条；未找到 {len(plan['missing'])} 条；"
          f"剩余空闲空间 {plan['alloc'].remaining()} 字节")
    for en, zh, l, n, why in plan['skipped']:
        print(f"  [跳过·{why}] {en!r} -> {zh!r}（原 {l} 字节，译文 {n} 字节）")
    for en, d, t in plan['partial']:
        print(f"  [部分] {en!r}：{t} 处中 {d} 处已汉化")
    if plan['unsafe']:
        print("  [长度不确定，跳过]", ", ".join(repr(x) for x in plan['unsafe'][:40]))
    if plan['missing']:
        print("  [未找到]", ", ".join(repr(x) for x in plan['missing'][:40]),
              "…" if len(plan['missing']) > 40 else "")


def apply_plan(m: MachO, plan):
    buf = bytearray(m.data)
    text_addr, text_off, ins = plan['text_addr'], plan['text_off'], plan['ins']
    for lit, nb, cp in plan['inplace']:
        assert buf[lit.off:lit.off + lit.len] == lit.text.encode('utf-8')
        buf[lit.off:lit.off + lit.len] = nb
        for q, kind, tail in cp:
            val = int.from_bytes(tail, 'little')
            w = ins[q]
            imm = (val & 0xFFFF) if kind == 'z' else (val >> 16)
            struct.pack_into('<I', buf, text_off + q * 4, (w & ~(0xFFFF << 5)) | (imm << 5))
    for lit, zb, fo, patches in plan['relocs']:
        buf[fo:fo + len(zb)] = zb
        new_addr = m.fileoff_to_addr(fo)
        for p in patches:
            if p[0] == 'fat':
                raw, _ = struct.unpack_from('<QQ', buf, p[1])
                low = (raw & ((1 << 36) - 1)) + (new_addr - lit.addr)
                raw = (raw & ~((1 << 36) - 1)) | (low & ((1 << 36) - 1))
                struct.pack_into('<QQ', buf, p[1], raw, len(zb))
            else:
                _, i, j, k = p
                pc = text_addr + i * 4
                struct.pack_into('<I', buf, text_off + i * 4, encode_adrp(ins[i], pc, new_addr))
                struct.pack_into('<I', buf, text_off + j * 4, encode_add(ins[j], new_addr))
                struct.pack_into('<I', buf, text_off + k * 4, encode_movz(ins[k], len(zb)))
    return bytes(buf)


# ---------- 命令 ----------
def exe_path(app): return os.path.join(app, 'Contents/MacOS/delta')

def backup_path(app):
    ver = subprocess.run(['defaults', 'read', os.path.join(app, 'Contents/Info.plist'), 'CFBundleShortVersionString'],
                         capture_output=True, text=True).stdout.strip() or 'unknown'
    return os.path.join(BACKUP_DIR, f'delta-{ver}.orig')

def original_binary(app):
    """返回未打过补丁的原始程序内容（优先用备份）。"""
    exe = exe_path(app)
    bk = backup_path(app)
    data = open(exe, 'rb').read()
    if os.path.exists(bk):
        bkdata = open(bk, 'rb').read()
        if MachO(bkdata).sections == MachO(data).sections:
            return bkdata, True
    return data, False

def do_apply(app, dict_path, dry):
    if not os.path.exists(exe_path(app)): sys.exit(f"找不到 {exe_path(app)}")
    data, from_backup = original_binary(app)
    m = MachO(data)
    table = load_dict(dict_path)
    plan = make_plan(m, table)
    report(plan, table)
    if dry: return
    out = apply_plan(m, plan)
    bk = backup_path(app)
    if not from_backup:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        shutil.copy2(exe_path(app), bk)
        print(f"已备份原始程序到 {bk}")
    write_binary(app, out)
    print("完成。启动 Delta 即可看到中文界面。")

def write_binary(app, out: bytes):
    """把新的主程序写回 app 包并重新签名。macOS 的"应用管理"隐私保护会拒绝直接改写
    其它 App 包内的文件（EPERM），这时改为：复制整个包 → 在副本里写入 → 整包换回去。"""
    if subprocess.run(['pgrep', '-f', exe_path(app)], capture_output=True).returncode == 0:
        sys.exit("Delta 正在运行，请先退出 Delta 再执行。")
    try:
        with open(exe_path(app), 'wb') as f:
            f.write(out)
        resign(app)
        return
    except PermissionError:
        print("直接写入被系统拒绝（应用管理保护），改用整包替换……")
    parent = os.path.dirname(os.path.abspath(app))
    tmp = tempfile.mkdtemp(prefix='delta-zh-')
    tmp_app = os.path.join(tmp, os.path.basename(app))
    shutil.copytree(app, tmp_app, symlinks=True)
    with open(exe_path(tmp_app), 'wb') as f:
        f.write(out)
    resign(tmp_app)
    old = os.path.join(parent, '.' + os.path.basename(app) + '.replaced')
    shutil.rmtree(old, ignore_errors=True)
    os.rename(app, old)
    try:
        shutil.move(tmp_app, app)
    except Exception:
        os.rename(old, app); raise
    shutil.rmtree(old, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)


CERT_NAME = "Delta zh-CN Patch"


def signing_identity():
    """优先用固定的自签名证书（make-cert 创建），这样每次打补丁后签名身份不变，
    钥匙串授权（"始终允许"）只需做一次；没有就退回 ad-hoc。"""
    r = subprocess.run(['security', 'find-identity', '-v', '-p', 'codesigning'], capture_output=True, text=True)
    return CERT_NAME if f'"{CERT_NAME}"' in r.stdout else '-'


def do_make_cert():
    if signing_identity() == CERT_NAME:
        print(f"证书「{CERT_NAME}」已存在。"); return
    tmp = tempfile.mkdtemp()
    key, cert, p12 = (os.path.join(tmp, n) for n in ('key.pem', 'cert.pem', 'id.p12'))
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
                    '-keyout', key, '-out', cert, '-subj', f'/CN={CERT_NAME}',
                    '-addext', 'keyUsage=critical,digitalSignature',
                    '-addext', 'extendedKeyUsage=critical,codeSigning'], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkcs12', '-export', '-out', p12, '-inkey', key, '-in', cert,
                    '-passout', 'pass:delta', '-macalg', 'sha1',                 # macOS 只认旧算法
                    '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES'], check=True, capture_output=True)
    keychain = os.path.expanduser('~/Library/Keychains/login.keychain-db')
    subprocess.run(['security', 'import', p12, '-k', keychain, '-P', 'delta',
                    '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'], check=True)
    print("接下来 macOS 会弹窗要求输入登录密码，用来把这张证书标记为「代码签名可信」……")
    r = subprocess.run(['security', 'add-trusted-cert', '-r', 'trustRoot', '-p', 'codeSign', '-k', keychain, cert])
    shutil.rmtree(tmp, ignore_errors=True)
    if r.returncode != 0 or signing_identity() != CERT_NAME:
        sys.exit("证书创建失败。可以继续使用 ad-hoc 签名（每次打补丁后钥匙串需重新点一次「始终允许」）。")
    print(f"已创建证书「{CERT_NAME}」。之后 apply 会自动用它签名；重新执行 apply 即可生效。")


def resign(app):
    ent = subprocess.run(['codesign', '-d', '--entitlements', ':-', app], capture_output=True).stdout
    identity = signing_identity()
    args = ['codesign', '--force', '--deep', '--sign', identity, '--options', 'runtime']
    tmpdir = tempfile.mkdtemp()
    if ent.strip():
        entf = os.path.join(tmpdir, 'delta.entitlements')
        open(entf, 'wb').write(ent)
        args += ['--entitlements', entf]
    r = subprocess.run(args + [app], capture_output=True, text=True)
    shutil.rmtree(tmpdir, ignore_errors=True)
    if r.returncode != 0:
        print(r.stderr); sys.exit("codesign 失败")
    subprocess.run(['xattr', '-dr', 'com.apple.quarantine', app], capture_output=True)
    print("已重新签名（ad-hoc）。首次启动如弹出钥匙串询问，请点「始终允许」；"
          "运行 `python3 delta_i18n.py make-cert` 可创建固定证书，避免每次打补丁后重复授权。"
          if identity == '-' else f"已用证书「{identity}」重新签名。")

def do_restore(app):
    bk = backup_path(app)
    if not os.path.exists(bk): sys.exit(f"没有备份（{bk}），请重新下载安装 Delta。")
    write_binary(app, open(bk, 'rb').read())
    print("已还原原版程序（签名为 ad-hoc；如需官方签名请重新安装 Delta）。")

def do_dump(app):
    data, _ = original_binary(app)
    m = MachO(data)
    lits, _, _ = analyze(m)
    seen = set()
    for lit in lits:
        t = lit.text
        if t in seen or len(t) < 2 or not re.search(r'[A-Za-z]', t): continue
        if re.search(r'::|\{|\}|</|https?:|\.rs$|^[a-z_]+$|^[A-Z_]+$|\\', t): continue
        if not (t[0].isupper() or ' ' in t): continue
        if sum(c.isalpha() or c.isspace() or c in ".,'’:;!?()-—/&%…" for c in t) / len(t) < 0.85: continue
        if re.match(r'^[A-Z][a-z]+[A-Z]', t): continue
        seen.add(t)
        print(f"{lit.addr:#x}\t{lit.len}\t{'E' if lit.exact else '-'}\t{json.dumps(t, ensure_ascii=False)}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['apply', 'check', 'restore', 'dump', 'make-cert'])
    ap.add_argument('--app', default='/Applications/Delta.app')
    ap.add_argument('--dict', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'translations.json'))
    a = ap.parse_args()
    if a.cmd == 'apply': do_apply(a.app, a.dict, dry=False)
    elif a.cmd == 'check': do_apply(a.app, a.dict, dry=True)
    elif a.cmd == 'restore': do_restore(a.app)
    elif a.cmd == 'dump': do_dump(a.app)
    elif a.cmd == 'make-cert': do_make_cert()

if __name__ == '__main__':
    main()

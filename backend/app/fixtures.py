"""纯字节合成 x86-64 ELF64 ET_REL 与 GNU ar 测试固件。

这些合成件与 ``as``/``ar`` 产出的字节结构一致（可被 readelf 与
``elfparser`` 同时解析），用于页面演示、解析规则测试与 API 冒烟。
"""
from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

EM_X86_64 = 62
ET_REL = 1

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_SECTION = 3

SHN_UNDEF = 0
SHN_COMMON = 0xFFF2


@dataclass
class ObjSpec:
    name: str
    strong: List[str] = field(default_factory=list)
    weak: List[str] = field(default_factory=list)
    common: List[str] = field(default_factory=list)
    undefined: List[str] = field(default_factory=list)
    weak_undefined: List[str] = field(default_factory=list)


def _strtab(strings: List[bytes]) -> Tuple[bytes, Dict[bytes, int]]:
    blob = b"\0"
    offsets: Dict[bytes, int] = {}
    for s in strings:
        if s not in offsets:
            offsets[s] = len(blob)
            blob += s + b"\0"
    return blob, offsets


def build_elf64_rel(spec: ObjSpec) -> bytes:
    """构造小端 x86-64 ET_REL 对象。"""
    # ---- 字符串表 ----
    sec_names = [b".text", b".symtab", b".strtab", b".shstrtab"]
    shstrtab, sh_off = _strtab(sec_names)

    sym_names = sorted(
        {s.encode() for s in spec.strong + spec.weak + spec.common
         + spec.undefined + spec.weak_undefined}
    )
    strtab, st_off = _strtab(sym_names)

    # ---- .text：每个强/弱定义一个 0x90 ----
    text = b"\x90" * (len(spec.strong) + len(spec.weak))

    # ---- 符号表：0=null, 1=.text section(local), 其后全局/弱 ----
    syms: List[Tuple[str, int, int, int, int, int]] = []
    # name, binding, shndx, value, size
    syms.append(("", STB_LOCAL, SHN_UNDEF, 0, 0))            # STN_UNDEF
    syms.append(("", STB_LOCAL, 1, 0, 0))                    # section .text
    val = 0
    for nm in spec.strong:
        syms.append((nm, STB_GLOBAL, 1, val, 1)); val += 1
    for nm in spec.weak:
        syms.append((nm, STB_WEAK, 1, val, 1)); val += 1
    for nm in spec.common:
        syms.append((nm, STB_GLOBAL, SHN_COMMON, 8, 8))
    for nm in spec.undefined:
        syms.append((nm, STB_GLOBAL, SHN_UNDEF, 0, 0))
    for nm in spec.weak_undefined:
        syms.append((nm, STB_WEAK, SHN_UNDEF, 0, 0))

    sh_info = 2  # 首个非局部符号下标
    symtab = b""
    for nm, bind, shndx, value, size in syms:
        st_name = st_off.get(nm.encode(), 0)
        st_info = (bind << 4) | STT_NOTYPE
        if nm == "" and shndx == 1:
            st_info = (STB_LOCAL << 4) | STT_SECTION
        if nm == "" and shndx == SHN_UNDEF and bind == STB_LOCAL:
            st_info = 0
        symtab += struct.pack(
            "<IBBHQQ", st_name, st_info, 0, shndx, value, size
        )

    # ---- 布局 ----
    ehsize = 64
    off_text = ehsize
    off_symtab = off_text + len(text)
    off_strtab = off_symtab + len(symtab)
    off_shstrtab = off_strtab + len(strtab)
    shentsize = 64
    e_shoff = off_shstrtab + len(shstrtab)
    # 节：0 null, 1 .text, 2 .symtab, 3 .strtab, 4 .shstrtab
    e_shnum = 5
    e_shstrndx = 4

    def shdr(name, typ, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_off[name], typ, flags, addr, offset, size, link, info,
            align, entsize,
        )

    shdrs = b""
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    shdrs += shdr(b".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0,
                  off_text, len(text), 0, 0, 16, 0)
    shdrs += shdr(b".symtab", SHT_SYMTAB, 0, 0,
                  off_symtab, len(symtab), 3, sh_info, 8, 24)
    shdrs += shdr(b".strtab", SHT_STRTAB, 0, 0,
                  off_strtab, len(strtab), 0, 0, 1, 0)
    shdrs += shdr(b".shstrtab", SHT_STRTAB, 0, 0,
                  off_shstrtab, len(shstrtab), 0, 0, 1, 0)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident
    ehdr += struct.pack("<HHI", ET_REL, EM_X86_64, 1)
    ehdr += struct.pack("<Q", 0)              # e_entry
    ehdr += struct.pack("<Q", 0)              # e_phoff
    ehdr += struct.pack("<Q", e_shoff)
    ehdr += struct.pack("<I", 0)              # e_flags
    ehdr += struct.pack("<HHH", ehsize, 0, 0)          # ehsize/phentsize/phnum
    ehdr += struct.pack("<HHH", shentsize, e_shnum, e_shstrndx)
    assert len(ehdr) == 64

    return ehdr + text + symtab + strtab + shstrtab + shdrs


# --------------------------------------------------------------------------- #
# GNU ar 合成
# --------------------------------------------------------------------------- #
def _ar_header(name: bytes, size: int) -> bytes:
    return (
        name.ljust(16)
        + b"0".ljust(12)        # mtime
        + b"0".ljust(6)         # uid
        + b"0".ljust(6)         # gid
        + b"100644".ljust(8)    # mode
        + str(size).encode().ljust(10)
        + b"`\n"
    )


def _pad(blob: bytes) -> bytes:
    return blob + (b"\n" if len(blob) % 2 == 1 else b"")


def build_gnu_ar(archive_name: str, specs: List[ObjSpec],
                 defined_index: Optional[object] = None) -> bytes:
    """构造带 GNU 符号索引 '/' 的归档。

    defined_index 为 None 时按成员真实定义生成；
    可为 {符号: 成员名} 字典，或 [(符号, 成员名), ...] 列表（允许重复符号名）。
    """
    members = [(s.name + ".o", build_elf64_rel(s)) for s in specs]

    magic = b"!<arch>\n"
    if defined_index is None:
        idx_symbols: List[Tuple[str, str]] = []
        for spec, (mname, _blob) in zip(specs, members):
            for nm in spec.strong + spec.weak + spec.common:
                idx_symbols.append((nm, mname))
    elif isinstance(defined_index, dict):
        idx_symbols = list(defined_index.items())
    else:
        idx_symbols = list(defined_index)

    names_blob = b"".join(nm.encode() + b"\0" for nm, _ in idx_symbols)
    idx_body_size = 4 + 4 * len(idx_symbols) + len(names_blob)

    pos = len(magic)
    pos += len(_ar_header(b"/", idx_body_size)) + idx_body_size
    pos += (1 if (len(_ar_header(b"/", idx_body_size)) + idx_body_size) % 2 else 0)

    offsets: Dict[str, int] = {}
    for mname, blob in members:
        offsets[mname] = pos
        name_field = (mname + "/").encode()
        if len(name_field) > 16:
            raise ValueError("演示固件成员名须短于 16 字节")
        pos += len(_ar_header(name_field, len(blob))) + len(blob)
        if (len(_ar_header(name_field, len(blob))) + len(blob)) % 2:
            pos += 1

    # ---- 实际拼装 ----
    out = bytearray(magic)
    idx = struct.pack(">I", len(idx_symbols))
    for _nm, mname in idx_symbols:
        idx += struct.pack(">I", offsets[mname])
    idx += names_blob
    out += _ar_header(b"/", len(idx)) + idx
    if (len(_ar_header(b"/", len(idx))) + len(idx)) % 2:
        out += b"\n"

    for mname, blob in members:
        hdr = _ar_header((mname + "/").encode(), len(blob))
        out += hdr + blob
        if (len(hdr) + len(blob)) % 2:
            out += b"\n"

    return bytes(out)


def b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")

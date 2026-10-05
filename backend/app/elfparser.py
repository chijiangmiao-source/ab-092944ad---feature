"""原始字节级 ELF64 ET_REL 与 GNU ar 解析。

只接受小端 x86-64 的 ET_REL 对象；归档只接受
``!<arch>\\n`` 魔法的 GNU/SysV 格式（无压缩成员，不接受 BSD 变体）。
所有边界、成员头、名称表、符号索引与 ELF 符号表均逐字节校验。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

ELFMAG = b"\x7fELF"
AR_MAGIC = b"!<arch>\n"

EM_X86_64 = 62
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_REL = 1

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

SHF_ALLOC = 0x2

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_SECTION = 3
STT_FILE = 4

SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_XINDEX = 0xFFFF

GNU_NAME_TABLE = "//"
GNU_SYMBOL_TABLE = "/"


class ParseError(ValueError):
    """输入字节违反格式约束；message 与 where 记录首个触发位置。"""

    def __init__(self, message: str, where: str = "", evidence: dict | None = None):
        super().__init__(f"{where}: {message}" if where else message)
        self.message = message
        self.where = where
        self.evidence = evidence or {}


@dataclass
class ELFSymbol:
    name: str
    binding: int          # STB_GLOBAL / STB_WEAK
    shndx: int
    defined: bool
    index: int = -1       # 在所属对象 .symtab 中的下标


@dataclass
class ParsedObject:
    label: str
    symbols: List[ELFSymbol] = field(default_factory=list)
    strong_defs: dict = field(default_factory=dict)   # name -> symtab 下标
    weak_defs: dict = field(default_factory=dict)     # name -> symtab 下标
    undefined_strong: List[str] = field(default_factory=list)
    undefined_weak: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# 基础读取
# --------------------------------------------------------------------------- #
class _Reader:
    __slots__ = ("data", "base_label")

    def __init__(self, data: bytes, base_label: str):
        self.data = data
        self.base_label = base_label

    def slice(self, off: int, size: int, what: str) -> bytes:
        if off < 0 or size < 0 or off + size > len(self.data):
            raise ParseError(
                f"{what} 越界: offset={off} size={size} 总长={len(self.data)}",
                self.base_label,
            )
        return self.data[off : off + size]

    def u16(self, off: int, what: str) -> int:
        return struct.unpack_from("<H", self.slice(off, 2, what))[0]

    def u32(self, off: int, what: str) -> int:
        return struct.unpack_from("<I", self.slice(off, 4, what))[0]

    def u64(self, off: int, what: str) -> int:
        return struct.unpack_from("<Q", self.slice(off, 8, what))[0]


def _cstring(buf: bytes, start: int, what: str, where: str) -> str:
    if start < 0 or start >= len(buf):
        raise ParseError(f"{what} 字符串下标越界: {start}", where)
    end = buf.find(b"\0", start)
    if end < 0:
        raise ParseError(f"{what} 字符串缺少 NUL 终止", where)
    raw = buf[start:end]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseError(f"{what} 字符串非合法 UTF-8: {raw!r}", where)


# --------------------------------------------------------------------------- #
# ELF64
# --------------------------------------------------------------------------- #
def parse_elf_object(data: bytes, label: str) -> ParsedObject:
    r = _Reader(data, label)

    if len(data) < 64:
        raise ParseError(f"长度 {len(data)} 小于 ELF64 头 64 字节", label)
    ident = r.slice(0, 16, "ELF e_ident")
    if ident[:4] != ELFMAG:
        raise ParseError("错误的 ELF 魔数", f"{label} byte 0")
    if ident[4] != ELFCLASS64:
        raise ParseError(f"仅支持 ELF64 (EI_CLASS={ident[4]})", f"{label} e_ident[EI_CLASS]")
    if ident[5] != ELFDATA2LSB:
        raise ParseError(f"仅支持小端 (EI_DATA={ident[5]})", f"{label} e_ident[EI_DATA]")
    if ident[6] != 1:
        raise ParseError(f"不支持的 EI_VERSION={ident[6]}", f"{label} e_ident[EI_VERSION]")

    e_type = r.u16(16, "e_type")
    if e_type != ET_REL:
        raise ParseError(f"仅支持 ET_REL，发现 e_type={e_type}", f"{label} e_type@16")
    e_machine = r.u16(18, "e_machine")
    if e_machine != EM_X86_64:
        raise ParseError(
            f"仅支持 EM_X86_64(62)，发现 e_machine={e_machine}",
            f"{label} e_machine@18",
        )
    if r.u32(20, "e_version") != 1:
        raise ParseError("e_version 必须为 EV_CURRENT(1)", f"{label} e_version@20")
    e_flags = r.u32(36, "e_flags")
    if e_machine == EM_X86_64 and e_flags != 0:
        raise ParseError(
            f"x86-64 ET_REL 的 e_flags 必须为 0，发现 {e_flags}",
            f"{label} e_flags@36",
        )

    e_phoff = r.u64(32, "e_phoff")
    if e_type == ET_REL and e_phoff != 0:
        raise ParseError(
            f"ET_REL 不应含程序头表，发现 e_phoff={e_phoff}", f"{label} e_phoff@32"
        )
    e_ehsize = r.u16(52, "e_ehsize")
    if e_ehsize not in (0, 64):
        raise ParseError(
            f"e_ehsize={e_ehsize} 非法（ELF64 应为 64）", f"{label} e_ehsize@52"
        )

    e_shoff = r.u64(40, "e_shoff")
    e_shentsize = r.u16(58, "e_shentsize")
    e_shnum = r.u16(60, "e_shnum")
    e_shstrndx = r.u16(62, "e_shstrndx")

    if e_shoff == 0 or e_shnum == 0:
        raise ParseError("缺少节头表", f"{label} e_shoff/e_shnum")
    if e_shentsize < 64:
        raise ParseError(
            f"e_shentsize={e_shentsize} 小于 Elf64_Shdr(64)", f"{label} e_shentsize@58"
        )
    sh_end = e_shoff + e_shnum * e_shentsize
    if sh_end > len(data):
        raise ParseError(
            f"节头表越界: [{e_shoff}, {sh_end}) 总长={len(data)}",
            f"{label} section header table",
        )
    if e_shstrndx == SHN_XINDEX:
        raise ParseError("不支持扩展节索引 SHN_XINDEX(0xffff)", f"{label} e_shstrndx")
    if e_shstrndx >= e_shnum:
        raise ParseError(f"e_shstrndx={e_shstrndx} 超出节数 {e_shnum}", f"{label} e_shstrndx@62")

    sections: list[dict] = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = {
            "name_off": r.u32(off, "sh_name"),
            "type": r.u32(off + 4, "sh_type"),
            "flags": r.u64(off + 8, "sh_flags"),
            "offset": r.u64(off + 24, "sh_offset"),
            "size": r.u64(off + 32, "sh_size"),
            "link": r.u32(off + 40, "sh_link"),
            "info": r.u32(off + 44, "sh_info"),
            "entsize": r.u64(off + 56, "sh_entsize"),
        }
        if sh["type"] != SHT_NOBITS and (
            sh["offset"] > len(data) or sh["offset"] + sh["size"] > len(data)
        ):
            raise ParseError(
                f"节[{i}] 数据越界: offset={sh['offset']} size={sh['size']}",
                f"{label} Elf64_Shdr[{i}]",
            )
        sections.append(sh)

    symtab_sections = [i for i, s in enumerate(sections) if s["type"] == SHT_SYMTAB]
    if len(symtab_sections) > 1:
        raise ParseError(
            f"存在 {len(symtab_sections)} 个 SHT_SYMTAB，无法唯一确定符号表",
            f"{label} section headers",
        )

    obj = ParsedObject(label=label)
    if not symtab_sections:
        return obj

    si = symtab_sections[0]
    sym_sh = sections[si]
    link = sym_sh["link"]
    if link >= e_shnum:
        raise ParseError(
            f".symtab sh_link={link} 超出节数", f"{label} Elf64_Shdr[{si}].sh_link"
        )
    if sections[link]["type"] != SHT_STRTAB:
        raise ParseError(
            f".symtab sh_link 指向类型 {sections[link]['type']}，应为 STRTAB(3)",
            f"{label} Elf64_Shdr[{link}]",
        )
    strtab = r.slice(sections[link]["offset"], sections[link]["size"], "符号字符串表")

    ent = sym_sh["entsize"] or 24
    if ent < 24:
        raise ParseError(
            f"符号表表项大小 {ent} 小于 Elf64_Sym(24)",
            f"{label} Elf64_Shdr[{si}].sh_entsize",
        )
    size = sym_sh["size"]
    if size % ent != 0:
        raise ParseError(f"符号表大小 {size} 不能被表项 {ent} 整除", f"{label} .symtab")

    local_boundary = sym_sh["info"]
    n_syms = size // ent
    if local_boundary > n_syms:
        raise ParseError(
            f"sh_info={local_boundary} 超出符号项数 {n_syms}",
            f"{label} Elf64_Shdr[{si}].sh_info",
        )

    for n in range(n_syms):
        off = sym_sh["offset"] + n * ent
        st_name = r.u32(off, "st_name")
        st_info = data[off + 4]
        # st_other 中的可见性对静态 ET_REL 链接闭包无影响（与 ld 一致，不拒绝）。
        st_shndx = r.u16(off + 6, "st_shndx")
        binding = st_info >> 4
        stype = st_info & 0xF

        if n < local_boundary and binding != STB_LOCAL:
            raise ParseError(
                f"局部区(下标<{local_boundary})内出现非 STB_LOCAL 符号(binding={binding})",
                f"{label} .symtab[{n}]",
            )
        if n >= local_boundary and binding == STB_LOCAL and stype != STT_FILE:
            raise ParseError("局部符号未排在全局符号之前", f"{label} .symtab[{n}]")
        if binding == STB_LOCAL:
            continue
        if stype in (STT_SECTION, STT_FILE):
            continue
        if st_shndx == SHN_XINDEX:
            raise ParseError(
                "不支持扩展节索引 SHN_XINDEX", f"{label} .symtab[{n}].st_shndx"
            )
        if binding not in (STB_GLOBAL, STB_WEAK):
            raise ParseError(
                f"符号使用不支持的绑定 binding={binding}", f"{label} .symtab[{n}]"
            )

        name = _cstring(strtab, st_name, f"符号[{n}]", f"{label} .symtab[{n}].st_name")
        if not name:
            continue

        defined = st_shndx != SHN_UNDEF
        if defined and st_shndx not in (SHN_ABS, SHN_COMMON):
            if st_shndx >= e_shnum:
                raise ParseError(
                    f"符号 {name!r} 的 st_shndx={st_shndx} 超出节数",
                    f"{label} .symtab[{n}]",
                )
            # 注：GNU ld 的归档抽取按符号索引进行，即使定义位于非 ALLOC 节
            # （调试节等）也会抽取并在链接闭包中满足引用，此处保持一致。

        sym = ELFSymbol(name=name, binding=binding, shndx=st_shndx,
                        defined=defined, index=n)
        obj.symbols.append(sym)

        if st_shndx == SHN_COMMON:
            # COMMON 暂定定义按强定义处理（ld 为其分配存储）。
            obj.strong_defs[name] = n
        elif not defined:
            if binding == STB_WEAK:
                obj.undefined_weak.append(name)
            else:
                obj.undefined_strong.append(name)
        elif binding == STB_WEAK:
            obj.weak_defs[name] = n
        else:
            obj.strong_defs[name] = n

    return obj


# --------------------------------------------------------------------------- #
# GNU ar
# --------------------------------------------------------------------------- #
@dataclass
class ArMember:
    name: str
    data: bytes
    header_offset: int
    data_offset: int
    ordinal: int                 # 普通成员序号（不含特殊成员），-1 表示特殊成员
    special: bool = False
    parsed: Optional[ParsedObject] = None


@dataclass
class ArArchive:
    label: str
    members: List[ArMember] = field(default_factory=list)          # 仅普通成员
    symbol_index: dict = field(default_factory=dict)               # 符号 -> 首个成员
    index_pairs: list = field(default_factory=list)                # 索引原始 (符号, 成员) 对
    member_order: List[ArMember] = field(default_factory=list)     # 归档内顺序


def _decimal_field(b: bytes, what: str, where: str) -> int:
    s = b.strip()
    if not s:
        return 0
    if not s.isdigit():
        raise ParseError(f"{what} 字段非十进制整数: {s!r}", where)
    return int(s)


def _octal_field(b: bytes, what: str, where: str) -> int:
    s = b.strip()
    if not s:
        return 0
    if not all(c in b"01234567" for c in s):
        raise ParseError(f"{what} 字段非八进制整数: {s!r}", where)
    return int(s, 8)


def parse_ar(data: bytes, label: str) -> ArArchive:
    """解析 GNU/SysV ar 归档，校验名称表与符号索引，并解析全部普通成员。"""
    if len(data) < 8 or data[:8] != AR_MAGIC:
        raise ParseError("错误的 ar 魔数（应为 b'!<arch>\\n'）", f"{label} byte 0")

    raw_members: List[ArMember] = []
    name_table: Optional[bytes] = None
    name_table_seen = False
    sym_index_member: Optional[ArMember] = None
    seen_regular_names: set = set()

    pos = 8
    while pos < len(data):
        hdr_off = pos
        if pos + 60 > len(data):
            raise ParseError(
                f"剩余 {len(data) - pos} 字节不足 60 字节成员头",
                f"{label} ar header@{hdr_off}",
            )
        header = data[pos : pos + 60]
        raw_name = bytes(header[0:16])
        _decimal_field(header[16:28], "mtime", f"{label} ar header@{hdr_off}")
        _decimal_field(header[28:34], "uid", f"{label} ar header@{hdr_off}")
        _decimal_field(header[34:40], "gid", f"{label} ar header@{hdr_off}")
        _octal_field(header[40:48], "mode", f"{label} ar header@{hdr_off}")
        size = _decimal_field(header[48:58], "size", f"{label} ar header@{hdr_off}")
        if header[58:60] != b"`\n":
            raise ParseError(
                f"成员头结束标记损坏: {header[58:60]!r}（应为 b'`\\n'）",
                f"{label} ar header@{hdr_off}",
            )

        data_off = pos + 60
        if data_off + size > len(data):
            raise ParseError(
                f"成员数据越界: header@{hdr_off} size={size}，归档总长={len(data)}",
                f"{label} ar member@{hdr_off}",
            )
        body = data[data_off : data_off + size]

        nm = bytes(raw_name).rstrip()
        special = False
        display = ""
        if nm == b"/":
            special = True
            display = GNU_SYMBOL_TABLE
        elif nm == b"//":
            special = True
            display = GNU_NAME_TABLE
            if name_table_seen:
                raise ParseError(
                    "出现重复的名称表成员 '//'", f"{label} ar header@{hdr_off}"
                )
            name_table_seen = True
            name_table = _validate_name_table(body, label, hdr_off)
        elif nm.startswith(b"/") and len(nm) > 1 and nm[1:].isdigit():
            if name_table is None:
                raise ParseError(
                    f"长名引用 {nm.decode()} 出现在名称表 // 之前",
                    f"{label} ar header@{hdr_off}",
                )
            ref = int(nm[1:])
            if ref >= len(name_table):
                raise ParseError(
                    f"长名偏移 /{ref} 超出名称表长度 {len(name_table)}",
                    f"{label} ar header@{hdr_off}",
                )
            end = name_table.find(b"/\n", ref)
            if end < 0:
                raise ParseError(
                    f"长名引用 /{ref} 找不到终止 '/\\n'",
                    f"{label} ar header@{hdr_off}",
                )
            if end == ref:
                raise ParseError(
                    f"长名引用 /{ref} 指向空名称", f"{label} ar header@{hdr_off}"
                )
            try:
                display = name_table[ref:end].decode("utf-8")
            except UnicodeDecodeError:
                raise ParseError(
                    f"长名引用 /{ref} 非 UTF-8", f"{label} ar header@{hdr_off}"
                )
        elif nm.startswith(b"#1/") or nm.startswith(b"/SYM64/") or nm == b"__.SYMDEF":
            raise ParseError(
                f"不支持的归档成员名格式（仅 GNU，无压缩成员）: {nm.decode('ascii', 'replace')}",
                f"{label} ar header@{hdr_off}",
            )
        else:
            short = nm[:-1] if nm.endswith(b"/") else nm
            if not short:
                raise ParseError("成员名为空", f"{label} ar header@{hdr_off}")
            try:
                display = short.decode("utf-8")
            except UnicodeDecodeError:
                raise ParseError(
                    f"短成员名非 UTF-8: {short!r}", f"{label} ar header@{hdr_off}"
                )

        if not special:
            if display in seen_regular_names:
                raise ParseError(
                    f"归档内出现重名成员 {display!r}",
                    f"{label} ar header@{hdr_off}",
                )
            seen_regular_names.add(display)

        member = ArMember(
            name=display, data=body, header_offset=hdr_off,
            data_offset=data_off, ordinal=-1, special=special,
        )
        if special and display == GNU_SYMBOL_TABLE:
            if sym_index_member is not None:
                raise ParseError(
                    "出现重复的符号索引成员 '/'", f"{label} ar header@{hdr_off}"
                )
            sym_index_member = member
        raw_members.append(member)

        pos = data_off + size
        if pos % 2 == 1:
            if pos < len(data):
                if data[pos : pos + 1] != b"\n":
                    raise ParseError(
                        f"奇数成员后期望填充 b'\\n'，得到 {data[pos:pos+1]!r}",
                        f"{label} ar padding@{pos}",
                    )
                pos += 1
            # 文件恰好结束时允许无填充字节。

    archive = ArArchive(label=label)
    ordinal = 0
    for m in raw_members:
        if not m.special:
            m.ordinal = ordinal
            ordinal += 1
            m.parsed = parse_elf_object(m.data, f"{label}!{m.name}")
            archive.members.append(m)
            archive.member_order.append(m)

    if sym_index_member is not None:
        archive.symbol_index, archive.index_pairs = _validate_symbol_index(
            sym_index_member.data, raw_members, label
        )
        _cross_check_index(archive, label)
    else:
        # GNU 正常归档（ar rcs）总带符号索引；无索引则成员永不抽取，按损坏拒绝。
        raise ParseError(
            "归档缺少 GNU 符号索引成员 '/'（无法按索引抽取成员）", label
        )

    return archive


def _validate_name_table(body: bytes, label: str, hdr_off: int) -> bytes:
    if not body:
        raise ParseError("名称表 // 为空", f"{label} ar header@{hdr_off}")
    if not body.endswith(b"\n"):
        raise ParseError(
            "名称表缺少终止换行", f"{label} ar name table@{hdr_off + 60}"
        )
    entries = body.split(b"\n")
    if entries[-1] != b"":
        raise ParseError("名称表末项异常", f"{label} ar name table")
    cursor = 0
    for ent in entries[:-1]:
        if not ent.endswith(b"/"):
            raise ParseError(
                f"名称表条目缺少 '/' 终止: {ent!r}",
                f"{label} ar name table offset {cursor}",
            )
        if len(ent) == 1:
            raise ParseError(
                "名称表存在空成员名", f"{label} ar name table offset {cursor}"
            )
        try:
            ent[:-1].decode("utf-8")
        except UnicodeDecodeError:
            raise ParseError(
                f"名称表条目非 UTF-8: {ent[:-1]!r}",
                f"{label} ar name table offset {cursor}",
            )
        cursor += len(ent) + 1
    return bytes(body)


def _validate_symbol_index(body: bytes, raw_members: List[ArMember], label: str) -> dict:
    """校验 GNU 符号索引：大端 count、count 个成员头偏移、NUL 分隔符号名。"""
    if len(body) < 4:
        raise ParseError(
            f"符号索引体仅 {len(body)} 字节，不足 4 字节计数",
            f"{label} ar symbol index '/'",
        )
    count = struct.unpack_from(">I", body, 0)[0]
    offsets_end = 4 + 4 * count
    if offsets_end > len(body):
        raise ParseError(
            f"符号索引声称 {count} 项，但表体仅 {len(body)} 字节（需要 {offsets_end}）",
            f"{label} ar symbol index '/'",
        )
    offsets = [
        struct.unpack_from(">I", body, 4 + 4 * i)[0] for i in range(count)
    ]
    names_region = body[offsets_end:]
    names: List[str] = []
    p = 0
    while p < len(names_region):
        end = names_region.find(b"\0", p)
        if end < 0:
            raise ParseError(
                "符号索引名称区缺少 NUL 终止",
                f"{label} ar symbol index '/' name+{p}",
            )
        raw = names_region[p:end]
        if not raw:
            if end == len(names_region) - 1:
                break  # 末尾单个填充 NUL，允许
            raise ParseError(
                "符号索引存在空符号名",
                f"{label} ar symbol index '/' name+{p}",
            )
        try:
            names.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            raise ParseError(
                f"符号索引符号名非 UTF-8: {raw!r}",
                f"{label} ar symbol index '/' name+{p}",
            )
        p = end + 1
    if len(names) != count:
        raise ParseError(
            f"符号索引名称数 {len(names)} 与偏移项数 {count} 不一致（索引损坏）",
            f"{label} ar symbol index '/'",
        )

    header_offsets = {m.header_offset: m for m in raw_members}
    pairs: list = []
    index: dict = {}
    for i, (off, name) in enumerate(zip(offsets, names)):
        target = header_offsets.get(off)
        if target is None:
            raise ParseError(
                f"符号索引项[{i}] {name!r} 的偏移 {off} 不指向任何成员头",
                f"{label} ar symbol index '/' offset[{i}]",
            )
        if target.special:
            raise ParseError(
                f"符号索引项[{i}] {name!r} 的偏移 {off} 指向特殊成员 {target.name!r}",
                f"{label} ar symbol index '/' offset[{i}]",
            )
        pairs.append((name, target))
        index.setdefault(name, target)
    return index, pairs


def _cross_check_index(archive: "ArArchive", label: str) -> None:
    """符号索引必须与成员实际定义一致：

    * 索引中每条 (符号, 成员) 对，该成员的 .symtab 必须真实定义该符号；
    * 每个成员定义的每个全局/弱符号必须至少被一条索引项覆盖。
    （ranlib 允许同一符号出现在多个成员的索引项中，抽取时首个成员胜出。）
    """
    indexed_for: dict = {}
    for name, member in archive.index_pairs:
        indexed_for.setdefault(id(member), set()).add(name)

    for name, member in archive.index_pairs:
        actual = {s.name for s in member.parsed.symbols if s.shndx != SHN_UNDEF}
        if name not in actual:
            raise ParseError(
                f"符号索引声称成员 {member.name!r} 定义 {name!r}，"
                f"但该成员的 .symtab 中并无此全局/弱定义",
                f"{label} ar symbol index '/' -> !{member.name}",
            )

    for m in archive.member_order:
        actual = {s.name for s in m.parsed.symbols if s.shndx != SHN_UNDEF}
        missing = actual - indexed_for.get(id(m), set())
        if missing:
            raise ParseError(
                f"成员 {m.name!r} 定义了索引未收录的全局/弱符号 "
                f"{sorted(missing)!r}（符号索引陈旧/损坏）",
                f"{label} ar symbol index '/' -> !{m.name}",
            )

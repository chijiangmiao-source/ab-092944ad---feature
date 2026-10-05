"""解析规则测试：ELF64 ET_REL 与 GNU ar 的字节级边界/表项校验。"""
from __future__ import annotations

import struct

import pytest

from app.elfparser import ParseError, parse_ar, parse_elf_object
from app.fixtures import ObjSpec, build_elf64_rel, build_gnu_ar


# --------------------------------------------------------------------------- #
# ELF
# --------------------------------------------------------------------------- #
def _elf(spec=None):
    return build_elf64_rel(spec or ObjSpec("x", strong=["f"], undefined=["g"]))


def test_elf_happy_path():
    obj = parse_elf_object(_elf(), "x.o")
    assert set(obj.strong_defs) == {"f"}
    assert obj.undefined_strong == ["g"]
    assert obj.label == "x.o"


def test_elf_bad_magic():
    blob = bytearray(_elf())
    blob[0] ^= 0xFF
    with pytest.raises(ParseError) as ei:
        parse_elf_object(bytes(blob), "x.o")
    assert "魔数" in ei.value.message
    assert ei.value.where == "x.o byte 0"


def test_elf_rejects_elf32():
    blob = bytearray(_elf())
    blob[4] = 1  # EI_CLASS = ELFCLASS32
    with pytest.raises(ParseError, match="ELF64"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_rejects_big_endian():
    blob = bytearray(_elf())
    blob[5] = 2
    with pytest.raises(ParseError, match="小端"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_rejects_non_rel():
    blob = bytearray(_elf())
    struct.pack_into("<H", blob, 16, 2)  # ET_EXEC
    with pytest.raises(ParseError, match="ET_REL"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_rejects_non_x86_64():
    blob = bytearray(_elf())
    struct.pack_into("<H", blob, 18, 183)  # EM_AARCH64
    with pytest.raises(ParseError, match="EM_X86_64"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_truncated_header():
    with pytest.raises(ParseError, match="64"):
        parse_elf_object(_elf()[:63], "x.o")


def test_elf_section_table_runs_past_eof():
    blob = bytearray(_elf())
    struct.pack_into("<Q", blob, 40, len(blob) - 10)  # e_shoff 推到接近末尾
    with pytest.raises(ParseError, match="节头表越界"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_symtab_link_out_of_range():
    blob = bytearray(_elf())
    e_shoff = struct.unpack_from("<Q", blob, 40)[0]
    struct.pack_into("<I", blob, e_shoff + 2 * 64 + 40, 99)  # .symtab sh_link
    with pytest.raises(ParseError, match="sh_link"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_symbol_name_not_in_strtab():
    blob = bytearray(_elf())
    e_shoff = struct.unpack_from("<Q", blob, 40)[0]
    sym_off = struct.unpack_from("<Q", blob, e_shoff + 2 * 64 + 24)[0]
    struct.pack_into("<I", blob, sym_off + 2 * 24, 0xFFFFFF)  # 第 3 个符号 st_name
    with pytest.raises(ParseError, match="字符串下标越界"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_shstrndx_out_of_range():
    blob = bytearray(_elf())
    struct.pack_into("<H", blob, 62, 40)
    with pytest.raises(ParseError, match="e_shstrndx"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_local_global_ordering():
    blob = bytearray(_elf())
    e_shoff = struct.unpack_from("<Q", blob, 40)[0]
    # sh_info=1，但下标 1 为 SECTION LOCAL 没问题；把 sh_info 改成 3 且符号 2 为 GLOBAL
    struct.pack_into("<I", blob, e_shoff + 2 * 64 + 44, 3)
    with pytest.raises(ParseError, match="STB_LOCAL"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_rejects_nonzero_eflags():
    blob = bytearray(_elf())
    struct.pack_into("<I", blob, 36, 0x1)  # e_flags
    with pytest.raises(ParseError, match="e_flags"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_rejects_phoff_in_rel():
    blob = bytearray(_elf())
    struct.pack_into("<Q", blob, 32, 64)  # ET_REL 不应有程序头
    with pytest.raises(ParseError, match="e_phoff"):
        parse_elf_object(bytes(blob), "x.o")


def test_elf_common_and_weak_classified():
    blob = _elf(ObjSpec(
        "c", strong=["s"], weak=["w"], common=["k"],
        undefined=["u"], weak_undefined=["v"],
    ))
    obj = parse_elf_object(blob, "c.o")
    assert set(obj.strong_defs) == {"s", "k"}
    assert set(obj.weak_defs) == {"w"}
    assert obj.undefined_strong == ["u"]
    assert obj.undefined_weak == ["v"]


# --------------------------------------------------------------------------- #
# ar
# --------------------------------------------------------------------------- #
def _ar():
    return build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa"], undefined=["fb"]),
        ObjSpec("b", strong=["fb"]),
    ])


def test_ar_happy_path():
    arc = parse_ar(_ar(), "lib.a")
    assert [m.name for m in arc.member_order] == ["a.o", "b.o"]
    assert set(arc.symbol_index) == {"fa", "fb"}
    assert arc.symbol_index["fa"].name == "a.o"


def test_ar_bad_magic():
    blob = bytearray(_ar())
    blob[0] = ord("?")
    with pytest.raises(ParseError, match="ar 魔数"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_truncated_member_header():
    blob = _ar()
    # 保留魔数与符号索引成员，裁掉普通成员头的一部分
    with pytest.raises(ParseError, match="成员头|越界|长度"):
        parse_ar(blob[: len(blob) - 30], "lib.a")


def test_ar_bad_fmag():
    blob = bytearray(_ar())
    # 找到第一个成员头的结束标记（偏移 58/59 处）
    idx = blob.find(b"`\n")
    blob[idx : idx + 2] = b"XX"
    with pytest.raises(ParseError, match="结束标记"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_bad_size_field():
    blob = bytearray(_ar())
    blob[8 + 48 : 8 + 58] = b"not-a-size!"
    with pytest.raises(ParseError, match="size"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_member_runs_past_eof():
    blob = bytearray(_ar())
    blob[8 + 48 : 8 + 58] = b"9999999999"
    with pytest.raises(ParseError, match="越界"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_missing_symbol_index_rejected():
    blob = _ar()
    # 定位第一个普通成员头（名称字段 "a.o/" 出现处，头在其前 16 字节），
    # 删除魔数之后到该头之间的整个 '/' 索引成员。
    name_pos = blob.find(b"a.o/")
    member_hdr_off = name_pos          # 名称字段即成员头起始
    stripped = blob[:8] + blob[member_hdr_off:]
    with pytest.raises(ParseError, match="符号索引"):
        parse_ar(stripped, "lib.a")


def test_ar_index_count_too_large():
    blob = bytearray(_ar())
    struct.pack_into(">I", blob, 8 + 60, 0xFFFFFFFF)
    with pytest.raises(ParseError, match="符号索引声称"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_index_name_count_mismatch():
    blob = bytearray(build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa"]),
        ObjSpec("b", strong=["fb"]),
    ]))
    # 名称区位于索引体内 4 + 4*2 字节处；抹掉 "fa" 后的 NUL，使名称数变为 1
    names = 8 + 60 + 4 + 8
    assert blob[names + 2] == 0
    blob[names + 2] = ord("X")
    with pytest.raises(ParseError, match="不一致"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_index_offset_points_nowhere():
    blob = bytearray(_ar())
    # 第一个偏移项改成不存在的头偏移
    struct.pack_into(">I", blob, 8 + 60 + 4, 0x12345)
    with pytest.raises(ParseError, match="不指向任何成员头"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_index_points_to_special_member():
    blob = bytearray(_ar())
    # 让索引偏移指向索引自身头（偏移 8）
    struct.pack_into(">I", blob, 8 + 60 + 4, 8)
    with pytest.raises(ParseError, match="特殊成员"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_index_same_symbol_two_members_allowed():
    # ranlib 允许同一符号在两个成员的索引项中各出现一次（抽取首个命中）
    arc = parse_ar(build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa"]),
        ObjSpec("b", strong=["fa", "fb"]),
    ], defined_index=[("fa", "a.o"), ("fa", "b.o"), ("fb", "b.o")]), "lib.a")
    assert arc.symbol_index["fa"].name == "a.o"
    pairs = [(n, m.name) for n, m in arc.index_pairs]
    assert ("fa", "b.o") in pairs


def test_ar_index_pair_claims_symbol_member_lacks():
    # 索引项 (fa, b.o) 但 b.o 未定义 fa -> 损坏
    blob = build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa"]),
        ObjSpec("b", strong=["fb"]),
    ], defined_index=[("fa", "a.o"), ("fa", "b.o"), ("fb", "b.o")])
    with pytest.raises(ParseError, match="并无此"):
        parse_ar(blob, "lib.a")


def test_ar_index_stale_member_defined_symbol_missing():
    # 成员定义了符号，但符号索引漏收 -> 陈旧索引必须拒绝
    blob = build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa", "secret"], undefined=["fb"]),
        ObjSpec("b", strong=["fb"]),
    ], defined_index={"fa": "a.o", "fb": "b.o"})
    with pytest.raises(ParseError, match="未收录|陈旧"):
        parse_ar(blob, "lib.a")


def test_ar_index_claims_symbol_member_lacks():
    # 索引声称成员定义某符号，但 .symtab 没有 -> 拒绝
    blob = build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa"], undefined=["fb"]),
        ObjSpec("b", strong=["fb"]),
    ], defined_index={"ghost": "a.o", "fb": "b.o"})
    with pytest.raises(ParseError, match="ghost"):
        parse_ar(blob, "lib.a")


def test_ar_rejects_bsd_longname_marker():
    blob = bytearray(_ar())
    blob[8:24] = b"#1/8/".ljust(16)
    with pytest.raises(ParseError, match="不支持"):
        parse_ar(bytes(blob), "lib.a")


def test_ar_duplicate_member_name():
    inner = _ar()
    # 复制第二个成员头+数据并追加，名称仍为 b.o
    # 简化：直接构造两个同名 ObjSpec
    blob = build_gnu_ar("lib", [
        ObjSpec("x", strong=["x1"]),
        ObjSpec("x", strong=["x2"]),
    ])
    with pytest.raises(ParseError, match="重名成员"):
        parse_ar(blob, "lib.a")

"""链接裁决测试：左至右、归档闭包、成组反复扫描、强/弱/COMMON 规则。"""
from __future__ import annotations

import pytest

from app.fixtures import ObjSpec, build_elf64_rel, build_gnu_ar
from app.elfparser import parse_ar
from app.linker import InputUnit, LinkError, Resolver
from app.service import audit


def _obj_unit(spec: ObjSpec, pos: int, group=None) -> InputUnit:
    from app.elfparser import parse_elf_object
    return InputUnit(
        pos, spec.name + ".o", "object",
        obj=parse_elf_object(build_elf64_rel(spec), spec.name + ".o"),
        group=group,
    )


def _ar_unit(name: str, specs, pos: int, group=None) -> InputUnit:
    from app.elfparser import parse_ar
    return InputUnit(
        pos, name + ".a", "archive",
        archive=parse_ar(build_gnu_ar(name, specs), name + ".a"),
        group=group,
    )


def _run(units):
    return Resolver(units=units).run()


# --------------------------------------------------------------------------- #
def test_plain_objects_resolve():
    r = _run([
        _obj_unit(ObjSpec("main", undefined=["a", "b"]), 1),
        _obj_unit(ObjSpec("liba", strong=["a"]), 2),
        _obj_unit(ObjSpec("libb", strong=["b"]), 3),
    ])
    assert r["final_undefined"] == []
    assert r["definitions"]["a"]["binding"] == "strong"


def test_final_undefined_rejected():
    with pytest.raises(LinkError) as ei:
        _run([_obj_unit(ObjSpec("main", undefined=["a", "ghost"]), 1)])
    assert ei.value.code == "UNDEFINED_SYMBOL"
    assert set(ei.value.evidence["undefined"]) == {"a", "ghost"}
    assert "main.o" in ei.value.location


def test_duplicate_strong_in_two_objects():
    with pytest.raises(LinkError) as ei:
        _run([
            _obj_unit(ObjSpec("m", undefined=["d"]), 1),
            _obj_unit(ObjSpec("x", strong=["d"]), 2),
            _obj_unit(ObjSpec("y", strong=["d"]), 3),
        ])
    assert ei.value.code == "DUPLICATE_STRONG"
    assert "x.o" in ei.value.evidence["first_definition"]
    assert "y.o" in ei.value.location


def test_duplicate_strong_reports_first_trigger_position():
    with pytest.raises(LinkError) as ei:
        _run([
            _obj_unit(ObjSpec("x", strong=["d"]), 1),
            _obj_unit(ObjSpec("y", strong=["d"]), 2),
        ])
    assert "输入#2" in ei.value.location


def test_weak_then_strong_strong_wins():
    r = _run([
        _obj_unit(ObjSpec("m", undefined=["f"]), 1),
        _obj_unit(ObjSpec("w", weak=["f"]), 2),
        _obj_unit(ObjSpec("s", strong=["f"]), 3),
    ])
    assert r["definitions"]["f"]["binding"] == "strong"
    assert any(e["action"] == "strong_overrides_weak" for e in r["resolutions"])


def test_strong_then_weak_weak_silently_ignored():
    r = _run([
        _obj_unit(ObjSpec("s", strong=["f"]), 1),
        _obj_unit(ObjSpec("w", weak=["f"]), 2),
    ])
    assert r["definitions"]["f"]["binding"] == "strong"


def test_common_merges_with_common_and_strong():
    r = _run([
        _obj_unit(ObjSpec("c1", common=["k"]), 1),
        _obj_unit(ObjSpec("c2", common=["k"]), 2),
        _obj_unit(ObjSpec("s", strong=["k"]), 3),
    ])
    assert r["definitions"]["k"]["binding"] == "strong"


def test_weak_undefined_never_errors():
    r = _run([
        _obj_unit(ObjSpec("m", weak_undefined=["opt"]), 1),
    ])
    assert r["weak_unresolved"] == ["opt"]
    assert r["final_undefined"] == []


# --------------------------------------------------------------------------- #
# 归档
# --------------------------------------------------------------------------- #
def test_archive_member_extracted_on_demand():
    r = _run([
        _obj_unit(ObjSpec("m", undefined=["fa"]), 1),
        _ar_unit("lib", [
            ObjSpec("a", strong=["fa"], undefined=["fb"]),
            ObjSpec("b", strong=["fb"]),
        ], 2),
    ])
    assert [e["member"] for e in r["extraction_order"]] == ["a.o", "b.o"]
    assert r["final_undefined"] == []
    # 归档内第二轮证据
    passes = [p for p in r["rounds"] if p["scope"] == "archive"]
    assert passes[-1]["changed"] is False


def test_archive_unneeded_member_not_extracted():
    r = _run([
        _obj_unit(ObjSpec("m", undefined=["fa"]), 1),
        _ar_unit("lib", [
            ObjSpec("a", strong=["fa"]),
            ObjSpec("unused", strong=["unneeded"]),
        ], 2),
    ])
    assert [e["member"] for e in r["extraction_order"]] == ["a.o"]


def test_plain_archives_do_not_resolve_cross_cycle():
    # main->a(libX) a->c(libY) c->b(libX 后一个成员，已路过)
    with pytest.raises(LinkError) as ei:
        _run([
            _obj_unit(ObjSpec("m", undefined=["a"]), 1),
            _ar_unit("libX", [
                ObjSpec("amem", strong=["a"], undefined=["c"]),
                ObjSpec("bmem", strong=["b"]),
            ], 2),
            _ar_unit("libY", [
                ObjSpec("cmem", strong=["c"], undefined=["b"]),
            ], 3),
        ])
    assert ei.value.code == "UNDEFINED_SYMBOL"
    assert ei.value.evidence["undefined"] == ["b"]


def test_grouped_archives_rescan_to_fixpoint():
    r = _run([
        _obj_unit(ObjSpec("m", undefined=["a"]), 1),
        _ar_unit("libX", [
            ObjSpec("amem", strong=["a"], undefined=["c"]),
            ObjSpec("bmem", strong=["b"]),
        ], 2, group="G1"),
        _ar_unit("libY", [
            ObjSpec("cmem", strong=["c"], undefined=["b"]),
        ], 3, group="G1"),
    ])
    members = [(e["archive"], e["member"]) for e in r["extraction_order"]]
    assert ("libX.a", "amem.o") in members
    assert ("libY.a", "cmem.o") in members
    assert ("libX.a", "bmem.o") in members
    group_rounds = [p for p in r["rounds"] if p["scope"] == "group"]
    assert group_rounds[-1]["changed"] is False
    assert group_rounds[-1]["undefined_after"] == []


def test_duplicate_definition_across_two_pulled_archive_members():
    # am.o 定义 d；xm.o 同时定义 x 与 d。main 引用 x 与 d：
    # 抽取首个命中 am.o 满足 d，xm.o 因 x 被抽取后暴露第二个强定义。
    arc = parse_ar(build_gnu_ar("libd", [
        ObjSpec("amem", strong=["d"]),
        ObjSpec("xmem", strong=["x", "d"]),
    ], defined_index=[("d", "amem.o"), ("d", "xmem.o"), ("x", "xmem.o")]), "libd.a")
    units = [
        _obj_unit(ObjSpec("m", undefined=["x", "d"]), 1),
        InputUnit(2, "libd.a", "archive", archive=arc),
    ]
    resolver = Resolver(units=units)
    with pytest.raises(LinkError) as ei:
        resolver.run()
    assert ei.value.code == "DUPLICATE_STRONG"
    assert "amem.o" in ei.value.evidence["first_definition"]
    assert "xmem.o" in ei.value.location
    assert resolver.extraction_log[-1]["triggered_error"] is True


def test_archive_duplicate_strong_detected_after_extraction():
    with pytest.raises(LinkError) as ei:
        _run([
            _obj_unit(ObjSpec("m", undefined=["d"]), 1),
            _ar_unit("lib", [ObjSpec("a", strong=["d"])], 2),
            _obj_unit(ObjSpec("y", strong=["d"]), 3),
        ])
    assert ei.value.code == "DUPLICATE_STRONG"
    assert "lib.a!成员 a.o" in ei.value.evidence["first_definition"]
    assert "输入#3" in ei.value.location


def test_archive_member_triggering_duplicate_is_in_extraction_evidence():
    from app.elfparser import parse_ar
    archive = parse_ar(build_gnu_ar("lib", [
        ObjSpec("a", strong=["d"], undefined=["x"]),
        ObjSpec("xmem", strong=["x", "d"]),
    ]), "lib.a")
    units = [
        _obj_unit(ObjSpec("m", undefined=["d"]), 1),
        InputUnit(2, "lib.a", "archive", archive=archive),
    ]
    resolver = Resolver(units=units)
    with pytest.raises(LinkError) as ei:
        resolver.run()
    assert ei.value.code == "DUPLICATE_STRONG"
    members = [e["member"] for e in resolver.extraction_log]
    assert "xmem.o" in members
    assert resolver.extraction_log[-1]["triggered_error"] is True


def test_round_evidence_shows_undefined_sets():
    r = _run([
        _obj_unit(ObjSpec("m", undefined=["a"]), 1),
        _ar_unit("libX", [
            ObjSpec("amem", strong=["a"], undefined=["c"]),
            ObjSpec("bmem", strong=["b"]),
        ], 2, group="G"),
        _ar_unit("libY", [
            ObjSpec("cmem", strong=["c"], undefined=["b"]),
        ], 3, group="G"),
    ])
    first_group_round = next(p for p in r["rounds"] if p["scope"] == "group")
    assert first_group_round["undefined_before"] == ["a"]
    assert "b" in first_group_round["undefined_after"]


# --------------------------------------------------------------------------- #
# service.audit 端到端（冻结结论形状）
# --------------------------------------------------------------------------- #
def _inputs(*specs_and_archives):
    items = []
    for i, item in enumerate(specs_and_archives, 1):
        if item[0] == "obj":
            _, spec, group = item
            items.append({
                "name": spec.name + ".o",
                "data_b64": __import__("app.fixtures", fromlist=["b64"]).b64(
                    build_elf64_rel(spec)),
                "group": group,
            })
        else:
            _, name, arspecs, group = item
            items.append({
                "name": name + ".a",
                "data_b64": __import__("app.fixtures", fromlist=["b64"]).b64(
                    build_gnu_ar(name, arspecs)),
                "group": group,
            })
    return items


def test_service_accepted_verdict():
    v = audit("AUDIT-OK-1", _inputs(
        ("obj", ObjSpec("m", undefined=["fa"]), None),
        ("ar", "lib", [ObjSpec("a", strong=["fa"])], None),
    ))
    assert v["status"] == "accepted"
    assert v["error"] is None
    assert v["inputs"][1]["kind"] == "ar"
    assert v["extraction_order"][0]["member"] == "a.o"


def test_service_undefined_is_frozen_rejection():
    v = audit("AUDIT-UNDEF-1", _inputs(
        ("obj", ObjSpec("m", undefined=["ghost"]), None),
    ))
    assert v["status"] == "rejected"
    assert v["error"]["code"] == "UNDEFINED_SYMBOL"
    assert v["error"]["evidence"]["undefined"] == ["ghost"]
    assert v["error"]["evidence"]["first_reference"].endswith(".symtab[2]")


def test_service_corrupt_index_rejected():
    good = build_gnu_ar("lib", [
        ObjSpec("a", strong=["fa", "secret"]),
    ], defined_index={"fa": "a.o"})  # 漏收 secret
    from app.fixtures import b64
    v = audit("AUDIT-BADIDX-1", [
        {"name": "m.o", "data_b64": b64(build_elf64_rel(ObjSpec("m", undefined=["fa"])))},
        {"name": "lib.a", "data_b64": b64(good)},
    ])
    assert v["status"] == "rejected"
    assert v["error"]["code"] == "CORRUPT_BINARY"
    assert "lib.a" in v["error"]["location"]


def test_service_illegal_blob_rejected():
    from app.fixtures import b64
    v = audit("AUDIT-JUNK-1", [
        {"name": "junk.bin", "data_b64": b64(b"not an elf or ar file at all!!")},
    ])
    assert v["status"] == "rejected"
    assert v["error"]["code"] == "ILLEGAL_MEMBER"
    assert v["error"]["location"].endswith("byte 0")

"""逐符号轨迹测试：引用/弱强定义/归档索引命中/实际抽取的归因与截断。"""
from __future__ import annotations

import pytest

from app.fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar
from app.elfparser import parse_ar
from app.linker import InputUnit, Resolver
from app.service import audit
from app.trace import TraceNotFound, get_trace, list_symbols


def _obj_unit(spec: ObjSpec, pos: int, group=None) -> InputUnit:
    from app.elfparser import parse_elf_object
    return InputUnit(
        pos, spec.name + ".o", "object",
        obj=parse_elf_object(build_elf64_rel(spec), spec.name + ".o"),
        group=group,
    )


def _ar_unit(name: str, specs, pos: int, group=None, defined_index=None) -> InputUnit:
    blob = build_gnu_ar(name, specs, defined_index=defined_index)
    return InputUnit(
        pos, name + ".a", "archive",
        archive=parse_ar(blob, name + ".a"),
        group=group,
    )


def _trace_demo_verdict(audit_id="TRACE-T-1"):
    return audit(audit_id, [
        {"name": "main.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("main", undefined=["a", "w", "ghost"])))},
        {"name": "weakprov.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("weakprov", weak=["w"])))},
        {"name": "strongprov.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("strongprov", strong=["w"])))},
        {"name": "libdep.a", "data_b64": b64(build_gnu_ar("libdep", [
            ObjSpec("amem", strong=["a"], undefined=["b"]),
            ObjSpec("bmem", strong=["b"]),
        ]))},
    ])


# --------------------------------------------------------------------------- #
def test_accepted_verdict_carries_symbol_traces():
    resolver = Resolver(units=[
        _obj_unit(ObjSpec("m", undefined=["a"]), 1),
        _obj_unit(ObjSpec("s", strong=["a"]), 2),
    ])
    resolver.run()
    payload = resolver.symbol_trace_payload()
    assert payload["symbols"] == ["a"]
    assert payload["terminal_error"] is None
    t = payload["symbol_traces"]["a"]
    assert t["final_state"] == "strong"
    assert [e["type"] for e in t["events"]] == [
        "strong_reference", "strong_definition"
    ]


def test_cross_member_archive_satisfaction_trace():
    v = _trace_demo_verdict()
    t = v["symbol_traces"]["b"]
    types = [e["type"] for e in t["events"]]
    assert types == [
        "strong_reference",     # amem 引用 b
        "archive_index_hit",    # libdep 索引 b -> bmem
        "member_extracted",     # bmem 实际抽取
        "strong_definition",    # bmem 强定义满足
    ]
    hit = next(e for e in t["events"] if e["type"] == "archive_index_hit")
    assert hit["archive"] == "libdep.a"
    assert hit["member"] == "bmem.o"
    assert hit["index_pair_ordinal"] == 1
    ext = next(e for e in t["events"] if e["type"] == "member_extracted")
    assert ext["matched_index_symbols"] == ["b"]
    assert "b" in ext["undefined_before"]
    assert "b" not in ext["undefined_after"]
    final = t["events"][-1]
    assert final["effect"]  # 每项必须带对未定义集合/绑定的影响说明
    assert final["binding_after"] == "strong"
    # 每项都带输入位置
    assert all(e["input_position"] in (1, 4) for e in t["events"])
    assert t["adopted_definition"]["source"].endswith("bmem.o")


def test_weak_to_strong_keeps_both_and_marks_adopted():
    v = _trace_demo_verdict()
    t = v["symbol_traces"]["w"]
    weak = next(e for e in t["events"] if e["type"] == "weak_definition")
    strong = next(e for e in t["events"] if e["type"] == "strong_definition")
    assert weak["location"].endswith("weakprov.o .symtab[2]")
    assert strong["location"].endswith("strongprov.o .symtab[2]")
    assert strong["binding_before"] == "weak"
    assert strong["binding_after"] == "strong"
    assert "weakprov" in strong["previous_binding_source"]
    assert strong["adopted_source"].endswith("strongprov.o")
    assert t["adopted_definition"]["binding"] == "strong"
    assert "strongprov" in t["adopted_definition"]["source"]


def test_undefined_symbol_trace_stops_at_rejection_evidence():
    v = _trace_demo_verdict()
    assert v["status"] == "rejected"
    assert v["error"]["code"] == "UNDEFINED_SYMBOL"
    g = v["symbol_traces"]["ghost"]
    assert g["final_state"] == "undefined"
    assert g["adopted_definition"] is None
    last = g["events"][-1]
    assert last["type"] == "final_undefined"
    assert last["terminal"] is True
    assert last["rejection"]["code"] == "UNDEFINED_SYMBOL"
    assert "ghost" in last["final_undefined"]
    # 拒绝后不存在任何编造事件
    assert sum(1 for e in g["events"] if e.get("terminal")) == 1
    assert v["terminal_error"]["code"] == "UNDEFINED_SYMBOL"


def test_duplicate_strong_trace_ends_at_first_conflict():
    v = audit("TRACE-DUP", [
        {"name": "m.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("m", undefined=["d", "z"])))},
        {"name": "x.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("x", strong=["d"])))},
        {"name": "y.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("y", strong=["d", "z"])))},
    ])
    assert v["error"]["code"] == "DUPLICATE_STRONG"
    t = v["symbol_traces"]["d"]
    assert [e["type"] for e in t["events"]] == [
        "strong_reference", "strong_definition", "strong_definition"
    ]
    terminal = t["events"][-1]
    assert terminal["terminal"] is True
    assert terminal["rejection"]["code"] == "DUPLICATE_STRONG"
    assert "x.o" in terminal["rejection"]["evidence"]["first_definition"]
    assert terminal["location"].endswith("y.o .symtab[2]")
    # y.o 在 d 冲突处即中止：同一成员稍后下标的 z 不得留下事件。
    z = v["symbol_traces"]["z"]
    assert all("输入#3" not in e["location"] for e in z["events"])


def test_duplicate_strong_in_pulled_member_terminal_in_extraction():
    archive = parse_ar(build_gnu_ar("lib", [
        ObjSpec("a", strong=["d"], undefined=["x"]),
        ObjSpec("xmem", strong=["x", "d"]),
    ]), "lib.a")
    resolver = Resolver(units=[
        _obj_unit(ObjSpec("m", undefined=["d"]), 1),
        InputUnit(2, "lib.a", "archive", archive=archive),
    ])
    with pytest.raises(Exception):
        resolver.run()
    payload = resolver.symbol_trace_payload()
    d = payload["symbol_traces"]["d"]
    assert d["events"][-1]["terminal"] is True
    assert d["events"][-1]["type"] == "strong_definition"
    assert "xmem.o" in d["events"][-1]["location"]


def test_weak_reference_does_not_extract_and_resolves_weak():
    resolver = Resolver(units=[
        _obj_unit(ObjSpec("m", weak_undefined=["opt"]), 1),
    ])
    result = resolver.run()
    t = resolver.symbol_trace_payload()["symbol_traces"]["opt"]
    assert t["final_state"] == "weak_unresolved"
    assert t["events"][0]["type"] == "weak_reference"
    assert result["weak_unresolved"] == ["opt"]


def test_index_hit_lists_all_indexed_members_when_duplicated():
    arc = parse_ar(build_gnu_ar("libd", [
        ObjSpec("amem", strong=["d"]),
        ObjSpec("xmem", strong=["x", "d"]),
    ], defined_index=[("d", "amem.o"), ("d", "xmem.o"), ("x", "xmem.o")]),
        "libd.a")
    resolver = Resolver(units=[
        _obj_unit(ObjSpec("m", undefined=["d"]), 1),
        InputUnit(2, "libd.a", "archive", archive=arc),
    ])
    resolver.run()
    hit = next(
        e for e in resolver.symbol_events["d"]
        if e["type"] == "archive_index_hit"
    )
    # ranlib 允许同一符号索引到多个成员；轨迹标明全部候选但首个成员被抽取。
    assert hit["indexed_members_for_symbol"] == ["amem.o", "xmem.o"]
    assert hit["member"] == "amem.o"


# --------------------------------------------------------------------------- #
# 只读查询服务
# --------------------------------------------------------------------------- #
def test_get_trace_unknown_symbol_is_actionable():
    v = _trace_demo_verdict("TRACE-Q-1")
    with pytest.raises(TraceNotFound) as ei:
        get_trace(v, "no_such_symbol")
    assert ei.value.code == "SYMBOL_NOT_RECORDED"
    assert ei.value.http_status == 404
    assert set(ei.value.alternatives) == {"a", "b", "w", "ghost"}
    assert "no_such_symbol" in ei.value.message


def test_get_trace_known_symbol_returns_events():
    v = _trace_demo_verdict("TRACE-Q-2")
    body, status = get_trace(v, "b")
    assert status == 200
    assert body["frozen"] is True
    assert body["trace"]["symbol"] == "b"
    assert body["event_labels"]["archive_index_hit"] == "归档索引命中"


def test_list_symbols_summarizes_final_states():
    v = _trace_demo_verdict("TRACE-Q-3")
    body = list_symbols(v)
    by = {s["symbol"]: s for s in body["symbols"]}
    assert by["b"]["final_state"] == "strong"
    assert by["ghost"]["final_state"] == "undefined"
    assert by["ghost"]["terminal"] is True
    assert by["w"]["terminal"] is False


def test_trace_query_does_not_mutate_frozen_verdict():
    v = _trace_demo_verdict("TRACE-Q-4")
    import copy
    snapshot = copy.deepcopy(v)
    list_symbols(v)
    get_trace(v, "b")
    with pytest.raises(TraceNotFound):
        get_trace(v, "missing")
    assert v == snapshot


def test_trace_unavailable_for_legacy_verdict():
    legacy = {"audit_id": "OLD-1", "status": "accepted"}
    with pytest.raises(TraceNotFound) as ei:
        get_trace(legacy, "a")
    assert ei.value.code == "TRACE_UNAVAILABLE"
    assert ei.value.http_status == 409
    assert list_symbols(legacy)["trace_available"] is False

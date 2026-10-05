"""符号归因追查测试：轨迹时序、弱转强覆盖、拒绝终点、未收录反馈与只读性。

所有追查均基于已冻结结论（``symbol_events``），不重新解析或重放。
"""
from __future__ import annotations

import copy
import os

import pytest

# app.main 在导入时按 AUDIT_DB 实例化存储；测试（含 verify 容器）使用内存库。
os.environ.setdefault("AUDIT_DB", ":memory:")

from app.fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar
from app.service import audit
from app.tracer import (
    TraceRequestError,
    list_frozen_symbols,
    trace_symbol,
)


def _trace_demo_verdict(audit_id: str = "TRACE-DEMO") -> dict:
    return audit(audit_id, [
        {"name": "main.o", "data_b64": b64(build_elf64_rel(ObjSpec(
            "main", undefined=["need", "pull", "missing"],
            weak_undefined=["wref"])))},
        {"name": "weakplaceholder.o",
         "data_b64": b64(build_elf64_rel(ObjSpec("weakplaceholder", weak=["need"])))},
        {"name": "lib1.a", "data_b64": b64(build_gnu_ar("lib1", [
            ObjSpec("providermem", strong=["backsym"]),
            ObjSpec("consumermem", strong=["pull", "need"],
                    undefined=["backsym"]),
        ]))},
    ])


# --------------------------------------------------------------------------- #
def test_symbol_listing_order_and_states():
    v = _trace_demo_verdict()
    listing = list_frozen_symbols(v)
    assert listing["frozen"] is True and listing["read_only"] is True
    names = [s["symbol"] for s in listing["symbols"]]
    # 按命令行处理中的首次出现顺序。
    assert names == ["need", "pull", "missing", "wref", "backsym"]
    states = {s["symbol"]: s["final_state"] for s in listing["symbols"]}
    assert states["need"] == "bound_strong"
    assert states["pull"] == "bound_strong"
    assert states["backsym"] == "bound_strong"
    assert states["missing"] == "final_undefined"
    assert states["wref"] == "weak_unresolved"
    need = next(s for s in listing["symbols"] if s["symbol"] == "need")
    assert need["has_weak_to_strong"] is True
    backsym = next(s for s in listing["symbols"] if s["symbol"] == "backsym")
    assert backsym["has_archive_hit"] is True


def test_archive_cross_member_satisfaction_trace():
    """backsym：被先抽取的 consumermem 引用，第 2 趟反向抽取 providermem 满足。"""
    v = _trace_demo_verdict()
    t = trace_symbol(v, "backsym")
    types = [e["type"] for e in t["timeline"]]
    assert types == [
        "strong_reference", "archive_index_hit", "strong_definition",
    ]
    hit, definition = t["timeline"][1], t["timeline"][2]
    assert hit["member"] == "providermem.o"
    assert hit["detail"]["pass_or_round"] == 2
    # 命中时刻 backsym 在强未定义集合中；成员装入后被其强定义移除。
    assert "backsym" in hit["undefined_before"]
    assert "backsym" not in (hit["undefined_after"] or [])
    assert definition["member"] == "providermem.o"
    assert definition["effect"] == "strong_definition_resolves_reference"
    assert "backsym" not in definition["undefined_after"]
    # 实际抽取成员与冻结的 extraction_order 交叉引用一致。
    assert len(t["archive_extractions"]) == 1
    ext = t["archive_extractions"][0]
    assert ext["member"] == "providermem.o" and ext["seq"] == 2
    assert ext["relation"] == "index_hit_for_symbol"


def test_pull_trace_shows_full_index_hit_extraction_chain():
    v = _trace_demo_verdict()
    t = trace_symbol(v, "pull")
    assert [e["type"] for e in t["timeline"]] == [
        "strong_reference", "archive_index_hit", "strong_definition",
    ]
    ref = t["timeline"][0]
    assert "pull" in ref["undefined_after"]
    assert ref["location"].startswith("输入#1")
    assert t["archive_extractions"][0]["seq"] == 1


def test_weak_then_strong_keeps_both_and_marks_final_adopter():
    v = _trace_demo_verdict()
    t = trace_symbol(v, "need")
    weak_ev = next(e for e in t["timeline"]
                   if e["type"] == "weak_definition")
    strong_ev = next(e for e in t["timeline"]
                     if e["type"] == "strong_definition")
    # 弱定义与覆盖它的强定义同时保留。
    assert weak_ev["is_superseded"] is True
    assert weak_ev["detail"]["adopted_by_event_no"] == strong_ev["event_no"]
    assert "consumermem.o" in weak_ev["detail"]["adopted_by_location"]
    assert strong_ev["is_final_binding"] is True
    assert strong_ev["effect"] == "strong_overrides_weak"
    assert strong_ev["detail"]["replaces_event_no"] == weak_ev["event_no"]
    assert t["final"]["binding"] == "strong"
    assert "consumermem.o" in t["final"]["bound_location"]
    # need 并非自身命中索引：成员因 pull 被抽取，但其内强定义了 need。
    assert t["archive_extractions"][0]["relation"] == "member_defined_symbol"


def test_undefined_symbol_trace_ends_at_rejection_evidence():
    v = _trace_demo_verdict()
    t = trace_symbol(v, "missing")
    last = t["timeline"][-1]
    assert last["type"] == "final_undefined_rejection"
    assert last["is_terminal"] is True
    assert set(last["detail"]["undefined"]) == {"missing"}
    # 拒绝之前仅有：强引用登记 + 收敛趟索引不收录。
    assert [e["type"] for e in t["timeline"][:-1]] == [
        "strong_reference", "archive_index_miss",
    ]
    miss = t["timeline"][1]
    assert miss["effect"] == "archive_index_miss"
    assert t["final"]["state"] == "final_undefined"


def test_duplicate_strong_trace_stops_at_first_conflict_no_fabrication():
    # y.o 触发重复强定义；z.o 位于其后，绝不能出现在轨迹中。
    v = audit("DUP-TRACE", [
        {"name": "m.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("m", undefined=["d"])))},
        {"name": "x.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("x", strong=["d"])))},
        {"name": "y.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("y", strong=["d"])))},
        {"name": "z.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("z", strong=["later"])))},
    ])
    assert v["status"] == "rejected"
    assert v["error"]["code"] == "DUPLICATE_STRONG"
    t = trace_symbol(v, "d")
    types = [e["type"] for e in t["timeline"]]
    assert types == [
        "strong_reference", "strong_definition",
        "duplicate_strong_definition",
    ]
    terminal = t["timeline"][-1]
    assert terminal["is_terminal"] is True
    assert "y.o" in terminal["location"]
    assert terminal["detail"]["first_definition"].endswith(
        "x.o .symtab[2]"
    ) or "x.o" in terminal["detail"]["first_definition"]
    assert t["final"]["state"] == "duplicate_strong_rejected"
    # 后续输入从未处理：全部符号事件中不得出现 later。
    assert not any(e["symbol"] == "later" for e in v["symbol_events"])


def test_symbol_not_recorded_gives_actionable_feedback():
    v = _trace_demo_verdict()
    result = trace_symbol(v, "ned")  # 与 need 近似
    assert result["found"] is False
    assert result["error"]["code"] == "SYMBOL_NOT_IN_VERDICT"
    assert "need" in result["error"]["evidence"]["closest_matches"]
    assert "need" in result["action"]["recorded_symbols"]
    assert result["action"]["steps"], "必须给出可操作建议"
    assert result["action"]["symbols_endpoint"].endswith("/symbols")


def test_unrelated_symbol_not_recorded_has_no_false_match():
    v = _trace_demo_verdict()
    result = trace_symbol(v, "totally_unrelated_xyz")
    assert result["found"] is False
    assert result["error"]["evidence"]["closest_matches"] == []


def test_trace_is_read_only_and_does_not_mutate_frozen_verdict():
    v = _trace_demo_verdict("READONLY-1")
    snapshot = copy.deepcopy(v)
    list_frozen_symbols(v)
    for name in ["need", "pull", "backsym", "missing", "wref"]:
        trace_symbol(v, name)
    trace_symbol(v, "ghost")
    assert v == snapshot


def test_invalid_symbol_query():
    v = _trace_demo_verdict()
    with pytest.raises(TraceRequestError) as ei:
        trace_symbol(v, "")
    assert ei.value.code == "INVALID_SYMBOL"


def test_weak_unresolved_symbol_state():
    v = _trace_demo_verdict()
    t = trace_symbol(v, "wref")
    assert t["final"]["state"] == "weak_unresolved"
    assert [e["type"] for e in t["timeline"]] == ["weak_reference"]
    assert t["timeline"][0]["effect"] == "weak_undefined_registered"


def test_late_weak_definition_ignored_event():
    v = audit("LATE-WEAK", [
        {"name": "s.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("s", strong=["f"])))},
        {"name": "w.o", "data_b64": b64(build_elf64_rel(
            ObjSpec("w", weak=["f"])))},
    ])
    t = trace_symbol(v, "f")
    effects = [e["effect"] for e in t["timeline"]]
    assert "weak_definition_ignored" in effects
    assert t["final"]["binding"] == "strong"


# --------------------------------------------------------------------------- #
def test_trace_http_endpoints():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    d = _trace_demo_verdict_dict("HTTP-TRACE-1")
    post = client.post("/api/audits", json=d)
    assert post.status_code == 422  # rejected 结论同样冻结

    r = client.get("/api/audits/HTTP-TRACE-1/symbols")
    assert r.status_code == 200
    assert {s["symbol"] for s in r.json()["symbols"]} == {
        "need", "pull", "missing", "wref", "backsym",
    }

    r = client.get("/api/audits/HTTP-TRACE-1/symbols/need")
    assert r.status_code == 200
    body = r.json()
    assert body["found"] is True and body["read_only"] is True
    assert body["final"]["binding"] == "strong"

    r = client.get("/api/audits/HTTP-TRACE-1/symbols/missing")
    assert r.status_code == 200
    assert r.json()["final"]["state"] == "final_undefined"

    r = client.get("/api/audits/HTTP-TRACE-1/symbols/ghost")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "SYMBOL_NOT_IN_VERDICT"

    assert client.get("/api/audits/NO-SUCH/symbols").status_code == 404
    assert client.get("/api/audits/NO-SUCH/symbols/x").status_code == 404


def _trace_demo_verdict_dict(audit_id: str) -> dict:
    from app.main import demo_trace
    d = demo_trace()
    d["audit_id"] = audit_id
    return d

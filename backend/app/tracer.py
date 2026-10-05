"""冻结结论的符号追查：从已冻结裁决中只读组装单符号归因轨迹。

本模块**不重新解析输入、不重放链接裁决、不写入存储**：所有事件均来自
POST /api/audits 时裁决器按命令行处理顺序记录并随结论一起冻结的
``symbol_events``。因此追查结果与冻结重放严格一致，查询不可能改变
既有结论、抽取顺序或冻结重放行为。
"""
from __future__ import annotations

import difflib
from typing import List, Optional

MAX_SYMBOL_LEN = 512

# 事件类型 -> 中文归类（引用 / 弱定义 / 强定义 / 归档索引 / 成员抽取 / 拒绝）
EVENT_CATEGORIES = {
    "strong_reference": "strong_reference",
    "weak_reference": "weak_reference",
    "common_reference": "definition",
    "weak_definition": "weak_definition",
    "strong_definition": "strong_definition",
    "common_definition": "definition",
    "duplicate_strong_definition": "rejection",
    "archive_index_hit": "archive_index",
    "archive_index_skip": "archive_index",
    "archive_index_miss": "archive_index",
    "final_undefined_rejection": "rejection",
}

CATEGORY_LABELS = {
    "strong_reference": "强引用",
    "weak_reference": "弱引用",
    "weak_definition": "弱定义",
    "strong_definition": "强定义",
    "definition": "其他定义",
    "archive_index": "归档索引",
    "rejection": "拒绝证据",
}

# 与归档成员抽取（extraction_order）对应的事件类型
EXTRACTION_EVENT_TYPES = {"archive_index_hit", "archive_index_skip"}


class TraceRequestError(ValueError):
    def __init__(self, code: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def _final_state(verdict: dict, name: str, events: List[dict]) -> dict:
    """综合冻结结论与事件，给出符号的最终绑定/拒绝状态。"""
    status = verdict.get("status")
    error = verdict.get("error") or {}
    evidence = error.get("evidence") or {}
    defs = verdict.get("definitions") or {}

    terminal = events[-1] if events and events[-1].get("detail", {}).get(
        "rejection"
    ) else None

    if terminal is not None:
        if terminal["type"] == "final_undefined_rejection":
            return {
                "state": "final_undefined",
                "state_label": "最终未定义（裁决拒绝）",
                "binding": None,
                "bound_location": None,
                "terminal_event_no": terminal["event_no"],
            }
        return {
            "state": "duplicate_strong_rejected",
            "state_label": "重复强定义（裁决拒绝）",
            "binding": None,
            "bound_location": None,
            "terminal_event_no": terminal["event_no"],
        }

    if name in defs:
        d = defs[name]
        binding = d.get("binding")
        return {
            "state": f"bound_{binding}",
            "state_label": {
                "strong": "最终采用强定义",
                "weak": "最终仅弱定义（占位）",
                "common": "最终采用 COMMON 暂定定义",
            }.get(binding, f"最终绑定：{binding}"),
            "binding": binding,
            "bound_location": d.get("source"),
            "terminal_event_no": None,
        }

    if name in (verdict.get("weak_unresolved") or []):
        return {
            "state": "weak_unresolved",
            "state_label": "弱未定义残留（仅报告、不判错）",
            "binding": None,
            "bound_location": None,
            "terminal_event_no": None,
        }

    # 兜底：事件存在但结论中无绑定（理论上不应出现）。
    return {
        "state": "no_effect_binding",
        "state_label": "未形成绑定",
        "binding": None,
        "bound_location": None,
        "terminal_event_no": None,
    }


def list_frozen_symbols(verdict: dict) -> dict:
    """从冻结结论中提取已出现符号清单（按首次出现的处理顺序）。"""
    events = verdict.get("symbol_events") or []
    order: List[str] = []
    seen: set = set()
    per: dict = {}

    for ev in events:
        name = ev.get("symbol")
        if name is None:
            continue
        if name not in seen:
            seen.add(name)
            order.append(name)
            per[name] = {"event_count": 0, "types": set(),
                         "first_event_no": ev["event_no"]}
        rec = per[name]
        rec["event_count"] += 1
        rec["types"].add(ev["type"])

    symbols = []
    for name in order:
        rec = per[name]
        evs = [e for e in events if e["symbol"] == name]
        finfo = _final_state(verdict, name, evs)
        flags = {
            "has_strong_reference": "strong_reference" in rec["types"],
            "has_weak_reference": "weak_reference" in rec["types"],
            "has_weak_definition": "weak_definition" in rec["types"],
            "has_strong_definition": "strong_definition" in rec["types"],
            "has_archive_hit": "archive_index_hit" in rec["types"],
            "has_archive_miss": "archive_index_miss" in rec["types"],
            "has_rejection": any(
                e.get("detail", {}).get("rejection") for e in evs
            ),
            "has_weak_to_strong": any(
                e.get("effect") == "strong_overrides_weak" for e in evs
            ),
        }
        symbols.append({
            "symbol": name,
            "first_event_no": rec["first_event_no"],
            "event_count": rec["event_count"],
            "event_types": sorted(rec["types"]),
            "final_state": finfo["state"],
            "final_state_label": finfo["state_label"],
            "binding": finfo["binding"],
            "bound_location": finfo["bound_location"],
            **flags,
        })

    return {
        "audit_id": verdict.get("audit_id"),
        "status": verdict.get("status"),
        "frozen": True,
        "read_only": True,
        "count": len(symbols),
        "symbols": symbols,
    }


def _not_recorded(verdict: dict, name: str) -> dict:
    """不存在于冻结结论中的符号：给出可操作的未收录反馈。"""
    listing = list_frozen_symbols(verdict)
    known = [s["symbol"] for s in listing["symbols"]]
    matches = difflib.get_close_matches(name, known, n=5, cutoff=0.4)
    return {
        "found": False,
        "frozen": True,
        "read_only": True,
        "audit_id": verdict.get("audit_id"),
        "symbol": name,
        "error": {
            "code": "SYMBOL_NOT_IN_VERDICT",
            "message": (
                f"符号 {name!r} 未出现在该冻结结论记录的任何引用、定义或归档"
                f"索引事件中（已收录 {len(known)} 个符号）。追查仅基于冻结"
                f"证据，不会从原始输入重新推断，也不会改变结论或重放行为。"
            ),
            "location": "query.symbol",
            "evidence": {
                "recorded_symbol_count": len(known),
                "closest_matches": matches,
            },
        },
        "action": {
            "headline": "可操作的排查建议",
            "steps": [
                "从下方已收录符号清单中选择符号，或先调用符号清单接口获取全集",
                *(
                    [f"名称可能拼写相近：{', '.join(matches)}，请核对后重试"]
                    if matches else []
                ),
                "若该符号确实参与了本次链接，说明它来自未提交给审计的输入，"
                "需以新的审计标识另行提交（既有冻结结论不可修改）",
                "重新 GET 冻结结论可核对原始输入与归档索引收录范围",
            ],
            "symbols_endpoint": (
                f"/api/audits/{verdict.get('audit_id')}/symbols"
            ),
            "recorded_symbols": known,
        },
    }


def trace_symbol(verdict: dict, name: str) -> dict:
    """组装单个符号的完整归因轨迹（只读）。"""
    if not isinstance(name, str) or not name:
        raise TraceRequestError(
            "INVALID_SYMBOL", "symbol 查询参数不能为空字符串"
        )
    if len(name) > MAX_SYMBOL_LEN:
        raise TraceRequestError(
            "INVALID_SYMBOL",
            f"符号名长度超过 {MAX_SYMBOL_LEN} 字节上限",
            http_status=414,
        )

    events = verdict.get("symbol_events") or []
    own = [e for e in events if e.get("symbol") == name]
    if not own:
        return _not_recorded(verdict, name)

    final = _final_state(verdict, name, own)

    # 归档索引命中与实际抽取成员（与冻结的 extraction_order 交叉引用）。
    extraction_seqs = sorted(
        e.get("detail", {}).get("extraction_seq")
        for e in own
        if e["type"] == "archive_index_hit"
    )
    extraction_seqs = [s for s in extraction_seqs if s is not None]
    # 符号本身未必触发索引命中（例如弱定义占位后随其他命中成员一并装入），
    # 故同时按轨迹中定义事件所在的 (输入位置, 成员) 关联实际抽取记录。
    defining_members = {
        (e.get("input_position"), e.get("member"))
        for e in own
        if e.get("input_kind") == "archive"
        and e.get("member")
        and e["type"] in (
            "strong_definition", "weak_definition", "common_definition",
            "duplicate_strong_definition",
        )
    }
    extractions = []
    for entry in verdict.get("extraction_order") or []:
        via_index = entry.get("seq") in extraction_seqs or name in (
            entry.get("matched_index_symbols") or []
        )
        via_member = (entry.get("input_position"),
                      entry.get("member")) in defining_members
        if not (via_index or via_member):
            continue
        extractions.append({
            "seq": entry["seq"],
            "input_position": entry["input_position"],
            "archive": entry["archive"],
            "member": entry["member"],
            "matched_index_symbols": entry.get(
                "matched_index_symbols", []
            ),
            "relation": (
                "index_hit_for_symbol" if via_index
                else "member_defined_symbol"
            ),
            "context": entry.get("context"),
            "pass_or_round": entry.get("pass_or_round"),
            "undefined_before": entry.get("undefined_before"),
            "undefined_after": entry.get("undefined_after"),
            "triggered_error": entry.get("triggered_error", False),
        })

    timeline = []
    for ev in own:
        detail = ev.get("detail") or {}
        timeline.append({
            "event_no": ev["event_no"],
            "category": EVENT_CATEGORIES.get(ev["type"], "other"),
            "category_label": CATEGORY_LABELS.get(
                EVENT_CATEGORIES.get(ev["type"], "other"), ev["type"]
            ),
            "type": ev["type"],
            "location": ev["location"],
            "input_position": ev.get("input_position"),
            "input_name": ev.get("input_name"),
            "input_kind": ev.get("input_kind"),
            "member": ev.get("member"),
            "binding": ev.get("binding"),
            "effect": ev.get("effect"),
            "effect_text": ev.get("effect_text"),
            "undefined_before": ev.get("undefined_before"),
            "undefined_after": ev.get("undefined_after"),
            "detail": detail,
            "is_terminal": bool(detail.get("rejection")),
            "is_final_binding": bool(
                detail.get("final")
                and ev["type"] in (
                    "strong_definition", "weak_definition",
                    "common_definition",
                )
            ),
            "is_superseded": detail.get("final_status") == "superseded",
            "extraction_seq": detail.get("extraction_seq"),
        })

    return {
        "found": True,
        "frozen": True,
        "read_only": True,
        "audit_id": verdict.get("audit_id"),
        "verdict_status": verdict.get("status"),
        "symbol": name,
        "final": final,
        "counts": {
            "strong_references": sum(
                1 for e in own if e["type"] == "strong_reference"
            ),
            "weak_references": sum(
                1 for e in own if e["type"] == "weak_reference"
            ),
            "weak_definitions": sum(
                1 for e in own if e["type"] == "weak_definition"
            ),
            "strong_definitions": sum(
                1 for e in own if e["type"] == "strong_definition"
            ),
            "archive_index_hits": sum(
                1 for e in own if e["type"] == "archive_index_hit"
            ),
            "archive_members_extracted": len(extractions),
        },
        "archive_extractions": extractions,
        "timeline": timeline,
    }

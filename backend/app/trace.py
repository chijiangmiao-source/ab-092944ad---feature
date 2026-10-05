"""冻结结论的逐符号轨迹查询（只读）。

查询完全基于已冻结的结论 JSON：不重新解析输入、不重跑链接裁决，
因此不会改变既有结论、归档抽取顺序或冻结重放行为。
"""
from __future__ import annotations

from typing import Optional, Tuple

# 轨迹事件类型 -> 中文展示标签
EVENT_LABELS = {
    "strong_reference": "强未定义引用",
    "weak_reference": "弱未定义引用",
    "weak_definition": "弱定义",
    "strong_definition": "强定义",
    "common_definition": "COMMON 暂定定义",
    "archive_index_hit": "归档索引命中",
    "member_extracted": "实际抽取成员",
    "final_undefined": "最终未定义拒绝证据",
}


class TraceNotFound(Exception):
    """符号未收录于该冻结结论；携带可操作反馈。"""

    def __init__(self, code: str, message: str, http_status: int = 404,
                 alternatives: Optional[list] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.alternatives = alternatives or []


def _has_trace_data(verdict: dict) -> bool:
    return isinstance(verdict.get("symbol_traces"), dict)


def available_symbols(verdict: dict) -> list:
    """冻结结论中已收录、可追查的全部符号。"""
    traces = verdict.get("symbol_traces") or {}
    return sorted(traces)


def get_trace(verdict: dict, symbol: str) -> Tuple[dict, int]:
    """返回 (响应体, HTTP 状态)。符号未收录抛 TraceNotFound。"""
    if not _has_trace_data(verdict):
        raise TraceNotFound(
            "TRACE_UNAVAILABLE",
            f"冻结结论 {verdict.get('audit_id')!r} 生成于符号轨迹功能上线前，"
            "结论中不含逐符号轨迹；可使用当前版本以新的审计标识重新提交同一组输入，"
            "再按新标识追查（原冻结结论保持不变）。",
            http_status=409,
        )

    traces = verdict["symbol_traces"]
    if symbol not in traces:
        names = sorted(traces)
        hint = ""
        if names:
            hint = f"可在该冻结结论已收录的 {len(names)} 个符号中选择：{names[:20]}"
            if len(names) > 20:
                hint += f" …（其余 {len(names) - 20} 个见符号列表接口）"
        raise TraceNotFound(
            "SYMBOL_NOT_RECORDED",
            f"符号 {symbol!r} 未收录于冻结结论 {verdict.get('audit_id')!r}："
            "该符号未作为任何输入的外部引用、定义或归档索引条目参与本次裁决，"
            "因此不存在可重放的轨迹。请核对符号名拼写，"
            + (hint if hint else "且本次裁决没有收录任何外部符号。"),
            http_status=404,
            alternatives=names,
        )

    trace = traces[symbol]
    return {
        "audit_id": verdict.get("audit_id"),
        "status": verdict.get("status"),
        "frozen": True,
        "query": {"symbol": symbol},
        "event_labels": EVENT_LABELS,
        "trace": trace,
        "terminal_error": verdict.get("terminal_error"),
    }, 200


def list_symbols(verdict: dict) -> dict:
    """列出冻结结论中可追查的符号及其最终状态（供详情页选择）。"""
    traces = verdict.get("symbol_traces") or {}
    items = []
    for name in sorted(traces):
        t = traces[name]
        items.append({
            "symbol": name,
            "final_state": t.get("final_state"),
            "adopted_definition": t.get("adopted_definition"),
            "event_count": len(t.get("events", [])),
            "terminal": t.get("terminal") is not None,
        })
    return {
        "audit_id": verdict.get("audit_id"),
        "status": verdict.get("status"),
        "frozen": True,
        "trace_available": _has_trace_data(verdict),
        "symbols": items,
    }

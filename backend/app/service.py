"""审计服务：解码输入、判定 ELF/ar、运行链接裁决，并冻结结论。"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import List, Optional

from .elfparser import (
    AR_MAGIC,
    ELFMAG,
    ParseError,
    parse_ar,
    parse_elf_object,
)
from .linker import InputUnit, LinkError, Resolver

MAX_INPUTS = 12
MAX_TOTAL_BYTES = 16 * 1024 * 1024
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,127}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

class AuditRejected(Exception):
    """审计被拒绝；携带机器码、首触发位置与证据。"""

    def __init__(self, code: str, message: str, location: str,
                 evidence: Optional[dict] = None, http_status: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.location = location
        self.evidence = evidence or {}
        self.http_status = http_status


@dataclass
class InputPayload:
    position: int
    name: str
    blob: bytes
    group: Optional[str] = None


def _decode_b64(position: int, name: str, data: str) -> bytes:
    if not isinstance(data, str) or not data:
        raise AuditRejected(
            "EMPTY_INPUT", f"输入#{position} {name} 的数据为空",
            f"输入#{position} {name}",
        )
    compact = "".join(data.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuditRejected(
            "INVALID_BASE64",
            f"输入#{position} {name} 不是合法 Base64: {exc}",
            f"输入#{position} {name}",
            {"detail": str(exc)},
        )


def validate_request(audit_id: str, raw_inputs: list) -> List[InputPayload]:
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id or ""):
        raise AuditRejected(
            "INVALID_AUDIT_ID",
            "稳定审计标识须为 1-64 位字母数字及 ._-，且以字母数字开头",
            "audit_id",
        )
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise AuditRejected(
            "NO_INPUTS", "至少需要一个链接输入", "inputs", http_status=400
        )
    if len(raw_inputs) > MAX_INPUTS:
        raise AuditRejected(
            "TOO_MANY_INPUTS",
            f"至多 {MAX_INPUTS} 个输入，收到 {len(raw_inputs)} 个",
            f"inputs[{MAX_INPUTS}]",
            {"limit": MAX_INPUTS, "received": len(raw_inputs)},
        )

    payloads: List[InputPayload] = []
    total = 0
    seen_groups: dict = {}
    for i, item in enumerate(raw_inputs, start=1):
        if not isinstance(item, dict):
            raise AuditRejected(
                "MALFORMED_INPUT", f"输入#{i} 必须是对象", f"inputs[{i - 1}]"
            )
        name = item.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise AuditRejected(
                "INVALID_NAME",
                f"输入#{i} 名称不合法（1-128 位文件名字符）",
                f"inputs[{i - 1}].name",
            )
        group = item.get("group")
        if group is not None:
            if not isinstance(group, str) or not GROUP_RE.match(group):
                raise AuditRejected(
                    "INVALID_GROUP",
                    f"输入#{i} 成组标签不合法",
                    f"inputs[{i - 1}].group",
                )
            if group in seen_groups and seen_groups[group] != i - 1:
                # 组成员必须连续出现（对应 --start-group ... --end-group）。
                prev = seen_groups[group]
                if prev != i - 2:
                    raise AuditRejected(
                        "NON_CONTIGUOUS_GROUP",
                        f"成组归档 {group!r} 的成员必须在命令行中连续排列",
                        f"inputs[{i - 1}].group",
                        {"group": group, "first_position": prev + 1},
                    )
            seen_groups[group] = i - 1

        blob = _decode_b64(i, name, item.get("data_b64", ""))
        if not blob:
            raise AuditRejected(
                "EMPTY_INPUT", f"输入#{i} {name} 解码后为 0 字节",
                f"输入#{i} {name}",
            )
        total += len(blob)
        if total > MAX_TOTAL_BYTES:
            raise AuditRejected(
                "PAYLOAD_TOO_LARGE",
                f"输入总字节超过 {MAX_TOTAL_BYTES} 字节上限",
                f"inputs[{i - 1}]",
                {"limit": MAX_TOTAL_BYTES},
                http_status=413,
            )
        payloads.append(InputPayload(i, name, blob, group))

    return payloads


def _sniff(blob: bytes) -> str:
    if blob[:4] == ELFMAG:
        return "elf"
    if blob[:8] == AR_MAGIC:
        return "ar"
    return "unknown"


def _freeze_definitions(resolver) -> dict:
    """拒绝时刻的绑定快照：即使结论被拒绝，已处理符号的最终绑定也须可追查。"""
    if resolver is None:
        return {}
    return {
        name: {"binding": d.binding, "source": d.source}
        for name, d in sorted(resolver.defs.items())
    }


def audit(audit_id: str, raw_inputs: list) -> dict:
    """执行完整审计；任何违例抛 AuditRejected。返回可冻结的结论字典。"""
    payloads = validate_request(audit_id, raw_inputs)

    def reject_verdict(exc: AuditRejected) -> dict:
        return {
            "audit_id": audit_id,
            "status": "rejected",
            "error": {
                "code": exc.code,
                "message": exc.message,
                "location": exc.location,
                "evidence": exc.evidence,
            },
            "inputs": input_records,
            "extraction_order": getattr(resolver, "extraction_log", []),
            "rounds": getattr(resolver, "round_log", []),
            "resolutions": getattr(resolver, "resolutions", []),
            "symbol_events": getattr(resolver, "symbol_events", []),
            "definitions": _freeze_definitions(resolver),
            "weak_unresolved": sorted(getattr(resolver, "weak_undef", {})),
        }

    units: List[InputUnit] = []
    input_records = []
    resolver: Optional[Resolver] = None
    try:
        for p in payloads:
            kind = _sniff(p.blob)
            record = {
                "position": p.position,
                "name": p.name,
                "group": p.group,
                "bytes": len(p.blob),
                "kind": kind,
            }
            try:
                if kind == "unknown":
                    raise AuditRejected(
                        "ILLEGAL_MEMBER",
                        f"输入#{p.position} {p.name} 既非 ELF 也非 ar 归档"
                        f"（头部 {p.blob[:8]!r}）",
                        f"输入#{p.position} {p.name} byte 0",
                        {"magic": p.blob[:8].hex(), "input": record},
                    )
                if kind == "elf":
                    obj = parse_elf_object(p.blob, f"输入#{p.position} {p.name}")
                    record["symbols"] = len(obj.symbols)
                    units.append(InputUnit(p.position, p.name, "object", obj=obj,
                                           group=p.group))
                else:
                    archive = parse_ar(p.blob, f"输入#{p.position} {p.name}")
                    record["members"] = [
                        {"name": m.name, "symbols": len(m.parsed.symbols)}
                        for m in archive.member_order
                    ]
                    record["index_symbols"] = len(archive.symbol_index)
                    units.append(InputUnit(p.position, p.name, "archive",
                                           archive=archive, group=p.group))
            except ParseError as exc:
                raise AuditRejected(
                    "CORRUPT_BINARY",
                    exc.message,
                    exc.where or f"输入#{p.position} {p.name}",
                    {"input": record, **exc.evidence},
                )
            input_records.append(record)

        resolver = Resolver(units=units)
        result = resolver.run()
    except AuditRejected as exc:
        return reject_verdict(exc)
    except LinkError as exc:
        return {
            "audit_id": audit_id,
            "status": "rejected",
            "error": {
                "code": exc.code,
                "message": exc.message,
                "location": exc.location,
                "evidence": exc.evidence,
            },
            "inputs": input_records,
            "extraction_order": resolver.extraction_log if resolver else [],
            "rounds": resolver.round_log if resolver else [],
            "resolutions": resolver.resolutions if resolver else [],
            "symbol_events": resolver.symbol_events if resolver else [],
            "definitions": _freeze_definitions(resolver),
            "weak_unresolved": sorted(resolver.weak_undef) if resolver else [],
        }

    return {
        "audit_id": audit_id,
        "status": "accepted",
        "error": None,
        "inputs": input_records,
        **result,
    }

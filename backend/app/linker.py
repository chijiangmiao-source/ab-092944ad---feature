"""按命令行顺序的左至右链接裁决。

语义（与 GNU ld 行为对齐）：

* 可重定位对象在命令行位置整体装入；
* 普通归档经过时按 GNU 符号索引抽取成员，同一归档内反复扫描到
  本归档不再新增成员（归档内闭包）；
* 成组单元（连续带有相同 group 标签的输入）按顺序反复整组扫描，
  直到某一轮没有新成员被抽取（未定义集合不再变化）；
* 强定义满足引用；弱定义仅占位，强定义可覆盖弱定义，反之忽略；
  COMMON 暂定定义与强定义兼容（强定义胜出），COMMON 之间合并；
* 弱未定义引用不抽取归档成员，最终残留仅报告、不判错；
* 一个外部符号只能有一个强定义；第二个互不相容的强定义首次出现即拒绝。

裁决同时为每个外部符号记录一条按命令行处理序排列的轨迹
（``symbol_traces``）：引用、弱/强/COMMON 定义、归档索引命中、
实际成员抽取，每项都带输入位置及对未定义集合/绑定结果的影响。
裁决被拒绝时，相关符号的轨迹止于首个拒绝证据，不补造后续事件。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .elfparser import ArArchive, ELFSymbol, ParsedObject, STB_WEAK

SHN_COMMON = 0xFFF2


class LinkError(Exception):
    def __init__(self, code: str, message: str, location: str, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.location = location
        self.evidence = evidence or {}


@dataclass
class Definition:
    binding: str          # "strong" | "weak" | "common"
    source: str
    input_position: int
    member: Optional[str] = None


@dataclass
class InputUnit:
    position: int                  # 1-based 命令行位置
    name: str
    kind: str                      # "object" | "archive"
    obj: Optional[ParsedObject] = None
    archive: Optional[ArArchive] = None
    group: Optional[str] = None


@dataclass
class Resolver:
    units: List[InputUnit]
    defs: Dict[str, Definition] = field(default_factory=dict)
    strong_undef: Dict[str, str] = field(default_factory=dict)   # 名称 -> 首次引用位置
    weak_undef: Dict[str, str] = field(default_factory=dict)
    loaded_members: set = field(default_factory=set)            # (position, member)
    loaded_objects: set = field(default_factory=set)
    extraction_log: List[dict] = field(default_factory=list)
    round_log: List[dict] = field(default_factory=list)
    resolutions: List[dict] = field(default_factory=list)
    symbol_events: Dict[str, List[dict]] = field(default_factory=dict)
    terminal: Optional[dict] = None
    _seq: int = 0
    _trace_seq: int = 0
    _cur_pos: int = 0
    _cur_ctx: str = ""
    _cur_pass: int = 0
    _cur_extraction_seq: Optional[int] = None

    # ------------------------------------------------------------------ #
    def _source(self, pos: int, member: Optional[str] = None) -> str:
        u = self.units[pos - 1]
        if member is not None:
            return f"输入#{pos} 归档 {u.name}!成员 {member}"
        return f"输入#{pos} {u.kind} {u.name}"

    # ------------------------------------------------------------------ #
    # 符号轨迹
    # ------------------------------------------------------------------ #
    def _trace(self, name: str, etype: str, location: str, effect: str,
               detail: Optional[dict] = None) -> dict:
        self._trace_seq += 1
        ev = {
            "seq": self._trace_seq,
            "type": etype,
            "input_position": self._cur_pos,
            "location": location,
            "context": self._cur_ctx,
            "pass_or_round": self._cur_pass,
            "extraction_seq": self._cur_extraction_seq,
            "effect": effect,
        }
        if detail:
            ev.update(detail)
        self.symbol_events.setdefault(name, []).append(ev)
        return ev

    def _udef_snapshot(self) -> List[str]:
        return sorted(self.strong_undef)

    def _record_terminal(self, name: str, etype: str, location: str,
                         effect: str, detail: dict) -> None:
        ev = self._trace(name, etype, location, effect, detail)
        ev["terminal"] = True
        ev["strong_undefined_after"] = self._udef_snapshot()

    # ------------------------------------------------------------------ #
    def _satisfy(self, name: str, binding: str, loc: str, member: Optional[str]) -> None:
        """登记/替换定义，并从待解析集合中移除。"""
        existing = self.defs.get(name)
        if existing is None:
            if name in self.strong_undef or name in self.weak_undef:
                self.resolutions.append({
                    "symbol": name,
                    "action": f"resolved_by_{binding}",
                    "definition": loc,
                    "first_strong_reference": self.strong_undef.get(name),
                })
        elif existing.binding == "weak" and binding in ("strong", "common"):
            self.resolutions.append({
                "symbol": name,
                "action": f"{binding}_overrides_weak",
                "weak_source": existing.source,
                "new_source": loc,
            })
        elif existing.binding == "common" and binding == "strong":
            self.resolutions.append({
                "symbol": name,
                "action": "strong_overrides_common",
                "common_source": existing.source,
                "new_source": loc,
            })
        self.defs[name] = Definition(
            binding, loc, self._cur_pos, member
        )
        self.strong_undef.pop(name, None)
        self.weak_undef.pop(name, None)

    def _apply_symbol(self, sym: ELFSymbol, pos: int, member: Optional[str]) -> None:
        self._cur_pos = pos
        loc = self._source(pos, member)
        at = f"{loc} .symtab[{sym.index}]"
        name_in_undef = sym.name in self.strong_undef
        existing = self.defs.get(sym.name)

        if sym.shndx == SHN_COMMON:
            if existing is None:
                self._satisfy(sym.name, "common", loc, member)
                self._trace(
                    sym.name, "common_definition", at,
                    "暂定 COMMON 定义占位"
                    + ("；将符号移出未定义集合" if name_in_undef else "（此前无引用）"),
                    {
                        "binding_before": None,
                        "binding_after": "common",
                        "undefined_removed": name_in_undef,
                        "strong_undefined_after": self._udef_snapshot(),
                        "symtab_index": sym.index,
                    },
                )
            elif existing.binding == "weak":
                self._satisfy(sym.name, "common", loc, member)
                self._trace(
                    sym.name, "common_definition", at,
                    "COMMON 覆盖先前弱定义；最终绑定暂为 common，遇强定义仍可被满足",
                    {
                        "binding_before": "weak",
                        "binding_after": "common",
                        "previous_binding_source": existing.source,
                        "undefined_removed": name_in_undef,
                        "strong_undefined_after": self._udef_snapshot(),
                        "symtab_index": sym.index,
                    },
                )
            else:
                # 已有 strong/common：COMMON 退化为引用，合并/被满足。
                self._trace(
                    sym.name, "common_definition", at,
                    "已存在同绑定或更强定义，COMMON 退化为引用并被满足，绑定不变",
                    {
                        "binding_before": existing.binding,
                        "binding_after": existing.binding,
                        "kept_source": existing.source,
                        "undefined_removed": False,
                        "strong_undefined_after": self._udef_snapshot(),
                        "symtab_index": sym.index,
                    },
                )
            return

        if sym.defined:
            if sym.binding == STB_WEAK:
                if existing is None:
                    weak_present = sym.name in self.weak_undef
                    self._satisfy(sym.name, "weak", loc, member)
                    self._trace(
                        sym.name, "weak_definition", at,
                        "弱定义占位"
                        + ("；满足既有引用并移出未定义集合，后续强定义仍可覆盖"
                           if (name_in_undef or weak_present)
                           else "；后续强定义可覆盖，后到弱定义将被忽略"),
                        {
                            "binding_before": None,
                            "binding_after": "weak",
                            "undefined_removed": name_in_undef,
                            "strong_undefined_after": self._udef_snapshot(),
                            "symtab_index": sym.index,
                        },
                    )
                else:
                    self._trace(
                        sym.name, "weak_definition", at,
                        "弱定义被静默忽略：已存在先到定义，绑定结果不变",
                        {
                            "binding_before": existing.binding,
                            "binding_after": existing.binding,
                            "kept_source": existing.source,
                            "undefined_removed": False,
                            "strong_undefined_after": self._udef_snapshot(),
                            "symtab_index": sym.index,
                        },
                    )
                return

            if existing is not None and existing.binding == "strong":
                terminal = {
                    "code": "DUPLICATE_STRONG",
                    "message": f"外部符号 {sym.name!r} 存在重复强定义",
                    "location": at,
                    "evidence": {
                        "symbol": sym.name,
                        "first_definition": existing.source,
                        "conflicting_definition": at,
                    },
                }
                self.terminal = terminal
                self._record_terminal(
                    sym.name, "strong_definition", at,
                    "第二个强定义首次出现：裁决在此被拒绝（DUPLICATE_STRONG），"
                    "轨迹止于本证据",
                    {
                        "binding_before": "strong",
                        "binding_after": "strong",
                        "kept_source": existing.source,
                        "rejected": True,
                        "rejection": terminal,
                        "undefined_removed": False,
                        "symtab_index": sym.index,
                    },
                )
                raise LinkError(
                    "DUPLICATE_STRONG",
                    f"外部符号 {sym.name!r} 存在重复强定义",
                    at,
                    {
                        "symbol": sym.name,
                        "first_definition": existing.source,
                        "conflicting_definition": at,
                    },
                )

            before_binding = existing.binding if existing else None
            if before_binding == "weak":
                effect = (
                    "强定义覆盖先前弱定义：弱定义保留在轨迹中，最终采用本强定义"
                    + ("；符号同时移出未定义集合" if name_in_undef
                       else "（符号此前已由弱定义移出未定义集合）")
                )
                action = "strong_overrides_weak"
            elif before_binding == "common":
                effect = (
                    "强定义满足先前 COMMON 暂定定义：最终采用本强定义"
                    + ("；符号同时移出未定义集合" if name_in_undef else "")
                )
                action = "strong_overrides_common"
            else:
                effect = ("强定义绑定符号"
                          + ("并将其移出未定义集合" if name_in_undef
                             else "（此前无未定义引用）"))
                action = "strong_definition_binds"
            self._satisfy(sym.name, "strong", loc, member)
            self._trace(
                sym.name, "strong_definition", at, effect,
                {
                    "binding_before": before_binding,
                    "binding_after": "strong",
                    "adopted_source": loc,
                    **({"previous_binding_source": existing.source}
                       if existing is not None else {}),
                    "override_action": action,
                    "undefined_removed": name_in_undef,
                    "strong_undefined_after": self._udef_snapshot(),
                    "symtab_index": sym.index,
                },
            )
            return

        # 未定义引用
        if sym.name in self.defs:
            self._trace(
                sym.name,
                "weak_reference" if sym.binding == STB_WEAK else "strong_reference",
                at, "引用出现时符号已有绑定，未定义集合与绑定均不变",
                {
                    "bound_binding": self.defs[sym.name].binding,
                    "bound_source": self.defs[sym.name].source,
                    "undefined_added": False,
                    "strong_undefined_after": self._udef_snapshot(),
                    "symtab_index": sym.index,
                },
            )
            return
        if sym.binding == STB_WEAK:
            already = sym.name in self.weak_undef
            if not already:
                self.weak_undef.setdefault(sym.name, at)
            self._trace(
                sym.name, "weak_reference", at,
                "弱未定义引用：不触发归档成员抽取；最终残留仅报告、不判错"
                + ("（首引位置已记录，此处不改变集合）" if already else ""),
                {
                    "undefined_added": not already,
                    "weak_unresolved_after": sorted(self.weak_undef),
                    "strong_undefined_after": self._udef_snapshot(),
                    "symtab_index": sym.index,
                },
            )
        else:
            already = sym.name in self.strong_undef
            if not already:
                self.strong_undef.setdefault(sym.name, at)
            self._trace(
                sym.name, "strong_reference", at,
                ("强未定义引用已在集合中（首引位置保留），集合不变"
                 if already else
                 "加入强未定义集合：后续归档按符号索引命中时可抽取成员满足"),
                {
                    "undefined_added": not already,
                    "strong_undefined_after": self._udef_snapshot(),
                    "symtab_index": sym.index,
                },
            )

    # ------------------------------------------------------------------ #
    def _load(self, pos: int, obj: ParsedObject, member: Optional[str],
              why: Optional[List[str]], context: str, pass_no: int) -> None:
        prev_ctx = (self._cur_ctx, self._cur_pass, self._cur_extraction_seq)
        self._cur_ctx = context
        self._cur_pass = pass_no
        if member is not None:
            key = (pos, member)
            if key in self.loaded_members:
                self._cur_ctx, self._cur_pass, self._cur_extraction_seq = prev_ctx
                return
            self.loaded_members.add(key)
        else:
            if pos in self.loaded_objects:
                self._cur_ctx, self._cur_pass, self._cur_extraction_seq = prev_ctx
                return
            self.loaded_objects.add(pos)

        before = sorted(self.strong_undef)
        entry = None
        trace_events: List[dict] = []
        if member is not None:
            self._seq += 1
            self._cur_extraction_seq = self._seq
            archive_name = self.units[pos - 1].name
            entry = {
                "seq": self._seq,
                "context": context,
                "pass_or_round": pass_no,
                "input_position": pos,
                "archive": archive_name,
                "member": member,
                "matched_index_symbols": why or [],
                "undefined_before": before,
                "undefined_after": before,
            }
            self.extraction_log.append(entry)
            for name in why or []:
                ev = self._trace(
                    name, "member_extracted",
                    f"{self._source(pos, member)}（实际抽取）",
                    f"命中归档索引后实际装入成员；命中符号 {why}，"
                    "成员内符号按下标顺序施加于未定义集合/绑定",
                    {
                        "archive": archive_name,
                        "member": member,
                        "matched_index_symbols": list(why or []),
                        "undefined_before": before,
                    },
                )
                trace_events.append(ev)

        try:
            for sym in obj.symbols:
                self._apply_symbol(sym, pos, member)
        except LinkError:
            after = sorted(self.strong_undef)
            if entry is not None:
                entry["undefined_after"] = after
                entry["triggered_error"] = True
            for ev in trace_events:
                ev["undefined_after"] = after
                ev["triggered_error"] = True
            self._cur_ctx, self._cur_pass, self._cur_extraction_seq = prev_ctx
            raise
        if entry is not None:
            entry["undefined_after"] = sorted(self.strong_undef)
        for ev in trace_events:
            ev["undefined_after"] = sorted(self.strong_undef)
        self._cur_ctx, self._cur_pass, self._cur_extraction_seq = prev_ctx

    # ------------------------------------------------------------------ #
    def _eligible(self, pos: int, member) -> List[str]:
        """按归档符号索引，返回当前强未定义集合中映射到该成员的符号。"""
        archive = self.units[pos - 1].archive
        return sorted(
            name for name in self.strong_undef
            if archive.symbol_index.get(name) is member
        )

    def _record_index_hits(self, pos: int, member, matched: List[str],
                           context: str, pass_no: int) -> None:
        archive = self.units[pos - 1].archive
        archive_name = self.units[pos - 1].name
        prev_ctx = (self._cur_ctx, self._cur_pass, self._cur_extraction_seq)
        self._cur_pos = pos
        self._cur_ctx = context
        self._cur_pass = pass_no
        for name in matched:
            ordinal = None
            for i, (iname, imember) in enumerate(archive.index_pairs):
                if iname == name and imember is member:
                    ordinal = i
                    break
            self._trace(
                name, "archive_index_hit",
                f"输入#{pos} 归档 {archive_name} 符号索引 '/' 项[{ordinal}] "
                f"{name} -> 成员 {member.name}",
                f"符号 {name!r} 在强未定义集合中且归档索引映射到成员 "
                f"{member.name}：本趟抽取该成员（同一符号多成员命中时取首个）",
                {
                    "archive": archive_name,
                    "member": member.name,
                    "member_ordinal": member.ordinal,
                    "index_pair_ordinal": ordinal,
                    "indexed_members_for_symbol": sorted({
                        m.name for n, m in archive.index_pairs if n == name
                    }),
                    "matched_strong_undefined": list(matched),
                },
            )
        self._cur_ctx, self._cur_pass, self._cur_extraction_seq = prev_ctx

    def _scan_archive(self, pos: int, pass_no: int, context: str,
                      extracted_acc: List[str]) -> bool:
        archive = self.units[pos - 1].archive
        moved = False
        for member in archive.member_order:
            if (pos, member.name) in self.loaded_members:
                continue
            matched = self._eligible(pos, member)
            if matched:
                self._record_index_hits(pos, member, matched, context, pass_no)
                self._load(pos, member.parsed, member.name, matched, context, pass_no)
                extracted_acc.append(member.name)
                moved = True
        return moved

    def _process_plain_archive(self, pos: int) -> None:
        name = self.units[pos - 1].name
        pass_no = 0
        while True:
            pass_no += 1
            before = sorted(self.strong_undef)
            extracted: List[str] = []
            try:
                moved = self._scan_archive(
                    pos, pass_no, f"archive:{name}", extracted
                )
            except LinkError:
                self.round_log.append({
                    "scope": "archive",
                    "input_position": pos,
                    "archive": name,
                    "pass": pass_no,
                    "extracted": extracted,
                    "undefined_before": before,
                    "undefined_after": sorted(self.strong_undef),
                    "changed": bool(extracted),
                    "triggered_error": True,
                })
                raise
            self.round_log.append({
                "scope": "archive",
                "input_position": pos,
                "archive": name,
                "pass": pass_no,
                "extracted": extracted,
                "undefined_before": before,
                "undefined_after": sorted(self.strong_undef),
                "changed": moved,
            })
            if not moved:
                break

    # ------------------------------------------------------------------ #
    def _process_group(self, run: List[InputUnit], label: str) -> None:
        round_no = 0
        while True:
            round_no += 1
            before = sorted(self.strong_undef)
            scans = []
            moved = False
            try:
                for unit in run:
                    extracted: List[str] = []
                    if unit.kind == "object":
                        if unit.position not in self.loaded_objects:
                            self._load(unit.position, unit.obj, None, None,
                                       f"group:{label}", round_no)
                            extracted.append(unit.name)
                            moved = True
                    else:
                        if self._scan_archive(unit.position, round_no,
                                              f"group:{label}", extracted):
                            moved = True
                    if extracted:
                        scans.append({
                            "input_position": unit.position,
                            "name": unit.name,
                            "kind": unit.kind,
                            "extracted": extracted,
                        })
            except LinkError:
                self.round_log.append({
                    "scope": "group",
                    "group": label,
                    "round": round_no,
                    "scans": scans,
                    "undefined_before": before,
                    "undefined_after": sorted(self.strong_undef),
                    "changed": moved,
                    "triggered_error": True,
                })
                raise
            self.round_log.append({
                "scope": "group",
                "group": label,
                "round": round_no,
                "scans": scans,
                "undefined_before": before,
                "undefined_after": sorted(self.strong_undef),
                "changed": moved,
            })
            if not moved:
                break

    # ------------------------------------------------------------------ #
    def run(self) -> dict:
        i = 0
        while i < len(self.units):
            label = self.units[i].group
            if label:
                j = i
                while j + 1 < len(self.units) and self.units[j + 1].group == label:
                    j += 1
                self._process_group(self.units[i : j + 1], label)
                i = j + 1
                continue

            unit = self.units[i]
            if unit.kind == "object":
                self._load(unit.position, unit.obj, None, None, "command_line", 0)
            else:
                self._process_plain_archive(unit.position)
            i += 1

        if self.strong_undef:
            first_name = next(iter(self.strong_undef))
            terminal = {
                "code": "UNDEFINED_SYMBOL",
                "message": f"外部符号 {first_name!r} 最终仍未定义",
                "location": self.strong_undef[first_name],
                "evidence": {
                    "undefined": sorted(self.strong_undef),
                    "first_reference": self.strong_undef[first_name],
                    "first_symbol": first_name,
                },
            }
            self.terminal = terminal
            self._record_terminal(
                first_name, "final_undefined",
                self.strong_undef[first_name],
                "命令行处理结束后符号仍在强未定义集合中：裁决在此被拒绝"
                "（UNDEFINED_SYMBOL），轨迹止于本证据",
                {
                    "rejected": True,
                    "rejection": terminal,
                    "final_undefined": sorted(self.strong_undef),
                },
            )
            raise LinkError(
                "UNDEFINED_SYMBOL",
                f"外部符号 {first_name!r} 最终仍未定义",
                self.strong_undef[first_name],
                {
                    "undefined": sorted(self.strong_undef),
                    "first_reference": self.strong_undef[first_name],
                    "first_symbol": first_name,
                },
            )

        return {
            "definitions": {
                name: {"binding": d.binding, "source": d.source}
                for name, d in sorted(self.defs.items())
            },
            "extraction_order": self.extraction_log,
            "rounds": self.round_log,
            "resolutions": self.resolutions,
            "weak_unresolved": sorted(self.weak_undef),
            "final_undefined": [],
        }

    # ------------------------------------------------------------------ #
    def symbol_trace_payload(self) -> dict:
        """生成冻结用的逐符号轨迹（只读快照，不改变任何裁决状态）。"""
        names = set(self.symbol_events) | set(self.defs) \
            | set(self.strong_undef) | set(self.weak_undef)
        traces: Dict[str, dict] = {}
        terminal = self.terminal
        for name in sorted(names):
            events = [dict(e) for e in self.symbol_events.get(name, [])]
            events.sort(key=lambda e: e["seq"])
            d = self.defs.get(name)
            if d is not None:
                final_state = d.binding
                adopted = {"binding": d.binding, "source": d.source,
                           "input_position": d.input_position}
            elif name in self.strong_undef:
                final_state = "undefined"
                adopted = None
            else:
                final_state = "weak_unresolved"
                adopted = None

            sym_terminal = None
            if terminal is not None:
                if any(e.get("terminal") for e in events):
                    sym_terminal = terminal
                elif final_state == "undefined":
                    # 该符号在拒绝时仍残留未定义；拒绝证据以首个未定义符号为准。
                    sym_terminal = {
                        "code": terminal["code"],
                        "location": terminal["location"],
                        "note": "该符号同在最终未定义集合中；裁决拒绝证据见首符号",
                        "evidence_symbol": terminal["evidence"].get("first_symbol"),
                    }
            traces[name] = {
                "symbol": name,
                "final_state": final_state,
                "adopted_definition": adopted,
                "first_strong_reference": self.strong_undef.get(name)
                if name in self.strong_undef else None,
                "events": events,
                "terminal": sym_terminal,
            }
        return {
            "symbols": sorted(traces),
            "symbol_traces": traces,
            "terminal_error": None if terminal is None else {
                "code": terminal["code"],
                "location": terminal["location"],
            },
        }

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
    # 按真实处理顺序追加的逐符号轨迹；拒绝时止于首个拒绝证据，不补造后续事件。
    symbol_events: List[dict] = field(default_factory=list)
    _seq: int = 0
    _cur_pos: int = 0
    _event_no: int = 0
    _binding_event: Dict[str, int] = field(default_factory=dict)  # 名称 -> 当前绑定事件号
    _member_seq: Dict[tuple, int] = field(default_factory=dict)   # (pos, member) -> seq

    # ------------------------------------------------------------------ #
    # 逐符号轨迹
    # ------------------------------------------------------------------ #
    def _record(self, name: str, etype: str, loc: str, pos: int,
                member: Optional[str], binding: Optional[str], effect: str,
                effect_text: str, detail: Optional[dict] = None,
                *, before: Optional[List[str]] = None,
                after: Optional[List[str]] = None) -> dict:
        self._event_no += 1
        unit = self.units[pos - 1]
        event = {
            "event_no": self._event_no,
            "symbol": name,
            "type": etype,
            "location": loc,
            "input_position": pos,
            "input_name": unit.name,
            "input_kind": unit.kind,
            "member": member,
            "binding": binding,
            "effect": effect,
            "effect_text": effect_text,
            "undefined_before": before,
            "undefined_after": after,
            "detail": detail or {},
        }
        self.symbol_events.append(event)
        return event

    def _index_loc(self, pos: int) -> str:
        return f"输入#{pos} 归档 {self.units[pos - 1].name} GNU '/' 符号索引"

    def _record_index_decision(self, pos: int, member, loaded: bool,
                               context: str, pass_no: int) -> List[int]:
        """扫描到某成员时，为所有“当前强未定义且索引指向该成员”的符号留证。"""
        archive = self.units[pos - 1].archive
        hit_nos: List[int] = []
        for name in sorted(self.strong_undef):
            if archive.symbol_index.get(name) is not member:
                continue
            if loaded:
                self._record(
                    name, "archive_index_skip", self._index_loc(pos), pos,
                    member.name, None, "archive_member_already_extracted",
                    f"索引将 {name!r} 指向成员 {member.name}，但该成员已于第 "
                    f"{self._member_seq.get((pos, member.name))} 次抽取装入，"
                    f"归档成员不重复抽取，未定义集合不变",
                    {
                        "archive": self.units[pos - 1].name, "member": member.name,
                        "context": context, "pass_or_round": pass_no,
                        "first_extraction_seq": self._member_seq.get(
                            (pos, member.name)
                        ),
                    },
                    before=sorted(self.strong_undef),
                    after=sorted(self.strong_undef),
                )
            else:
                ev = self._record(
                    name, "archive_index_hit", self._index_loc(pos), pos,
                    member.name, None, "archive_index_hit",
                    f"{name!r} 在强未定义集合中，GNU '/' 符号索引命中归档 "
                    f"{self.units[pos - 1].name} 的成员 {member.name}，按命令行处理顺序"
                    f"抽取该成员",
                    {
                        "archive": self.units[pos - 1].name, "member": member.name,
                        "context": context, "pass_or_round": pass_no,
                    },
                    before=sorted(self.strong_undef),
                )
                hit_nos.append(ev["event_no"])
        return hit_nos

    def _backfill_hits(self, hit_nos: List[int], seq: Optional[int]) -> None:
        after = sorted(self.strong_undef)
        for no in hit_nos:
            ev = self.symbol_events[no - 1]
            ev["undefined_after"] = after
            if seq is not None:
                ev["detail"]["extraction_seq"] = seq

    def _record_index_misses(self, positions: List[int], scope: str,
                             pass_no: int) -> None:
        """收敛（不再有新增成员）时，为索引不提供残留符号的归档留证。"""
        for pos in positions:
            archive = self.units[pos - 1].archive
            for name in sorted(self.strong_undef):
                if name in archive.symbol_index:
                    continue
                self._record(
                    name, "archive_index_miss", self._index_loc(pos), pos,
                    None, None, "archive_index_miss",
                    f"反复扫描已收敛：{name!r} 仍强未定义，归档 {self.units[pos - 1].name} "
                    f"的 GNU '/' 符号索引中不存在该符号，没有成员可抽取",
                    {
                        "archive": self.units[pos - 1].name, "scope": scope,
                        "pass_or_round": pass_no,
                    },
                    before=sorted(self.strong_undef),
                    after=sorted(self.strong_undef),
                )

    # ------------------------------------------------------------------ #
    def _source(self, pos: int, member: Optional[str] = None) -> str:
        u = self.units[pos - 1]
        if member is not None:
            return f"输入#{pos} 归档 {u.name}!成员 {member}"
        return f"输入#{pos} {u.kind} {u.name}"

    def _satisfy(self, name: str, binding: str, loc: str, member: Optional[str],
                 sym_index: int) -> None:
        """登记/替换定义，并从待解析集合中移除符号。同时留下绑定轨迹。"""
        pos = self._cur_pos
        before = sorted(self.strong_undef)
        existing = self.defs.get(name)
        was_pending = name in self.strong_undef or name in self.weak_undef
        replaces = None
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
        self.defs[name] = Definition(binding, loc, pos, member)
        self.strong_undef.pop(name, None)
        self.weak_undef.pop(name, None)
        after = sorted(self.strong_undef)

        at = f"{loc} .symtab[{sym_index}]"
        if existing is not None and existing.binding == "weak" \
                and binding in ("strong", "common"):
            old_no = self._binding_event.get(name)
            ev = self._record(
                name, f"{binding}_definition", at, pos, member, binding,
                f"{binding}_overrides_weak",
                f"{binding.capitalize()}定义覆盖先前弱定义：{name!r} 最终采用"
                f"{at}，先前弱定义 {existing.source} 保留在轨迹中但不再生效；"
                f"未定义集合中不再有该符号",
                {"replaces_event_no": old_no,
                 "replaced_location": existing.source,
                 "replaced_binding": "weak", "final": True},
                before=before, after=after,
            )
            replaces = ev["event_no"]
            if old_no is not None:
                old = self.symbol_events[old_no - 1]
                old["detail"]["final"] = False
                old["detail"]["final_status"] = "superseded"
                old["detail"]["adopted_by_event_no"] = replaces
                old["detail"]["adopted_by_location"] = at
        elif existing is not None and existing.binding == "common" \
                and binding == "strong":
            old_no = self._binding_event.get(name)
            ev = self._record(
                name, "strong_definition", at, pos, member, "strong",
                "strong_overrides_common",
                f"强定义覆盖先前 COMMON 暂定定义：{name!r} 最终采用 {at}；"
                f"COMMON 暂定定义 {existing.source} 保留在轨迹中但不再生效",
                {"replaces_event_no": old_no,
                 "replaced_location": existing.source,
                 "replaced_binding": "common", "final": True},
                before=before, after=after,
            )
            replaces = ev["event_no"]
            if old_no is not None:
                old = self.symbol_events[old_no - 1]
                old["detail"]["final"] = False
                old["detail"]["final_status"] = "superseded"
                old["detail"]["adopted_by_event_no"] = replaces
                old["detail"]["adopted_by_location"] = at
        else:
            if existing is None and was_pending:
                effect = f"{binding}_definition_resolves_reference"
                text = (f"{binding.capitalize()}定义满足先前未定义引用："
                        f"{name!r} 绑定到 {at}，从强未定义集合移除")
            elif existing is None:
                effect = f"{binding}_definition_registered"
                text = f"{binding.capitalize()}定义登记：{name!r} 绑定到 {at}"
            else:
                # common 遇到 common：合并进既有暂定定义，绑定不变。
                effect = f"{binding}_definition_merged"
                text = (f"{binding.capitalize()}暂定定义并入既有同类定义 "
                        f"{existing.source}，绑定结果不变")
            ev = self._record(
                name,
                "common_definition" if binding == "common"
                else f"{binding}_definition",
                at, pos, member, binding, effect, text,
                {"final": existing is None},
                before=before, after=after,
            )
        if replaces is not None:
            self._binding_event[name] = replaces
        else:
            self._binding_event[name] = self.symbol_events[-1]["event_no"]

    def _apply_symbol(self, sym: ELFSymbol, pos: int, member: Optional[str]) -> None:
        self._cur_pos = pos
        loc = self._source(pos, member)
        at = f"{loc} .symtab[{sym.index}]"

        if sym.shndx == SHN_COMMON:
            existing = self.defs.get(sym.name)
            if existing is None:
                self._satisfy(sym.name, "common", loc, member, sym.index)
            elif existing.binding == "weak":
                self._satisfy(sym.name, "common", loc, member, sym.index)
            else:
                # 已有 strong/common：COMMON 退化为引用，合并/被满足。
                before = sorted(self.strong_undef)
                self._record(
                    sym.name, "common_reference", at, pos, member, "common",
                    "common_merges_into_existing",
                    f"COMMON 暂定定义遇到既有 {existing.binding} 定义 "
                    f"{existing.source}：退化为引用并入既有绑定，绑定不变，"
                    f"未定义集合不变",
                    {"existing_binding": existing.binding,
                     "existing_location": existing.source, "final": False},
                    before=before, after=before,
                )
            return

        if sym.defined:
            if sym.binding == STB_WEAK:
                existing = self.defs.get(sym.name)
                if existing is None:
                    self._satisfy(sym.name, "weak", loc, member, sym.index)
                else:
                    # 弱定义遇到任何既有定义一律忽略。
                    before = sorted(self.strong_undef)
                    self._record(
                        sym.name, "weak_definition", at, pos, member, "weak",
                        "weak_definition_ignored",
                        f"弱定义被忽略：{sym.name!r} 已存在 {existing.binding} "
                        f"定义 {existing.source}，后来的弱定义不改变绑定结果",
                        {"existing_binding": existing.binding,
                         "existing_location": existing.source, "final": False},
                        before=before, after=before,
                    )
                return

            existing = self.defs.get(sym.name)
            if existing is not None and existing.binding == "strong":
                before = sorted(self.strong_undef)
                ev = self._record(
                    sym.name, "duplicate_strong_definition", at, pos, member,
                    "strong", "rejected_duplicate_strong",
                    f"拒绝证据：{sym.name!r} 存在第二个强定义 {at}，与先前强定义 "
                    f"{existing.source} 冲突；裁决在此中止，不产生后续事件",
                    {"first_definition": existing.source,
                     "conflicting_definition": at, "final": True,
                     "rejection": True},
                    before=before, after=before,
                )
                raise LinkError(
                    "DUPLICATE_STRONG",
                    f"外部符号 {sym.name!r} 存在重复强定义",
                    at,
                    {
                        "symbol": sym.name,
                        "first_definition": existing.source,
                        "conflicting_definition": at,
                        "trace_event_no": ev["event_no"],
                    },
                )
            self._satisfy(sym.name, "strong", loc, member, sym.index)
            return

        # 未定义引用
        if sym.name in self.defs:
            before = sorted(self.strong_undef)
            self._record(
                sym.name,
                "weak_reference" if sym.binding == STB_WEAK else "strong_reference",
                at, pos, member,
                "weak" if sym.binding == STB_WEAK else "strong",
                "reference_already_bound",
                f"{'弱' if sym.binding == STB_WEAK else '强'}未定义引用被既有"
                f"{self.defs[sym.name].binding}定义满足，绑定与未定义集合不变",
                {"bound_to": self.defs[sym.name].source,
                 "bound_binding": self.defs[sym.name].binding, "final": False},
                before=before, after=before,
            )
            return
        if sym.binding == STB_WEAK:
            if sym.name not in self.weak_undef:
                before = sorted(self.strong_undef)
                self.weak_undef.setdefault(sym.name, at)
                self._record(
                    sym.name, "weak_reference", at, pos, member, "weak",
                    "weak_undefined_registered",
                    f"弱未定义引用登记：{sym.name!r} 不触发归档成员抽取，"
                    f"不进入强未定义集合；最终残留只报告、不判错",
                    {"final": False},
                    before=before, after=before,
                )
        else:
            if sym.name not in self.strong_undef:
                before = sorted(self.strong_undef)
                self.strong_undef.setdefault(sym.name, at)
                after = sorted(self.strong_undef)
                self._record(
                    sym.name, "strong_reference", at, pos, member, "strong",
                    "strong_undefined_registered",
                    f"强未定义引用登记：{sym.name!r} 进入强未定义集合，"
                    f"后续经过的归档将按 GNU '/' 符号索引尝试抽取满足它的成员",
                    {"final": False},
                    before=before, after=after,
                )
            else:
                before = sorted(self.strong_undef)
                self._record(
                    sym.name, "strong_reference", at, pos, member, "strong",
                    "strong_reference_repeated",
                    f"强未定义引用在 {at} 再次出现；该符号已在强未定义集合中，"
                    f"首次引用位置保留不变",
                    {"first_reference": self.strong_undef[sym.name],
                     "final": False},
                    before=before, after=before,
                )

    # ------------------------------------------------------------------ #
    def _load(self, pos: int, obj: ParsedObject, member: Optional[str],
              why: Optional[List[str]], context: str, pass_no: int,
              hit_nos: Optional[List[int]] = None) -> None:
        if member is not None:
            key = (pos, member)
            if key in self.loaded_members:
                return
            self.loaded_members.add(key)
        else:
            if pos in self.loaded_objects:
                return
            self.loaded_objects.add(pos)

        before = sorted(self.strong_undef)
        entry = None
        if member is not None:
            self._seq += 1
            self._member_seq[(pos, member)] = self._seq
            entry = {
                "seq": self._seq,
                "context": context,
                "pass_or_round": pass_no,
                "input_position": pos,
                "archive": self.units[pos - 1].name,
                "member": member,
                "matched_index_symbols": why or [],
                "undefined_before": before,
                "undefined_after": before,
            }
            self.extraction_log.append(entry)

        try:
            for sym in obj.symbols:
                self._apply_symbol(sym, pos, member)
        except LinkError:
            after = sorted(self.strong_undef)
            if entry is not None:
                entry["undefined_after"] = after
                entry["triggered_error"] = True
            self._backfill_hits(hit_nos or [], entry["seq"] if entry else None)
            raise
        after = sorted(self.strong_undef)
        if entry is not None:
            entry["undefined_after"] = after
        self._backfill_hits(hit_nos or [], entry["seq"] if entry else None)

    # ------------------------------------------------------------------ #
    def _scan_archive(self, pos: int, pass_no: int, context: str,
                      extracted_acc: List[str]) -> bool:
        archive = self.units[pos - 1].archive
        moved = False
        for member in archive.member_order:
            loaded = (pos, member.name) in self.loaded_members
            hit_nos = self._record_index_decision(
                pos, member, loaded, context, pass_no
            )
            if loaded:
                continue
            if hit_nos:
                self._load(pos, member.parsed, member.name,
                           [self.symbol_events[no - 1]["symbol"] for no in hit_nos],
                           context, pass_no, hit_nos)
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
                # 收敛趟：为仍强未定义符号留下“索引不收录”的负证据。
                self._record_index_misses([pos], f"archive:{name}", pass_no)
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
                # 收敛轮：为仍强未定义符号在组内每个归档留下“索引不收录”负证据。
                archive_positions = [u.position for u in run if u.kind == "archive"]
                self._record_index_misses(
                    archive_positions, f"group:{label}", round_no
                )
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
            first_at = self.strong_undef[first_name]
            remaining = sorted(self.strong_undef)
            after = sorted(self.strong_undef)
            self._event_no += 1
            end_event = {
                "event_no": self._event_no,
                "symbol": first_name,
                "type": "final_undefined_rejection",
                "location": first_at,
                "input_position": 0,
                "input_name": None,
                "input_kind": None,
                "member": None,
                "binding": "strong",
                "effect": "rejected_final_undefined",
                "effect_text": (
                    f"拒绝证据：命令行所有输入处理完毕，{first_name!r} 仍处于"
                    f"强未定义集合（首次引用 {first_at}）；最终未定义集合 "
                    f"{remaining}。轨迹在此中止，不编造后续事件"
                ),
                "undefined_before": after,
                "undefined_after": after,
                "detail": {
                    "first_reference": first_at,
                    "first_symbol": first_name,
                    "undefined": remaining,
                    "final": True,
                    "rejection": True,
                },
            }
            self.symbol_events.append(end_event)
            raise LinkError(
                "UNDEFINED_SYMBOL",
                f"外部符号 {first_name!r} 最终仍未定义",
                first_at,
                {
                    "undefined": remaining,
                    "first_reference": first_at,
                    "first_symbol": first_name,
                    "trace_event_no": self._event_no,
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
            "symbol_events": self.symbol_events,
            "weak_unresolved": sorted(self.weak_undef),
            "final_undefined": [],
        }

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
    _seq: int = 0
    _cur_pos: int = 0

    # ------------------------------------------------------------------ #
    def _source(self, pos: int, member: Optional[str] = None) -> str:
        u = self.units[pos - 1]
        if member is not None:
            return f"输入#{pos} 归档 {u.name}!成员 {member}"
        return f"输入#{pos} {u.kind} {u.name}"

    def _satisfy(self, name: str, binding: str, loc: str, member: Optional[str]) -> None:
        """登记/替换定义，并从待解析集合中移除符号。"""
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
        self.defs[name] = Definition(binding, loc, self._cur_pos, member)
        self.strong_undef.pop(name, None)
        self.weak_undef.pop(name, None)

    def _apply_symbol(self, sym: ELFSymbol, pos: int, member: Optional[str]) -> None:
        self._cur_pos = pos
        loc = self._source(pos, member)
        at = f"{loc} .symtab[{sym.index}]"

        if sym.shndx == SHN_COMMON:
            existing = self.defs.get(sym.name)
            if existing is None:
                self._satisfy(sym.name, "common", loc, member)
            elif existing.binding == "weak":
                self._satisfy(sym.name, "common", loc, member)
            # 已有 strong/common：COMMON 退化为引用，合并/被满足。
            return

        if sym.defined:
            if sym.binding == STB_WEAK:
                existing = self.defs.get(sym.name)
                if existing is None:
                    self._satisfy(sym.name, "weak", loc, member)
                # 弱定义遇到任何既有定义一律忽略。
                return

            existing = self.defs.get(sym.name)
            if existing is not None and existing.binding == "strong":
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
            self._satisfy(sym.name, "strong", loc, member)
            return

        # 未定义引用
        if sym.name in self.defs:
            return
        if sym.binding == STB_WEAK:
            self.weak_undef.setdefault(sym.name, at)
        else:
            self.strong_undef.setdefault(sym.name, at)

    # ------------------------------------------------------------------ #
    def _load(self, pos: int, obj: ParsedObject, member: Optional[str],
              why: Optional[List[str]], context: str, pass_no: int) -> None:
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
            if entry is not None:
                entry["undefined_after"] = sorted(self.strong_undef)
                entry["triggered_error"] = True
            raise
        if entry is not None:
            entry["undefined_after"] = sorted(self.strong_undef)

    # ------------------------------------------------------------------ #
    def _eligible(self, pos: int, member) -> List[str]:
        """按归档符号索引，返回当前强未定义集合中映射到该成员的符号。"""
        archive = self.units[pos - 1].archive
        return sorted(
            name for name in self.strong_undef
            if archive.symbol_index.get(name) is member
        )

    def _scan_archive(self, pos: int, pass_no: int, context: str,
                      extracted_acc: List[str]) -> bool:
        archive = self.units[pos - 1].archive
        moved = False
        for member in archive.member_order:
            if (pos, member.name) in self.loaded_members:
                continue
            matched = self._eligible(pos, member)
            if matched:
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

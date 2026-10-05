"""FastAPI 应用：审计提交、按标识重开冻结结论、健康端点。"""
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .service import AuditRejected, audit
from .fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar
from .storage import AuditStore
from .trace import TraceNotFound, get_trace, list_symbols

DB_PATH = os.environ.get("AUDIT_DB", "/data/audits.db")

app = FastAPI(title="机载维护镜像链接审计", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

store = AuditStore(DB_PATH)


class InputItem(BaseModel):
    name: str = Field(..., description="输入文件名，仅用于展示")
    data_b64: str
    group: Optional[str] = Field(
        None, description="成组标签；相同标签且连续的输入构成一个归档组"
    )


class AuditRequest(BaseModel):
    audit_id: str
    audit_type: str = Field(
        "link_closure",
        description="审计类型；当前唯一支持 link_closure（归档闭合）",
    )
    inputs: List[InputItem]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "link-audit", "checks": {"db": "ok"}}


@app.get("/api/demo/cycle")
def demo_cycle() -> dict:
    """页面「循环依赖示例」的真实输入集（合成 x86-64 ET_REL/ar 字节）。

    main.o 需要 a；libX.a 含 a(引用 c) 与 b；libY.a 含 c(引用 b)。
    普通顺序下残留 b 未定义；三个输入成同一组后扫描到闭包。
    """
    obj = lambda s: {"name": s.name + ".o", "data_b64": b64(build_elf64_rel(s))}
    arc = lambda nm, specs: {
        "name": nm + ".a", "data_b64": b64(build_gnu_ar(nm, specs)),
    }
    return {
        "audit_id": "MAINT-CYCLE-DEMO-0001",
        "inputs": [
            {**obj(ObjSpec("main", undefined=["a"])), "group": "G1"},
            {**arc("libX", [
                ObjSpec("amem", strong=["a"], undefined=["c"]),
                ObjSpec("bmem", strong=["b"]),
            ]), "group": "G1"},
            {**arc("libY", [
                ObjSpec("cmem", strong=["c"], undefined=["b"]),
            ]), "group": "G1"},
        ],
        "explanation": "main→a→c→b 构成跨归档循环；成组后第 2 轮抽取 libX 的 bmem 闭合",
    }


@app.get("/api/demo/symbol-trace")
def demo_symbol_trace() -> dict:
    """页面「符号轨迹示例」的真实输入集。

    一个冻结结论中同时包含三类可追查归因：

    * b：main 引用 a → libdep.a 索引命中抽取 amem → amem 引用 b →
      同归档索引命中 bmem → 实际抽取 bmem 并以强定义满足（归档跨成员满足）；
    * w：main 引用 → weakprov.o 弱定义占位 → strongprov.o 强定义覆盖，
      轨迹同时保留弱、强两者并标明最终采用强定义；
    * ghost：仅被 main 引用，任何成员/索引都不能满足，
      裁决以 UNDEFINED_SYMBOL 拒绝，轨迹止于首个拒绝证据。
    """
    obj = lambda s: {"name": s.name + ".o", "data_b64": b64(build_elf64_rel(s))}
    arc = lambda nm, specs: {
        "name": nm + ".a", "data_b64": b64(build_gnu_ar(nm, specs)),
    }
    return {
        "audit_id": "MAINT-TRACE-DEMO-0001",
        "inputs": [
            obj(ObjSpec("main", undefined=["a", "w", "ghost"])),
            obj(ObjSpec("weakprov", weak=["w"])),
            obj(ObjSpec("strongprov", strong=["w"])),
            arc("libdep", [
                ObjSpec("amem", strong=["a"], undefined=["b"]),
                ObjSpec("bmem", strong=["b"]),
            ]),
        ],
        "explanation": (
            "a 抽取 amem 后引出 b，归档内继续抽取 bmem 跨成员满足；"
            "w 弱定义被后到强定义覆盖（两者均保留）；"
            "ghost 最终未定义，裁决被拒绝"
        ),
        "focus_symbols": {
            "cross_member": "b",
            "weak_to_strong": "w",
            "undefined": "ghost",
        },
    }


@app.get("/api/audits")
def list_audits() -> dict:
    return {"audits": store.list_ids()}


@app.get("/api/audits/{audit_id}")
def reopen(audit_id: str) -> JSONResponse:
    verdict = store.get(audit_id)
    if verdict is None:
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "error": {
                    "code": "NOT_FOUND",
                    "message": f"审计标识 {audit_id!r} 尚无冻结结论",
                    "location": "path",
                },
            },
        )
    return JSONResponse(content=verdict)


@app.get("/api/audits/{audit_id}/symbols")
def list_audit_symbols(audit_id: str) -> JSONResponse:
    """列出冻结结论中已收录、可追查的外部符号（详情页选择用）。只读。"""
    verdict = store.get(audit_id)
    if verdict is None:
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "error": {
                    "code": "NOT_FOUND",
                    "message": f"审计标识 {audit_id!r} 尚无冻结结论",
                    "location": "path",
                },
            },
        )
    return JSONResponse(content=list_symbols(verdict))


@app.get("/api/audits/{audit_id}/symbols/{symbol}")
def audit_symbol_trace(audit_id: str, symbol: str) -> JSONResponse:
    """按命令行处理顺序返回某符号在冻结结论中的完整轨迹。只读、不重放。"""
    verdict = store.get(audit_id)
    if verdict is None:
        return JSONResponse(
            status_code=404,
            content={
                "status": "error",
                "error": {
                    "code": "NOT_FOUND",
                    "message": f"审计标识 {audit_id!r} 尚无冻结结论",
                    "location": "path",
                },
            },
        )
    try:
        body, status = get_trace(verdict, symbol)
    except TraceNotFound as exc:
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "status": "error",
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "location": "symbol",
                    "available_symbols": exc.alternatives,
                },
            },
        )
    return JSONResponse(status_code=status, content=body)


@app.post("/api/audits")
async def submit(req: AuditRequest) -> JSONResponse:
    if req.audit_type != "link_closure":
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": {
                    "code": "UNSUPPORTED_AUDIT_TYPE",
                    "message": f"不支持的审计类型 {req.audit_type!r}",
                    "location": "audit_type",
                },
            },
        )

    try:
        verdict = audit(req.audit_id, [i.model_dump() for i in req.inputs])
    except AuditRejected as exc:
        # 请求级校验失败（Base64、标识、数量等）：不构成可冻结的二进制结论。
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "audit_id": req.audit_id,
                "status": "rejected",
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "location": exc.location,
                    "evidence": exc.evidence,
                },
            },
        )

    created = store.save(audit_id=req.audit_id, verdict=verdict)
    if not created:
        # 同一稳定标识的结论已冻结：忽略本次重算，返回既有冻结结论。
        frozen = store.get(req.audit_id)
        return JSONResponse(
            status_code=409,
            content={**frozen, "frozen": True},
        )

    # accepted 或因二进制/链接规则被拒绝的结论都作为冻结结论返回。
    status = 201 if verdict["status"] == "accepted" else 422
    return JSONResponse(status_code=status, content=verdict)

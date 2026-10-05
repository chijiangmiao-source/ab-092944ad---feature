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

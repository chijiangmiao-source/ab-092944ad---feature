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
from .tracer import TraceRequestError, list_frozen_symbols, trace_symbol

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


@app.get("/api/demo/trace")
def demo_trace() -> dict:
    """页面「符号归因示例」的真实输入集（合成 x86-64 ET_REL/ar 字节）。

    命令行顺序（均不成组）：
      main.o : 强引用 need、pull、missing；弱引用 wref
      weak.o : need 的弱定义（占位；按 ld 语义弱定义不会触发归档抽取）
      lib1.a : 成员顺序 providermem、consumermem
        providermem : 强定义 backsym
        consumermem : 强定义 pull、need，引用 backsym

    lib1.a 第 1 趟：providermem 无命中（backsym 尚无未定义引用）；
    consumermem 因 pull 命中被抽取，其强定义 need 覆盖 weak.o 的弱定义，
    并引入 backsym 未定义。第 2 趟反向抽取 providermem 跨成员满足 backsym；
    missing 索引始终不收录，最终未定义拒绝。
    """
    obj = lambda s: {"name": s.name + ".o",
                     "data_b64": b64(build_elf64_rel(s))}
    arc = lambda nm, specs: {
        "name": nm + ".a", "data_b64": b64(build_gnu_ar(nm, specs)),
    }
    return {
        "audit_id": "MAINT-TRACE-DEMO-0001",
        "inputs": [
            obj(ObjSpec("main", undefined=["need", "pull", "missing"],
                        weak_undefined=["wref"])),
            obj(ObjSpec("weakplaceholder", weak=["need"])),
            arc("lib1", [
                ObjSpec("providermem", strong=["backsym"]),
                ObjSpec("consumermem",
                        strong=["pull", "need"], undefined=["backsym"]),
            ]),
        ],
        "trace_focus": ["need", "pull", "backsym", "missing"],
        "explanation": (
            "need：弱定义占位→consumermem 因 pull 命中被抽取，强定义 need 覆盖弱定义；"
            "pull：强引用→归档索引命中→成员抽取→强定义满足的完整链路；"
            "backsym：consumermem 引用，第 2 趟反向抽取 providermem 跨成员满足；"
            "missing：索引不收录，最终未定义拒绝；wref：弱引用残留不判错"
        ),
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
def audit_symbols(audit_id: str) -> JSONResponse:
    """只读：列出冻结结论中按处理顺序已出现的外部符号供详情页选择。

    不解析输入、不重放裁决、不写存储，仅消费冻结结论中的轨迹证据。
    """
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
    return JSONResponse(content=list_frozen_symbols(verdict))


@app.get("/api/audits/{audit_id}/symbols/{symbol:path}")
def audit_symbol_trace(audit_id: str, symbol: str) -> JSONResponse:
    """只读：按命令行处理顺序返回某符号的引用/弱定义/强定义/归档索引命中/
    实际抽取成员的归因轨迹。

    轨迹完全来自冻结证据：强覆盖弱时两者并存并标明最终采用者；
    DUPLICATE_STRONG / 最终未定义拒绝时轨迹止于首个拒绝证据；
    符号未被该冻结结论收录时返回可操作的未收录反馈。
    """
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
        result = trace_symbol(verdict, symbol)
    except TraceRequestError as exc:
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "status": "error",
                "error": {"code": exc.code, "message": exc.message,
                          "location": "query.symbol"},
            },
        )
    if not result.get("found"):
        return JSONResponse(status_code=404, content=result)
    return JSONResponse(content=result)


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

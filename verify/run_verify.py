#!/usr/bin/env python3
"""verify 服务一次性入口：

1. 解析规则测试（pytest，覆盖 ELF/ar 字节级校验）；
2. 前端构建检查（vite build）；
3. 归档闭合 API/HTTP 冒烟（健康端点、提交、拒绝、冻结重开）；
4. 逐符号轨迹只读冒烟（跨成员满足 / 弱转强 / 未定义 / 未收录 404 / 不改结论）。

任一步失败即以非零退出码结束，并在最后打印汇总。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import os

BACKEND_URL = os.environ.get("AUDIT_BACKEND_URL", "http://backend:8000").rstrip("/")
ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"

# 每次运行使用唯一标识后缀，避免复跑命中既有冻结结论（409）。
RUN_TAG = os.environ.get("VERIFY_RUN_TAG") or str(int(time.time()))


def _tag(prefix: str) -> str:
    return f"{prefix}-{RUN_TAG}"

results: list[tuple[str, bool, str]] = []


def step(name: str):
    def deco(fn):
        def wrapped():
            print(f"\n=== verify: {name} ===", flush=True)
            try:
                detail = fn() or "通过"
                results.append((name, True, detail))
                print(f"[PASS] {name}: {detail}", flush=True)
            except Exception as exc:  # noqa: BLE001
                results.append((name, False, str(exc)))
                print(f"[FAIL] {name}: {exc}", flush=True)
        return wrapped
    return deco


def run(cmd: list[str], cwd: Path, timeout: int = 300) -> str:
    proc = subprocess.run(
        cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-25:])
        raise AssertionError(
            f"命令 {' '.join(cmd)} 退出码 {proc.returncode}\n{tail}"
        )
    return proc.stdout + proc.stderr


@step("解析规则测试 pytest")
def _parser_tests() -> str:
    out = run([sys.executable, "-m", "pytest", "tests", "-q"], BACKEND)
    line = next((l for l in reversed(out.splitlines()) if "passed" in l), out[-200:])
    return line.strip()


@step("前端构建检查 vite build")
def _frontend_build() -> str:
    if not (FRONTEND / "node_modules").exists():
        run(["npm", "install", "--no-audit", "--no-fund"], FRONTEND, timeout=600)
    out = run(["npm", "run", "build"], FRONTEND, timeout=300)
    line = next((l for l in out.splitlines() if "built in" in l), "构建完成")
    return line.strip()


def _request(method: str, path: str, payload=None, timeout: int = 10):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BACKEND_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _wait_health(deadline_s: int = 60) -> None:
    start = time.time()
    last = ""
    while time.time() - start < deadline_s:
        try:
            status, body = _request("GET", "/health", timeout=3)
            if status == 200 and body.get("status") == "ok":
                return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        time.sleep(1)
    raise AssertionError(f"后端健康端点在 {deadline_s}s 内不可用: {last}")


@step("健康端点 GET /health")
def _health() -> str:
    _wait_health()
    _, body = _request("GET", "/health")
    return f"status={body['status']}"


@step("冒烟：成组循环依赖闭合（accepted）")
def _grouped_cycle() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    demo["audit_id"] = _tag("VERIFY-GROUP")
    status, body = _request("POST", "/api/audits", demo)
    if status != 201 or body["status"] != "accepted":
        raise AssertionError(f"status={status} body={json.dumps(body, ensure_ascii=False)[:600]}")
    members = [(e["archive"], e["member"]) for e in body["extraction_order"]]
    if len(members) != 3:
        raise AssertionError(f"期望抽取 3 个成员，实际 {members}")
    rounds = [r for r in body["rounds"] if r["scope"] == "group"]
    if rounds[-1]["changed"] is not False:
        raise AssertionError("组扫描最终一轮应收敛 changed=false")
    return f"抽取 {[m[1] for m in members]}，{len(rounds)} 轮收敛"


@step("冒烟：不成组循环依赖残留未定义（rejected）")
def _ungrouped_cycle() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    demo["audit_id"] = _tag("VERIFY-NOGROUP")
    for item in demo["inputs"]:
        item["group"] = None
    status, body = _request("POST", "/api/audits", demo)
    if status != 422 or body["status"] != "rejected":
        raise AssertionError(f"status={status} body={json.dumps(body)[:500]}")
    err = body["error"]
    if err["code"] != "UNDEFINED_SYMBOL" or err["evidence"]["undefined"] != ["b"]:
        raise AssertionError(f"期望残留 b 未定义，实际 {err}")
    return f"{err['code']} @ {err['location']}"


@step("冒烟：重复强定义拒绝（DUPLICATE_STRONG）")
def _duplicate_strong() -> str:
    sys.path.insert(0, str(BACKEND))
    from app.fixtures import ObjSpec, b64, build_elf64_rel
    payload = {
        "audit_id": _tag("VERIFY-DUP"),
        "inputs": [
            {"name": "m.o", "data_b64": b64(build_elf64_rel(ObjSpec("m", undefined=["d"])))},
            {"name": "x.o", "data_b64": b64(build_elf64_rel(ObjSpec("x", strong=["d"])))},
            {"name": "y.o", "data_b64": b64(build_elf64_rel(ObjSpec("y", strong=["d"])))},
        ],
    }
    status, body = _request("POST", "/api/audits", payload)
    if status != 422 or body["error"]["code"] != "DUPLICATE_STRONG":
        raise AssertionError(f"status={status} body={json.dumps(body)[:500]}")
    loc = body["error"]["location"]
    if "输入#3" not in loc:
        raise AssertionError(f"首次触发位置应指向输入#3，实际 {loc}")
    return loc


@step("冒烟：损坏归档索引拒绝（CORRUPT_BINARY）")
def _corrupt_index() -> str:
    from app.fixtures import ObjSpec, b64, build_elf64_rel, build_gnu_ar
    bad = build_gnu_ar("lib", [ObjSpec("a", strong=["fa", "secret"])],
                       defined_index={"fa": "a.o"})
    payload = {
        "audit_id": _tag("VERIFY-BADAR"),
        "inputs": [
            {"name": "m.o", "data_b64": b64(build_elf64_rel(ObjSpec("m", undefined=["fa"])))},
            {"name": "lib.a", "data_b64": b64(bad)},
        ],
    }
    status, body = _request("POST", "/api/audits", payload)
    if status != 422 or body["error"]["code"] != "CORRUPT_BINARY":
        raise AssertionError(f"status={status} body={json.dumps(body)[:500]}")
    return body["error"]["location"]


@step("冒烟：冻结结论按标识重开（GET 409→200）")
def _freeze_reopen() -> str:
    _, demo = _request("GET", "/api/demo/cycle")
    fid = _tag("VERIFY-FREEZE"); demo["audit_id"] = fid
    s1, b1 = _request("POST", "/api/audits", demo)
    if s1 != 201:
        raise AssertionError(f"首次提交应 201，实际 {s1}")
    # 篡改输入后重提：不得覆盖冻结结论
    demo["inputs"] = demo["inputs"][:1]
    s2, b2 = _request("POST", "/api/audits", demo)
    if s2 != 409 or b2.get("status") != "accepted":
        raise AssertionError(f"重复标识应 409 返回冻结结论，实际 {s2} {b2.get('status')}")
    s3, b3 = _request("GET", f"/api/audits/{fid}")
    if s3 != 200 or len(b3.get("extraction_order", [])) != 3:
        raise AssertionError("重开冻结结论内容与首次不一致")
    return "201 → 409(冻结) → 200(重开)"


@step("冒烟：逐符号轨迹（跨成员满足/弱转强/未定义归因/未收录反馈/只读）")
def _symbol_trace() -> str:
    _, demo = _request("GET", "/api/demo/symbol-trace")
    fid = _tag("VERIFY-TRACE"); demo["audit_id"] = fid
    status, body = _request("POST", "/api/audits", demo)
    if status != 422 or body["error"]["code"] != "UNDEFINED_SYMBOL":
        raise AssertionError(f"轨迹示例应因 ghost 未定义被 422 拒绝，实际 {status} {body.get('error',{}).get('code')}")

    # 可追查符号列表来自真实只读接口
    s, lst = _request("GET", f"/api/audits/{fid}/symbols")
    if s != 200:
        raise AssertionError(f"符号列表应 200，实际 {s}")
    listed = {x["symbol"] for x in lst["symbols"]}
    if not {"a", "b", "w", "ghost"} <= listed:
        raise AssertionError(f"符号列表缺少焦点符号：{listed}")

    def types_of(sym):
        sc, tr = _request("GET", f"/api/audits/{fid}/symbols/{sym}")
        if sc != 200:
            raise AssertionError(f"符号 {sym} 轨迹应 200，实际 {sc}")
        t = tr["trace"]
        return t, [e["type"] for e in t["events"]]

    # 1) 归档跨成员满足：引用 → 索引命中 → 实际抽取 → 强定义
    tb, btypes = types_of("b")
    if btypes != ["strong_reference", "archive_index_hit",
                  "member_extracted", "strong_definition"]:
        raise AssertionError(f"b 跨成员归因事件序列不符：{btypes}")
    hit = next(e for e in tb["events"] if e["type"] == "archive_index_hit")
    if hit["archive"] != "libdep.a" or hit["member"] != "bmem.o":
        raise AssertionError(f"b 的索引命中位置错误：{hit.get('archive')} {hit.get('member')}")
    if not all(e.get("location") and e.get("effect") for e in tb["events"]):
        raise AssertionError("b 轨迹存在缺少输入位置或影响说明的事件")
    if not tb["adopted_definition"]["source"].endswith("bmem.o"):
        raise AssertionError("b 最终采用定义应来自 bmem.o")

    # 2) 弱转强覆盖：弱定义与强定义同时保留，最终采用强定义
    tw, wtypes = types_of("w")
    if wtypes != ["strong_reference", "weak_definition", "strong_definition"]:
        raise AssertionError(f"w 弱转强事件序列不符：{wtypes}")
    ov = tw["events"][-1]
    if ov["binding_before"] != "weak" or ov["binding_after"] != "strong":
        raise AssertionError("w 覆盖事件绑定前后状态错误")
    if "weakprov.o" not in ov["previous_binding_source"] \
            or not ov["adopted_source"].endswith("strongprov.o"):
        raise AssertionError("w 轨迹未同时保留弱定义来源与强定义采用者")
    if tw["adopted_definition"]["binding"] != "strong":
        raise AssertionError("w 最终绑定应为 strong")

    # 3) 未定义符号归因：轨迹止于首个拒绝证据，不编造后续事件
    tg, gtypes = types_of("ghost")
    if gtypes != ["strong_reference", "final_undefined"]:
        raise AssertionError(f"ghost 归因事件序列不符：{gtypes}")
    term = tg["events"][-1]
    if not term.get("terminal") or term["rejection"]["code"] != "UNDEFINED_SYMBOL":
        raise AssertionError("ghost 轨迹未止于 UNDEFINED_SYMBOL 拒绝证据")
    if tg["terminal"]["code"] != "UNDEFINED_SYMBOL" or tg["adopted_definition"] is not None:
        raise AssertionError("ghost 终态信息错误")

    # 4) 未收录符号：可操作反馈 + 已收录候选
    sn, nf = _request("GET", f"/api/audits/{fid}/symbols/not_in_verdict_xyz")
    if sn != 404 or nf["error"]["code"] != "SYMBOL_NOT_RECORDED":
        raise AssertionError(f"未收录符号应 404 SYMBOL_NOT_RECORDED，实际 {sn} {nf.get('error',{}).get('code')}")
    if "not_in_verdict_xyz" not in nf["error"]["message"]:
        raise AssertionError("未收录反馈未给出可操作说明")
    if not {"a", "b", "w", "ghost"} <= set(nf["error"]["available_symbols"]):
        raise AssertionError("未收录反馈缺少已收录符号候选")

    # 5) 查询不得改变冻结结论/抽取顺序
    _, before = _request("GET", f"/api/audits/{fid}")
    for sym in ("b", "w", "ghost", "missing_symbol"):
        _request("GET", f"/api/audits/{fid}/symbols/{sym}")
    _, after = _request("GET", f"/api/audits/{fid}")
    if before != after:
        raise AssertionError("轨迹只读查询改变了冻结结论")

    return (f"b:{btypes[1]}→{btypes[2]}；w 弱→强({ov['adopted_source'].split()[-1]})；"
            f"ghost 止于 {term['rejection']['code']}；未收录 404；查询只读")


def main() -> int:
    # 测试与构建不依赖后端，先跑；冒烟前等待健康端点。
    _parser_tests()
    _frontend_build()
    _health()
    _grouped_cycle()
    _ungrouped_cycle()
    _duplicate_strong()
    _corrupt_index()
    _freeze_reopen()
    _symbol_trace()

    print("\n================ verify 汇总 ================")
    width = max(len(n) for n, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name.ljust(width)}  {detail}")
        failed += 0 if ok else 1
    print(f"\n合计 {len(results)} 项，失败 {failed} 项")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

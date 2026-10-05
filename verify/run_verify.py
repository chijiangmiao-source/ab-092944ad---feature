#!/usr/bin/env python3
"""verify 服务一次性入口：

1. 解析规则测试（pytest，覆盖 ELF/ar 字节级校验）；
2. 前端构建检查（vite build）；
3. 归档闭合 API/HTTP 冒烟（健康端点、提交、拒绝、冻结重开）。

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


@step("冒烟：符号归因追查（跨成员满足/弱转强/未定义/未收录/只读）")
def _symbol_trace() -> str:
    _, demo = _request("GET", "/api/demo/trace")
    tid = _tag("VERIFY-TRACE"); demo["audit_id"] = tid
    status, body = _request("POST", "/api/audits", demo)
    if status != 422 or body["status"] != "rejected":
        raise AssertionError(f"归因示例应因 missing 未定义拒绝，实际 {status}")
    if body["error"]["code"] != "UNDEFINED_SYMBOL":
        raise AssertionError(f"期望 UNDEFINED_SYMBOL，实际 {body['error']}")

    def trace(sym):
        st, tb = _request("GET", f"/api/audits/{tid}/symbols/{sym}")
        if st != 200:
            raise AssertionError(f"追查 {sym} 失败：{st} {tb}")
        return tb

    # 1) 归档跨成员满足：backsym 经第 2 趟反向抽取 providermem 满足。
    bt = trace("backsym")
    btypes = [e["type"] for e in bt["timeline"]]
    if btypes != ["strong_reference", "archive_index_hit", "strong_definition"]:
        raise AssertionError(f"backsym 轨迹异常：{btypes}")
    hit = bt["timeline"][1]
    if hit["member"] != "providermem.o" or hit["detail"]["pass_or_round"] != 2:
        raise AssertionError(f"backsym 索引命中证据异常：{hit['member']} pass={hit['detail']}")
    if bt["archive_extractions"][0]["seq"] != 2:
        raise AssertionError("backsym 实际抽取成员序号应为 2")

    # 2) 弱转强覆盖：弱定义与强定义并存，最终采用归档成员中的强定义。
    nt = trace("need")
    weak = next(e for e in nt["timeline"] if e["type"] == "weak_definition")
    strong = next(e for e in nt["timeline"] if e["type"] == "strong_definition")
    if not weak["is_superseded"]:
        raise AssertionError("弱定义事件必须标记为已被覆盖并保留")
    if weak["detail"]["adopted_by_event_no"] != strong["event_no"]:
        raise AssertionError("弱定义必须指向最终采用的强定义事件")
    if not strong["is_final_binding"] or \
            strong["effect"] != "strong_overrides_weak":
        raise AssertionError("强定义必须标注为最终采用者且动作为覆盖弱定义")
    if nt["final"]["binding"] != "strong" or \
            "consumermem.o" not in nt["final"]["bound_location"]:
        raise AssertionError(f"need 最终绑定异常：{nt['final']}")
    if nt["archive_extractions"][0]["relation"] != "member_defined_symbol":
        raise AssertionError("need 随 pull 命中的成员装入，关联应为 member_defined_symbol")

    # 3) 未定义符号归因：轨迹止于首个最终未定义拒绝证据。
    mt = trace("missing")
    last = mt["timeline"][-1]
    if last["type"] != "final_undefined_rejection" or not last["is_terminal"]:
        raise AssertionError(f"missing 轨迹必须止于拒绝证据：{last}")
    if last["detail"]["undefined"] != ["missing"]:
        raise AssertionError(f"最终未定义集合异常：{last['detail']}")
    if any(e["type"] not in (
        "strong_reference", "archive_index_miss", "final_undefined_rejection"
    ) for e in mt["timeline"]):
        raise AssertionError("missing 轨迹不得编造其他事件")

    # 4) 未收录符号：可操作反馈，且不改变冻结结论。
    before = _request("GET", f"/api/audits/{tid}")[1]
    st, nf = _request("GET", f"/api/audits/{tid}/symbols/ghost%20sentinel")
    if st != 404 or nf.get("error", {}).get("code") != "SYMBOL_NOT_IN_VERDICT":
        raise AssertionError(f"未收录反馈异常：{st} {nf}")
    if not nf.get("action", {}).get("steps"):
        raise AssertionError("未收录反馈必须包含可操作建议")
    if "need" not in nf["action"]["recorded_symbols"]:
        raise AssertionError("未收录反馈必须回列已收录符号")
    st, near = _request("GET", f"/api/audits/{tid}/symbols/nee")
    if st != 404 or "need" not in near["error"]["evidence"]["closest_matches"]:
        raise AssertionError("近似符号名应给出相近匹配建议")
    after = _request("GET", f"/api/audits/{tid}")[1]
    if after != before:
        raise AssertionError("追查查询改变了冻结结论（违反只读要求）")

    # 5) 重复强定义：轨迹止于首个冲突证据，后续输入事件不得出现。
    sys.path.insert(0, str(BACKEND))
    from app.fixtures import ObjSpec as _OS, b64 as _b64, build_elf64_rel as _b
    dup = {
        "audit_id": _tag("VERIFY-DUPTRACE"),
        "inputs": [
            {"name": "m.o", "data_b64": _b64(_b(_OS("m", undefined=["d"])))},
            {"name": "x.o", "data_b64": _b64(_b(_OS("x", strong=["d"])))},
            {"name": "y.o", "data_b64": _b64(_b(_OS("y", strong=["d"])))},
            {"name": "z.o", "data_b64": _b64(_b(_OS("z", strong=["later"])))},
        ],
    }
    _, db = _request("POST", "/api/audits", dup)
    dt = _request("GET", f"/api/audits/{dup['audit_id']}/symbols/d")[1]
    dtypes = [e["type"] for e in dt["timeline"]]
    if dtypes != ["strong_reference", "strong_definition",
                  "duplicate_strong_definition"]:
        raise AssertionError(f"重复强定义轨迹异常：{dtypes}")
    if not dt["timeline"][-1]["is_terminal"]:
        raise AssertionError("重复强定义轨迹必须止于冲突事件")
    if any(e["symbol"] == "later" for e in db["symbol_events"]):
        raise AssertionError("拒绝后不得编造后续输入事件")

    return ("backsym 第2趟跨成员满足；need 弱→强覆盖；missing 止于拒绝证据；"
            "未收录可操作反馈；结论只读不变")


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


def main() -> int:
    # 测试与构建不依赖后端，先跑；冒烟前等待健康端点。
    _parser_tests()
    _frontend_build()
    _health()
    _grouped_cycle()
    _ungrouped_cycle()
    _duplicate_strong()
    _corrupt_index()
    _symbol_trace()
    _freeze_reopen()

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

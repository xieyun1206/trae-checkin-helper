#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
checkin.py — TRAE 自动签到领积分 · 每日签到状态机

接口（逆向自 TRAE 主进程 out/main.js，详见 ../references/endpoints.md）：
  - POST {host}/trae/api/v2/ug/checkin_credits/status   查签到状态（body {}）
      响应 data：{ enable: bool, checked_in: bool, credits?: number, ... }
      - enable     签到功能是否开放（非 boolean 视为协议异常）
      - checked_in 今日是否已签到（客户端用其做协议校验，可靠字段）
  - POST {host}/trae/api/v2/ug/checkin_credits/claim    执行签到（body {}）
      响应：{ code: number, ... }；code === 0 成功；code !== 0 业务错误
      - code = 10001 → 今日已签到（幂等兜底，不视为失败）

状态机（校验 → 防重复 → claim → 结果）：
  1. 获取登录态（可注入 cred，401 时可经 on_token_expired 回调刷新后重试一次）
  2. status：网络异常 / 非 200 / 协议字段缺失 → failed
             enable=false → skipped（功能未开放）
             checked_in=true → already_checked（防重复短路）
  3. claim：code=0 → success（提取 credits）
            code=10001 → already_checked（并发/竞态下的幂等兜底）
            其它 → failed

返回结构（统一，可被上层/自动化直接消费）：
  成功：   {"task":"checkin","status":"success","credit":N,"message":"..."}
  已签到： {"task":"checkin","status":"already_checked","message":"今日已签到"}
  未开放： {"task":"checkin","status":"skipped","message":"签到功能未开放"}
  失败：   {"task":"checkin","status":"failed","reason":"..."}

安全：access_token 仅在内存中使用，绝不打印 / 写日志 / 落盘 / 上传第三方。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
import credentials  # noqa: E402
import http_client  # noqa: E402

CODE_SUCCESS = 0
CODE_ALREADY_CHECKED = 10001


def _result(status: str, **fields) -> dict:
    out = {"task": "checkin", "status": status}
    out.update(fields)
    return out


def _request(
    method: str,
    host: str,
    path: str,
    cred: dict,
    timeout: int | None = None,
) -> tuple[int, dict]:
    """带鉴权与设备头的请求；传输层失败抛 HttpTransportError。"""
    return http_client.request_json(
        method,
        host + path,
        body={},
        token=cred["access_token"],
        device_id=cred.get("device_id", ""),
        timeout=timeout,
    )


def _query_status(cred: dict) -> dict:
    """查签到状态，返回 {"status": ..., "data": ...} 或失败结果 dict。"""
    host = cred.get("host") or config.api_host()
    try:
        code, body = _request("POST", host, config.CHECKIN_STATUS_PATH, cred)
    except http_client.HttpTransportError as e:
        return _result("failed", reason="查询签到状态失败（网络异常）：" + str(e))

    if code == 401:
        return _result("failed", reason="令牌已过期（401）")
    if code != 200:
        return _result(
            "failed", reason="查询签到状态失败：HTTP {}".format(code)
        )
    # 响应为平铺结构（code/enable/checked_in/credits 同层），个别版本可能包一层 data，兼容两种
    payload = body.get("data") if isinstance(body.get("data"), dict) else body
    enable = payload.get("enable")
    checked_in = payload.get("checked_in")
    if not isinstance(enable, bool) or not isinstance(checked_in, bool):
        return _result(
            "failed",
            reason="签到状态接口响应异常（enable/checked_in 缺失，协议可能已变更）",
        )
    return {"status": "ok", "data": payload}


def _do_claim(cred: dict) -> dict:
    """执行签到 claim，返回结果 dict。"""
    host = cred.get("host") or config.api_host()
    try:
        code, body = _request("POST", host, config.CHECKIN_CLAIM_PATH, cred)
    except http_client.HttpTransportError as e:
        return _result("failed", reason="签到请求失败（网络异常）：" + str(e))

    if code == 401:
        return _result("failed", reason="令牌已过期（401）")
    if code != 200:
        return _result("failed", reason="签到请求失败：HTTP {}".format(code))

    biz_code = body.get("code")
    if not isinstance(biz_code, int):
        return _result(
            "failed",
            reason="签到接口响应异常（缺少数字 code，协议可能已变更）",
        )

    if biz_code == CODE_SUCCESS:
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        credit = data.get("credit")
        if not isinstance(credit, int):
            credit = None
        return _result(
            "success",
            credit=credit,
            message="签到成功" + (("，获得 {} 积分".format(credit)) if credit else ""),
        )
    if biz_code == CODE_ALREADY_CHECKED:
        return _result("already_checked", message="今日已签到")

    msg = body.get("msg") or body.get("message") or ""
    return _result(
        "failed",
        reason="签到未成功：code={}{}".format(biz_code, " " + msg if msg else ""),
    )


def query_status(cred: dict | None = None) -> dict:
    """只读查询签到状态（不执行任何 claim）。"""
    try:
        cred = cred or credentials.load_credentials()
    except credentials.CredentialError as e:
        return _result("failed", reason="登录态读取失败：" + str(e))
    st = _query_status(cred)
    if st["status"] == "failed":
        return st
    data = st["data"]
    return _result(
        "ok",
        checked_in=data.get("checked_in"),
        enable=data.get("enable"),
        credits=data.get("credits"),
    )


def run_checkin(
    cred: dict | None = None,
    on_token_expired=None,
    timeout: int | None = None,
) -> dict:
    """
    执行一次完整签到流程（校验 → 防重复 → claim）。
      - cred：登录态（None 时内部加载）
      - on_token_expired：可选回调（无参），令牌 401 时调用；应返回刷新后的 cred
        （或 None 表示刷新失败/不支持）。调用成功后自动重试一次。
    返回统一结构化结果（不含任何敏感信息）。
    """
    try:
        cred = cred or credentials.load_credentials()
    except credentials.CredentialError as e:
        return _result("failed", reason="登录态读取失败：" + str(e))

    # 1. 查询签到状态（含防重复快速短路）
    st = _query_status(cred)
    if st["status"] == "failed":
        if st["reason"].endswith("（401）") and on_token_expired:
            refreshed = _try_refresh(on_token_expired)
            if refreshed:
                return run_checkin(refreshed, on_token_expired=on_token_expired, timeout=timeout)
        return st
    data = st["data"]
    if data.get("enable") is False:
        return _result("skipped", message="签到功能未开放（enable=false）")
    if data.get("checked_in") is True:
        # 防重复：状态已确认今日签到，直接短路，不再发起 claim
        return _result("already_checked", message="今日已签到")

    # 2. 执行签到
    result = _do_claim(cred)
    if result["status"] == "failed" and result["reason"].endswith("（401）") and on_token_expired:
        refreshed = _try_refresh(on_token_expired)
        if refreshed:
            return run_checkin(refreshed, on_token_expired=on_token_expired, timeout=timeout)
    return result


def _try_refresh(on_token_expired) -> dict | None:
    """调用刷新回调，返回新 cred 或 None（刷新失败时上层保留原失败结果）。"""
    try:
        new_cred = on_token_expired()
    except Exception:
        return None
    if not new_cred:
        return None
    return new_cred


if __name__ == "__main__":
    import json

    print(json.dumps(run_checkin(), ensure_ascii=False))

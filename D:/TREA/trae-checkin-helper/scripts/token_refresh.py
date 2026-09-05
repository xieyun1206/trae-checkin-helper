#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
token_refresh.py — TRAE 自动签到领积分 · token 刷新（登录态保持）

登录态保持机制：access token 过期（HTTP 401 / expiredAt）时，用 refreshToken
调用 ExchangeToken 接口换取新 token，并加密写回 storage.json（见 credentials.py）。

接口与签名（逆向自 main.js，完整细节见 ../references/endpoints.md）：

  POST {host}/trae/api/v3/oauth/ExchangeToken
  Body:
    ClientID:     clientId（SOLO 默认 en1oxy7wnw8j9n，TRAE 默认 ono9krqynydwx5）
    ClientSecret: ""
    RefreshToken: refreshToken
    DeviceInfo:   { DeviceID, MachineID, PlatformCode, DeviceType:"PC",
                    DeviceName, DeviceModel, ClientVersion, DevicePublicKey }
    DeviceProof:  { Signature, Timestamp, Nonce }
    IDEVersion:   appVersion

  DeviceProof 签名（main.js MDe，与 Node crypto.sign("sha256", ...) 输出等价）：
    消息 = "POST\\n/trae/api/v3/oauth/ExchangeToken\\n<ClientID>\\n<RefreshToken>\\n<Timestamp>\\n<Nonce>"
    算法 = ECDSA P-256 + SHA-256（DER 签名，base64）
    私钥 = storage.json 中 `iCubeAuthInfo://icube-dc:<deviceId>` 条目的 privateKeyPEM
    Timestamp = Unix 秒；Nonce = 16 随机字节 hex

  DeviceProof 校验失败/刷新 401 时 refreshToken 亦失效，需用户重新登录 TRAE 桌面端。

安全：新 token 仅返回给调用方内存使用；写回 storage.json 前先备份、后原子写。
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
import credentials  # noqa: E402
import ecdsa  # noqa: E402
import http_client  # noqa: E402

REFRESH_GRACE_SECONDS = 300  # token 过期前 5 分钟视为"即将过期"，可提前刷新


def _device_info(cred: dict) -> dict:
    """构造 DeviceInfo（字段与 main.js j() 一致）。

    PlatformCode 与 main.js k() 一致：SOLO 产品为 "SOLO_PC"，其他为 "IDE_PC"。
    本机未知字段（DeviceModel/Brand/CPU/OSInfo/OSVersion）用空串，服务端不强制。
    """
    is_solo = config.is_solo_product()
    return {
        "DeviceID": cred.get("device_id", ""),
        "MachineID": config.machine_id() or cred.get("device_id", ""),
        "PlatformCode": os.environ.get(
            "TRAE_CHECKIN_PLATFORM_CODE", ""
        ).strip() or ("SOLO_PC" if is_solo else "IDE_PC"),
        "DeviceType": "PC",
        "DeviceName": config.device_name(),
        "DeviceModel": "",
        "ClientVersion": config.ide_version(),
        "DevicePublicKey": cred.get("public_key_pem", ""),
        "DeviceBrand": "",
        "DeviceCPU": "",
        "OSInfo": "",
        "OSVersion": "",
    }


def _device_proof(cred: dict, refresh_token: str) -> dict:
    """生成 DeviceProof（签名消息与 main.js MDe 完全一致）。"""
    client_id = config.client_id()
    timestamp = int(time.time())
    nonce = os.urandom(16).hex()
    message = "\n".join(
        ["POST", config.EXCHANGE_TOKEN_PATH, client_id, refresh_token,
         str(timestamp), nonce]
    ).encode("utf-8")
    signature = ecdsa.sign_sha256(message, cred["private_key_pem"])
    return {
        "Signature": signature,
        "Timestamp": timestamp,
        "Nonce": nonce,
    }


def _parse_exchange_response(body: dict) -> dict | None:
    """从 ExchangeToken 响应中提取 {token, refresh_token, expired_at}。

    兼容三种结构（按优先级）：
      1. marscode 风格：{"ResponseMetadata": {...}, "Result": {Token, ...}}（main.js l() 取 r.Result）
      2. 通用：{"code":0, "data": {Token, ...}}
      3. 平铺：{Token, RefreshToken, ...}
    结构异常返回 None。
    """
    result = body.get("Result") if isinstance(body, dict) else None
    if isinstance(result, dict) and ("Token" in result or "token" in result):
        payload = result
    else:
        data = body.get("data") if isinstance(body, dict) else None
        if isinstance(data, dict) and ("Token" in data or "token" in data):
            payload = data
        elif "Token" in body or "token" in body:
            payload = body
        else:
            return None
    token = payload.get("Token") or payload.get("token") or ""
    refresh = payload.get("RefreshToken") or payload.get("refreshToken") or ""
    if not isinstance(token, str) or not token:
        return None
    # TokenExpireAt 为毫秒时间戳（main.js ODe 处理）；个别版本可能返回 ISO 串，兼容两种
    expire_at = payload.get("TokenExpireAt") or payload.get("expireAt") or ""
    expired_at = _normalize_expire(expire_at, payload.get("TokenExpireDuration"))
    return {
        "token": token,
        "refresh_token": refresh if isinstance(refresh, str) else "",
        "expired_at": expired_at,
    }


def _response_error(resp: dict) -> str:
    """提取 marscode 风格业务错误（ResponseMetadata.Error.Code/Message）；无错误返回空串。"""
    meta = resp.get("ResponseMetadata") if isinstance(resp, dict) else None
    err = meta.get("Error") if isinstance(meta, dict) else None
    if not isinstance(err, dict):
        return ""
    code = err.get("Code") or ""
    message = err.get("Message") or ""
    if not code:
        return ""
    return "{} {}".format(code, message).strip()


def _normalize_expire(expire_at, duration) -> str:
    """把 TokenExpireAt（毫秒时间戳 / ISO 串）归一化为 ISO 字符串；异常时返回空串。"""
    try:
        if isinstance(expire_at, (int, float)):
            ts_ms = int(expire_at)
            return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts_ms / 1000))
        if isinstance(expire_at, str) and expire_at.strip():
            text = expire_at.strip()
            if text.endswith("Z") or "T" in text:
                return text
            ts_ms = int(text)
            return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts_ms / 1000))
    except (ValueError, TypeError, OverflowError):
        pass
    return ""


def refresh_token(cred: dict | None = None, write_back: bool = True) -> dict:
    """
    用 refreshToken 换取新 token，可选写回 storage.json（登录态保持）。

    返回（新 token 仅存在于 cred 字段，供调用方内存使用，绝不记录/打印）：
      {"status":"ok", "cred": {新登录态}, "backup": "<备份路径>", "warning": ...}
      {"status":"failed", "reason": "..."}
      {"status":"skipped", "reason": "无刷新凭据（需重新登录）"}
    """
    try:
        cred = cred or credentials.load_credentials()
    except credentials.CredentialError as e:
        return {"status": "failed", "reason": "登录态读取失败：" + str(e)}

    refresh_token_val = cred.get("refresh_token", "")
    if not refresh_token_val:
        return {
            "status": "skipped",
            "reason": "登录态缺少 refreshToken，无法自动续期，请重新登录 TRAE 桌面端",
        }
    if not cred.get("private_key_pem"):
        return {
            "status": "skipped",
            "reason": "登录态缺少设备 ECDSA 密钥（privateKeyPEM），无法签名刷新，请重新登录 TRAE 桌面端",
        }

    host = cred.get("host") or config.api_host()
    body = {
        "ClientID": config.client_id(),
        "ClientSecret": "",
        "RefreshToken": refresh_token_val,
        "DeviceInfo": _device_info(cred),
        "DeviceProof": _device_proof(cred, refresh_token_val),
        "IDEVersion": config.ide_version(),
    }

    try:
        code, resp = http_client.post_json(
            host + config.EXCHANGE_TOKEN_PATH,
            body=body,
            token=cred["access_token"],
            device_id="",
            use_auth_header=False,
            extra_headers={"x-cloudide-token": cred["access_token"]},
        )
    except http_client.HttpTransportError as e:
        return {"status": "failed", "reason": "刷新请求网络异常：" + str(e)}

    if code == 401:
        return {
            "status": "failed",
            "reason": "刷新被拒绝（401）：refreshToken 已失效，请重新登录 TRAE 桌面端",
        }
    if code != 200:
        return {"status": "failed", "reason": "刷新请求失败：HTTP {}".format(code)}

    # marscode 风格业务错误：{"ResponseMetadata":{"Error":{"Code":...}}}
    meta_err = _response_error(resp)
    if meta_err:
        return {"status": "failed", "reason": "刷新业务失败：{}".format(meta_err)}

    biz_code = resp.get("code")
    if isinstance(biz_code, int) and biz_code != 0:
        msg = resp.get("msg") or resp.get("message") or ""
        return {
            "status": "failed",
            "reason": "刷新业务失败：code={}{}".format(biz_code, " " + msg if msg else ""),
        }

    parsed = _parse_exchange_response(resp)
    if not parsed:
        return {
            "status": "failed",
            "reason": "刷新响应缺少 Token 字段（协议可能已变更，建议更新本 Skill）",
        }

    # 内存中构造新登录态（供本次会话继续使用）
    new_cred = dict(cred)
    new_cred["access_token"] = parsed["token"]
    if parsed["refresh_token"]:
        new_cred["refresh_token"] = parsed["refresh_token"]
    if parsed["expired_at"]:
        new_cred["expired_at"] = parsed["expired_at"]

    if not write_back:
        return {"status": "ok", "cred": new_cred}

    saved = credentials.save_refreshed_token(
        cred,
        new_token=parsed["token"],
        new_refresh_token=parsed["refresh_token"] or refresh_token_val,
        expired_at=parsed["expired_at"],
    )
    if saved["status"] != "ok":
        return {
            "status": "failed",
            "reason": "刷新成功但写回 storage.json 失败：" + saved.get("reason", ""),
        }
    result = {"status": "ok", "cred": new_cred, "backup": saved.get("backup", "")}
    if saved.get("warning"):
        result["warning"] = saved["warning"]
    return result


def should_refresh(cred: dict) -> bool:
    """按 expiredAt 判断是否应提前刷新（过期或临近过期）。"""
    return credentials.is_token_expired(cred, clock_skew_seconds=REFRESH_GRACE_SECONDS)


if __name__ == "__main__":
    import json

    result = refresh_token()
    # 输出脱敏结果：不打印新 token / refreshToken
    safe = {
        "status": result.get("status"),
        "reason": result.get("reason", ""),
        "backup": result.get("backup", ""),
        "warning": result.get("warning", ""),
    }
    print(json.dumps(safe, ensure_ascii=False))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
http_client.py — TRAE 自动签到领积分 · 统一 HTTP 客户端（带鉴权 + 重试）

职责：
  - 统一封装带鉴权的 JSON 请求：Authorization: Cloud-IDE-JWT <token>
    + 设备头 x-device-id / x-device-brand / x-device-type（逆向自 main.js）
  - 重试机制：传输层失败与可重试 HTTP 状态（429/5xx）按指数退避重试
    （重试次数与退避基数由 config 控制，可用环境变量覆盖）
  - 401 不重试：令牌失效时重试无意义，交由上层触发 token 刷新

设计：
  - 基于标准库 urllib，无第三方依赖
  - 返回 (http_status, parsed_json)；传输层失败经重试后仍失败时抛 HttpTransportError
  - HTTP 错误状态（4xx/5xx）不抛异常，仍尝试解析响应体后原样返回状态码与解析结果，
    由调用方按业务码（401 / code=10001 等）判断
  - 响应体非 JSON 时返回 {"__non_json__": true} 标记，不保留原始报文（避免夹带敏感信息）

安全：
  - token 仅作为请求头在内存中传递，绝不打印、不写日志、不落盘
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

import config  # noqa: E402

DEFAULT_UA = "Trae/1.0 (checkin-helper)"


class HttpTransportError(RuntimeError):
    """网络传输层失败（未收到 HTTP 响应：DNS/连接/超时/重置等）。"""


def _parse_json(raw: str) -> dict:
    try:
        return json.loads(raw)
    except Exception:
        return {"__non_json__": True}


def _build_headers(
    token: str | None,
    device_id: str,
    extra: dict | None,
    use_auth_header: bool,
) -> dict:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_UA,
    }
    if token and use_auth_header:
        headers["Authorization"] = "{} {}".format(config.HEADER_AUTH_PREFIX, token)
    if device_id:
        headers["x-device-id"] = device_id
    brand = config.device_brand()
    if brand:
        headers["x-device-brand"] = brand
    dtype = config.device_type()
    if dtype:
        headers["x-device-type"] = dtype
    if extra:
        headers.update(extra)
    return headers


def _single_request(
    method: str,
    url: str,
    body: dict | None,
    headers: dict,
    timeout: int,
) -> tuple[int, dict]:
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, _parse_json(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", "replace")
            return e.code, _parse_json(raw)
        except Exception:
            return e.code, {}
    except Exception as e:
        raise HttpTransportError(str(e))


def request_json(
    method: str,
    url: str,
    body: dict | None = None,
    token: str | None = None,
    device_id: str = "",
    extra_headers: dict | None = None,
    use_auth_header: bool = True,
    timeout: int | None = None,
    max_retries: int | None = None,
) -> tuple[int, dict]:
    """
    发起一次带重试的 JSON 请求。
    返回 (http_status, parsed_json)。
    传输层失败且重试耗尽时抛 HttpTransportError。
    """
    timeout = timeout or config.http_timeout()
    max_retries = max_retries if max_retries is not None else config.http_max_retries()
    headers = _build_headers(token, device_id, extra_headers, use_auth_header)

    attempt = 0
    while True:
        try:
            status, parsed = _single_request(method, url, body, headers, timeout)
        except HttpTransportError:
            if attempt < max_retries:
                attempt += 1
                time.sleep(_backoff(attempt))
                continue
            raise
        # HTTP 错误中仅 429/5xx 值得重试；4xx（含 401）业务含义明确，直接返回
        if status in config.HTTP_RETRYABLE_CODES and attempt < max_retries:
            attempt += 1
            time.sleep(_backoff(attempt))
            continue
        return status, parsed


def _backoff(attempt: int) -> float:
    """指数退避 + 随机抖动（1.5^attempt 秒 ±30%）。"""
    base = config.HTTP_BACKOFF_BASE ** attempt
    jitter = random.uniform(0.7, 1.3)
    return base * jitter


def post_json(
    url: str,
    body: dict | None = None,
    use_auth_header: bool = True,
    **kwargs,
) -> tuple[int, dict]:
    return request_json("POST", url, body=body, use_auth_header=use_auth_header, **kwargs)


def get_json(url: str, **kwargs) -> tuple[int, dict]:
    return request_json("GET", url, body=None, **kwargs)

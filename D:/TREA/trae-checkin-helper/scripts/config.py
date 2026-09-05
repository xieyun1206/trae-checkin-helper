#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.py — TRAE 自动签到领积分 · 集中配置

职责：
  - 探测 storage.json（TRAE 登录态库）候选路径（多平台 / 多应用目录名变体）
  - API 端点与鉴权头模板（来自 main.js 逆向，详见 ../references/endpoints.md）
  - 重试参数（次数 / 退避基数 / 超时）
  - 定时调度参数（每日执行时刻 / 抖动窗口）
  - 设备信息（x-device-brand / x-device-type 默认值，device id 由 credentials 提取）

所有值均可通过环境变量 TRAE_CHECKIN_* 覆盖，便于无代码定制。
"""

from __future__ import annotations

import os
import socket
import sys

# ---------------------------------------------------------------------------
# 应用目录名候选（VS Code 系配置布局：<base>/<AppName>/User/globalStorage/）
# ---------------------------------------------------------------------------
APP_NAMES = (
    "TRAE SOLO CN",   # 国内版 SOLO（实测本机）
    "Trae CN",        # 国内版旧目录名
    "Trae",           # 国际版
    "TraePro",        # 国际版旧目录名
)

# storage.json 中登录态条目的 key 前缀
AUTH_KEY_PREFIX = "iCubeAuthInfo://"

# 主登录态 key（token / refreshToken / host / userId / expiredAt ...）
AUTH_KEY_MAIN = AUTH_KEY_PREFIX + "icube.cloudide"

# 设备密钥 key 前缀：iCubeAuthInfo://icube-dc:<deviceId>
DEVICE_KEY_PREFIX = AUTH_KEY_PREFIX + "icube-dc:"

# 用户标签 key（userId -> region）
USERTAG_KEY = AUTH_KEY_PREFIX + "usertag"


def _home() -> str:
    return os.path.expanduser("~")


def _appdata() -> str:
    return os.environ.get("APPDATA", "")


def _xdg_config() -> str:
    return os.environ.get("XDG_CONFIG_HOME", os.path.join(_home(), ".config"))


def storage_candidates() -> list[str]:
    """storage.json 候选路径（按平台 × 应用目录名），按命中概率排序。"""
    rels = []
    for name in APP_NAMES:
        rels.append(os.path.join(name, "User", "globalStorage", "storage.json"))
    if sys.platform == "darwin":
        base = os.path.join(_home(), "Library", "Application Support")
    elif sys.platform == "win32":
        base = _appdata()
    else:
        base = _xdg_config()
    return [os.path.join(base, rel) for rel in rels]


def storage_override() -> str:
    """环境变量 TRAE_CHECKIN_STORAGE 可显式指定 storage.json 路径。"""
    return os.environ.get("TRAE_CHECKIN_STORAGE", "").strip()


# ---------------------------------------------------------------------------
# API 端点（逆向自 main.js，详见 references/endpoints.md）
# ---------------------------------------------------------------------------
# 登录态中的 host 字段（如 https://api.trae.cn）作为 API 基址；
# 未命中时回退到该默认值。
DEFAULT_API_HOST = "https://api.trae.cn"

# 签到状态查询 / 执行签到（POST，body 固定 {}）
CHECKIN_STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CHECKIN_CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"

# 刷新 token（POST，ExchangeToken，需要 ECDSA 签名 DeviceProof）
EXCHANGE_TOKEN_PATH = "/trae/api/v3/oauth/ExchangeToken"

# 客户端标识（main.js Bb()：SOLO 产品默认 en1oxy7wnw8j9n，TRAE 默认 ono9krqynydwx5）
CLIENT_ID_SOLO = "en1oxy7wnw8j9n"
CLIENT_ID_TRAE = "ono9krqynydwx5"
DEFAULT_CLIENT_ID = CLIENT_ID_SOLO

# IDE 版本（ExchangeToken 请求体 IDEVersion 字段；本机 TRAE SOLO CN 1.107.1）
DEFAULT_IDE_VERSION = "1.107.1"

# 请求头模板（Cloud-IDE-JWT 认证 + 设备三件套）
HEADER_AUTH_PREFIX = "Cloud-IDE-JWT"


def api_host() -> str:
    return os.environ.get("TRAE_CHECKIN_HOST", "").strip() or DEFAULT_API_HOST


def client_id() -> str:
    return os.environ.get("TRAE_CHECKIN_CLIENT_ID", "").strip() or DEFAULT_CLIENT_ID


def is_solo_product() -> bool:
    """是否 SOLO 产品线（影响 PlatformCode 与 ClientID 默认值）。

    main.js k()：SOLO 产品 PlatformCode="SOLO_PC"，否则 "IDE_PC"。
    本 Skill 面向 TRAE SOLO CN，默认 True；可用环境变量覆盖。
    """
    val = os.environ.get("TRAE_CHECKIN_SOLO", "").strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return True


def ide_version() -> str:
    """IDEVersion 字段；未配置时用本机 TRAE SOLO CN 已知版本（1.107.1）。

    ExchangeToken 请求体要求该字段，服务端会校验格式；版本不匹配一般不影响，
    可通过环境变量 TRAE_CHECKIN_IDE_VERSION 指定当前安装版本。
    """
    return os.environ.get(
        "TRAE_CHECKIN_IDE_VERSION", ""
    ).strip() or DEFAULT_IDE_VERSION


def machine_id() -> str:
    """DeviceInfo.MachineID；未配置时回退到设备 id（由 credentials 填充）。"""
    return os.environ.get("TRAE_CHECKIN_MACHINE_ID", "").strip()


def device_name() -> str:
    return os.environ.get("TRAE_CHECKIN_DEVICE_NAME", "").strip() or socket.gethostname()


# ---------------------------------------------------------------------------
# HTTP 客户端（重试机制）
# ---------------------------------------------------------------------------
HTTP_TIMEOUT = 15            # 单次请求超时（秒）
HTTP_MAX_RETRIES = 3         # 传输层失败 / 5xx 的重试次数（不含首次）
HTTP_BACKOFF_BASE = 1.5      # 指数退避基数（秒）：1.5^attempt
HTTP_RETRYABLE_CODES = (429, 500, 502, 503, 504)


def http_timeout() -> int:
    return int(os.environ.get("TRAE_CHECKIN_TIMEOUT", "").strip() or HTTP_TIMEOUT)


def http_max_retries() -> int:
    return int(os.environ.get("TRAE_CHECKIN_MAX_RETRIES", "").strip() or HTTP_MAX_RETRIES)


# ---------------------------------------------------------------------------
# 定时调度
# ---------------------------------------------------------------------------
DEFAULT_SCHEDULE = "10:00"   # 每日执行时刻（24h），失败/抖动窗口见 scheduler.py
SCHEDULE_JITTER_SECONDS = 300  # 允许的执行抖动窗口（分钟级调度时 ±5 分钟）


def schedule_time() -> str:
    return os.environ.get("TRAE_CHECKIN_SCHEDULE", "").strip() or DEFAULT_SCHEDULE


# ---------------------------------------------------------------------------
# 设备信息（签到请求头）
# ---------------------------------------------------------------------------
# x-device-brand / x-device-type 由 TRAE 的 commonParams 提供；CLI 环境下未知，
# 提供可覆盖的默认值（仅作请求头字段，服务端以 device id 为准）。
DEFAULT_DEVICE_BRAND = ""
DEFAULT_DEVICE_TYPE = ""


def device_brand() -> str:
    return os.environ.get("TRAE_CHECKIN_DEVICE_BRAND", "").strip() or DEFAULT_DEVICE_BRAND


def device_type() -> str:
    return os.environ.get("TRAE_CHECKIN_DEVICE_TYPE", "").strip() or DEFAULT_DEVICE_TYPE


# ---------------------------------------------------------------------------
# 路径与日志
# ---------------------------------------------------------------------------
def skill_root() -> str:
    """本 Skill 根目录（scripts/ 的上一级）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def logs_dir() -> str:
    return os.environ.get(
        "TRAE_CHECKIN_LOG_DIR", ""
    ).strip() or os.path.join(skill_root(), "logs")


def results_log_path() -> str:
    return os.path.join(logs_dir(), "results.jsonl")


def history_dir() -> str:
    return os.path.join(logs_dir(), "history")

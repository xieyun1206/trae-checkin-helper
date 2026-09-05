#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
credentials.py — TRAE 自动签到领积分 · 登录态读取 / 解密 / 刷新写回

数据来源：TRAE 桌面端 `User/globalStorage/storage.json`（VS Code 系全局存储）。
登录态条目以 TRAE byteCrypto 加密（见 crypto.py），本模块负责：

  - 探测 storage.json（config.storage_candidates()，多平台 × 多应用目录名）
  - 解密 `iCubeAuthInfo://icube.cloudide` → access_token / refresh_token / host / userId / expiredAt
  - 从 `iCubeAuthInfo://icube-dc:<deviceId>` 提取 device_id，并解密设备 ECDSA 密钥
    （privateKeyPEM / publicKeyPEM，token 刷新签名用）
  - token 过期判断（expiredAt ISO 时间）
  - 刷新成功后写回 storage.json（先备份、后原子写，只替换加密 blob 不动其它条目）

统一返回结构（load_credentials()）：
  {
    "access_token": "...",      # 等同账号密码：仅内存使用，禁止打印/写日志/落盘
    "refresh_token": "...",
    "host": "https://api.trae.cn",
    "user_id": "...",
    "device_id": "...",
    "private_key_pem": "...",   # ECDSA P-256 私钥（PEM）
    "public_key_pem": "...",
    "expired_at": "2026-09-19T02:29:36.769Z",   # 可能为空
    "source": "<storage.json 绝对路径>"
  }

安全规则（继承 workbuddy-reward-helper 的 Phase 1 约定）：
  - access_token / refresh_token / 私钥等同账号密码：仅在内存中使用，
    禁止输出到 stdout / 写日志 / 保存副本 / 提交仓库 / 上传第三方
  - 只读为主：load_credentials() 绝不修改 TRAE 的任何文件
  - 唯一写入口 save_refreshed_token()：先整文件备份，再原子替换单个条目
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
import crypto  # noqa: E402

# storage.json 内（其它命名空间）非登录态条目：读取时原样忽略，写回时原样保留
# （storage.json 只读 JSON 对象，顶层即 key → value 的映射）

_PERM_DENIED: list[str] = []


class CredentialError(RuntimeError):
    """登录态读取 / 写回失败的统一异常（信息中不含任何 token）。"""


def _read_storage(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise CredentialError("无法读取 storage.json：{}".format(e)) from e
    except json.JSONDecodeError as e:
        raise CredentialError("storage.json 解析失败（可能正在写入中）：{}".format(e)) from e
    if not isinstance(data, dict):
        raise CredentialError("storage.json 顶层结构异常（应为 JSON 对象）")
    return data


def _find_storage_path() -> str:
    """探测 storage.json；显式指定（TRAE_CHECKIN_STORAGE）优先。"""
    override = config.storage_override()
    if override:
        if not os.path.isfile(override):
            raise CredentialError("TRAE_CHECKIN_STORAGE 指定的路径不存在：" + override)
        return override
    for path in config.storage_candidates():
        try:
            os.stat(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            _PERM_DENIED.append(path)
            continue
        except OSError:
            continue
        return path
    if _PERM_DENIED:
        raise CredentialError(
            "检测到 storage.json 但被系统拒绝读取（权限受限）："
            + "；".join(_PERM_DENIED)
            + "。请以当前登录用户运行。"
        )
    raise CredentialError(
        "未找到 TRAE 登录态（storage.json）。请先安装并登录 TRAE 桌面端（TRAE SOLO CN / Trae），"
        "或设置环境变量 TRAE_CHECKIN_STORAGE 指向实际的 storage.json。"
    )


def _extract_device_id(data: dict) -> str:
    """从 `iCubeAuthInfo://icube-dc:<deviceId>` 条目提取设备 id。"""
    prefix = config.DEVICE_KEY_PREFIX
    for key in data:
        if key.startswith(prefix):
            return key[len(prefix):]
    return ""


def load_credentials() -> dict:
    """
    读取本地登录态，返回统一结构（见模块 docstring）。
    失败时抛出 CredentialError。
    """
    path = _find_storage_path()
    data = _read_storage(path)

    main = data.get(config.AUTH_KEY_MAIN)
    if not isinstance(main, str) or not main:
        raise CredentialError(
            "storage.json 中缺少登录态条目 {}，请确认已登录 TRAE 桌面端。".format(
                config.AUTH_KEY_MAIN
            )
        )
    try:
        plain = crypto.decrypt_string(main)
    except crypto.CryptoError as e:
        raise CredentialError("登录态解密失败：{}".format(e)) from e
    try:
        info = json.loads(plain)
    except json.JSONDecodeError as e:
        raise CredentialError("登录态明文不是 JSON（解密逻辑可能已随版本变化）".format(e)) from e

    token = info.get("token")
    if not isinstance(token, str) or not token:
        raise CredentialError("登录态缺少 access token 字段")

    device_id = _extract_device_id(data)
    private_key_pem = ""
    public_key_pem = ""
    if device_id:
        dev_entry = data.get(config.DEVICE_KEY_PREFIX + device_id)
        if isinstance(dev_entry, str) and dev_entry:
            try:
                dev_plain = crypto.decrypt_string(dev_entry)
                dev_info = json.loads(dev_plain)
                private_key_pem = dev_info.get("privateKeyPEM", "") or ""
                public_key_pem = dev_info.get("publicKeyPEM", "") or ""
            except (crypto.CryptoError, json.JSONDecodeError):
                # 设备密钥缺失不阻断签到（仅刷新需要），记录为空串即可
                pass

    return {
        "access_token": token,
        "refresh_token": info.get("refreshToken", "") or "",
        "host": info.get("host", "") or config.api_host(),
        "user_id": str(info.get("userId", "") or ""),
        "device_id": device_id,
        "private_key_pem": private_key_pem,
        "public_key_pem": public_key_pem,
        "expired_at": info.get("expiredAt", "") or "",
        "source": path,
    }


def is_token_expired(cred: dict, clock_skew_seconds: int = 300) -> bool:
    """按 expiredAt 判断 token 是否临近/已经过期；无过期时间时保守视为未过期。
    clock_skew_seconds 为提前量（秒），避免边界竞态。"""
    raw = cred.get("expired_at") or ""
    if not raw:
        return False
    try:
        # 兼容 '2026-09-19T02:29:36.769Z' 与带毫秒/不带毫秒两种格式
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in raw else "%Y-%m-%dT%H:%M:%SZ"
        expired = time.mktime(time.strptime(raw, fmt)) + clock_skew_seconds
    except (ValueError, TypeError):
        return False
    return time.time() >= expired


# ---------------------------------------------------------------------------
# 刷新写回（唯一写入口）
# ---------------------------------------------------------------------------
def save_refreshed_token(
    cred: dict,
    new_token: str,
    new_refresh_token: str,
    expired_at: str = "",
    refresh_expired_at: str = "",
) -> dict:
    """
    把刷新得到的新 token 加密写回 storage.json。

    安全设计：
      1. 先把整个 storage.json 备份为 storage.json.<ts>.bak（同目录）
      2. 只更新 `iCubeAuthInfo://icube.cloudide` 一个条目，其余条目原样保留
      3. 临时文件 + os.replace 原子写，避免写一半损坏
      4. 失败时不动原文件

    返回 {"status": "ok", "backup": <备份路径>} 或 {"status": "failed", "reason": ...}。
    TRAE 正在运行时，其内存中的登录态副本可能在退出时覆盖写回结果——返回警告字段
    （不影响本次会话内使用新 token）。
    """
    path = cred.get("source") or _find_storage_path()
    try:
        data = _read_storage(path)
    except CredentialError as e:
        return {"status": "failed", "reason": "读取 storage.json 失败：" + str(e)}

    main = data.get(config.AUTH_KEY_MAIN)
    if not isinstance(main, str) or not main:
        return {"status": "failed", "reason": "storage.json 中缺少登录态条目，无法写回"}

    # 在原明文基础上仅更新 token 相关字段，其余（userId/host/account/...）保持原值
    try:
        plain = crypto.decrypt_string(main)
        info = json.loads(plain)
    except (crypto.CryptoError, json.JSONDecodeError) as e:
        return {"status": "failed", "reason": "解密现有登录态失败：" + str(e)}

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    info["token"] = new_token
    info["refreshToken"] = new_refresh_token
    if expired_at:
        info["expiredAt"] = expired_at
    if refresh_expired_at:
        info["refreshExpiredAt"] = refresh_expired_at
    info["tokenReleaseAt"] = now_iso

    try:
        new_blob = crypto.encrypt_string(json.dumps(info, ensure_ascii=False).encode("utf-8"))
    except crypto.CryptoError as e:
        return {"status": "failed", "reason": "加密新登录态失败：" + str(e)}

    # 备份
    backup = ""
    try:
        ts = time.strftime("%Y%m%d%H%M%S")
        backup = path + ".{}.bak".format(ts)
        shutil.copy2(path, backup)
    except OSError as e:
        return {"status": "failed", "reason": "备份 storage.json 失败：" + str(e)}

    # 原子写：只替换目标条目
    data[config.AUTH_KEY_MAIN] = new_blob
    try:
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(path), prefix=".storage.", suffix=".tmp"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return {"status": "failed", "reason": "写回 storage.json 失败：" + str(e)}

    warning = ""
    if _trae_process_running():
        warning = (
            "检测到 TRAE 桌面端正在运行，其退出时可能用内存中的旧登录态覆盖本次写回；"
            "建议关闭 TRAE 后重跑刷新，或在 TRAE 内保持登录（其自身也会自动续期）。"
        )
    result = {"status": "ok", "backup": backup}
    if warning:
        result["warning"] = warning
    return result


def _trae_process_running() -> bool:
    """粗略探测 TRAE 桌面端进程是否在运行（仅用于写回警告，失败静默）。"""
    try:
        if sys.platform == "win32":
            import subprocess

            out = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10,
            ).stdout.lower()
            return any(n in out for n in ("trae", "trae solo"))
        if sys.platform == "darwin":
            import subprocess

            out = subprocess.run(
                ["pgrep", "-x", "Trae"], capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            return bool(out)
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 脱敏工具（安全打印 / 日志）
# ---------------------------------------------------------------------------
def mask_secret(secret: str) -> str:
    if not secret:
        return "<空>"
    return "<已读取（不展示）, 长度 {}>".format(len(secret))


def mask_uid(uid: str) -> str:
    if not uid:
        return "<空>"
    if len(uid) <= 6:
        return "*" * len(uid)
    return uid[:2] + "*" * (len(uid) - 4) + uid[-2:]


def describe(cred: dict) -> dict:
    """把 load_credentials() 结果转成可安全打印的脱敏描述（不含真实 token / 私钥）。"""
    return {
        "source": cred.get("source", ""),
        "access_token": mask_secret(cred.get("access_token", "")),
        "refresh_token": mask_secret(cred.get("refresh_token", "")),
        "device_id": mask_uid(cred.get("device_id", "")),
        "user_id": mask_uid(cred.get("user_id", "")),
        "host": cred.get("host", ""),
        "expired_at": cred.get("expired_at", ""),
        "has_ecdsa_key": bool(cred.get("private_key_pem")),
    }


if __name__ == "__main__":
    # 直接运行时仅打印脱敏结果，绝不打印真实 token / 私钥。
    try:
        c = load_credentials()
    except CredentialError as e:
        print("[失败] 读取登录态失败：{}".format(e))
        sys.exit(1)
    d = describe(c)
    print("[成功] 登录态来源：{}".format(d["source"]))
    print("[成功] access_token：{}".format(d["access_token"]))
    print("[成功] refresh_token：{}".format(d["refresh_token"]))
    print("[成功] device_id：{}".format(d["device_id"]))
    print("[成功] user_id：{}".format(d["user_id"]))
    print("[成功] host：{}".format(d["host"]))
    print("[成功] expired_at：{}".format(d["expired_at"]))
    print("[信息] 是否含 ECDSA 刷新密钥：{}".format("是" if d["has_ecdsa_key"] else "否"))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logger.py — TRAE 自动签到领积分 · 执行结果记录

记录每次执行的摘要到 logs/results.jsonl（一行一个 JSON），并支持按天历史文件。

安全约定（必须遵守）：
  - 只记录任务 / 状态 / 关键数字（credit 等）/ 脱敏原因
  - 绝不记录 access_token / refresh_token / 私钥 / 响应原文
  - 失败原因仅保留业务信息（HTTP 状态码 / 业务 code / 网络异常类别），
    网络异常 str(e) 可能包含 URL（无 token）但不会包含鉴权头，可安全记录
"""

from __future__ import annotations

import json
import os
import time

import config  # noqa: E402

_MAX_REASON_LEN = 200


def _now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _safe_reason(reason: str) -> str:
    """截断并清洗失败原因，避免夹带敏感内容。"""
    if not reason:
        return ""
    return str(reason)[:_MAX_REASON_LEN]


def log_result(task: str, result: dict, mode: str = "once") -> str | None:
    """
    追加一条执行结果到 logs/results.jsonl。
    返回写入的文件路径；失败返回 None（不影响主流程）。
    """
    record = {
        "ts": _now_text(),
        "task": task,
        "status": result.get("status", "unknown"),
        "mode": mode,
    }
    for key in ("credit", "streak_days"):
        if result.get(key) is not None:
            record[key] = result[key]
    if result.get("message"):
        record["message"] = str(result["message"])[:_MAX_REASON_LEN]
    if result.get("reason"):
        record["reason"] = _safe_reason(result["reason"])
    # skipped / warning 类补充信息
    if result.get("warning"):
        record["warning"] = str(result["warning"])[:_MAX_REASON_LEN]

    try:
        os.makedirs(config.logs_dir(), exist_ok=True)
        path = config.results_log_path()
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return path
    except OSError:
        return None


def read_history(n: int = 10) -> list[dict]:
    """读取最近 n 条结果记录（倒序）。"""
    path = config.results_log_path()
    records: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return records[-n:][::-1]


def last_status() -> dict | None:
    """最近一条执行记录（供调度器幂等判断：同一自然日不重复执行）。"""
    records = read_history(1)
    return records[0] if records else None

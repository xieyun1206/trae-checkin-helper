#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py — TRAE 自动签到领积分 · 统一入口

子命令：
  checkin   执行每日签到（推荐日常用法；token 过期时自动刷新并重试一次）
  refresh   仅刷新 token 并写回 storage.json（登录态保持）
  status    只读查询签到状态（不执行任何签到/领取动作）
  schedule  定时守护：每天 HH:MM 自动签到（默认 10:00，--schedule 或
            TRAE_CHECKIN_SCHEDULE 可覆盖；同一自然日防重复）
  history   查看最近执行记录（--history N，默认 10 条）
  help      用法说明

通用参数：
  --json      强制 JSON 输出（checkin/status/history 默认即 JSON）
  --schedule  HH:MM 覆盖调度时刻（仅 schedule 子命令）
  --history   N 指定查看条数（仅 history 子命令）

环境变量（详见 scripts/config.py）：
  TRAE_CHECKIN_STORAGE / TRAE_CHECKIN_HOST / TRAE_CHECKIN_SCHEDULE /
  TRAE_CHECKIN_MAX_RETRIES / TRAE_CHECKIN_TIMEOUT / TRAE_CHECKIN_DEVICE_BRAND ...

设计原则（与 workbuddy-reward-helper 一致）：
  - 本入口不自行创建系统级定时任务；schedule 为前台常驻进程（Ctrl+C 停止），
    需要后台常驻可配合系统计划任务 / supervisor 运行 `main.py schedule`
  - token 仅内存使用：不打印、不写日志、不落盘；唯一落盘为 refresh 写回的
    加密 storage.json（先备份、后原子写）
  - 每次执行结果记录到 logs/results.jsonl（仅摘要，绝无敏感信息）
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import checkin  # noqa: E402
import config  # noqa: E402
import credentials  # noqa: E402
import logger  # noqa: E402
import scheduler  # noqa: E402
import token_refresh  # noqa: E402

COMMANDS = ("checkin", "refresh", "status", "schedule", "history", "help")

USAGE = """TRAE 自动签到领积分 · 统一入口
用法：python3 main.py [checkin|refresh|status|schedule|history|help] [--schedule HH:MM]
  checkin   执行每日签到（默认；token 过期自动刷新重试）
  refresh   仅刷新 token（登录态保持）
  status    只读查询签到状态
  schedule  定时守护：每天定时自动签到（默认 10:00）
  history   查看最近执行记录
  help      用法说明"""


def _refresh_on_expired() -> dict | None:
    """401 时的刷新回调：成功返回新登录态，失败/不支持返回 None。"""
    result = token_refresh.refresh_token()
    if result.get("status") == "ok":
        return result.get("cred")
    return None


def cmd_checkin(mode: str = "once") -> dict:
    result = checkin.run_checkin(on_token_expired=_refresh_on_expired)
    logger.log_result("checkin", result, mode)
    return result


def cmd_refresh() -> dict:
    result = token_refresh.refresh_token()
    return {
        "task": "refresh",
        "status": result.get("status"),
        "reason": result.get("reason", ""),
        "backup": result.get("backup", ""),
        "warning": result.get("warning", ""),
    }


def cmd_status() -> dict:
    result = checkin.query_status()
    logger.log_result("checkin_status", result, "once")
    return result


def cmd_schedule(schedule_time: str | None) -> None:
    print("[调度] 启动：每天 {} 自动签到（Ctrl+C 停止）".format(
        schedule_time or config.schedule_time()
    ))

    def job() -> None:
        result = cmd_checkin(mode="scheduled")
        print(json.dumps(result, ensure_ascii=False))

    scheduler.run_daily(job, schedule=schedule_time)


def cmd_history(n: int = 10) -> dict:
    records = logger.read_history(n)
    return {"task": "history", "status": "ok", "count": len(records), "records": records}


def _emit(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trae-checkin", description="TRAE 自动签到领积分", add_help=False
    )
    parser.add_argument("command", nargs="?", default="checkin")
    parser.add_argument("--schedule", default=None, help="定时时刻 HH:MM（schedule 子命令）")
    parser.add_argument("--history", type=int, default=10, help="查看最近 N 条记录")
    parser.add_argument("--json", action="store_true", help="强制 JSON 输出")
    args, _ = parser.parse_known_args(argv)

    command = args.command if args.command in COMMANDS else "help"

    if command == "help":
        print(USAGE)
        return 0
    if command == "checkin":
        _emit(cmd_checkin(mode="once"))
        return 0
    if command == "refresh":
        _emit(cmd_refresh())
        return 0
    if command == "status":
        _emit(cmd_status())
        return 0
    if command == "schedule":
        try:
            cmd_schedule(args.schedule)
        except scheduler.ScheduleFormatError as e:
            print("[错误] {}".format(e))
            return 2
        return 0
    if command == "history":
        _emit(cmd_history(max(1, args.history)))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

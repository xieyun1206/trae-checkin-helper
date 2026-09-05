#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scheduler.py — TRAE 自动签到领积分 · 可配置定时执行

支持以守护进程方式每天在指定时刻（HH:MM，默认 10:00，可用 TRAE_CHECKIN_SCHEDULE
或 --schedule 覆盖）执行签到回调：

  - 抖动窗口：进程在计划时刻 ± 窗口（默认 5 分钟）内启动/唤醒时立即补执行，
    避免「差几秒错过」导致当天漏签；窗口之外启动则等到下一个计划时刻
  - 防重复：以 logs/.last_scheduled_day 记录最近一次**调度**执行的自然日，
    同一自然日不重复触发（手动执行互不影响；签到接口本身也幂等）
  - 常驻循环：执行完自动进入下一天等待，可被 Ctrl+C 安全中断

纯标准库实现；时间计算均用本地时区。
"""

from __future__ import annotations

import os
import sys
import time

import config  # noqa: E402

_LAST_DAY_FILE = ".last_scheduled_day"
_SLEEP_STEP = 5  # 长等待按 5 秒步进，便于响应中断


class ScheduleFormatError(ValueError):
    """HH:MM 格式错误。"""


def parse_time(text: str) -> tuple[int, int]:
    """解析 'HH:MM'（24h），返回 (hour, minute)。"""
    try:
        hour_s, minute_s = text.strip().split(":")
        hour = int(hour_s)
        minute = int(minute_s)
    except (ValueError, AttributeError) as e:
        raise ScheduleFormatError(
            "调度时刻格式错误（应为 HH:MM，如 10:00）：{!r}".format(text)
        ) from e
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ScheduleFormatError("调度时刻超出范围：{!r}".format(text))
    return hour, minute


def _target_time(hour: int, minute: int, offset_days: int = 0) -> float:
    """本地时区下，距今天 offset_days 天的 HH:MM 对应时间戳。"""
    t = time.localtime()
    base = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, hour, minute, 0, 0, 0, -1))
    return base + offset_days * 86400


def next_run_delay(
    schedule: str | None = None,
    jitter_seconds: int | None = None,
    now: float | None = None,
) -> float:
    """
    计算距下一次可执行时刻的等待秒数。
      - 当前时间已过今日 HH:MM 但在抖动窗口内 → 0（立即补执行）
      - 已超过抖动窗口 → 等待到明日 HH:MM
    """
    schedule = schedule or config.schedule_time()
    jitter = jitter_seconds if jitter_seconds is not None else config.SCHEDULE_JITTER_SECONDS
    hour, minute = parse_time(schedule)
    now = time.time() if now is None else now
    target = _target_time(hour, minute, 0)
    if now <= target + jitter:
        return max(target - now, 0.0)
    target = _target_time(hour, minute, 1)
    return target - now


def _day_stamp(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts) if ts else None)


def _mark_ran_today() -> None:
    try:
        os.makedirs(config.logs_dir(), exist_ok=True)
        path = os.path.join(config.logs_dir(), _LAST_DAY_FILE)
        with open(path, "w", encoding="utf-8") as f:
            f.write(_day_stamp() + "\n")
    except OSError:
        pass


def already_ran_today() -> bool:
    """当日是否已由调度执行过（标记文件不存在视为否）。"""
    path = os.path.join(config.logs_dir(), _LAST_DAY_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() == _day_stamp()
    except OSError:
        return False


def _sleep_until(ts: float) -> None:
    """分步睡眠至时间戳（每步 5 秒，便于响应 Ctrl+C）。"""
    while True:
        remain = ts - time.time()
        if remain <= 0:
            return
        time.sleep(min(remain, _SLEEP_STEP))


def run_daily(
    callback,
    schedule: str | None = None,
    jitter_seconds: int | None = None,
) -> None:
    """
    常驻守护：每天在指定时刻执行一次 callback()（同一自然日防重复）。
    若进程在抖动窗口内启动且当日未执行，先立即补执行一次，再进入常规循环。
    """
    schedule = schedule or config.schedule_time()
    jitter = jitter_seconds if jitter_seconds is not None else config.SCHEDULE_JITTER_SECONDS
    parse_time(schedule)  # 提前校验格式

    # 抖动窗口内启动且当日未执行 → 立即补执行
    if not already_ran_today() and next_run_delay(schedule, jitter) <= 0:
        _invoke(callback)

    while True:
        try:
            _sleep_until(time.time() + next_run_delay(schedule, jitter))
        except KeyboardInterrupt:
            print("\n[调度] 已停止。")
            return
        if already_ran_today():
            continue
        _invoke(callback)


def _next_ts(schedule: str) -> float:
    """下一个计划时刻（窗口内已过则明日）的时间戳。"""
    return time.time() + next_run_delay(schedule)


def _invoke(callback) -> None:
    """执行回调并记录当日标记（回调异常不中断守护进程）。"""
    try:
        callback()
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print("[调度] 回调执行异常：{}".format(e))
    finally:
        _mark_ran_today()


if __name__ == "__main__":
    # 直接运行时打印下一个执行时刻（供预览/排错）
    try:
        delay = next_run_delay()
    except ScheduleFormatError as e:
        print("[错误] {}".format(e))
        sys.exit(1)
    nxt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + delay))
    print("[调度] 计划时刻：{}（下次执行：{}）".format(config.schedule_time(), nxt))

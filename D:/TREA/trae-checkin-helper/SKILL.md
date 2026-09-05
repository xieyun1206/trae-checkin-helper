***

name: trae-checkin-helper
version: "1.0.0"
display\_name: TRAE自动签到领积分
display\_name\_en: TRAE Checkin Helper
description: TRAE 平台自动签到领积分：一条命令完成账号登录态读取、每日签到、积分领取。自动解密本地登录态（byteCrypto），带签到状态校验与防重复签到（已签到自动跳过）、token 过期自动刷新（ECDSA 签名续期，登录态保持）、网络异常/5xx 指数退避重试、每次结果 JSONL 记录，支持可配置定时执行（默认每日 10:00，防重复）。全程本机运行、无后端，token 不落盘不上传第三方。触发词：TRAE 签到、TRAE 积分、签到领积分、checkin、积分助手、自动签到。
description\_zh: TRAE自动签到领积分助手，帮你每天自动完成 TRAE 平台的签到任务并领取积分，重复操作交给 AI 自动完成。
description\_en: TRAE Checkin Helper automates daily check-in and credit claiming on the TRAE platform, letting AI handle the repetitive work for you.
license: MIT
------------

# TRAE 自动签到领积分（trae-checkin-helper）

一条命令完成 TRAE 平台的每日签到领积分：

1. **自动登录**——解密本地登录态（`storage.json` 中 `iCubeAuthInfo://icube.cloudide`，TRAE byteCrypto 纯 Python 实现，无需 Electron）。
2. **每日签到**——`checkin_credits/status` 校验 → `checkin_credits/claim` 领取积分；**防重复**：`checked_in=true` 或 `code=10001` 自动跳过。
3. **登录态保持**——token 过期（401 / expiredAt）时用 refreshToken + 设备 ECDSA 私钥签名自动换新并写回（先备份后原子写）。
4. **异常重试**——网络传输失败与 429/5xx 按指数退避重试（默认 3 次）。
5. **结果记录**——每次执行摘要写入 `logs/results.jsonl`（绝不记录 token）。
6. **定时执行**——`main.py schedule` 每天定时自动签到（默认 10:00，`--schedule` / `TRAE_CHECKIN_SCHEDULE` 可配置，同一自然日防重复）。

全流程在本机完成：读取本地登录态 → 调用官方接口。**无后端服务，token 不落盘、不打印、不上传任何第三方。**

## 首次回复

用户首次触发本 Skill 时，用下面这段话开场：

> 你好，我是TRAE自动签到领积分助手。
> 我可以帮你：
>
> 1. 检查 TRAE 签到状态
> 2. 自动完成每日签到并领取积分
> 3. 定时自动执行（每天固定时刻）
>
> 你可以直接说：
> “帮我签到”
> 或者：
> “帮我设置每日自动签到”

## 快速开始

前提：本机已安装并**登录** TRAE 桌面端（TRAE SOLO CN / Trae）+ Python 3.10+（仅标准库，无需 pip 安装）。

```bash
python3 scripts/main.py checkin    # 执行签到（推荐日常用法，token 过期自动刷新重试）
python3 scripts/main.py status     # 只读查询签到状态（不做任何领取）
python3 scripts/main.py refresh    # 仅刷新登录态（token 续期）
python3 scripts/main.py schedule   # 定时守护：每天 10:00 自动签到（Ctrl+C 停止）
python3 scripts/main.py history    # 查看最近执行记录
```

输出示例（checkin）：

```json
{"task": "checkin", "status": "success", "credit": 100, "message": "签到成功，获得 100 积分"}
{"task": "checkin", "status": "already_checked", "message": "今日已签到"}
{"task": "checkin", "status": "skipped", "message": "签到功能未开放（enable=false）"}
{"task": "checkin", "status": "failed", "reason": "签到未成功：code=10002 ..."}
```

## 定时执行

```bash
python3 scripts/main.py schedule                    # 默认每天 10:00
python3 scripts/main.py schedule --schedule 08:30   # 自定义时刻
set TRAE_CHECKIN_SCHEDULE=08:30                     # 或环境变量（Windows）
python3 scripts/main.py schedule
```

- 抖动窗口：进程在计划时刻 ±5 分钟内启动时立即补执行，避免漏签。

- 防重复：同一自然日只执行一次（标记 `logs/.last_scheduled_day`）；签到接口本身幂等。

- 常驻前台：Ctrl+C 停止；需要后台常驻时请配合系统计划任务 / supervisor / 开机自启运行 `main.py schedule`。

## 登录态与安全

- 登录态来源：TRAE 桌面端 `User/globalStorage/storage.json`（自动探测多平台多目录名，也可用 `TRAE_CHECKIN_STORAGE` 指定）。

- token / refreshToken / 设备私钥 **等同账号密码**：仅在内存使用，绝不打印、不写日志、不落盘；唯一落盘为刷新写回的加密 storage.json（先备份、后原子写，仅替换单个条目）。

- 本 Skill 只调用 TRAE 官方接口（`api.trae.cn`），不做任何第三方请求。

- 接口细节（逆向自 TRAE 主进程 main.js）见 `references/endpoints.md`，接口随版本变更时按该文档核对。

## 配置（环境变量）

| 变量                                    | 默认                    | 说明                                                |
| ------------------------------------- | --------------------- | ------------------------------------------------- |
| `TRAE_CHECKIN_STORAGE`                | 自动探测                  | 指定 storage.json 路径                                |
| `TRAE_CHECKIN_HOST`                   | `https://api.trae.cn` | API 基址                                            |
| `TRAE_CHECKIN_SCHEDULE`               | `10:00`               | 定时时刻 HH:MM                                        |
| `TRAE_CHECKIN_MAX_RETRIES`            | `3`                   | 重试次数（传输失败/5xx/429）                                |
| `TRAE_CHECKIN_TIMEOUT`                | `15`                  | 单次请求超时（秒）                                         |
| `TRAE_CHECKIN_CLIENT_ID`              | `en1oxy7wnw8j9n`      | 刷新签名 ClientID                                     |
| `TRAE_CHECKIN_IDE_VERSION`            | `1.107.1`             | ExchangeToken 的 IDEVersion 字段                     |
| `TRAE_CHECKIN_SOLO`                   | `true`                | SOLO 产品线（PlatformCode=`SOLO_PC`；false 时 `IDE_PC`） |
| `TRAE_CHECKIN_PLATFORM_CODE`          | 自动                    | 强制指定 PlatformCode                                 |
| `TRAE_CHECKIN_DEVICE_BRAND` / `_TYPE` | 空                     | 签到请求设备头                                           |

## 目录结构

```
trae-checkin-helper/
├── SKILL.md
├── scripts/
│   ├── main.py            统一入口（checkin/status/refresh/schedule/history）
│   ├── config.py          路径探测 / 端点 / 重试 / 调度 / 设备配置
│   ├── crypto.py          TRAE byteCrypto 加解密（AES-128-CBC + SHA-512 派生）
│   ├── ecdsa.py           纯 Python ECDSA P-256 签名（刷新 DeviceProof）
│   ├── credentials.py     登录态读取 / 解密 / device id 提取 / 刷新写回
│   ├── http_client.py     带鉴权 JSON 请求 + 指数退避重试
│   ├── checkin.py         签到状态机（校验 → 防重复 → claim → 结果）
│   ├── token_refresh.py   refreshToken 换新（ECDSA 签名，登录态保持）
│   ├── logger.py          JSONL 结果记录 + history
│   └── scheduler.py       可配置定时执行（抖动窗口 + 防重复）
├── references/
│   └── endpoints.md       接口逆向参考
├── tests/                 unittest（无网络依赖，mock 验证状态机/幂等/重试）
└── logs/                  results.jsonl / history（运行时生成）
```

## 排错

| 现象         | 处理                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------- |
| 未找到登录态     | 确认已登录 TRAE 桌面端；或用 `TRAE_CHECKIN_STORAGE` 指定 storage.json                                     |
| 401 / 刷新被拒 | 刷新用 `x-cloudide-token` 头（非 Authorization）+ PlatformCode=`SOLO_PC`；仍失败 → refreshToken 失效，重新登录 |
| 签到功能未开放    | `enable=false`，账号/地区不支持该活动（需 CN 账号 + marscode scope）                                         |
| 协议异常       | 接口随版本变更，按 `references/endpoints.md` 核对响应结构并更新解析                                              |
| 写回被覆盖警告    | TRAE 正在运行时写回可能被其退出覆盖，建议关闭 TRAE 后重跑 refresh                                                   |


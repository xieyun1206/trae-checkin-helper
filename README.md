# TRAE Checkin Helper · TRAE 自动签到领积分

一条命令完成 TRAE 平台的每日签到领积分：自动解密本地登录态 → 调用官方签到接口 → 领取积分奖励。token 过期自动续期（登录态保持），支持定时执行、防重复签到与执行结果记录。

> 全程本机运行、无后端服务：token 不落盘、不打印、不上传任何第三方，只调用 TRAE 官方接口（`api.trae.cn`）。

## 功能特性

- **自动登录**：解密 TRAE 桌面端本地登录态（`storage.json` 中 `iCubeAuthInfo://icube.cloudide`，byteCrypto 纯 Python 实现，无需 Electron）
- **每日签到**：`checkin_credits/status` 状态校验 → `checkin_credits/claim` 领取积分；防重复：`checked_in=true` 或 `code=10001` 自动跳过
- **登录态保持**：token 过期（401 / expiredAt）时用 refreshToken + 设备 ECDSA 私钥签名自动续期并写回（先备份后原子写）
- **异常重试**：网络传输失败与 429/5xx 按指数退避重试（默认 3 次）
- **结果记录**：每次执行摘要写入 `logs/results.jsonl`（绝不记录 token）
- **定时执行**：`schedule` 命令每天定时自动签到（默认 10:00，可配置，同一自然日防重复）

## 环境要求

- 本机已安装并**登录** TRAE 桌面端（TRAE SOLO CN / Trae）
- **Python 3.10+ 仅源码方式需要**（仅标准库，无需 pip 安装）；技能包已附带 `bin/trae-checkin-helper.exe`，无 Python 的 Windows 机器也可直接运行
- 账号需为 CN 地区、`account.scope = marscode`（签到活动前提）

## 快速安装

### 方式一：上传 zip（TRAE 内安装）

下载 [trae-checkin-helper.zip](trae-checkin-helper.zip)（或自行打包根目录含 SKILL.md 的 zip）：

1. 打开 TRAE 侧边栏 → **技能** → 技能管理中心
2. 点击右上角 **上传技能**
3. 上传 zip 文件并确认，技能将自动安装并启用

### 方式二：让 AI 从 GitHub 安装

把本仓库地址发给 TRAE/SOLO：

> 帮我把这个 Skill 安装到当前项目：https://github.com/<your-name>/trae-checkin-helper

### 方式三：npx skills CLI（支持版本管理）

```bash
npx skills add <repo-url> --skill trae-checkin-helper --agent 'trae-cn'
```

### 方式四：手动放置

将 `trae-checkin-helper` 文件夹复制到技能目录：

- 全局技能（Windows）：`%userprofile%\.trae-cn\skills\trae-checkin-helper\`
- 项目技能：项目根目录 `.trae\skills\trae-checkin-helper\`

重启 TRAE 后即可在 `/` 命令列表看到该技能。

## 使用方法

运行方式二选一（推荐 exe，无需安装 Python）：

**方式 A · 免 Python 运行（推荐，Windows）**

技能包已附带 `bin/trae-checkin-helper.exe`，本机无需安装 Python：

```bat
bin\trae-checkin-helper.exe checkin    :: 执行签到（推荐日常用法，token 过期自动刷新重试）
bin\trae-checkin-helper.exe status     :: 只读查询签到状态（不做任何领取）
bin\trae-checkin-helper.exe refresh    :: 仅刷新登录态（token 续期）
bin\trae-checkin-helper.exe schedule   :: 定时守护：每天 10:00 自动签到（Ctrl+C 停止）
bin\trae-checkin-helper.exe history    :: 查看最近执行记录
```

**方式 B · 源码运行（需 Python 3.10+）**

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

### 定时执行

```bash
python3 scripts/main.py schedule                    # 默认每天 10:00
python3 scripts/main.py schedule --schedule 08:30   # 自定义时刻
set TRAE_CHECKIN_SCHEDULE=08:30                     # 或环境变量（Windows）
python3 scripts/main.py schedule
```

- 抖动窗口：进程在计划时刻 ±5 分钟内启动时立即补执行，避免漏签
- 防重复：同一自然日只执行一次（标记 `logs/.last_scheduled_day`），签到接口本身幂等
- 后台常驻：配合系统任务计划 / supervisor / 开机自启运行 `main.py schedule`

Windows 任务计划程序示例：

```bat
schtasks /Create /TN "TRAE-Daily-Checkin" /TR "python D:\path\to\trae-checkin-helper\scripts\main.py schedule" /SC DAILY /ST 09:50
```

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `TRAE_CHECKIN_STORAGE` | 自动探测 | 指定 storage.json 路径 |
| `TRAE_CHECKIN_HOST` | `https://api.trae.cn` | API 基址 |
| `TRAE_CHECKIN_SCHEDULE` | `10:00` | 定时时刻 HH:MM |
| `TRAE_CHECKIN_MAX_RETRIES` | `3` | 重试次数（传输失败/5xx/429） |
| `TRAE_CHECKIN_TIMEOUT` | `15` | 单次请求超时（秒） |
| `TRAE_CHECKIN_CLIENT_ID` | `en1oxy7wnw8j9n` | 刷新签名 ClientID |
| `TRAE_CHECKIN_IDE_VERSION` | `1.107.1` | ExchangeToken 的 IDEVersion 字段 |
| `TRAE_CHECKIN_SOLO` | `true` | SOLO 产品线（PlatformCode=`SOLO_PC`；false 时 `IDE_PC`） |
| `TRAE_CHECKIN_PLATFORM_CODE` | 自动 | 强制指定 PlatformCode |
| `TRAE_CHECKIN_DEVICE_BRAND` / `_TYPE` | 空 | 签到请求设备头 |

## 目录结构

```
trae-checkin-helper/
├── SKILL.md                 技能定义（agent 指令）
├── _skillhub_meta.json      SkillHub 元数据（slug/name/version）
├── README.md                本文档
├── LICENSE                  MIT 许可证
├── scripts/
│   ├── main.py              统一入口（checkin/status/refresh/schedule/history）
│   ├── config.py            路径探测 / 端点 / 重试 / 调度 / 设备配置
│   ├── crypto.py            TRAE byteCrypto 加解密（AES-128-CBC + SHA-512 派生）
│   ├── ecdsa.py             纯 Python ECDSA P-256 签名（刷新 DeviceProof）
│   ├── credentials.py       登录态读取 / 解密 / device id 提取 / 刷新写回
│   ├── http_client.py       带鉴权 JSON 请求 + 指数退避重试
│   ├── checkin.py           签到状态机（校验 → 防重复 → claim → 结果）
│   ├── token_refresh.py     refreshToken 换新（ECDSA 签名，登录态保持）
│   ├── logger.py            JSONL 结果记录 + history
│   └── scheduler.py         可配置定时执行（抖动窗口 + 防重复）
├── references/
│   └── endpoints.md         接口逆向参考
└── tests/                   unittest（无网络依赖，mock 验证状态机/幂等/重试）
```

## 安全说明

- access token / refreshToken / 设备私钥**等同账号密码**：仅在内存使用，绝不打印、不写日志、不落盘、不上传任何第三方
- 唯一落盘操作是刷新写回的加密 storage.json——先备份后原子写，且只替换 `icube.cloudide` 单一条目
- 本技能只调用 TRAE 官方接口（`api.trae.cn`），无任何第三方请求
- 本实现仅用于个人自动化；接口与加密方案随客户端版本可能变更，部署前请核对 `references/endpoints.md`

## 测试

```bash
python3 tests/run_tests.py
```

59 项单元测试全部通过（无网络依赖）：覆盖签到状态机、防重复/幂等、token 刷新签名、byteCrypto 加解密、HTTP 重试等。

## 免责声明

本技能仅供学习与个人自动化使用，与 TRAE 官方无任何关联。请遵守 TRAE 平台的服务条款与使用规范；因使用本技能产生的任何后果由使用者自行承担。

## License

[MIT](LICENSE)

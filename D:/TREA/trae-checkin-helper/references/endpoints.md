# TRAE 自动签到领积分 · 接口参考（逆向自 TRAE 桌面端）

> 本文件记录从 TRAE 主进程 `resources/app/out/main.js` 逆向得到的接口与算法细节，
> 供本 Skill 各模块维护与排错。**仅供学习与个人自动化使用。**
> 接口可能随版本变更：若签到/刷新失败且协议异常，请先核对本文件与当前版本差异。

## 1. 登录态存储

- 文件：`<配置目录>/User/globalStorage/storage.json`（VS Code 系全局存储）
  - Windows: `%APPDATA%\<AppName>\User\globalStorage\storage.json`
  - macOS:   `~/Library/Application Support/<AppName>/User/globalStorage/storage.json`
  - Linux:   `~/.config/<AppName>/User/globalStorage/storage.json`
  - AppName 候选：`TRAE SOLO CN`（国内版 SOLO，实测）、`Trae CN`、`Trae`、`TraePro`
  - 可用环境变量 `TRAE_CHECKIN_STORAGE` 显式指定
- 顶层为扁平 JSON 对象（key → 加密值字符串，base64）

| key | 内容 |
| --- | --- |
| `iCubeAuthInfo://icube.cloudide` | 主登录态（加密 blob，见下） |
| `iCubeAuthInfo://icube-dc:<deviceId>` | 设备 ECDSA 密钥对（PEM），key 后缀即设备 id |
| `iCubeAuthInfo://usertag` | `{ "<userId>": "<region>" }`（如 `"1360535524741834": "cn"`） |

### 主登录态明文结构（解密后 JSON）

```json
{
  "token": "<JWT access token>",
  "refreshToken": "<refresh token>",
  "expiredAt": "2026-09-19T02:29:36.769Z",
  "refreshExpiredAt": "...",
  "tokenReleaseAt": "...",
  "userId": "1360535524741834",
  "host": "https://api.trae.cn",
  "userRegion": {"region": "CN", "_aiRegion": "CN"},
  "account": { "...": "..." }
}
```

### 设备密钥明文结构

```json
{
  "privateKeyPEM": "-----BEGIN PRIVATE KEY-----\n...（PKCS#8 ECDSA P-256）",
  "publicKeyPEM":  "-----BEGIN PUBLIC KEY-----\n...（SPKI）"
}
```

## 2. byteCrypto 加密格式（crypto.py 实现）

- blob 头（6B）：`'tc' 0x05 0x10 0x00 0x00`（ASCII `tc` + 版本 5 + 块 16）
- 32B 随机 key32 → 派生：`SHA-512(key32) || (Ioe^Poe)` 再 `SHA-512`，前 16B 为 AES-128 key、次 16B 为 IV
- AES-128-CBC + PKCS#7 填充（WebCrypto 解密后剥离填充）
- 明文 = 64B SHA-512 校验前缀 + 载荷 JSON

## 3. 签到接口

| 接口 | 方法与路径 | Body | 说明 |
| --- | --- | --- | --- |
| 查状态 | `POST {host}/trae/api/v2/ug/checkin_credits/status` | `{}` | 见下 |
| 执行签到 | `POST {host}/trae/api/v2/ug/checkin_credits/claim` | `{}` | 见下 |

- `host` = 登录态 `host` 字段（`https://api.trae.cn`）
- 请求头：
  - `Authorization: Cloud-IDE-JWT <token>`
  - `x-device-id: <deviceId>`
  - `x-device-brand`（可选，device_model）
  - `x-device-type`（可选，os_name）
- 可用前提（客户端校验）：provider 为 CN 且 `account.scope == "marscode"`

### status 响应

```json
{
  "enable": true,        // 签到功能是否开放（必须为 boolean，否则协议异常）
  "checked_in": false,   // 今日是否已签到（可靠字段，客户端用其做协议校验）
  "credits": 100,        // 可领积分（正数时透出）
  "...": "..."
}
```

### claim 响应

```json
{ "code": 0, "...": "..." }
```

- `code == 0`：成功（data 中可能含 `credit` 等字段）
- `code == 10001`：今日已签到（幂等兜底，**不视为失败**）
- 其它非 0：业务错误

## 4. Token 刷新（登录态保持）

| 项 | 值 |
| --- | --- |
| 路径 | `POST {host}/trae/api/v3/oauth/ExchangeToken` |
| ClientID | SOLO 默认 `en1oxy7wnw8j9n`；TRAE 默认 `ono9krqynydwx5`（可配置覆盖） |
| 请求头 | `Content-Type: application/json`、`x-cloudide-token: <旧 access token>`（**不是** Authorization；main.js OAuth 类 `m()`） |
| IDEVersion | TRAE 桌面端版本（如 `1.107.1`） |

### 请求体

```json
{
  "ClientID": "en1oxy7wnw8j9n",
  "ClientSecret": "",
  "RefreshToken": "<refreshToken>",
  "DeviceInfo": {
    "DeviceID": "<deviceId>",
    "MachineID": "<deviceId>",
    "PlatformCode": "SOLO_PC",
    "DeviceType": "PC",
    "DeviceName": "<用户名+随机后缀>",
    "DeviceModel": "",
    "ClientVersion": "1.107.1",
    "DevicePublicKey": "<publicKeyPEM>",
    "DeviceBrand": "",
    "DeviceCPU": "",
    "OSInfo": "",
    "OSVersion": ""
  },
  "DeviceProof": { "Signature": "...", "Timestamp": 1700000000, "Nonce": "<32位hex>" },
  "IDEVersion": "1.107.1"
}
```

> `PlatformCode` 与 main.js `k()` 一致：SOLO 产品线为 `"SOLO_PC"`，其余为 `"IDE_PC"`
> （曾误用 `"windows"`，导致刷新 401）。DeviceInfo 其余字段（Model/Brand/CPU/OSInfo/OSVersion）
> 服务端不强制，CLI 环境可留空串。

### DeviceProof 签名（main.js `MDe`，等价 Node `crypto.sign`）

```
消息 = [
  "POST",
  "/trae/api/v3/oauth/ExchangeToken",
  "<ClientID>",
  "<RefreshToken>",
  "<Timestamp(Unix秒)>",
  "<Nonce(16随机字节hex)>"
].join("\n")

Signature = base64( ECDSA-P256-SHA256( 私钥=privateKeyPEM, 消息 ) )
```

- ECDSA 曲线：P-256（prime256v1）；摘要 SHA-256；DER 编码签名
- 私钥来自 `iCubeAuthInfo://icube-dc:<deviceId>` 的 `privateKeyPEM`
- 已用真实设备密钥与 Node `crypto.sign/verify` 交叉验证：本 Skill 的 ecdsa.py 签名可被
  Node 验证通过（ECDSA 随机 k，两次签名不必逐字节相同，验证通过即可）

### 响应结构（marscode 风格）

```json
{
  "ResponseMetadata": { "...": "..." },
  "Result": {
    "Token": "<新 access token>",
    "RefreshToken": "<新 refresh token>",
    "TokenExpireAt": 1766134304000,
    "TokenExpireDuration": 1209600000,
    "RefreshExpireAt": "..."
  }
}
```

- 成功响应 `Result.Token` 必填；`TokenExpireAt` 为毫秒时间戳
  （main.js `ODe`：早于当前时间戳时用 `now + TokenExpireDuration`）
- 业务错误在 `ResponseMetadata.Error.Code/Message`（HTTP 仍为 200）
- 新 token 加密写回 storage.json（先备份、后原子写，仅替换 `icube.cloudide` 条目）

## 5. 失败码速查

| 现象 | 含义 | 处理 |
| --- | --- | --- |
| HTTP 401 | access token 过期 | 自动刷新后重试一次；刷新也 401 → 重新登录 |
| claim `code=10001` | 今日已签到 | 视为成功（幂等） |
| 刷新 HTTP 401 | refreshToken 失效 / DeviceProof 校验失败 | 检查 PlatformCode 与 x-cloudide-token 头；仍失败 → 重新登录 |
| 刷新响应 `ResponseMetadata.Error` | 业务拒绝（如刷新太频繁） | 按 Code 判断；多为限流，稍后重试 |
| status 缺 enable/checked_in | 协议变更 | 更新本 Skill 的响应解析 |
| 刷新响应缺 Result/Token | 协议变更 | 更新本 Skill 的响应解析 |

# Xiaohe 代码审计报告

审计日期: 2026-10-29 · 范围: 第一方代码（`internal/`, `cmd/`），不含 `vendor/` 与 `patches/`
规模: 91 个 Go 文件，非测试代码 18,316 行，测试 5,565 行

## 结论

代码质量**高**：所有模块职责清晰、注释详尽（含实测约束、设计决策、已知缺陷）、错误处理一致、资源管理到位（defer/context/job object 全覆盖）。安全面总体扎实：环回绑定 + 会话令牌、crash-proof 系统代理备份、kill-on-close job object 防孤儿进程、私钥文件 0600 权限、更新下载走代理。

未发现 P0 级可利用漏洞。以下发现按严重性排列。

---

## P1 — 远程包更新无完整性校验（供应链风险）

`internal/updater/updater.go:310` `ApplyBundle` / `download`

- 从 manifest 的 URL 下载 zip（GUI + core），**无 SHA-256 校验、无签名验证**。只验证 zip 里有 .exe。
- 传输走 HTTP（client 未强制 TLS；`client(0).Get(rawURL)` 允许 `http://`）。
- 下载后 `stageBundle` 解压任意 .exe 到安装目录，随后 batch 脚本 `move` 覆盖原程序并重启。
- 影响：如果 manifest 被篡改（HTTPS 失效、DNS 劫持、发布仓库被攻破），可静默执行任意代码。这是全仓库最危险的信任链缺口。

**建议（按顺序）**:
1. manifest 增加 `sha256` 字段，`ApplyBundle` 下载后校验；失败即删除并报错。
2. 强制 `https://`（拒绝明文 URL）。
3. 签名验证（作者私钥签 manifest 或 bundle，内置公钥）。

---

## P2 — 本地 UI 令牌通过 URL query 传输，可能泄露给代理/日志

`internal/webbridge/bridge.go:211-213` `authorized` 接受 `?t=<token>`；`main.go` 打印 `http://127.0.0.1:<port>/?t=<token>`

- 令牌 32 hex（128 位随机，强度足够），页面加载时通过 query 传给浏览器，随后以 cookie（SameSite=Strict）维持。
- 风险：外部进程读到启动命令行/URL、或系统代理记录 URL 时，令牌可见。环回绑定限制了远程攻击面，`/api/system/open` 等端点只允许 http(s) 前缀。
- 令牌本身只对环回有效，单进程单令牌，无并发会话隔离（`app.Connect()` 有 `ErrAlreadyConnecting` 防重入）。

**建议**：低优先级。可在打印前加 `-print-url` 开关（已存在）默认关；令牌仅经 cookie 传递（首个页面经 cookie 而非 query）。

---

## P3 — 细节问题（不影响当前正确性）

| # | 位置 | 问题 |
|---|------|------|
| 1 | `internal/webbridge/bridge.go:114-120` `randomToken()` | `rand.Read` 失败时回退 `time.Now().UnixNano()`（可预测）。Go 1.24+ 的 `rand.Read` 实际不会失败，回退分支不可达；建议直接按 error panic 或去掉回退。 |
| 2 | `internal/webbridge/bridge.go:207-209` `static()` | 路径穿越防护 `strings.Contains(name, "..")` 只拦 `..`；对嵌入 fs 的 `fs.ReadFile` 而言，`assets` 是 `embed.FS` 子集，越界路径天然返回 NotFound，无实际风险。属防御冗余。 |
| 3 | `internal/app/settings.go` `SaveSettings` | `a.Settings = s` 无锁直接赋值；UI 读 `b.app.Settings`（`bridge.go` GET /api/settings）也无锁。单 goroutine 主流程 + HTTP handler 并发读，理论上竞态。实践中 settings 写入走同一 HTTP handler 串行，风险低。建议加 `sync.RWMutex`。 |
| 4 | `internal/wgtun/wgtun.go` 注释 | 已记录 2 个 KNOWN ISSUES：`routeManager.oldDNS` 复用不重置；物理网卡 on-link 零网关时 host route 无效。均未触发（app 每次连接新建 Manager），但属结构性隐患。 |
| 5 | `internal/wgtun/stacked.go` 注释 | TEMP-VERIFY 标记：inner adapter 的 metric/DNS 未持久化到 state 文件，硬杀后只恢复 endpoint route；outer/inner 共用单状态文件，重入会交错。当前 app 只跑单个 stacked connect，未触发。 |
| 6 | `internal/coremgr/process_backend.go:183-240` `Start` | `workDir` 来自 `os.UserConfigDir()`，`mkdir 0755`；核心日志写入该目录。无敏感数据直接落盘，可接受。 |
| 7 | `internal/sysproxy/pac.go` | `WritePAC` 的 `regexp:` 规则直接拼进 PAC 的 `/.../.test(host)`，未校验正则合法性（无效正则 → PAC 报错 → 该规则失效，fail-open，不会影响其他规则）。建议对 regexp 规则做一次 `regexp.Compile` 预校验。 |
| 8 | `internal/updater/updater.go:236-303` `LicenseStatus` | 远程 license 的 `TrialDays`/`Expiry` 由 manifest 控制，属"远程授权窗口"。fail-open（离线即放行）。这类设计本身可被绕过（改 firstrun 文件、断网），属产品决策而非缺陷。 |

---

## 架构与质量亮点（无需修改）

- **守护一致性**：kill switch 规则名 `AE-*` 前缀 + `Disable` 精确删除；系统代理备份文件 `proxy-backup.json` + 启动时 `RecoverStale`；wgtun 崩溃残留 state 恢复。
- **防泄漏设计**：TunnelDialer 源地址绑定 tunnel 接口，down 时 dial 拒绝（socks.go）；`takeString` FFI 边界用 unsafe.Add 安全转换。
- **私钥处理**：`register.go` 账号 JSON 目录 0700、文件 0600；日志只记指纹/短 key，从不打私钥；`i1gen` 与身份分离。
- **隧道安全**：`probe.go` disposable handshake 不触碰真实路由；data-plane 验证（`verifyDataPlane`）+ 失败回退（`connectDataPlaneFallback`）避免"绿 VPN 死流量"。
- **进程生命周期**：`ensureCoreJob` KILL_ON_JOB_CLOSE 防孤儿 aether.exe；`vpn/psiphon_windows.go` 清理残留 psiphon 孤儿。
- **测试**：5,565 行测试覆盖 failover/sweep/evict/rollback/PAC 等关键路径，测试均无网络依赖（mock server 注入）。

---

## 未覆盖项

- `patches/full/vendor/` 内的 wireguard-go 补丁（1,798 行）未审 —— 属第三方上游代码。
- 无法运行 `go vet`（本地 Go 1.25.10 < go.mod 要求 1.27，GOTOOLCHAIN=local）。
- `vendor/` 第三方依赖未审计（标准做法）。

---

## 建议优先级

1. **P1**: 给 `ApplyBundle` 加 sha256 校验 + 强制 HTTPS（半天工作量）。
2. **P3-3**: 给 `App.Settings` 加锁（1 小时）。
3. **P3-7**: PAC 正则规则预校验（30 分钟）。
4. 其余 P3 为文档化已知问题，按发布节奏处理。
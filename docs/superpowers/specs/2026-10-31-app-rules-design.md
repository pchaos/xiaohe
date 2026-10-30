# 分应用规则（程序级禁网）设计

- 日期：2026-10-31
- 状态：已决议，待实现
- 范围：一期（程序级禁网）；二期（TUN 连接归属）仅留口，不实现

## 背景与目标

用户按应用粒度控制网络访问（白名单/黑名单），约束：

- **无驱动**：不引入任何内核驱动（wintun 之外的第三方驱动、WFP Callout 均排除）
- **白+黑都要**：白名单（指定应用走代理）与黑名单（指定应用禁止联网）同时支持
- 入口挂在现有「分流」页；清单 = 预设 + 用户自定义 + 运行进程选择器

无驱动约束下，Windows 无法把不遵守系统代理的进程的流量强制转入隧道，因此
「白名单走代理」只能落地为**放行**（该应用自走系统代理或直连）或**阻断**（禁网）。
本项目按「阻断」实现；「按进程强制入隧道」为二期（TUN 归属）目标。

## 已决议语义

1. **黑名单 = 完全禁网**。netsh 程序规则按进程匹配、无法区分隧道/直连流量路径，
   黑名单进程的所有出站（含其经系统代理进入隧道的流量）都会被阻断。
   UI 文案按「禁止联网」写，不写「防泄漏」。
2. **白名单双模式**（开关 `AppRulesStrict`，默认关 = 宽松）：
   - 宽松：仅黑名单生效，白名单不产生任何防火墙规则；
   - 严格：白名单名单外**全部禁网**。基线放行：回环、LAN 网段、core exe、
     Xiaohe.exe 自身。svchost 等系统进程**不放行**（保持「名单外全禁」的纯粹
     语义），UI 必须警告严格模式会阻断系统服务联网。
   - **黑名单优先于白名单**：同一程序同时入白和黑时，两条规则都生成，
     依赖 Windows 防火墙「阻止优先于允许」的默认行为。
3. **常驻生效**：应用规则开关打开即应用，断开 VPN 连接后仍生效，重启后
   仍生效（netsh 规则持久化于系统防火墙）；**关闭开关时释放，程序退出不
   释放**——退出即清会让常驻语义在非管理员重启时失效。与 killswitch
   （连接期）生命周期正交，可共存。卸载后的规则残留清理不在本期范围
   （用户关闭开关即可触发清理）。
4. **要求管理员**：`netsh advfirewall` 需要管理员。非管理员会话下清单可编辑
   但不应用，UI 状态显示「未生效：请以管理员身份运行」。
5. **上限**：白名单、黑名单各 ≤ 100 条。超限返回明确错误，不静默截断。
6. 与 killswitch 共存时规则组互相独立（`AetherGUI App Rules` / `AE-App-*`），
   互不干扰。

## 技术选型

- **后端：netsh advfirewall 程序规则**（与 killswitch 同栈）。每条规则一次
  `netsh advfirewall firewall add rule` 子进程调用（约 100–200ms/条）；
  上限 100 条/清单 + 后台应用（严格模式最坏 ~200 条 ≈ 20-40s，状态行以
  「应用中」过渡）。
- **失败回滚**：应用中途失败 → 删除本组已添加的全部规则（killswitch
  `disableLocked` 同款），返回错误。
- **通配符**：`Derive` 之前把含 `*` 的路径在文件系统展开为真实 exe 路径，
  防火墙只收具体路径（确定性、可单测）。无通配路径原样保留；通配展开为空
  的条目丢弃。
- **不造 Backend 抽象接口**：一期直接 `internal/apprules` 包 + 包内导出函数；
  若将来升级 fwpmu（BFE 用户态 API，事务原子、毫秒级），只是包内实现替换，
  包边界即接缝。
- **清理时机**：只在 `enabled=false` 的 `Clear()` 里清理 `AE-App-*`（含崩溃
  残留）。**不做启动时无条件清理**——常驻语义下 netsh 规则持久化，无条件
  清理会让崩溃/重启后的「禁网」失效而用户不知情。

## 数据模型（`internal/config` Settings 新增 4 字段）

| 字段 | 类型 | JSON | 默认 | 说明 |
| --- | --- | --- | --- | --- |
| `AppRulesEnabled` | bool | `app_rules_enabled` | false | 总开关 |
| `AppRulesStrict` | bool | `app_rules_strict` | false | 双模式开关（false=宽松） |
| `AppWhitelist` | []string | `app_whitelist` | [] | exe 绝对路径，可含 `*` |
| `AppBlacklist` | []string | `app_blacklist` | [] | 同上 |

## 包：`internal/apprules`（新）

### 纯函数（平台无关，可单测）

- `ExpandWildcards(paths []string) []string`
  - 含 `*` 的条目用 `filepath.Glob` 展开；展开为空则丢弃该条目；
  - 无通配条目原样保留（netsh 允许规则指向不存在的程序，规则安全无副作用）。
- `Derive(opts Options) ([]Rule, error)`
  - `Options{Strict bool, Whitelist, Blacklist []string, CoreExe, XiaoheExe string}`
  - 宽松：仅生成黑名单 block 规则（无需 allow 基线——Windows 出站默认允许）。
  - 严格：allow 基线（回环 `127.0.0.0/8,::1/128`；LAN
    `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16`；core exe；Xiaohe.exe）
    → allow 白名单程序 → block 黑名单程序 → 兜底 block（无 program）。
    规则顺序覆盖 Windows 防火墙「更具体规则优先」的评估。
  - 去重、按 (action, name) 排序保证确定性；任一清单 >100 条返回明确错误。
- `Rule{Name, Program string, Action string}` 及 `Args() []string`
  - 规则名 `AE-App-<n>`；`Args` 生成 netsh 参数（含引号转义）。

### netsh 后端（`go:build windows`）

- `Apply(rules []Rule) error`：逐条 `netsh advfirewall firewall add rule`；
  中途失败 → 删除组内已加规则后返回错误。
- `Clear() error`：删除 `AE-App-*` 全组（`enabled=false` 时调用，同时消化
  崩溃残留）。
- `Applied() bool`：本次会话是否已应用（内存态）。

### 进程枚举（`go:build windows`，`processes_windows.go`）

- `ListProcesses() ([]Process, error)`：
  `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` → `Process32First/Next` →
  `QueryFullProcessImageName`；枚举失败的条目跳过；返回 `{PID, Name, Path}`。
- API 全部已存在于 vendor 的 `golang.org/x/sys/windows`，零新依赖。

## App 装配与接线

- **设置变更**（`app.UpdateSettings` 路径内）：检测 app-rules 字段
  （enabled/strict/whitelist/blacklist 任一）变更：
  - `false→true`：后台 `Apply(Derive(...))`；失败 → 状态=失败(原因)，开关保持开
    但规则未生效（UI 状态行指导用户重试/降级）；
  - 已开且清单/严格变更：`Clear()` 后全量重新 `Apply`（≤200 条规则，重放比
    diff 便宜且避免残留）；
  - `true→false`：`Clear()`。
- **启动**：按 `AppRulesEnabled` 分支，**不无条件清理**：
  - `enabled=true` 且管理员：幂等重新 `Apply`（重建规则与当前清单一致，
    同时消化崩溃残留与清单漂移）；
  - `enabled=true` 且非管理员：**保留现有规则不动**（删除会让用户以为仍在
    禁网而实际已失效），状态=未生效-需管理员，提示规则仍按上次配置生效；
  - `enabled=false`：`Clear()`（清理残留）。
- **退出**：不主动 `Clear()`（常驻语义；开关已关时规则已在设置变更路径清理）。
- **快照**（`internal/webbridge/snapshot.go`）：`appRules: {enabled, strict,
  whitelistCount, blacklistCount, state, error?}`，`state ∈ {off, applied,
  pending, not_elevated, failed}`。
- **API**：`POST /api/settings` 透传新增 4 字段（`internal/webbridge/protocol.go`
  schema 同步补齐）；新增 `GET /api/processes` 返回进程列表。
- **vpn 包零改动**。

## UI（分流页新增「应用规则」块）

- 总开关 + 严格模式开关（严格开启时显示警告：将阻断系统服务的联网，需自行将
  关键服务进程加入白名单）。
- 状态行：已生效 / 未生效（需要管理员）/ 应用中 / 失败（原因）。
- 白名单、黑名单两个可编辑列表：手动输入路径、删除、清空。
- 「从运行进程添加」：`GET /api/processes` 弹列表勾选。
- 预设一键添加：静态表（应用 → 候选路径数组），仅把**存在**的路径加入清单。
  一期预设：Chrome、Edge、Firefox、WeChat、QQ、Steam。

## 测试

### 单测（纯函数部分，跨平台）

- `ExpandWildcards`：无通配原样保留；通配展开；展开为空丢弃。
- `Derive`：宽松=仅黑名单 block 且无基线；严格=基线 allow + 白 allow + 黑 block
  + 兜底 block；同一程序黑白同入 → 两条规则都生成；空清单 → 零规则不报错；
  任一清单 101 条 → 明确错误；路径含空格/引号 → `Args` 转义正确；去重与排序稳定。
- `ListProcesses`：健壮性（失败条目跳过）。

### 实机验收（管理员会话，Windows）

1. `curl.exe` 入黑名单 → 应用后 `curl` 请求失败；移出黑名单 → 恢复。
2. 严格模式 + 白名单仅 chrome.exe → `curl.exe` 断网、chrome 正常；关严格 → 恢复。
3. 断开 VPN 连接后规则仍生效（常驻语义）。
4. `enabled=false` 时启动：手动 `netsh` 造 `AE-App-*` 伪规则 → 启动后被清。
4b. `enabled=true` 且管理员：清单含 app X → 启动后规则与清单一致（重建幂等）。
5. 非管理员 + `enabled=true`：现有防火墙规则被保留，状态=未生效-需管理员。
6. 回归：`go test ./...` 全绿。

## 二期（不实现，仅留口）

wgtun 数据面加 per-flow 连接归属（`GetExtendedTcpTable` → 本地端口→PID→进程名
+ 周期刷新），按进程规则查询接口决定 放行隧道 / 直连 / 丢弃；仅 native WG
模式（有 TUN）生效。届时复用 `apprules` 的黑白清单解析与上限校验，后端换
数据面查询实现。
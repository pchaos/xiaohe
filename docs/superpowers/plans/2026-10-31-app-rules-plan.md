# 实现计划：分应用规则（程序级禁网）

- 日期：2026-10-31
- 依据：docs/superpowers/specs/2026-10-31-app-rules-design.md（已批准）
- 方式：按依赖顺序分步实现，每步独立可验证；纯函数部分 TDD（先测试后实现）

## 步骤

### 0. `internal/apprules` 纯函数（跨平台，TDD）
- `rules.go`：`Rule{Name, Program, Action, RemoteIP}` + `Args() []string`
  （netsh 参数；`exec.Command` 无 shell，路径空格/引号安全，与 killswitch 同款）；
  `ExpandWildcards`（`\`↔`/` 归一后 `filepath.Glob`，展开为空丢弃，无通配原样保留）；
  `Options{Strict, Whitelist, Blacklist, CoreExe, XiaoheExe}`；
  `Derive`：
  - 宽松：仅黑名单 block（无基线——Windows 出站默认允许）；
  - 严格：基线 allow（回环 `127.0.0.0/8,::1/128`、LAN
    `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16`、core、Xiaohe.exe）
    → 白名单 allow → 黑名单 block → 兜底 block；
  - 组内按 (program, action) 排序保证确定性；同一程序黑白同入 → 两条规则（黑优先
    依赖防火墙默认）；任一清单 >100 → 明确错误；去重；空清单 → 空规则不报错。
- `rules_test.go`：spec §测试 全部单测用例。
- 验收：`go test ./internal/apprules` 全绿（Linux 可跑）。

### 1. `internal/apprules` netsh 后端（`go:build windows`）
- `netsh_windows.go`：`Apply(rules)` 逐条 `netsh advfirewall firewall add rule`，
  中途失败 → 删除组内已加规则后返回错误；`Clear()` 删除 `AE-App-*` 全组；
  `Applied() bool` 内存态。
- 验收：`GOOS=windows go build ./...`；实机 netsh 验证（管理员）。

### 2. `internal/apprules` 进程枚举（`go:build windows`）
- `processes_windows.go`：`ListProcesses()` —
  `CreateToolhelp32Snapshot` → `Process32First/Next` → `QueryFullProcessImageName`；
  枚举失败条目跳过；返回 `{PID, Name, Path}`。
- 验收：`GOOS=windows go build ./...`；实机枚举。

### 3. `internal/config`
- `config.go`：`Settings` 新增 `AppRulesEnabled`、`AppRulesStrict`、
  `AppWhitelist`、`AppBlacklist`（JSON：`app_rules_enabled/app_rules_strict/
  app_whitelist/app_blacklist`；默认 false/false/[]/[]），`DefaultSettings` 同步。
- `config_test.go` 断言默认值。
- 验收：`go test ./internal/config`。

### 4. `internal/webbridge`
- `protocol.go`：设置对象补齐 4 字段；`bridge.go` 新增 `GET /api/processes`
  （`apprules.ListProcesses` 包装，失败 500）；
  `snapshot.go`：`appRules {enabled, strict, whitelistCount, blacklistCount,
  state, error?}`，state 取 app 状态机。
- 验收：`go test ./internal/webbridge`；`-ui=none` 起服务后 curl 快照含 appRules、
  /api/processes 返回数组。

### 5. `internal/app` 状态机
- `app.go`：`UpdateSettings` 内检测 app-rules 字段（enabled/strict/whitelist/
  blacklist 任一）变更 → 后台应用：
  - `false→true`：Apply(Derive(...))；失败 → state=failed(原因)；
  - 已开且清单/严格变更：Clear 后全量重放；
  - `true→false`：Clear，state=off。
- 启动：按 enabled 三分支（管理员+开→重建；非管理员+开→保留+not_elevated；
  关→Clear）；退出不 Clear。
- `isElevated` 复用 `internal/app/elevate.go`。
- 验收：`go test ./...`；实机状态迁移。

### 6. WebUI（分流页「应用规则」块）
- `index.html` + `app.js`：总开关 + 严格开关（警告文案）、状态行（已生效/
  未生效-需管理员/应用中/失败）、白/黑两个可编辑列表、进程选择器弹窗
  （`/api/processes`）、预设一键添加（Chrome/Edge/Firefox/WeChat/QQ/Steam
  常见路径探测，仅加存在的）。
- 验收：`-ui=none -print-url` + 浏览器人工走查。

### 7. 整体验证
- `go test ./...`、`go vet ./...`、`GOOS=windows go build ./...`。
- 实机验收（管理员 Windows，spec §「实机验收」6 项）+ `/review`。

## 评审点
步骤 0-2 完成后过一遍 `internal/apprules` 包；5 完成后过状态机；全部完成后
`/review` + 提交。
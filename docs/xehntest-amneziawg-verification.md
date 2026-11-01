# amneziawg-go 迁移 — 真机验证清单

日期：2026-11-01 · 分支：`xehntest` · 提交：`488327d`

## 背景

native 路径（`internal/wgtun`、`cmd/aetherwg`）由「vendored wireguard-go +
自打 AWG junk 补丁（~1800 行）」迁移到上游 `amneziawg-go/v3`（v3.1.20260828），
junk/i1 能力改由官方实现提供。静态兼容面已核对（API 签名、UAPI 键、发送时序
同构），以下 4 项只能在本机（Windows）验证。

**目标判定**：4 项全过 → 合并 `xehntest`；任一项不过 → 回滚（见 §5），回滚成本 ≈ 0。

## 前置

1. 出包：`powershell -ExecutionPolicy Bypass -File scripts\build.ps1`（或
   `go build -tags wgtun ./cmd/aethergui`），确认 `bin\wintun.dll` 存在
2. 原生模式需要管理员权限（wintun 驱动）
3. 准备一个已注册的 WARP 身份（native WG/AWG 需要私钥/对端公钥，`cmd/aetherwg`
   可从 aether.toml 生成，或复用设置里已有的）

## 1. WARP 握手兼容性（最高优先）

```powershell
# 打开 GUI → 设置 → 网络 → 勾选「原生 WireGuard 加速」+「AWG」（混淆）
# 连接后验证出口：
curl https://www.cloudflare.com/cdn-cgi/trace
```

| 检查 | 通过标准 |
|---|---|
| 连接状态 | UI 变 Connected，不回落 Failed/Reconnecting 循环 |
| 出口 | trace 的 `ip=` 是 CF 边缘出口；**`warp=on`**（或 at least 非本机 IP） |
| 稳定性 | 保持 5 分钟不重连（观察日志无 “handshake did not complete”） |

失败观察点：日志反复 `Sending handshake initiation` 无响应 → junk/i1 形状
导致 WARP 拒收 → 记下 jc/jmin/jmax 与 i1 模板，改参数重试。

## 2. 吞吐 A/B（迁移前后对比）

```powershell
# 迁移前（旧补丁）：dev_base 出包，同网络同端点测
wgbench.exe -jc 0 -conf <identity.conf>          # 纯 WG 基准
wgbench.exe -jc 6 -jmin 10 -jmax 50 -conf <identity.conf>   # junk 开启
# 迁移后（xehntest）重复上面两条，对比下行 Mbps
```

| 判定 | 标准 |
|---|---|
| 纯 WG 基准（-jc 0） | 迁移后 ≥ 迁移前 90%（允许噪声；差异 >10% 需查 awg 的收发路径） |
| junk 开启 | 两条曲线同向（junk 会不会把吞吐打崩，前后行为一致） |

背景：项目历史中 `bind-windows-batch` 就因 55 vs 103 Mbps 的吞吐反转被弃 ——
性能差异只能实测，不可推断。

## 3. junk 时序抓包

```powershell
# 管理员：pktmon 或 Wireshark 抓 UDP（WARP 端点端口，常用 4233/1701）
pktmon start --capture --pkt-size 0
<触发一次 native AWG 连接>
pktmon stop
pktmon format pktmon.etl -o capture.pcapng   # Wireshark 打开
```

预期包序（amneziawg-go `device/send.go`）：`i1 假首包 → jc 个随机包 →
148 字节 WireGuard handshake initiation`。判定：前 2 类包出现且先于握手 =
时序正确；只有裸握手 = junk 未生效（查 UAPI 参数是否送达 `IpcSet`）。

## 4. 原生 WG 回归（AWG 关闭）

设置里只开「原生 WireGuard 加速」、不勾 AWG → 连接应表现为**纯净旧行为**
（junk 全关，与迁移前原生 WG 一致）：连接成功 + 无多余 UDP 包。

## 5. 回滚（任一项不过）

```powershell
git checkout dev_base -- go.mod go.sum vendor internal/wgtun cmd/aetherwg
git checkout HEAD -- scripts/build.ps1 scripts/apply-vendor-patches.ps1 README.md
# 重新 go mod vendor（若 vendor 目录被污染）+ 跑 apply-vendor-patches.ps1 -Apply 恢复补丁
```

依赖级改动，无任何持久副作用；补丁文件与注册表仍在 git 历史里。

## 判定汇总

| # | 项 | 结果（□） |
|---|---|---|
| 1 | WARP 握手兼容 + warp=on | □ |
| 2 | 吞吐 A/B（-jc 0 与 -jc 6） | □ |
| 3 | junk 时序抓包（i1 → junk → 握手） | □ |
| 4 | 原生 WG 无 AWG 回归 | □ |

4/4 通过 → 合并 xehntest 到 dev_base。失败项记录参数 → 回滚或调参重测。

## 6. 混淆参数对照（cmd/awgprobe）

想验证「i2..i5 / 更大 junk 对 WARP 有没有用」时直接用现成工具，不必等整个
连接流程：

```powershell
go build -o awgprobe.exe ./cmd/awgprobe        # 本机或 Win10 均可编译
awgprobe.exe                                    # 基线：无混淆
awgprobe.exe -i1 "<b 0d0a0d0a><t><r 24>"       # 单个假首包（HTTP 头模样）
awgprobe.exe -i1 ... -i2 ... -jc 12 -jmin 96 -jmax 420   # 全套
```

- 身份自动读 `%LOCALAPPDATA%\AetherGUI\aether.toml`（或 `-identity/-priv/-pub`）
- 握手由 `persistent_keepalive_interval=1` 驱动，不依赖隧道流量
- 模板语法是 amneziawg-go 的：`<b hex> <t> <r N> <rc N> <rd N>` —— **没有
  `<c>`、没有 `min-max` 区间**（那是核心 aethernoize 的语法，别混用）

**2026-11-01 首轮实测（Win10, 3 端点 × 3 次, 6s/次）**：

| 配置 | 通过率 |
|---|---|
| 基线（无混淆） | 5/9（56%，8.39.204.254 稳定 3/3） |
| i1 only | 3/9（33%，样本小，视为噪声内） |
| i1..i5 + jc 12（96-420B） | **0/9（0%）** |

解读：单假包对 WARP 无增益；**假包+decoy 堆满反而系统性恶化（0/9）**，
疑似触发 WARP 端点的突发丢弃/限速。这支持 one-sided 子集保持克制的设计
（xiaohe 现状：i1 一个 + jc 适度）。若要更强结论，加大 `-repeat` 复测。
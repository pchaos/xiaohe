# xehntest 调研结论(2026-11-01)

分支:`xehntest`(基于 `dev_base`,含 noize UI 提交)。范围:native WG/AWG
路径由「vendored wireguard-go + 自打 awgjunk 补丁」迁移到上游
`amneziawg-go/v3`,并在真机(Win10, D1581ZTSSD)完成对照实测。

## 结论(按决策优先级)

### 1. 迁移本身:通过,无引擎差距
- amneziawg-go 与 wireguard-go 的 API 同构(`NewDevice`/`IpcSet`/`tun`/`conn`),
  Xiaohe 的引用面(3 个文件)只需改 import 路径;补丁 ~1800 行 + ps1 注册
  条目可整体退役(只剩 webview2 一项)。
- 两个引擎在同一台机、同一端点、同一身份下都能握手成功 —— **不存在引擎
  兼容性差异,迁移无行为回退**。
- 迁移中发现并修复 2 个继承差异:
  - `IpcSet` 键序:junk 键必须在 peer 块之前(amneziawg-go 无 staging);
    否则 `IPC error -22: invalid UAPI peer key`(已修,`b35ba23`)。
  - i1 格式:`i1=<hex>` → `i1=<b hex>`(模板语法,字节不变)。

### 2. 当前网络的 WARP UDP 是「黑洞」—— 真机验证必须换网络
- 证据链:
  - DNS UDP:Google/国内 DNS 正常;Cloudflare(1.1.1.1:53/443、全部 WARP
    端点)超时。
  - 握手:探针 27 次/配置,基线通过率 48%,且同一端点几分钟内 3/3 → 0/3
    反复(时通时断)。
  - **数据面:握手成功(3/3)后推 20MB UDP 进隧道,回包 rx=0** —— 加密数据
    流也被吞(Xiaohe 日志同款 `handshake ok but data plane dead`)。
- 影响:吞吐 A/B、20MB 下载采样、warp=on 验证在当前网络测不出真实数字。

### 3. 混淆参数对照:假包对 WARP 是净负
- 27 次/配置实测:`基线 48%` → `i1 only 11%` → `i1..i5 + jc12 7%`;稳定
  端点 8.39.204.254 从 7/9 一路到 0/9。
- Xiaohe 默认参数(quic i1 + jc6)实测 19%(且 jc6 相较`仅 i1`无明显差异)。
- 结论:**对 WARP,单假包无增益、堆满假包/deco 系统性恶化握手**。
  one-sided 子集保持克制是对的。
- 建议:AWG 默认应关(jc=0、i1=none),改为用户按需开启;或运行时提供
  「AWG 开/关」真实连接 A/B 后再定。

### 4. native 的 s1-s4 / h1-h4 / header_protection_key 对 WARP 不可用
- s(消息尾部 padding)/ h(消息 type 伪装)会改写 WireGuard 协议字节,
  需要 AmneziaWG 兼容对端 + shared key —— WARP 必拒。只对自建 AWG
  服务器有意义。安全子集 = i1-i5 + jc/jmin/jmax(包外)。

## 工具与交付
- `cmd/awgprobe`:握手通过率探针(`-repeat`)、混淆参数对照(`-i1profile`,
  `-i1..-i5`,`-jc`)、数据面/吞吐(`-datatest MB`);包构建有单元测试。
- `docs/xehntest-amneziawg-verification.md` §6:用法与历次数据。
- 分支 commits:`488327d`(迁移)→ `b35ba23`(键序)→ `d7ed094`(端口)→
  `b7eda91`/`e75c222`(退出口)→ `58032af`(分流页摘要)→
  `d0ab7ea`/`095fa29`/`633d434`(awgprobe+数据)→ `776714a`(datatest)。

## 遗留动作
1. 换网络后跑验证清单 4 项(握手/warp=on、吞吐 A/B、junk 时序、WG 回归)。
2. AWG 默认参数决策(AWG 默认关?)—— 需一次真实连接 A/B。
3. 全过则合并 xehntest → dev_base,补丁退役收尾(README/AUDIT/patch 说明)。
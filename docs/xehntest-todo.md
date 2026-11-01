# xehntest 收尾 TODO(2026-11-01)

状态:□ 未开始 · ◐ 进行中 · ✅ 完成。背景与结论见
[docs/xehntest-conclusions.md](xehntest-conclusions.md)。

## 前置(阻塞项)

- [ ] **换可用网络**:当前网络对 Cloudflare UDP 握手+数据面为黑洞
  (48% 握手、20MB 数据面 rx=0),真机验证无法完成。换网络后从头跑。

## 1. 真机验证清单(换网络后,~30 分钟)

参考 [xehntest-amneziawg-verification.md](xehntest-amneziawg-verification.md):

- [ ] 1a native AWG 连接 WARP → `warp=on`,稳定 5 分钟
- [ ] 1b 吞吐 A/B:`wgbench -jc 0` 与 `-jc 6`,迁移前后对比(±10% 内)
- [ ] 1c 抓包确认 `i1 → junk → 148B 握手` 时序
- [ ] 1d 原生 WG(关 AWG)无回归
- [ ] 1e `awgprobe -datatest 20` 数据面 rx>0(隧道真有数据)

## 2. AWG 默认参数决策

- [ ] 2a 真实连接 A/B:AWG 开(默认 quic i1+jc6)vs 关,jc 记录成功率
- [ ] 2b 依据实测(AWG 默认 19% vs 基线 48%)决定:默认关 AWG / i1=none?
- [ ] 2c 如默认关:调整 `config.Defaults()` + UI 文案 + 发布说明

## 3. 合并与收尾(xehntest → dev_base)

- [ ] 3a 确认 1/2 全过后合并
- [ ] 3b 合并后清理:README「未修改官方二进制」口径与迁移说明、
  AUDIT-REPORT 补丁引用、`patches/full` 只剩 webview2 的验证
- [ ] 3c 删除 `docs/xehntest-*.md`(或归档到正式文档)
- [ ] 3d 发布笔记:amneziawg 迁移 + AWG 默认参数变化的 user 可见条目

## 4. 已交付、待你在 Win10 复核(不阻塞合并)

- [ ] 4a 关闭窗口退出:未连接 3s / 已连接 8s;`-ui none` 端口非 unsafe
- [ ] 4b 分流页规则摘要显示(直连/屏蔽条数)
- [ ] 4c noize 档位透传(dev_base 已提交,设置→网络→混淆档位)

## 备注

- Win10:`D:\xiaohe` 当前为 xehntest 最新(含全部修复),备份在
  `D:\xiaohe-bak-20261101-113817`;`%USERPROFILE%\awgprobe.exe` 可复测。
- 合并前如遇冲突:先 cherry-pick 或 rebase dev_base 再合并,勿用 force push。
# MoonCIDR Audit 项目申报书

## 基本信息

- 项目名称：MoonCIDR Audit — 面向网关、代理与运维配置的 IPv4/CIDR 规则审计库
- 参赛者：高本乾
- 联系方式：已通过官方报名问卷提交
- GitHub：github.com/BeiLaDuo/mooncidr-audit
- Mooncakes：BeiLaDuo/cidr-audit
- 许可证：Apache-2.0

## 项目简介

MoonCIDR Audit 是一个使用 MoonBit 实现的 IPv4/CIDR 规则审计库，面向网关、反向代理、云安全组和 ACL 中的 allow/deny 规则。项目不实现防火墙或真实网络控制，而是提供可复用的离线分析能力，帮助开发者在规则上线前发现遮蔽、冲突、过宽放行、全局拒绝、非规范 CIDR、重复配置和覆盖空洞等问题。

## 现有基础（v0.1.2）

| 维度 | 内容 |
|------|------|
| **源码** | 生产代码 3,021 行，测试代码 1,001 行，合计 4,022 行 |
| **测试** | 118 项测试在 wasm、wasm-gc、JavaScript、native 四个目标全部通过 |
| **核心功能** | IPv4 解析与 CIDR 归一化；规则审计（遮蔽/冲突/过宽/全局拒绝/重复）；地址区间合并与覆盖分析；Nginx/CSV 导入；文本/Markdown/JSON 报告；CI 门禁；`is_public()` 公网地址判断；安全策略文档 |
| **CI** | GitHub Actions |
| **发布** | 已上架 Mooncakes |

## 本次活动计划新增

补充 CIDR 边界和异常输入测试；稳定文本/Markdown/JSON 报告字段；完善网关、云安全组和 CI 门禁示例；整理 README、查重说明、提交清单和版本记录。

## 技术路线

项目使用 `UInt` 表示 IPv4 地址，基于前缀掩码计算网络/广播地址。CIDR 层提供包含、重叠、归一化；规则层按配置顺序匹配；审计层输出结构化风险发现；聚合层负责去重和网段合并；导入层将外部文本转为统一规则模型；门禁层给出 CI 通过/失败判断。核心边界保持离线配置审计，不接触真实网络或云凭据。

## 预计交付

构建/测试可直接复现的 MoonBit 库；118 项测试；网关和云安全组审计示例；README、API 文档、SECURITY.md；Mooncakes 正式版本。

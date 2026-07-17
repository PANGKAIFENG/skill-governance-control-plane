# 技术债与 Roadmap

本清单只保留对公开用户有意义、可以独立跟进的问题。具体排期以 GitHub Issues 为准。

## 近期

- 降低启动依赖：Portal 的只读资产盘点不应强制要求 GitHub CLI。
- 增加环境诊断：启动前检查 Python、Skillshare、配置和可读目标，并提供用户可操作的错误提示。
- 提升盘点兼容性：补充更多 Skillshare 版本和不同 Agent 目录结构的测试矩阵。
- 完善空状态引导：没有初始化 Skillshare 或没有发现 Skill 时，给出明确的下一步操作。
- 将浏览器刷新流程纳入持续集成，覆盖刷新成功、失败保留旧快照和移动端布局。

## 中期

- 支持用户声明新的 Agent 目标，而不需要修改核心代码。
- 为 GitHub Adapter 补齐统一的 discover、plan 和 publish 契约。
- 增加只读 Multica discover/export PoC，再决定是否提供写入能力。
- 为团队场景增加角色、策略模板和多人审批，但不改变个人模式的低配置体验。
- 增加资产变更时间线和可导出的治理报告。

## 已知实现债

- `RuntimeInventoryReadResult` 仍可在类型层构造互相矛盾的可用状态与错误码组合。
- Runtime inventory 的极端文件替换竞态仍可进一步收紧。
- 安装覆盖率应按唯一目标名称计算，避免同一 Agent 下重复实例造成 `2/1` 展示。
- Portal 需要受控的结构化服务端日志，同时保证错误信息不泄露敏感路径。
- Portal 表单请求需要独立于 `Content-Length` 的读取硬上限。
- Deployment Ledger 仍需真实多进程并发追加测试。

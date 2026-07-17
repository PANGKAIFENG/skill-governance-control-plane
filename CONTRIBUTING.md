# 贡献指南

感谢你帮助改进 Skill Governance Control Plane。这个项目优先解决真实的多 Agent Skill
管理问题；提交功能前，请先在 Issue 中描述用户场景、当前行为和期望结果。

## 本地开发

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m playwright install chromium
```

提交前运行：

```bash
ruff check .
mypy src
pytest
```

## 变更原则

- 新行为先补可观察的失败测试，再实现最小修复。
- 核心领域保持平台无关；具体 Agent、Skillshare、GitHub 和 Multica 行为放在 Adapter 后。
- 盘点默认只读，任何外部写入都必须是显式动作并支持 dry-run 或审批。
- 不提交真实 Skill、用户名、本机绝对路径、token、日志或私有仓库信息。
- 面向用户的文档优先使用清晰语言，避免把内部实现过程当作产品说明。

## Pull Request

PR 请说明问题、解决方式、验证命令、安全影响和界面截图（如适用）。保持单一目的，避免
同时混入无关重构。

# 安全政策

## 支持范围

当前只对最新 `main` 分支提供安全修复。项目仍处于早期 MVP 阶段，不建议将 Portal 暴露
到公网；默认只允许监听 `127.0.0.1` 或 `localhost`。

## 报告漏洞

请不要为未修复的漏洞创建公开 Issue。通过 GitHub 仓库的 **Security > Report a
vulnerability** 私下提交报告，并包含复现步骤、影响范围和建议修复方式。

维护者会尽快确认报告。修复发布前，请避免公开漏洞细节或真实凭据。

## 使用者责任

- 不要把 token、密码或私有 Skill 内容提交到 Issue、日志或治理文件。
- 执行 `apply`、`rollback` 或 Adapter 写入前先核对计划和目标路径。
- 仅从可信来源安装 Skillshare、本项目及第三方 Skill。

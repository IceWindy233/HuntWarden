# HuntWarden 处置闭环 Sprint

## 目标

在三套隔离 Docker Lab 中冻结首期写操作安全边界，并把底层工具、Electron GUI、审批票据、远程回执和审计视图串成可重复验收链。

## 已实现范围

- `npm run lab:reset` 删除并重建三个 Lab 容器，保留本地测试身份 Key，刷新 `known_hosts`，等待 SSH、Web 和 Tomcat 就绪。
- `npm run test:docker` 默认先重置 Lab，再执行真实 SSH 工具链。
- WebShell 隔离覆盖无票据、拒绝、批准、一次性消费、Evidence 哈希绑定、原子移动、`000` 权限以及本地/远端回执一致性。
- 账户禁用覆盖无票据、批准、锁定/过期验证，以及 `root`、当前 SSH 执行账户的永久拒绝。
- GUI 审批要求“批准一次”后再次点击“确认执行”，拒绝和批准均写入审计。
- GUI 审计页展示 ActionReceipt 的工具、状态、Action ID、目标指纹、时间和结构化结果。
- Agent 正常结束调查后任务进入 `COMPLETED`，报告生成期间进入 `REPORTING`，完成后回到 `COMPLETED`。
- Electron GUI E2E 使用仅限未打包测试进程的 Pi Faux 脚本模型，远端操作仍通过真实 SSH Helper 执行。

## 验收命令

```bash
npm run build
npm test
npm run probe:build
npm run test:docker
npm run test:gui:remediation
```

GUI E2E 包含：

1. 拒绝 WebShell 隔离，确认远端零写入且票据为 `DENIED`。
2. 二次确认 WebShell 隔离，确认票据为 `CONSUMED`、回执为 `SUCCEEDED`、源文件消失。
3. 二次确认禁用 `labroot`，确认账户锁定/过期、回执为 `SUCCEEDED`。

## 安全说明

- 测试只允许针对 `labs/docker-compose.yml` 创建的容器执行。
- `HUNTWARDEN_E2E_FAUX_SCENARIO` 只有在 `app.isPackaged === false` 且 `NODE_ENV=test` 时有效。
- 打包应用不会启用 Faux 测试模型。
- `test:docker` 和 `test:gui:remediation` 会真实改变容器状态；再次手工测试前执行 `npm run lab:reset`。

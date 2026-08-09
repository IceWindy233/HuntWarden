# 恢复报告闭环与 Linux 持久化调查

## Sprint A：恢复与报告

- 进程启动时把遗留的活动状态转换为 `ABORTED + recoveryRequired`，保留原状态与中断时间，并使旧的 `PENDING/APPROVED` 审批过期。
- 恢复必须由分析师在 GUI 中触发。SAFE 工具按原 `toolCallId` 重放；NEVER 工具先查询远端 `actionId` 回执，状态未知时重新审批。
- 调查结束后先停在 `COMPLETED`，由分析师复核 Finding、Evidence 与检测覆盖并手动确认生成不可变 Markdown 报告。路径为 `reports/<taskId>/vNNNN.md`，SQLite `reports` 表保存版本、哈希、模式与校验错误；仅已手动发起的 `REPORTING` 中断会在恢复时续完报告。
- 报告生成失败或引用校验失败时使用确定性模板；旧 `${taskId}.md` 文件仅懒导入，不覆盖原文件。
- `tests/e2e/gui-recovery.test.ts` 在六个持久化边界强制退出 Electron，并使用同一 `userData` 重启验证。

## Sprint B：Linux 持久化

第四类检测 `linux_persistence` 默认用于新任务；历史任务继续使用其创建时保存的检测集合。

受控工具：

- `list_cron_entries`
- `list_systemd_units`
- `list_ssh_persistence`
- `list_shell_startup_files`
- `inspect_persistence_item`
- `find_related_processes`
- `list_process_connections`
- `collect_persistence_artifact`

枚举工具产生任务内 `persistenceRef`，进程关联产生 `processRef`。后续工具不接受模型提供的路径、PID、用户名或网络目标。Helper 再次校验固定目录、文件类型、数量与当前哈希；SSH 结果只包含类型、指纹、选项标记和注释。

`Lab-Persistence` 使用 SSH 端口 `2225`，包含正常配置及无害 Cron、systemd、SSH Key、Shell 启动项和回环监听进程。容器不运行 systemd 管理器，因此 Unit 文件调查应返回 `PARTIAL` 并明确告警，而不是把环境限制解释为安全。

## 验证命令

```bash
npm run build
npm test
npm run probe:build
npm run test:docker
npm run test:gui:investigation
npm run test:gui:remediation
npm run test:gui:recovery
npm run make:gui
```

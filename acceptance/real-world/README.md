# HuntWarden 真实场景验收夹具

该夹具不属于固定答案的 `labs/` 样板。它从官方 Debian 12 基础镜像启动，每次动态生成事件编号、Web 文件名、隐藏进程名、Cron 文件名和 UID 0 账户名，再通过 HuntWarden 正式 SSH/Helper 链进行黑盒取证。

场景只使用无害载荷，Web 端口不映射到宿主机，网络 Beacon 仅连接容器内 `127.0.0.1`。WebShell 仿真保留请求输入、解码和命令执行原语，但使用恒不成立的条件，不能执行输入。

覆盖的 ATT&CK 行为：

- T1505.003 Web Shell
- T1053.003 Cron
- T1070.004 File Deletion（删除后运行）
- T1136.001 Local Account
- T1098.004 SSH Authorized Keys
- T1071/T1571 风格的周期性本地 Beacon（仅用于进程到 Socket 关联）

执行：

```bash
npm run test:acceptance:real-world
```

脚本会生成临时 SSH 身份、构建并启动目标、执行验收，然后自动删除容器和网络。身份文件保存在 gitignored 的 `.state/` 目录中以便复跑。

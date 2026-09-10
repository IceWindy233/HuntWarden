# 运维发布资格

运维资格由两个不可替代的阶段组成：目标 Linux 安装生命周期演练，以及控制端旧数据库迁移/回退/Evidence 导出演练。正式结果必须在同一个干净固定提交生成；结果只保留提交、平台、摘要、计数和布尔验收状态，不得包含目标地址、SSH 凭据或 Evidence 正文。

## 1. 目标端安装生命周期

`qualify-host.sh` 会先清除既有 HuntWarden 目标端组件和状态，再执行全新安装、原位升级、默认卸载及 `--purge-state` 彻底卸载。它会改写并最终清理以下路径：

- `/usr/local/libexec/huntwarden-helper`
- `/opt/huntwarden`
- `/var/lib/huntwarden`
- `/etc/sudoers.d/huntwarden`
- `/etc/systemd/system/huntwarden-operational-qualification.service`（PID 1 为 systemd 时）

因此只能在已授权、可销毁且不承载生产状态的 Linux 主机或 VM 上运行。不要在生产主机或需要保留 `/var/lib/huntwarden` 的目标上运行。运行前须已构建 Tomcat Probe，且执行用户必须存在并可由 root 通过 `su` 调用。

```bash
npm run probe:build
sudo acceptance/operational/qualify-host.sh \
  --executor-user <ssh-user> \
  --commit "$(git rev-parse HEAD)" \
  --output /outside/repository/operational-host.json
```

脚本验证：Helper/YARA/Probe/sudoers 的所有权、权限和源文件摘要；以执行用户经 sudo 调用 Manifest 3.0.0 Helper；升级不改已有 Action Receipt；默认卸载保留状态；彻底卸载移除状态、sudoers 和演练作业。任一步失败都会生成 `FAIL` 结果、清理演练路径并以非零状态退出。

## 2. 旧数据库迁移、回退与导出

准备生产数据的脱敏副本或等价的旧 schema 真实任务库。副本必须满足：

- `PRAGMA user_version` 低于当前运行时 schema；
- 指定任务在旧库中存在；
- 任务至少包含一条带本地 Artifact 的 Evidence；
- 数据目录、结果文件和导出目录均为演练专用路径。

命令拒绝绝对数据库文件名、数据目录内输出，以及已存在的结果文件/导出目录：

```bash
npm run qualify:operational -- \
  --data-dir /path/to/legacy-data-copy \
  --database runtime.db \
  --task TASK-ID \
  --host-result /outside/repository/operational-host.json \
  --export-directory /outside/repository/evidence-export \
  --output /outside/repository/operational.json
```

控制端会实际打开并迁移旧库，核对事务前备份、旧任务可读性，导出 Artifact 和脱敏 `EVIDENCE-MANIFEST.json`/`SHA256SUMS`，再把数据库恢复到迁移前备份并验证 schema、完整性和旧任务，最后恢复迁移后数据库并重新打开。正式输出状态必须为 `PASS`。

## 3. 接入发布资格

计算最终结果摘要，并把相对路径加入发布资格清单：

```json
{
  "operational": {
    "path": "operational.json",
    "sha256": "<operational.json SHA-256>"
  }
}
```

随后运行：

```bash
npm run release:qualification-check -- --qualification /path/to/qualification.json
```

发布校验器会重新绑定当前 HEAD、Helper 源码摘要和 `qualify-host.sh` 摘要，并拒绝缺失迁移前备份、旧任务读取、回退、重新迁移、Artifact、校验和或脱敏证明的结果。模板或手写布尔值不能替代执行器产物。

# HuntWarden v0.1.0 收口计划

> 目标：把 HuntWarden 收口为可复现、可验证、可下载的正式项目版本。
>
> 冻结日期：2026-08-17
>
> 本计划只定义 `v0.1.0` 的退出条件。LocalExecutor、离线 Collector、容器调查、Windows 和 Kubernetes 继续保留在长期路线，不阻塞本版本发布。

## 1. 当前证据基线

### 已经具备

- [x] WebShell、Tomcat/JDK 内存马、后门账户、Linux 持久化、Linux 入侵分诊五类检测包。
- [x] 确定性最低扫描图、Agent 扩展调查、Finding、Evidence、审计和手动版本化报告。
- [x] SCAN/REMEDIATE 工具范围隔离、一次性审批、远端 Action Receipt 和崩溃恢复。
- [x] Electron GUI、TUI、流式输出、安全 GFM Markdown、任务归档和报告视图。
- [x] DBAPP 威胁情报安全配置、受控 IOC 富化和真实 Key 人工在线验收。
- [x] 五套固定 Docker Lab 和三条 Electron GUI E2E。
- [x] `package.json` 版本已经是 `0.1.0`。
- [x] 已新增独立于固定 Lab 的 Debian 12 ARM64 动态真实场景验收夹具。

### 当前尚不能作为发布证据

- [x] VM 验收入口、手动 Docker 工作流与发布材料均已形成可追溯本地提交；本轮收口提交等待推送。
- [ ] Debian 12 动态场景是容器化行为验收，不等同于完整 systemd VM 验收。
- [x] 新增发行版识别与 `PARTIAL` 规则修复后，完整本地门禁已经重新执行。
- [x] 仓库已增加最小 GitHub Actions 工作流、手动 Docker 验证工作流和状态徽章；远端首次运行仍待推送后确认。
- [ ] 没有 Ubuntu 24.04 ARM64 与 Rocky Linux 9 x86_64/SELinux 的真实 VM 验收记录。
- [ ] 已有 Release Notes 草案和本地发布资产校验和，但尚无最终 `v0.1.0` tag、GitHub Release 及基于最终 tag 生成的校验和。
- [ ] `package.json` 已补齐 description、repository 与 author；许可证仍需由项目所有者确认后写入。

### 2026-08-17 本地验证进度

- [x] `npm run build`：PASS；Renderer 存在单个约 515 kB chunk 的非阻断体积警告。
- [x] `npm test`：25 个文件通过、7 个跳过；88 项通过、34 项跳过。
- [x] `npm run probe:build`：PASS；Gradle 9.3.1 提示 Gradle 10 兼容性弃用警告，当前不阻断。
- [x] 发行版识别/确定性规则定向测试：14 项通过、1 项按环境跳过。
- [x] `npm run test:acceptance:real-world`：Debian 12 ARM64 动态场景 6/6 通过。
- [x] `npm run test:docker`：修复固定时间夹具后，五套 Lab 10/10 通过。
- [x] `npm run test:gui:investigation`：4/4 通过。
- [x] `npm run test:gui:remediation`：3/3 通过。
- [x] `npm run test:gui:recovery`：6/6 通过。
- [x] `npm run package:gui`：PASS；随后从干净工作树运行 `npm run release:local`，生成 macOS arm64 ZIP/DMG 并实际启动打包 `.app`，未出现致命启动错误。
- [x] `npm run audit:prod`：0 个运行时依赖漏洞；完整开发依赖审计仍有 Electron Forge 工具链告警，已在发布说明中区分。
- [ ] 上述结果已在干净工作树复验，但仍需推送后由 GitHub CI 提供独立证据，不能用本机结果替代远端 Gate。

本轮 Docker 首次执行暴露了固定日期夹具会自然超出 24/168 小时时间窗的问题。Lab-Web 与 Lab-Linux-IR 已改为在容器启动时生成当前 UTC/本地系统日志时间并刷新测试文件 mtime，随后全量 Docker 回归通过；没有通过放宽检测时间窗规避缺陷。

## 2. v0.1.0 硬性退出条件

只有以下五个 Gate 全部完成，才创建 `v0.1.0` 标签。

### Gate A：工作树与自动化门禁

- [x] 审查并拆分当前修改，运行时 Key、`.state`、Evidence、数据库和打包产物均未进入提交。
- [x] `npm ci` 可以从干净工作树完成。
- [x] `npm run audit:prod` 通过；构建工具链告警已单独记录，没有用生产依赖为 0 替代完整审计说明。
- [x] `npm run build` 通过。
- [x] `npm test` 通过：25 个文件通过、7 个按环境跳过；88 项通过、34 项跳过。
- [x] `npm run probe:build` 通过。
- [x] `npm run test:docker` 通过：10/10。
- [x] `npm run test:acceptance:real-world` 通过：6/6。
- [x] `npm run test:gui:investigation` 通过：4/4。
- [x] `npm run test:gui:remediation` 通过：3/3。
- [x] `npm run test:gui:recovery` 通过：6/6。
- [x] `npm run release:local` 通过；ZIP/DMG 校验和复核成功，打包 `.app` 已完成隔离启动冒烟。

### Gate B：真实 VM 只读验收

`v0.1.0` 只要求两台差异最大的真实 VM；其余发行版仍标记为待验收。

1. **Ubuntu 24.04 ARM64**
   - AppArmor、dpkg、journald、arm64、标准 systemd VM。
2. **Rocky Linux 9 x86_64 + SELinux Enforcing**
   - rpm、`/var/log/secure`、SELinux、x86_64、标准 systemd VM。

每台 VM 必须保存：

- [ ] 官方镜像来源、镜像 ID/版本、架构、内核和测试时间。
- [ ] Host Key 带外核验记录；首次发现不能自动信任。
- [ ] Helper 安装、自检、版本和权限结果。
- [ ] 最低依赖下的能力降级结果。
- [ ] 完整依赖下 QUICK、STANDARD、DEEP 的任务结果。
- [ ] 五类检测分别运行时不存在未选择类别工具调用。
- [ ] 至少一个无害阳性样本和一个良性对照。
- [ ] Finding/Evidence/覆盖状态/报告引用正确。
- [ ] SCAN 远程写成功次数为 0。
- [ ] 结果回填 `docs/SUPPORT_MATRIX.md`，原始日志只保存脱敏副本。

### Gate C：GitHub CI

- [x] 新增最小必跑工作流：Node.js 22.19、`npm ci`、build、默认测试和 Java 17 probe；Actions 固定到已核对版本的提交 SHA。
- [x] Docker 与动态 Debian 验收采用独立手动工作流，避免普通提交不稳定和超长运行；Electron E2E 保持发布前本机门禁。
- [x] 最小 CI 不读取真实模型 Key、DBAPP TI Key、SSH 私钥或用户本地配置。
- [x] README 已接入对应工作流徽章；推送前只能证明链接配置正确，远端状态仍待首次运行。
- [ ] 分支保护或发布前检查要求由仓库所有者确认。

### Gate D：项目文档

- [x] README 提供项目定位、安全不变量、核心能力、安装验证和主要使用入口。
- [x] 架构、长期 TODO、支持矩阵、验收与发布计划保留在 `docs/`，README 不堆叠完整设计细节。
- [x] 真实 VM 验收模板、无害样本部署/清理步骤和失败判定规则均已固化。

### Gate E：发布

- [ ] 由项目所有者确认许可证；建议在 MIT 与 Apache-2.0 中选择，未确认前不擅自添加。
- [ ] `package.json` 的 description、repository 和 author 已补齐；license 等待项目所有者确认。
- [x] 完成 `CHANGELOG.md` 与 `docs/releases/v0.1.0.md` 草案；发布时替换真实 VM 与最终门禁占位信息。
- [x] 本地生成 macOS arm64 未签名 ZIP/DMG 并计算 SHA-256；正式 Release 必须从最终 tag 重新生成，不能直接复用预发布资产。
- [x] Release Notes 草案已明确验证范围占位、未签名提示、已知限制、数据边界和安全警告；正式发布前只需回填最终证据。
- [ ] 在干净提交上创建 annotated tag `v0.1.0`，推送后创建 GitHub Release。
- [ ] Release 页面提供应用包、SHA-256、文档入口和复现命令。

## 3. 执行顺序

### R0：稳定当前工作树

1. 审查 Debian 12 动态验收、发行版识别和 `PARTIAL` 规则修复。
2. 执行定向单测、Helper 集成和动态验收。
3. 执行完整 build/test/probe/Docker/GUI/package 门禁。
4. 按“功能修复 → 验收夹具 → 文档计划”拆分提交并推送。

### R1：建立 CI

1. 增加普通提交必跑 CI。
2. 增加手动 Docker 门禁；Electron GUI E2E 保持发布前本机完整门禁。
3. 验证 fork/无 Secret 场景不会访问真实外部服务。
4. README 接入真实徽章并记录最新测试数量。

### R2：两台真实 VM

1. Ubuntu 24.04 ARM64：先最小依赖，再完整依赖，再无害样本。
2. Rocky Linux 9 x86_64：保持 SELinux Enforcing，重复相同流程。
3. 每台测试完成后销毁或恢复快照，保存脱敏验收记录。
4. 任何失败先记为兼容性 TODO，不把 `PARTIAL/ERROR` 改写为安全。

### R3：文档收口

1. 校验 README 的安装、验证和使用命令。
2. 保持支持矩阵与真实验收结果一致。
3. 检查示例配置、路径、IP 和用户名不包含真实凭据或敏感数据。
4. 发布前复核 Changelog、Release Notes 和已知限制。

### R4：v0.1.0 发布

1. 冻结功能，只修发布阻断缺陷。
2. 在干净 checkout 重跑 Gate A。
3. 补齐元数据、许可证、Changelog、Release Notes 和校验和。
4. 创建 tag 和 GitHub Release。
5. 从 Release 下载资产重新安装/启动，完成最终冒烟。

## 4. 验收证据索引

| 目标 | 权威证据 | 当前状态 |
| --- | --- | --- |
| 核心功能可构建 | 干净 checkout 的 CI 日志 | 本机通过，远端 CI 待首次运行 |
| 五类检测和安全边界 | Vitest、Docker、GUI E2E 日志 | 本机完整门禁已通过 |
| 动态非固定样本能力 | `test:acceptance:real-world` 日志与报告 | 6/6 通过，已提交待推送 |
| Ubuntu 24.04 ARM64 | 独立 VM 验收记录、报告与脱敏日志 | 待执行 |
| Rocky 9 SELinux | 独立 VM 验收记录、报告与脱敏日志 | 待执行 |
| 威胁情报在线链 | DBAPP 人工在线验收记录，不保存 Key | 已完成 |
| 项目文档 | README、支持矩阵、验收与发布文档 | 已完成 |
| 可下载版本 | Git tag、GitHub Release、SHA-256 | 待发布 |

## 5. 明确不阻塞 v0.1.0 的事项

- 完整 10～12 台发行版/架构矩阵。
- SSH Agent、加密私钥和 ProxyJump。
- LocalExecutor、一次性 Collector、Offline Import。
- Docker/containerd 专项调查。
- Windows、Kubernetes、多主机和多 Agent。
- macOS Developer ID 签名、公证和自动更新。
- PDF 报告和更多威胁情报 Provider。

这些内容继续由 `TODO_PLAN_REAL_WORLD.md` 跟踪，不能在 v0.1.0 README 中宣称已经支持。

## 6. 下一动作

R0 的本地验证、最小 CI、手动 Docker 工作流、授权 VM 冒烟、无害验收夹具、项目文档与本地发布链路均已完成并提交。当前分支领先远端，`git push --dry-run` 已成功；下一动作是在获得推送授权后触发首次远端 CI，并在获得本地 VM 资源授权后执行 Ubuntu 24.04 ARM64 与 Rocky Linux 9 x86_64/SELinux 的 Gate B。许可证、最终 tag 和 GitHub Release 在两项外部验收通过后完成。

# HuntWarden v0.1.0 收口计划

> 目标：把 HuntWarden 收口为可复现、可验证、可下载的正式项目版本。
>
> 冻结日期：2026-08-17
>
> 最近更新：2026-08-20
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

- [x] VM 验收入口、手动 Docker 工作流、发布材料与 Ubuntu 24.04 ARM64 验收修复均已提交并推送到 `origin/main`。
- [ ] Debian 12 动态场景是容器化行为验收，不等同于完整 systemd VM 验收。
- [x] 新增发行版识别与 `PARTIAL` 规则修复后，完整本地门禁已经重新执行。
- [x] 仓库已增加最小 GitHub Actions 工作流、手动 Docker 验证工作流和状态徽章；`975ea2d` 的远端 CI 已成功。
- [x] Ubuntu 24.04 ARM64 完整依赖 GUI 验收和最低依赖降级补测均已完成；项目所有者确认 Rocky Linux 9 x86_64/SELinux 不属于 `v0.1.0` 发布门槛。
- [ ] 已有 Release Notes 草案和本地发布资产校验和，但尚无最终 `v0.1.0` tag、GitHub Release 及基于最终 tag 生成的校验和。
- [x] 项目所有者已采用 MIT License；`LICENSE`、README 徽章与 `package.json` 的 `license` 元数据一致，description、repository 与 author 已补齐。

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
- [x] 该批结果随后已推送；GitHub CI 在 `2569344`、验收修复提交 `975ea2d` 与文档同步后的 `dafd873` 上均成功。远端最小 CI 不替代 Docker、GUI E2E 与打包等本机扩展门禁。

本轮 Docker 首次执行暴露了固定日期夹具会自然超出 24/168 小时时间窗的问题。Lab-Web 与 Lab-Linux-IR 已改为在容器启动时生成当前 UTC/本地系统日志时间并刷新测试文件 mtime，随后全量 Docker 回归通过；没有通过放宽检测时间窗规避缺陷。

### 2026-08-20 增量验证进度

- [x] `975ea2d` 的 GitHub CI：PASS；覆盖 `npm ci`、Lint、core/renderer typecheck、build、默认测试、Java probe 与生产依赖审计。
- [x] `npm test`：32 个文件通过、7 个跳过；131 项通过、34 项跳过。
- [x] Ubuntu 24.04.4 ARM64 完整依赖验收：真实 GUI、DeepSeek Provider、严格 SSH、Helper 0.4.2；5 个 QUICK、1 个 STANDARD、1 个 DEEP 均完成。
- [x] D1 正式报告：模型生成 v1，47 个完整 Finding/Evidence 引用全部有效，自动校验错误为 0；7 个有效 SCAN 任务远程写、审批与 Action Receipt 均为 0。
- [x] VM 冒烟：4/4 通过；验收后固定夹具、VM、快照和专用 SSH Key 已按验收人确认清理。
- [x] Ubuntu 最低依赖补测：VM 冒烟 4/4；GUI 任务 `TASK-4a7068b5-cb50-46ae-b4ca-c8c796a5b83e` 完成，YARA/JDK 缺失为 `NOT_CHECKED`，auditd 缺失保留 `PARTIAL/ERROR`，Approval/Action Receipt 均为 0；随后 VM 与临时凭据原路径清理。
- [ ] 五套 Docker、动态 Debian、三条 GUI E2E 和 macOS 打包尚未在 `975ea2d` 最终候选上重跑；最近完整扩展门禁仍是 2026-08-17 的记录。

## 2. v0.1.0 硬性退出条件

只有以下五个 Gate 全部完成，才创建 `v0.1.0` 标签。

### Gate A：工作树与自动化门禁

- [x] 审查并拆分当前修改，运行时 Key、`.state`、Evidence、数据库和打包产物均未进入提交。
- [x] `npm ci` 可以从干净工作树完成。
- [x] `npm run audit:prod` 通过；构建工具链告警已单独记录，没有用生产依赖为 0 替代完整审计说明。
- [x] `npm run build` 通过。
- [x] `npm test` 通过：32 个文件通过、7 个按环境跳过；131 项通过、34 项跳过。
- [x] `npm run probe:build` 通过。
- [ ] `npm run test:docker` 最近于 2026-08-17 通过 10/10；Helper 0.4.2 合入后的最终候选仍需重跑。
- [ ] `npm run test:acceptance:real-world` 最近于 2026-08-17 通过 6/6；最终候选仍需重跑。
- [ ] `npm run test:gui:investigation` 最近于 2026-08-17 通过 4/4；最终候选仍需重跑。
- [ ] `npm run test:gui:remediation` 最近于 2026-08-17 通过 3/3；最终候选仍需重跑。
- [ ] `npm run test:gui:recovery` 最近于 2026-08-17 通过 6/6；最终候选仍需重跑。
- [ ] `npm run release:local` 最近于 2026-08-17 通过；最终 tag 前须重新生成 ZIP/DMG、复核 SHA-256 并隔离启动打包 `.app`。

### Gate B：真实 VM 只读验收

`v0.1.0` 只要求 Ubuntu 24.04 ARM64 这一主使用平台完成真实 VM 闭环；其余发行版继续标记为待验收，不阻塞首版发布。

1. **Ubuntu 24.04 ARM64：完成**
   - 完整依赖下的 AppArmor、dpkg、journald、arm64、标准 systemd VM 验收为 `PASS_WITH_LIMITATIONS`；详见 [`VM_UBUNTU_24.04_ARM64_2026-08-20.md`](acceptance/VM_UBUNTU_24.04_ARM64_2026-08-20.md)。
   - 最低依赖下 YARA/auditd/JDK Attach 能力缺失已独立遍历：WebShell/Java 为 `NOT_CHECKED`，execve 历史为 `PARTIAL` 并形成 Linux 分诊 `ERROR` 覆盖项；没有误报安全。
2. **Rocky Linux 9 x86_64 + SELinux Enforcing：后续兼容性矩阵**
   - rpm、`/var/log/secure`、SELinux、x86_64、标准 systemd VM 仍待实机验证，但项目当前主要使用场景以 Ubuntu 为主，该项不阻塞 `v0.1.0`。

| Ubuntu 24.04 ARM64 必须保存 | 状态 |
| --- | --- |
| 官方镜像来源、镜像 ID/版本、架构、内核和测试时间 | PASS |
| Host Key 带外核验；首次发现不自动信任 | PASS |
| Helper 安装、自检、版本和权限 | PASS（Helper 0.4.2） |
| 最低依赖下的能力降级 | PASS |
| 完整依赖下 QUICK、STANDARD、DEEP | PASS |
| 五类单独运行时不存在未选择类别工具调用 | PASS |
| 无害阳性样本与良性对照 | PASS |
| Finding/Evidence/覆盖状态/报告引用 | PASS |
| SCAN 远程写成功次数为 0 | PASS |
| 支持矩阵与脱敏记录回填 | PASS |

### Gate C：GitHub CI

- [x] 新增最小必跑工作流：Node.js 22.19、`npm ci`、build、默认测试和 Java 17 probe；Actions 固定到已核对版本的提交 SHA。
- [x] Docker 与动态 Debian 验收采用独立手动工作流，避免普通提交不稳定和超长运行；Electron E2E 保持发布前本机门禁。
- [x] 最小 CI 不读取真实模型 Key、DBAPP TI Key、SSH 私钥或用户本地配置。
- [x] README 已接入对应工作流徽章；`dafd873` 的远端 CI 已完成且结论为 success。
- [x] 仓库所有者确认该个人项目采用直接更新 `main` 的轻量流程；发布前以干净工作树、完整本地门禁和 main CI 成功作为检查，不额外要求分支保护。

### Gate D：项目文档

- [x] README 提供项目定位、安全不变量、核心能力、安装验证和主要使用入口。
- [x] 架构、长期 TODO、支持矩阵、验收与发布计划保留在 `docs/`，README 不堆叠完整设计细节。
- [x] 真实 VM 验收模板、无害样本部署/清理步骤和失败判定规则均已固化。

### Gate E：发布

- [x] 项目所有者已采用 MIT License；仓库 `LICENSE` 与 README 徽章一致。
- [x] `package.json` 的 description、repository、author 与 `license: MIT` 已补齐。
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

### R2：真实 VM

1. Ubuntu 24.04 ARM64：先最小依赖，再完整依赖，再无害样本。
2. 每次测试完成后销毁或恢复快照，保存脱敏验收记录。
3. 任何失败先记为兼容性 TODO，不把 `PARTIAL/ERROR` 改写为安全。
4. Rocky Linux 9 x86_64/SELinux 作为后续非阻塞兼容性矩阵，使用场景扩大时再执行。

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
| 核心功能可构建 | 干净 checkout 的 CI 日志 | `dafd873` 远端 CI 成功；最终发布提交仍需成功 |
| 五类检测和安全边界 | Vitest、Docker、GUI E2E 日志 | 默认测试当前通过；Docker/GUI 扩展门禁待最终候选重跑 |
| 动态非固定样本能力 | `test:acceptance:real-world` 日志与报告 | 最近 6/6 通过；待最终候选重跑 |
| Ubuntu 24.04 ARM64 | 独立 VM 验收记录、报告与脱敏日志 | 完整依赖与最低依赖均完成，`PASS_WITH_LIMITATIONS` |
| Rocky 9 SELinux | 支持矩阵 | 待执行，非 `v0.1.0` 阻塞项 |
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
- Rocky/AlmaLinux 9 x86_64 + SELinux Enforcing 的实机兼容性验收。

这些内容继续由 `TODO_PLAN_REAL_WORLD.md` 跟踪，不能在 v0.1.0 README 中宣称已经支持。

## 6. 下一动作

最小 CI、Ubuntu 24.04 ARM64 完整依赖与最低依赖 GUI 验收、MIT 许可证和发布文档骨架均已完成。下一动作依次为：在最终候选上重跑 Docker、动态 Debian、三条 GUI E2E 与 macOS 打包；确认 main CI 成功并复核资产校验和；最后创建 `v0.1.0` annotated tag 与 GitHub Release。

# 高密度对象验收

该验收在一次性 Ubuntu 22.04 ARM64 容器中生成真实 `/proc` 进程、10 万个文件和 10 万条活动/gzip 轮转日志。第一阶段通过生产 Helper `3.0.0` 的 `enumerate`/Cursor 路径核对总集、重复项、扫描节点、页数、显式截断、耗时和容器资源；第二阶段通过严格 Host Key 绑定的 SSH 运行生产控制端完整调查，核对首屏异常进程的 Lead/Evidence 时序、分页总集、预算结算及控制端资源。

默认执行 1000 个子进程和 100000 个文件：

```bash
npm run test:acceptance:load
```

1 万进程需要至少 8 GiB 的一次性 Docker 环境并显式确认：

```bash
HUNTWARDEN_LOAD_PROCESS_COUNT=10000 \
HUNTWARDEN_LOAD_CONFIRM=I_HAVE_A_DISPOSABLE_8GB_DOCKER_ENV \
npm run test:acceptance:load
```

脚本始终在退出时删除容器和网络。容器结果用于验证 Helper 分页与资源行为，不替代发行版 VM、systemd 或 SELinux 平台验收。

日志采集按绑定源代次的逻辑位置逐页推进；每页最多返回 500 条、谓词页最多扫描 5000 个候选。默认夹具要求 100000 条活动及 gzip 轮转日志全部返回、身份唯一、扫描数与成本节点一致，并验证活动日志和 gzip 轮转日志哨兵。文件数、单文件扫描字节、时间或源数量超过 Helper 声明边界时仍必须返回 `PARTIAL` 和结构化 Gap；本验收不将不同来源合并成全局时间排序。`containerStats` 是验收结束时快照，不是峰值或连续资源曲线。

每次成功执行都会写入 Helper 结果 `result-<进程数>p-<文件数>f-<日志数>l.json` 和控制端结果 `control-result-<进程数>p.json`。可以分别通过 `HUNTWARDEN_LOAD_RESULT`、`HUNTWARDEN_LOAD_CONTROL_RESULT` 指定其他结果路径，便于 CI 保存为验收制品。

`resourceSampling` 保存 Helper 枚举期间的 Docker 周期采样，包含相对时间、CPU、内存、IO 与进程数；采样最大值不代表采样间隔内的瞬时峰值。各 Namespace 另记录首屏延迟、逐页延迟和总耗时。控制端以 50 ms 间隔保存进程 RSS/heap，并记录 CPU、首 Lead、首 Evidence、bootstrap 完成时间、首保全与末进程页事件序号，以及 PRESET/DISCOVERY/MODEL 预算的 used/reserved/remaining。采样不足或任何预算预留未归零时验收失败。

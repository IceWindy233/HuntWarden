# JVM Attach 流量验收

该验收使用 `tomcat:9.0-jdk17-temurin-jammy` 一次性容器，部署固定摘要的 Spring MVC `5.3.39`、真实 `/spring/health` Controller、Interceptor 和 `/ws/{id}` WebSocket endpoint。在静态页与 Spring Controller 混合的 8 路持续 HTTP 请求期间连续执行 12 次生产 Helper `jvm.tomcat.inventory`，核对请求失败数、P95/最大延迟、四类必需组件、每次 `probeCalls` 成本和 Attach 前后的稳定 JVM identity。

```bash
npm run test:docker
```

成功执行会生成 `result-docker.json`。该结果验证隔离 Tomcat 夹具在受控并发流量下的可用性和探针边界，不能代替真实业务 JVM 的流量分布、堆规模、GC、框架增强和长期副作用验收。

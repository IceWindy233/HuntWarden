# HuntWarden Tomcat 只读探针

该 Java 17 Agent 通过 Attach API 在一次 `list_components` 请求中采集 Tomcat 运行时组件与受控诊断摘要。探针不卸载组件、不重定义类、不重启 JVM；只有显式 `dump_class` 会临时安装 `ClassFileTransformer` 并通过 retransformation 捕获原始 Class 字节，随后立即移除 Transformer。

## `list_components` 输出

- `components`：Filter、Servlet、Listener、Valve，以及尽力枚举的 WebSocket Endpoint。运行时对象会携带 `classLoaderId`、CodeSource、ProtectionDomain 与 Module 身份。
- `diagnostics.jvm`：JVM 版本、启动时间、经过敏感参数脱敏的 JVM 参数、Java/native Agent 摘要，以及与 Tomcat 定位有关的系统属性。
- `diagnostics.threads`：线程状态计数与最多 256 个线程样本；每个样本最多 8 帧，并尽力关联 ContextClassLoader。
- `diagnostics.network`：Tomcat JMX ThreadPool/Connector/GlobalRequestProcessor 摘要。它不是操作系统 socket 表，不能替代 `/proc` 或主机侧网络取证。
- `diagnostics.collectors`：每个反射/诊断采集器的 `OK | NOT_PRESENT | PARTIAL` 状态。跨版本反射失败、对象图或数量达到硬上限时，顶层 `partial` 必为 `true`，错误保留在对应采集器中。

WebSocket 标准 API 不提供已注册 Endpoint 的读取接口。探针仅在 Tomcat WebSocket ServerContainer 的映射对象中执行有深度与节点上限的只读反射，因此 Tomcat 内部布局无法识别时会返回 `PARTIAL`，不会把“未枚举到”解释为不存在。

当前 Java 切片不枚举 Spring MVC Interceptor/Controller，也不直接读取操作系统 TCP/UDP 连接；这些能力应由后续专用框架适配器和主机 Helper 完成。

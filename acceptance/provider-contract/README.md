# Provider 协议契约验收

运行：

```bash
npm run test:acceptance:provider-contract
```

该验收启动一次性本机 HTTP/SSE Provider，分别验证 `openai-completions` 与 `openai-responses`：

- 请求确实经过 TCP/HTTP、携带模型、消息和函数工具 JSON Schema；
- 流式 Tool Call 参数被拆分发送后能够正确重组；
- 完成原因和 token usage 能够被运行时解析；
- `authentication: none` 仅可连接回环地址，并可通过 SDK 的前置凭据检查。
- 首次 HTTP 429 按有界策略只重试一次，每次状态和耗时均可单独审计；
- SSE 首分片后停滞由独立 `AbortSignal` 在硬超时内结束为 `aborted`，生产运行时将非完整流归为 `PROVIDER_FAILURE`（SDK 的响应头超时不作为替代）；空 assistant 不通过 Tool Call 冒烟。

本机 Provider 使用固定非秘密占位值满足 OpenAI SDK 的客户端前置条件，服务端不据此认证。该验收证明协议适配和真实网络栈可执行，不能替代厂商 Provider 的凭据、限流、代理、模型行为和服务可用性联合验收。

最近一次结构化结果写入 `result-local.json`。

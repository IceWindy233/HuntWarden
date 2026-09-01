import type { CheckCategory } from "../domain/types.js";

/**
 * v2 初始授权常量。类别由分析师在创建任务时显式选择，因此类别内最低
 * Preset 的这些授权不是模型扩权；模型后续 Scope/Sensitive 扩展仍必须走请求。
 */
const probesByCategory: Partial<Record<CheckCategory, readonly string[]>> = Object.freeze({
  java_memory_shell: Object.freeze(["jvm.tomcat.inventory", "jvm.class.inspect"]),
});
const discoveredScopesByCategory: Partial<Record<CheckCategory, Readonly<{ namespace: "file"; sourceNamespace: "web_root"; maximum: number }>>> = Object.freeze({
  webshell: Object.freeze({ namespace: "file", sourceNamespace: "web_root", maximum: 20 }),
});
const fixedScopesByCategory: Partial<Record<CheckCategory, readonly string[]>> = Object.freeze({
  linux_intrusion_triage: Object.freeze(["/usr/bin", "/tmp"]),
});

export const INITIAL_GRANT_POLICY = Object.freeze({ probesByCategory, discoveredScopesByCategory, fixedScopesByCategory });

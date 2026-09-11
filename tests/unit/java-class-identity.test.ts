import { describe, expect, it } from "vitest";
import type { FactRecord } from "../../src/protocol-v2/types.js";
import { observedJavaClassLoaderIds, selectJavaClassInspectionTargets } from "../../src/investigation/java-class-identity.js";

function component(subjectRef: string, className: string, classLoaderId: string, context = "/lab"): Pick<FactRecord, "namespace" | "subjectRef" | "privatePayload"> {
  return {
    namespace: "java_component", subjectRef,
    privatePayload: { className, classLoaderId, context, componentKind: "filter", name: "Filter" },
  };
}

describe("Java 精确类身份选择", () => {
  it("只返回同一精确类名在组件或类 Fact 中观察到的 loader", () => {
    expect(observedJavaClassLoaderIds([
      component("OBJ-A", "lab.Filter", "loader-2"),
      component("OBJ-B", "lab.Filter", "loader-1"),
      { namespace: "class", subjectRef: "OBJ-C", privatePayload: { className: "lab.Filter", loaderId: "loader-3" } },
      component("OBJ-D", "lab.Other", "loader-4"),
      component("OBJ-E", "lab.Filter", "unknown"),
    ], "lab.Filter")).toEqual(["loader-1", "loader-2", "loader-3"]);
    expect(observedJavaClassLoaderIds([], "lab.Filter")).toEqual([]);
  });

  it("同一逻辑组件有精确 Loader 时忽略 unknown 占位记录", () => {
    const selected = selectJavaClassInspectionTargets([
      component("OBJ-UNKNOWN", "example.Filter", "unknown"),
      component("OBJ-EXACT", "example.Filter", "loader-A"),
    ], ["OBJ-UNKNOWN", "OBJ-EXACT"], 20);
    expect(selected).toEqual({ targets: [{ className: "example.Filter", classLoaderId: "loader-A" }], incomplete: false });
  });

  it("只有占位 Loader 或超过探针上限时保留覆盖缺口", () => {
    expect(selectJavaClassInspectionTargets([
      component("OBJ-UNKNOWN", "example.Filter", "unknown"),
    ], ["OBJ-UNKNOWN"], 20)).toEqual({ targets: [], incomplete: true });
    const many = [component("OBJ-A", "example.A", "loader-A"), component("OBJ-B", "example.B", "loader-B")];
    expect(selectJavaClassInspectionTargets(many, ["OBJ-A", "OBJ-B"], 1)).toMatchObject({ targets: [{ className: "example.A", classLoaderId: "loader-A" }], incomplete: true });
  });
});

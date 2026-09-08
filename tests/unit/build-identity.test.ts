import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveControllerBuildIdentity } from "../../src/runtime/build-identity.js";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("控制端构建身份", () => {
  it("接受显式完整提交并独立记录干净状态", () => {
    vi.stubEnv("HUNTWARDEN_BUILD_COMMIT", "a".repeat(40));
    vi.stubEnv("HUNTWARDEN_BUILD_CLEAN", "true");
    expect(resolveControllerBuildIdentity()).toEqual({ commit: "a".repeat(40), clean: true });
  });

  it("拒绝格式无效的构建提交", () => {
    vi.stubEnv("HUNTWARDEN_BUILD_COMMIT", "main");
    expect(() => resolveControllerBuildIdentity()).toThrow(/40 位/);
  });
});

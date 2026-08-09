// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NewTaskDialog } from "../../src/renderer/components/NewTaskDialog.js";
import type { ConfigProfile } from "../../src/gui/contracts.js";
import { testConfig, testTask } from "../helpers.js";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function profile(): ConfigProfile {
  return {
    profileId: "triage", name: "Triage", provider: "openai", model: "test", active: true,
    updatedAt: new Date().toISOString(), config: testConfig("/tmp/huntwarden-triage-ui"), yamlPreview: "",
  };
}

describe("新建 Linux 入侵分诊任务", () => {
  it("默认选择分诊并提交预设、时间窗和结构化 IOC", async () => {
    const createTask = vi.fn(async (input) => ({ ...testTask(), ...input, taskId: "TASK-created" }));
    Object.defineProperty(window, "huntwarden", { configurable: true, value: { createTask } });
    render(<NewTaskDialog profile={profile()} onClose={vi.fn()} onCreated={vi.fn()} notify={vi.fn()} />);

    expect(screen.getByRole("button", { name: /Linux 入侵分诊/ }).className).toContain("active");
    fireEvent.change(screen.getByLabelText(/扫描预设/), { target: { value: "DEEP" } });
    expect((screen.getByLabelText("调查时间窗（小时）") as HTMLInputElement).value).toBe("720");
    fireEvent.change(screen.getByLabelText("IOC 文件 Hash"), { target: { value: `${"A".repeat(64)}, ${"B".repeat(64)}` } });
    fireEvent.change(screen.getByLabelText("IOC 域名"), { target: { value: "example.org\nbeacon.example" } });
    fireEvent.change(screen.getByLabelText("IOC 文件路径"), { target: { value: "/tmp/a, /opt/b" } });
    fireEvent.click(screen.getByRole("button", { name: "创建任务" }));

    await waitFor(() => expect(createTask).toHaveBeenCalledTimes(1));
    expect(createTask.mock.calls[0]?.[0]).toMatchObject({
      profile: "DEEP", timeWindowHours: 720,
      checks: expect.arrayContaining(["linux_intrusion_triage"]),
      iocs: {
        hash: ["A".repeat(64), "B".repeat(64)],
        domain: ["example.org", "beacon.example"],
        path: ["/tmp/a", "/opt/b"],
      },
    });
  });
});

// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TaskWorkspace } from "../../src/renderer/components/TaskWorkspace.js";
import type { TaskSnapshot } from "../../src/gui/contracts.js";
import { testTask } from "../helpers.js";

afterEach(cleanup);

describe("TaskWorkspace Agent 流式预览", () => {
  it("在调查视图即时展示增量文本和预览截断状态", () => {
    const task = { ...testTask(), status: "RUNNING" as const };
    const snapshot: TaskSnapshot = {
      task,
      findings: [], evidence: [], approvals: [], actionReceipts: [], reports: [], audit: [],
      conversation: [], toolRuns: [],
    };

    render(<TaskWorkspace
      snapshot={snapshot}
      refresh={vi.fn(async () => undefined)}
      notify={vi.fn()}
      liveStream={{
        taskId: task.taskId,
        streamId: "STREAM-1",
        text: "正在核验 WebShell 候选文件…",
        timestamp: Date.now(),
        phase: "streaming",
        truncated: true,
      }}
    />);

    expect(screen.getByText("SEC AGENT · LIVE")).toBeTruthy();
    expect(screen.getByText("正在核验 WebShell 候选文件…")).toBeTruthy();
    expect(screen.getByText(/实时预览已达 512K 字符/)).toBeTruthy();
    expect(document.querySelector(".stream-cursor")).toBeTruthy();
  });
});

// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("归档需要确认，并可从只读归档状态恢复", async () => {
    const archiveTask = vi.fn(async () => testTask());
    const restoreTask = vi.fn(async () => testTask());
    Object.defineProperty(window, "huntwarden", { configurable: true, value: { archiveTask, restoreTask } });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const task = { ...testTask(), status: "COMPLETED" as const };
    const base: TaskSnapshot = {
      task,
      findings: [], evidence: [], approvals: [], actionReceipts: [], reports: [], audit: [],
      conversation: [], toolRuns: [],
    };
    const refresh = vi.fn(async () => undefined);
    const view = render(<TaskWorkspace snapshot={base} refresh={refresh} notify={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "归档", exact: true }));
    expect(archiveTask).not.toHaveBeenCalled();
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "归档", exact: true }));
    await waitFor(() => expect(archiveTask).toHaveBeenCalledWith(task.taskId));

    view.rerender(<TaskWorkspace snapshot={{ ...base, task: { ...task, archivedAt: new Date().toISOString() } }} refresh={refresh} notify={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "重新生成报告" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "恢复归档" }));
    await waitFor(() => expect(restoreTask).toHaveBeenCalledWith(task.taskId));
    confirm.mockRestore();
  });
});

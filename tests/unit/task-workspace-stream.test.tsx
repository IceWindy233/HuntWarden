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

  it("只对 Agent 消息应用 Markdown，分析师与工具输出保持纯文本", () => {
    const task = { ...testTask(), status: "COMPLETED" as const };
    const snapshot: TaskSnapshot = {
      task,
      findings: [], evidence: [], approvals: [], actionReceipts: [], reports: [], audit: [], toolRuns: [],
      conversation: [
        { role: "user", text: "## 不应成为标题", timestamp: 1 },
        { role: "assistant", text: "## 已渲染标题\n\n- 条目一\n- 条目二", timestamp: 2 },
        { role: "tool", toolName: "probe", text: "**原始工具文本**", timestamp: 3 },
      ],
    };

    render(<TaskWorkspace snapshot={snapshot} refresh={vi.fn(async () => undefined)} notify={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "已渲染标题", level: 2 })).toBeTruthy();
    expect(screen.getByText("## 不应成为标题").tagName).toBe("DIV");
    expect(screen.getByText("**原始工具文本**").tagName).toBe("DIV");
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

  it("调查完成后必须由分析师确认才生成首版报告", async () => {
    const task = { ...testTask(), status: "COMPLETED" as const };
    const report = {
      reportId: "REPORT-1", taskId: task.taskId, version: 1, path: "/tmp/v0001.md",
      sha256: "a".repeat(64), generationMode: "FALLBACK" as const, validationErrors: [], createdAt: new Date().toISOString(),
    };
    const generateReport = vi.fn(async () => report);
    Object.defineProperty(window, "huntwarden", { configurable: true, value: {
      generateReport,
      listReports: vi.fn(async () => [report]),
      readReport: vi.fn(async () => ({ report, markdown: "# 报告" })),
    } });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const snapshot: TaskSnapshot = {
      task,
      findings: [], evidence: [], approvals: [], actionReceipts: [], reports: [], audit: [],
      conversation: [], toolRuns: [],
    };
    render(<TaskWorkspace snapshot={snapshot} refresh={vi.fn(async () => undefined)} notify={vi.fn()} />);

    expect(screen.getByText("调查已完成，报告待确认")).toBeTruthy();
    const workspace = document.querySelector(".workspace");
    expect(workspace?.children).toHaveLength(6);
    expect(workspace?.children[1]?.classList.contains("workspace-notices")).toBe(true);
    expect(workspace?.children[3]?.classList.contains("task-tabs")).toBe(true);
    expect(workspace?.children[4]?.classList.contains("task-content")).toBe(true);
    expect(workspace?.children[5]?.classList.contains("steering-composer")).toBe(true);
    expect(screen.getByRole("main", { name: "调查内容" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "确认并生成报告" }));
    expect(generateReport).not.toHaveBeenCalled();
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "确认并生成报告" }));
    await waitFor(() => expect(generateReport).toHaveBeenCalledWith(task.taskId));
    confirm.mockRestore();
  });
});

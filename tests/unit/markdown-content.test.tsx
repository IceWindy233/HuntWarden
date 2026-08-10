// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MarkdownContent } from "../../src/renderer/components/MarkdownContent.js";

afterEach(cleanup);

describe("安全 Markdown 渲染", () => {
  it("渲染 CommonMark 与 GFM，同时阻止 HTML、远程图片和链接导航", () => {
    const markdown = [
      "## 调查结论",
      "",
      "**高亮结论**与 `EV-123`",
      "",
      "| 检测项 | 状态 |",
      "| --- | --- |",
      "| WebShell | NO_FINDING |",
      "",
      "- [x] 已完成",
      "- [ ] 待复核",
      "",
      "```json",
      "{\"status\":\"success\"}",
      "```",
      "",
      "[外部情报](https://example.com/report)",
      "",
      "![远程图](https://example.com/tracker.png)",
      "",
      "<script>window.pwned = true</script>",
    ].join("\n");

    const view = render(<MarkdownContent text={markdown} />);

    expect(screen.getByRole("heading", { name: "调查结论", level: 2 })).toBeTruthy();
    expect(screen.getByText("高亮结论").tagName).toBe("STRONG");
    expect(screen.getByRole("table")).toBeTruthy();
    expect(view.container.querySelector(".markdown-table-wrap")).toBeTruthy();
    expect(view.container.querySelector("pre code")?.textContent).toContain('"status":"success"');
    expect(screen.getByText(/图片已阻止加载/)).toBeTruthy();
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("script")).toBeNull();
    const link = screen.getByRole("link", { name: "外部情报" });
    expect(fireEvent.click(link)).toBe(false);
  });
});

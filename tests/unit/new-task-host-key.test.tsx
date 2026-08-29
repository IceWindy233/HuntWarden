// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NewTaskDialog } from "../../src/renderer/components/NewTaskDialog.js";
import type { ConfigProfile } from "../../src/gui/contracts.js";
import type { SshHostKeyDiscovery } from "../../src/executor/ssh-host-key-service.js";
import { testConfig } from "../helpers.js";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function profile(): ConfigProfile {
  return {
    profileId: "test", name: "Test", provider: "deepseek", model: "test-model", active: true,
    updatedAt: new Date().toISOString(), config: testConfig("/tmp/huntwarden-host-key-ui"), yamlPreview: "",
  };
}

describe("新建任务 Host Key 发现", () => {
  it("未知 Key 不自动信任，只有二次确认后才写入并填充指纹", async () => {
    const unknown: SshHostKeyDiscovery = {
      host: "127.0.0.1", port: 22, resolvedAddresses: [{ address: "127.0.0.1", family: 4 }],
      algorithm: "ssh-ed25519", fingerprint: `SHA256:${"A".repeat(43)}`, keySummary: "AAAA…BBBB",
      trustStatus: "UNKNOWN", knownHostsPath: "/tmp/known_hosts", knownHostsExists: false,
      matchedHostTokens: [], existingFingerprints: [],
    };
    const trusted = { ...unknown, trustStatus: "TRUSTED" as const, knownHostsExists: true, matchedHostTokens: ["127.0.0.1"] };
    const discoverSshHostKey = vi.fn(async () => unknown);
    const confirmSshHostKey = vi.fn(async () => trusted);
    Object.defineProperty(window, "huntwarden", { configurable: true, value: { discoverSshHostKey, confirmSshHostKey } });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<NewTaskDialog profile={profile()} onClose={vi.fn()} onCreated={vi.fn()} notify={vi.fn()} />);

    const knownHosts = screen.getByLabelText("known_hosts") as HTMLInputElement;
    fireEvent.change(knownHosts, { target: { value: "/tmp/known_hosts" } });
    fireEvent.click(screen.getByRole("button", { name: "解析 Host Key" }));
    await waitFor(() => expect(discoverSshHostKey).toHaveBeenCalledWith({ host: "127.0.0.1", port: 22, knownHostsPath: "/tmp/known_hosts" }));
    expect(await screen.findByText("未知 Host Key")).toBeTruthy();
    expect((screen.getByPlaceholderText("SHA256:...") as HTMLInputElement).value).toBe("");

    fireEvent.click(screen.getByRole("button", { name: "确认信任并写入" }));
    expect(confirmSshHostKey).not.toHaveBeenCalled();
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "确认信任并写入" }));
    await waitFor(() => expect(confirmSshHostKey).toHaveBeenCalledWith({
      host: "127.0.0.1", port: 22, knownHostsPath: "/tmp/known_hosts", expectedFingerprint: unknown.fingerprint,
    }));
    expect((screen.getByPlaceholderText("SHA256:...") as HTMLInputElement).value).toBe(unknown.fingerprint);
    expect(screen.getByText("已信任")).toBeTruthy();
  });

  it("known_hosts 冲突时清空旧指纹并展示阻断状态", async () => {
    const changed: SshHostKeyDiscovery = {
      host: "server.example", port: 2222, resolvedAddresses: [{ address: "192.0.2.10", family: 4 }],
      algorithm: "ssh-ed25519", fingerprint: `SHA256:${"B".repeat(43)}`, keySummary: "AAAA…CCCC",
      trustStatus: "CHANGED", knownHostsPath: "/tmp/known_hosts", knownHostsExists: true,
      matchedHostTokens: ["[server.example]:2222"], existingFingerprints: [`SHA256:${"C".repeat(43)}`],
    };
    Object.defineProperty(window, "huntwarden", { configurable: true, value: {
      discoverSshHostKey: vi.fn(async () => changed), confirmSshHostKey: vi.fn(),
    } });
    render(<NewTaskDialog profile={profile()} onClose={vi.fn()} onCreated={vi.fn()} notify={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("目标主机"), { target: { value: changed.host } });
    fireEvent.change(screen.getByLabelText("SSH 端口"), { target: { value: String(changed.port) } });
    fireEvent.change(screen.getByLabelText("known_hosts"), { target: { value: changed.knownHostsPath } });
    fireEvent.change(screen.getByPlaceholderText("SHA256:..."), { target: { value: "SHA256:stale" } });
    fireEvent.click(screen.getByRole("button", { name: "解析 Host Key" }));
    expect(await screen.findByText("Host Key 已变化")).toBeTruthy();
    expect((screen.getByPlaceholderText("SHA256:...") as HTMLInputElement).value).toBe("");
    expect(screen.queryByRole("button", { name: "确认信任并写入" })).toBeNull();
  });
});

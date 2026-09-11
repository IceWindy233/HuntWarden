// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConfigProfile } from "../../src/gui/contracts.js";
import { SettingsView } from "../../src/renderer/components/SettingsView.js";
import { testConfig } from "../helpers.js";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("V2 配置中心", () => {
  it("编辑并保存运行时实际消费的预算与默认时间窗", async () => {
    const config = testConfig("/tmp/huntwarden-settings-v2");
    const profile: ConfigProfile = {
      profileId: "v2", name: "V2", provider: "openai", model: "gpt-5.6-terra", active: true,
      updatedAt: new Date().toISOString(), config, yamlPreview: "",
    };
    const validateConfigProfile = vi.fn(async () => ({ valid: true, issues: [], warnings: [] }));
    const saveConfigProfile = vi.fn(async (input) => ({ ...profile, ...input, updatedAt: new Date().toISOString() }));
    Object.defineProperty(window, "huntwarden", {
      configurable: true,
      value: {
        listModelProviders: vi.fn(async () => [{ id: "openai", name: "OpenAI", modelCount: 1 }]),
        getCredentialStatus: vi.fn(async (provider: string) => ({ provider, configured: false, persistent: false })),
        listKnownHashDataSets: vi.fn(async () => []),
        getConfigProfile: vi.fn(async () => profile),
        listModels: vi.fn(async () => [{
          id: "gpt-5.6-terra", name: "GPT-5.6 Terra", provider: "openai", protocol: "openai-responses",
          reasoning: true, thinkingLevels: ["medium"], contextWindow: 131_072, maxTokens: 16_384,
        }]),
        validateConfigProfile,
        saveConfigProfile,
      },
    });

    render(<SettingsView
      profiles={[profile]}
      activeProfileId={profile.profileId}
      onProfilesChanged={vi.fn(async () => undefined)}
      notify={vi.fn()}
    />);

    await screen.findByRole("heading", { name: "V2 远程预算" });
    fireEvent.change(screen.getByLabelText("Preset 远程调用"), { target: { value: "321" } });
    fireEvent.change(screen.getByLabelText("WebShell 默认时间窗（小时）"), { target: { value: "48" } });
    fireEvent.click(screen.getByRole("button", { name: "保存配置" }));

    await waitFor(() => expect(saveConfigProfile).toHaveBeenCalledTimes(1));
    const savedConfig = saveConfigProfile.mock.calls[0]?.[0].config;
    expect(validateConfigProfile).toHaveBeenCalledWith(expect.objectContaining({
      protocolV2: expect.objectContaining({
        remoteBudget: expect.objectContaining({ preset: expect.objectContaining({ remoteCalls: 321 }) }),
      }),
      webshell: { modifiedWithinHours: 48 },
    }));
    expect(savedConfig.protocolV2.remoteBudget.preset.remoteCalls).toBe(321);
    expect(savedConfig.webshell.modifiedWithinHours).toBe(48);
  });
});

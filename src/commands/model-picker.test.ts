import { describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import { promptDefaultModel } from "./model-picker.js";
import { makePrompter } from "./onboarding/__tests__/test-utils.js";

const loadModelCatalog = vi.hoisted(() => vi.fn());
vi.mock("../agents/model-catalog.js", () => ({
  loadModelCatalog,
}));

vi.mock("../agents/auth-profiles.js", () => ({
  ensureAuthProfileStore: () => ({ version: 1, profiles: {} }),
  listProfilesForProvider: () => [],
}));

vi.mock("../agents/model-auth.js", () => ({
  resolveEnvApiKey: () => undefined,
  getCustomProviderApiKey: () => undefined,
}));

describe("model-picker (unit)", () => {
  it("includes copilot-proxy/raptor-mini-preview when present in catalog", async () => {
    loadModelCatalog.mockResolvedValue([
      {
        provider: "copilot-proxy",
        id: "raptor-mini-preview",
        name: "Raptor Mini (Preview)",
        contextWindow: 200000,
      },
    ]);

    const select = vi.fn(async (params) => params.options[0]?.value ?? "");
    const prompter = makePrompter({ select });
    const config = { agents: { defaults: {} } } as OpenClawConfig;

    await promptDefaultModel({
      config,
      prompter,
      allowKeep: false,
      includeManual: false,
      ignoreAllowlist: true,
    });

    const options = select.mock.calls[0]?.[0]?.options ?? [];
    expect(options.some((opt) => opt.value === "copilot-proxy/raptor-mini-preview")).toBe(true);
  });
});

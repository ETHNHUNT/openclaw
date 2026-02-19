import { describe, test, expect, vi } from "vitest";

describe("copilot-proxy plugin model registration", () => {
  test("registers raptor-mini-preview with 200k contextWindow", async () => {
    const { default: copilotProxy } = await import("./index.js");

    let capturedProvider: any = null;

    const mockApi = {
      registerProvider(provider: any) {
        capturedProvider = provider;
      },
    } as any;

    // Register plugin (should call registerProvider)
    copilotProxy.register(mockApi as any);

    expect(capturedProvider).toBeTruthy();
    expect(capturedProvider.id).toBe("copilot-proxy");

    // Find the auth entry and call its run() with a fake prompter that returns
    // a base URL and a single model id 'raptor-mini-preview'
    const authEntry = capturedProvider.auth?.[0];
    expect(authEntry).toBeTruthy();

    const ctx = {
      prompter: {
        text: vi
          .fn()
          // baseUrl input
          .mockImplementationOnce(() => Promise.resolve("http://localhost:3000/v1"))
          // model ids input -> only include raptor-mini-preview to force creation
          .mockImplementationOnce(() => Promise.resolve("raptor-mini-preview")),
      },
    } as any;

    const result = await authEntry.run(ctx as any);

    const models = result?.configPatch?.models?.providers?.["copilot-proxy"]?.models ?? [];
    const raptor = models.find((m: any) => m.id === "raptor-mini-preview");

    expect(raptor).toBeDefined();
    expect(raptor.contextWindow).toBe(200000);
  });
});

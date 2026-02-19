import type { Api, Model } from "@mariozechner/pi-ai";
import type { ModelRegistry } from "../../agents/pi-model-discovery.js";
import type { RuntimeEnv } from "../../runtime.js";
import type { ModelRow } from "./list.types.js";
import { resolveForwardCompatModel } from "../../agents/model-forward-compat.js";
import { parseModelRef } from "../../agents/model-selection.js";
import { resolveConfiguredEntries } from "./list.configured.js";
import { formatErrorWithStack } from "./list.errors.js";
import { loadModelRegistry, toModelRow } from "./list.registry.js";
import { printModelTable } from "./list.table.js";
import { DEFAULT_PROVIDER, ensureFlagCompatibility, isLocalBaseUrl, modelKey } from "./shared.js";

/**
 * Check if a model is Antigravity Opus 4.6 (forward-compat variants that are disabled).
 * Forward-compat resolution for Antigravity Opus 4.6 is disabled; users should
 * explicitly configure these models in ~/.openclaw/models.json if they wish to use them.
 */
function isAntigravityRuntimeForwardCompat(provider: string, modelId: string): boolean {
  return (
    provider === "google-antigravity" &&
    (modelId === "claude-opus-4-6" || modelId === "claude-opus-4-6-thinking")
  );
}

export async function modelsListCommand(
  opts: {
    all?: boolean;
    local?: boolean;
    provider?: string;
    json?: boolean;
    plain?: boolean;
  },
  runtime: RuntimeEnv,
) {
  ensureFlagCompatibility(opts);
  const { loadConfig } = await import("../../config/config.js");
  const { ensureAuthProfileStore } = await import("../../agents/auth-profiles.js");
  const cfg = loadConfig();
  const authStore = ensureAuthProfileStore();
  const providerFilter = (() => {
    const raw = opts.provider?.trim();
    if (!raw) {
      return undefined;
    }
    const parsed = parseModelRef(`${raw}/_`, DEFAULT_PROVIDER);
    return parsed?.provider ?? raw.toLowerCase();
  })();

  let models: Model<Api>[] = [];
  let modelRegistry: ModelRegistry | undefined;
  let availableKeys: Set<string> | undefined;
  let availabilityErrorMessage: string | undefined;
  try {
    const loaded = await loadModelRegistry(cfg);
    modelRegistry = loaded.registry;
    models = loaded.models;
    availableKeys = loaded.availableKeys;
    availabilityErrorMessage = loaded.availabilityErrorMessage;
  } catch (err) {
    runtime.error(`Model registry unavailable:\n${formatErrorWithStack(err)}`);
    process.exitCode = 1;
    return;
  }
  if (availabilityErrorMessage !== undefined) {
    runtime.error(
      `Model availability lookup failed; falling back to auth heuristics for discovered models: ${availabilityErrorMessage}`,
    );
  }

  const modelByKey = new Map(models.map((model) => [modelKey(model.provider, model.id), model]));

  const { entries } = resolveConfiguredEntries(cfg);
  const configuredByKey = new Map(entries.map((entry) => [entry.key, entry]));

  const rows: ModelRow[] = [];

  if (opts.all) {
    const sorted = [...models].toSorted((a, b) => {
      const p = a.provider.localeCompare(b.provider);
      if (p !== 0) {
        return p;
      }
      return a.id.localeCompare(b.id);
    });

    for (const model of sorted) {
      if (providerFilter && model.provider.toLowerCase() !== providerFilter) {
        continue;
      }
      if (opts.local && !isLocalBaseUrl(model.baseUrl)) {
        continue;
      }
      const key = modelKey(model.provider, model.id);
      const configured = configuredByKey.get(key);
      rows.push(
        toModelRow({
          model,
          key,
          tags: configured ? Array.from(configured.tags) : [],
          aliases: configured?.aliases ?? [],
          availableKeys,
          cfg,
          authStore,
        }),
      );
    }
  } else {
    for (const entry of entries) {
      if (providerFilter && entry.ref.provider.toLowerCase() !== providerFilter) {
        continue;
      }
      let model = modelByKey.get(entry.key);
      if (!model && modelRegistry) {
        // Antigravity forward-compat synthesis is disabled;
        // users should explicitly configure models in ~/.openclaw/models.json
        const isAntigravityForwardCompat =
          entry.ref.provider === "google-antigravity" &&
          (entry.ref.model === "claude-opus-4-6" || entry.ref.model === "claude-opus-4-6-thinking");
        if (!isAntigravityForwardCompat) {
          const forwardCompat = resolveForwardCompatModel(
            entry.ref.provider,
            entry.ref.model,
            modelRegistry,
          );
          if (forwardCompat) {
            model = forwardCompat;
            modelByKey.set(entry.key, forwardCompat);
          }
        }
      }
      if (!model && !isAntigravityRuntimeForwardCompat(entry.ref.provider, entry.ref.model)) {
        const { resolveModel } = await import("../../agents/pi-embedded-runner/model.js");
        model = resolveModel(entry.ref.provider, entry.ref.model, undefined, cfg).model;
      }
      if (opts.local && model && !isLocalBaseUrl(model.baseUrl)) {
        continue;
      }
      if (opts.local && !model) {
        continue;
      }
      rows.push(
        toModelRow({
          model,
          key: entry.key,
          tags: Array.from(entry.tags),
          aliases: entry.aliases,
          availableKeys,
          cfg,
          authStore,
        }),
      );
    }
  }

  if (rows.length === 0) {
    runtime.log("No models found.");
    return;
  }

  printModelTable(rows, runtime, opts);
}

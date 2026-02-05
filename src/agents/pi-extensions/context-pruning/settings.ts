import { parseDurationMs } from "../../../cli/parse-duration.js";

export type ContextPruningToolMatch = {
  allow?: string[];
  deny?: string[];
};
export type ContextPruningMode = "off" | "cache-ttl";

export type ContextPruningConfig = {
  mode?: ContextPruningMode;
  /** TTL to consider cache expired (duration string, default unit: minutes). */
  ttl?: string;
  keepLastAssistants?: number;
  softTrimRatio?: number;
  hardClearRatio?: number;
  minPrunableToolChars?: number;
  tools?: ContextPruningToolMatch;
  softTrim?: {
    maxChars?: number;
    headChars?: number;
    tailChars?: number;
  };
  hardClear?: {
    enabled?: boolean;
    placeholder?: string;
  };
};

export type EffectiveContextPruningSettings = {
  mode: Exclude<ContextPruningMode, "off">;
  ttlMs: number;
  keepLastAssistants: number;
  softTrimRatio: number;
  hardClearRatio: number;
  minPrunableToolChars: number;
  tools: ContextPruningToolMatch;
  softTrim: {
    maxChars: number;
    headChars: number;
    tailChars: number;
  };
  hardClear: {
    enabled: boolean;
    placeholder: string;
  };
};

export const DEFAULT_CONTEXT_PRUNING_SETTINGS: EffectiveContextPruningSettings = {
  mode: "cache-ttl",
  ttlMs: 5 * 60 * 1000,
  keepLastAssistants: 3,
  softTrimRatio: 0.3,
  hardClearRatio: 0.5,
  minPrunableToolChars: 50_000,
  tools: {},
  softTrim: {
    maxChars: 4_000,
    headChars: 1_500,
    tailChars: 1_500,
  },
  hardClear: {
    enabled: true,
    placeholder: "[Old tool result content cleared]",
  },
};

/**
 * Computes context-window-aware pruning thresholds.
 * For small context windows (<=32K), use more aggressive pruning to prevent wasteful token usage.
 * Only adjusts values that are at their defaults to respect explicit user configuration.
 * @param contextWindowTokens The model's context window size in tokens
 * @param baseSettings The base settings to adjust
 * @returns Adjusted settings with context-aware thresholds
 */
export function makeContextAwareSettings(
  contextWindowTokens: number | undefined,
  baseSettings: EffectiveContextPruningSettings,
): EffectiveContextPruningSettings {
  if (!contextWindowTokens || contextWindowTokens <= 0) {
    return baseSettings;
  }

  const settings = { ...baseSettings };

  // For smaller context windows, be more aggressive with pruning
  // Only adjust if minPrunableToolChars is at the default value
  if (
    contextWindowTokens <= 32_000 &&
    baseSettings.minPrunableToolChars === DEFAULT_CONTEXT_PRUNING_SETTINGS.minPrunableToolChars
  ) {
    // Use 10% of context window or 50KB, whichever is smaller
    const contextBasedMin = Math.floor(contextWindowTokens * 0.1 * 4); // 4 chars/token
    settings.minPrunableToolChars = Math.min(50_000, contextBasedMin);

    // Only adjust ratios if they're at default values
    if (baseSettings.softTrimRatio === DEFAULT_CONTEXT_PRUNING_SETTINGS.softTrimRatio) {
      settings.softTrimRatio = 0.2;
    }
    if (baseSettings.hardClearRatio === DEFAULT_CONTEXT_PRUNING_SETTINGS.hardClearRatio) {
      settings.hardClearRatio = 0.35;
    }
  } else if (
    contextWindowTokens <= 128_000 &&
    baseSettings.minPrunableToolChars === DEFAULT_CONTEXT_PRUNING_SETTINGS.minPrunableToolChars
  ) {
    // Medium context windows: moderate adjustment
    const contextBasedMin = Math.floor(contextWindowTokens * 0.08 * 4);
    settings.minPrunableToolChars = Math.min(50_000, contextBasedMin);
  }
  // For large context windows (>128K), keep default settings

  return settings;
}

export function computeEffectiveSettings(raw: unknown): EffectiveContextPruningSettings | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const cfg = raw as ContextPruningConfig;
  if (cfg.mode !== "cache-ttl") {
    return null;
  }

  const s: EffectiveContextPruningSettings = structuredClone(DEFAULT_CONTEXT_PRUNING_SETTINGS);
  s.mode = cfg.mode;

  if (typeof cfg.ttl === "string") {
    try {
      s.ttlMs = parseDurationMs(cfg.ttl, { defaultUnit: "m" });
    } catch {
      // keep default ttl
    }
  }

  if (typeof cfg.keepLastAssistants === "number" && Number.isFinite(cfg.keepLastAssistants)) {
    s.keepLastAssistants = Math.max(0, Math.floor(cfg.keepLastAssistants));
  }
  if (typeof cfg.softTrimRatio === "number" && Number.isFinite(cfg.softTrimRatio)) {
    s.softTrimRatio = Math.min(1, Math.max(0, cfg.softTrimRatio));
  }
  if (typeof cfg.hardClearRatio === "number" && Number.isFinite(cfg.hardClearRatio)) {
    s.hardClearRatio = Math.min(1, Math.max(0, cfg.hardClearRatio));
  }
  if (typeof cfg.minPrunableToolChars === "number" && Number.isFinite(cfg.minPrunableToolChars)) {
    s.minPrunableToolChars = Math.max(0, Math.floor(cfg.minPrunableToolChars));
  }
  if (cfg.tools) {
    s.tools = cfg.tools;
  }
  if (cfg.softTrim) {
    if (typeof cfg.softTrim.maxChars === "number" && Number.isFinite(cfg.softTrim.maxChars)) {
      s.softTrim.maxChars = Math.max(0, Math.floor(cfg.softTrim.maxChars));
    }
    if (typeof cfg.softTrim.headChars === "number" && Number.isFinite(cfg.softTrim.headChars)) {
      s.softTrim.headChars = Math.max(0, Math.floor(cfg.softTrim.headChars));
    }
    if (typeof cfg.softTrim.tailChars === "number" && Number.isFinite(cfg.softTrim.tailChars)) {
      s.softTrim.tailChars = Math.max(0, Math.floor(cfg.softTrim.tailChars));
    }
  }
  if (cfg.hardClear) {
    if (typeof cfg.hardClear.enabled === "boolean") {
      s.hardClear.enabled = cfg.hardClear.enabled;
    }
    if (typeof cfg.hardClear.placeholder === "string" && cfg.hardClear.placeholder.trim()) {
      s.hardClear.placeholder = cfg.hardClear.placeholder.trim();
    }
  }

  return s;
}

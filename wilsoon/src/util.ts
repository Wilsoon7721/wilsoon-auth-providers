export const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

export const asString = (value: unknown): string | undefined => (typeof value === "string" && value.length > 0 ? value : undefined);

export const asStringArray = (value: unknown): string[] => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []);

export const asNumber = (value: unknown): number | undefined => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) return Number(value);
  return undefined;
};

/** Fallback seconds between polls when the provider names none, RFC 8628's default. */
export const DEFAULT_POLL_INTERVAL_SECONDS = 5;

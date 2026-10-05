import { isMachineToken, ProfileContext, ProviderProfile } from "@wilsoon/auth-core";
import { EscalationExtensions, escalationExtensions } from "./escalation";
import { PermissionExtensions, permissionExtensions } from "./permissions";
import { mapWilsoonUser, restoreFromProviderCookie, SessionExtensions, sessionExtensions, SessionVersionResolver } from "./session";

export const WILSOON_ISSUER = "https://id.wilsoon.dev";
export const WILSOON_API_AUDIENCE = "https://api.wilsoon.dev";

/** Authentication context classes, weakest first. To request with `acrValues` or check with `requiredAcr` */
export const ACR = Object.freeze({
  SOCIAL: "urn:wilsoon:acr:social",
  MFA: "urn:wilsoon:acr:mfa",
  PASSKEY: "urn:wilsoon:acr:passkey",
} as const);

/** 2.x storage names, kept so nobody is signed out by upgrade */
export const WILSOON_STORAGE_KEYS = Object.freeze({
  tokens: "wilsoon_id_tokens",
  state: "wilsoon_auth_state",
  nonce: "wilsoon_auth_nonce",
  codeVerifier: "wilsoon_auth_verifier",
} as const);

/** Options for {@link wilsoon}. All optional, the defaults match `id.wilsoon.dev`. */
export interface WilsoonProfileOptions {
  /** Base URL of the escalation API (default: `https://id.wilsoon.dev/api/escalate`). */
  escalationEndpoint?: string;
  /** URL of the permission registry (default: `https://id.wilsoon.dev/api/apps/permissions`). */
  permissionsEndpoint?: string;
  /** Default access token audience (default: `https://api.wilsoon.dev`). A config `apiAudience` overrides. */
  apiAudience?: string;
  /** How long a resolved platform session is reused before re-checking, in seconds (default 0). */
  platformSessionCacheSeconds?: number;
  /** How long a `liveAccess` answer is reused per token, in seconds (default 0). The IdP already caches and invalidates on every admin change. */
  liveAccessCacheSeconds?: number;
  /** Resolves a user's current `session_version` from your backend, for `isSessionCurrent` without a confidential client. */
  resolveSessionVersion?: SessionVersionResolver;
}

/** Everything `wilsoon()` adds under `client.wilsoon`. */
export interface WilsoonExtensions extends EscalationExtensions, SessionExtensions, PermissionExtensions {
  /** WilsoonID's authentication context classes. */
  readonly ACR: typeof ACR;
}

/**
 * The WilsoonID provider profile: 2.x behaviour and storage names, plus the provider's own functions under `client.wilsoon`.
 *
 * ```ts
 * const client = createAuthClient({ issuer: WILSOON_ISSUER, clientId, profile: wilsoon() });
 * await client.wilsoon.reauthorize(["passkey"], false, { idTokenHint });
 * ```
 */
export function wilsoon(options: WilsoonProfileOptions = {}): ProviderProfile<"wilsoon", WilsoonExtensions> {
  // The hooks share each client's extensions and their caches
  const perClient = new WeakMap<ProfileContext, WilsoonExtensions>();
  const forClient = (ctx: ProfileContext): WilsoonExtensions => {
    const extensions = perClient.get(ctx);
    if (!extensions) throw new Error("wilsoon(): a profile hook ran before extend() for this client.");
    return extensions;
  };

  const profile: ProviderProfile<"wilsoon", WilsoonExtensions> = {
    name: "wilsoon",
    storageKeys: WILSOON_STORAGE_KEYS,
    apiAudience: options.apiAudience ?? WILSOON_API_AUDIENCE,
    mapUser: mapWilsoonUser,
    // `token_use: "client"` first, then RFC 9068's `sub === client_id`
    isMachineToken: (claims: Readonly<Record<string, unknown>>) => isMachineToken(claims),
    /** @deprecated Cookie-based restore - remove once the provider stops writing `wilsoon_id_tokens`. Prefer `silentAuthorize()`. */
    restoreSession: restoreFromProviderCookie,
    resolveSharedSession: (ctx, accessToken, sessionOptions) => forClient(ctx).verifyPlatformSession(accessToken, sessionOptions),
    liveAccess: (ctx, token) => forClient(ctx).liveAccess(token),
    extend: (ctx) => {
      const extensions: WilsoonExtensions = {
        ...escalationExtensions(ctx, options.escalationEndpoint),
        ...sessionExtensions(ctx, options),
        ...permissionExtensions(ctx, options.permissionsEndpoint),
        ACR,
      };
      perClient.set(ctx, extensions);
      return extensions;
    },
  };
  return Object.freeze(profile);
}

export { definePermissionSet, MAX_PERMISSION_DESCRIPTION, MAX_PERMISSION_NODES, PermissionRegistryError } from "./permissions";
export type { PermissionExtensions, PermissionNode, PermissionRegistration, PermissionSet, RegisteredPermission } from "./permissions";
export type { EscalationExtensions } from "./escalation";
export { mapWilsoonUser } from "./session";
export type { SessionExtensions, SessionVersionResolver } from "./session";
export type { CreateEscalationOptions, EscalationRequest, EscalationResult, ReauthorizeOptions, VerifiedEscalation } from "@wilsoon/auth-core";

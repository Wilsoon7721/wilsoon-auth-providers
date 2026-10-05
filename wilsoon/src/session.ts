import { AuthenticatedUser, ClaimValidationError, decodeTokenPayloadUnsafe, LiveAccess, MachineTokenNotAllowedError, NoTokenError, PlatformSessionOptions, ProfileContext, ProfileUser, ProfileUserFields, SessionCheckUnavailableError, TokenVerificationError, UserRole } from "@wilsoon/auth-core";
import { asNumber, asString, asStringArray, isRecord } from "./util";

/** Upper bound on cached sessions and live answers, so a long-lived client cannot grow unbounded. */
const CACHE_MAX_ENTRIES = 500;

const LEGACY_ROLES: readonly string[] = ["admin", "user"];

/** Resolves the user's current `session_version` from your backend. `null` when unknown, which fails. */
export type SessionVersionResolver = (userId: string) => Promise<number | null | undefined> | number | null | undefined;

/**
 * Maps WilsoonID's claims onto a verified user: `permissions` (this app's `<slug>.<key>` nodes), `sid`, the legacy `role` and `session_version`.
 * An unrecognised `role` lands in `roles` but leaves the deprecated `role` unset, so it can never read as a known privilege.
 */
export function mapWilsoonUser(claims: Readonly<Record<string, unknown>>): ProfileUserFields {
  const fields = isRecord(claims.oidc_fields) ? claims.oidc_fields : claims;
  const role = asString(fields.role ?? claims.role);

  return {
    roles: role ? [role] : [],
    permissions: asStringArray(claims.permissions),
    role: !role ? "user" : LEGACY_ROLES.includes(role) ? (role as UserRole) : undefined,
    sessionVersion: asNumber(fields.session_version ?? claims.session_version),
    sid: asString(claims.sid),
    email: asString(fields.email) ?? asString(claims.email),
    name: asString(fields.name) ?? asString(claims.name),
    picture: asString(fields.picture) ?? asString(claims.picture),
  };
}

/**
 * The 2.x `hydrateSession`: userinfo with `credentials: "include"`, answered from the provider's `wilsoon_id_tokens` cookie on `.wilsoon.dev`.
 * Display claims only. Remove once the provider stops writing that cookie.
 */
export async function restoreFromProviderCookie(ctx: ProfileContext): Promise<ProfileUser | null> {
  try {
    const { userinfo_endpoint } = await ctx.getEndpoints();
    const response = await fetch(userinfo_endpoint, { credentials: "include" });
    if (!response.ok) return null;

    const raw: unknown = await response.json();
    if (!isRecord(raw)) return null;

    const id = asString(raw.sub) ?? asString(raw.id);
    if (!id) return null;

    return { id, email: asString(raw.email), emailVerified: typeof raw.email_verified === "boolean" ? raw.email_verified : undefined, name: asString(raw.name), picture: asString(raw.picture) };
  } catch {
    return null;
  }
}

export interface SessionExtensions {
  /**
   * Resolves a verified session from a platform access token issued to a sibling first-party client, through introspection.
   * Needs a `clientSecret`, with the access token audience defaulting to `https://api.wilsoon.dev`.
   *
   * @throws {TokenVerificationError} If the token fails verification, or the session is no longer active.
   * @throws {MachineTokenNotAllowedError} If the token came from the `client_credentials` grant.
   */
  verifyPlatformSession(accessToken: string, options?: PlatformSessionOptions): Promise<AuthenticatedUser>;
  /** `client.resolveSession()`, here for symmetry with 2.x. */
  resolveSession(tokens: { id_token?: string; access_token?: string }, options?: PlatformSessionOptions): Promise<AuthenticatedUser>;
  /**
   * Checks a verified user's `session_version` against the live one, so "sign out everywhere" lands before the token expires.
   * Uses `resolveSessionVersion` when configured, otherwise introspection of `options.token`.
   *
   * @throws {SessionCheckUnavailableError} If neither route is available, or the version cannot be determined.
   * @throws {MachineTokenNotAllowedError} If `options.token` is a machine token.
   */
  isSessionCurrent(user: Pick<AuthenticatedUser, "id" | "sessionVersion">, options?: { token?: string }): Promise<boolean>;
  /**
   * Immediate enforcement: whether the provider still honours the token, and what the user holds right now for this app.
   * `active: false` once the user loses `<slug>.access` or the token's `sid` was signed out. Confidential clients only.
   */
  liveAccess(token: string): Promise<LiveAccess>;
}

export interface SessionSettings {
  platformSessionCacheSeconds?: number;
  liveAccessCacheSeconds?: number;
  resolveSessionVersion?: SessionVersionResolver;
}

/** A small TTL cache that never outlives the token it is keyed by. */
function tokenCache<T>() {
  const entries = new Map<string, { value: T; expiresAt: number }>();
  return {
    get(token: string): T | undefined {
      const entry = entries.get(token);
      if (!entry) return undefined;
      if (entry.expiresAt <= Date.now()) {
        entries.delete(token);
        return undefined;
      }
      return entry.value;
    },
    set(token: string, value: T, seconds: number, tokenExpiresAt: number | undefined) {
      const expiresAt = Math.min(Date.now() + seconds * 1000, tokenExpiresAt !== undefined ? tokenExpiresAt * 1000 : Infinity);
      if (expiresAt <= Date.now()) return;
      if (entries.size >= CACHE_MAX_ENTRIES) {
        const oldest = entries.keys().next();
        if (!oldest.done) entries.delete(oldest.value);
      }
      entries.set(token, { value, expiresAt });
    },
  };
}

const unverifiedExpiry = (token: string): number | undefined => {
  try {
    return asNumber(decodeTokenPayloadUnsafe(token).exp);
  } catch {
    return undefined;
  }
};

/** Builds the session functions for a client, each with its own caches. */
export function sessionExtensions(ctx: ProfileContext, settings: SessionSettings): SessionExtensions {
  const sessions = tokenCache<AuthenticatedUser>();
  const live = tokenCache<LiveAccess>();
  const liveInFlight = new Map<string, Promise<LiveAccess>>();

  /** A routing hint only: the authoritative machine check runs on verified claims. */
  const looksLikeMachineToken = (token: string): boolean => {
    try {
      return ctx.classifyTokenUse(decodeTokenPayloadUnsafe(token)) === "client";
    } catch {
      return false;
    }
  };

  const verifyPlatformSession = async (accessToken: string, options: PlatformSessionOptions = {}): Promise<AuthenticatedUser> => {
    if (!asString(accessToken)) throw new NoTokenError("No access token was provided.");

    const cacheSeconds = options.cacheSeconds ?? settings.platformSessionCacheSeconds ?? ctx.config.platformSessionCacheSeconds ?? 0;
    if (!options.force && cacheSeconds > 0) {
      const cached = sessions.get(accessToken);
      if (cached) return cached;
    }

    const claims = await ctx.client.verifyAccessToken(accessToken, { allowMachineTokens: true });
    if (claims.tokenUse === "client") throw new MachineTokenNotAllowedError(`A platform session cannot be resolved from a client_credentials token: it was issued to the client ` + `"${claims.subject}" with no user behind it, so there is no identity to return. Machine callers should ` + "be authorized with `verifyMachineToken` instead of being given a session.", claims.subject);

    const introspection = await ctx.introspect(accessToken);

    if (!introspection.active) throw new TokenVerificationError("The platform session is no longer active: it was revoked, or superseded by a newer session.");
    if (introspection.sub && introspection.sub !== claims.subject) throw new ClaimValidationError("The introspection response describes a different subject than the token.");

    const liveFields = Object.fromEntries((["email", "email_verified", "name", "picture", "role", "amr", "session_version", "auth_time", "permissions", "sid"] as const).filter((key) => introspection[key] !== undefined).map((key) => [key, introspection[key]]));
    const user = ctx.toUser({ ...claims.claims, ...liveFields }, { source: "access_token", audience: claims.audience[0] ?? "" });

    if (cacheSeconds > 0) sessions.set(accessToken, user, cacheSeconds, user.expiresAt);
    return user;
  };

  const isSessionCurrent = async (user: Pick<AuthenticatedUser, "id" | "sessionVersion">, options: { token?: string } = {}): Promise<boolean> => {
    if (!user || !asString(user.id)) throw new SessionCheckUnavailableError("A verified user with an `id` is required to check the session version.");
    if (typeof user.sessionVersion !== "number") throw new SessionCheckUnavailableError("This token asserts no `session_version`, so revocation cannot be checked.");

    const resolver = settings.resolveSessionVersion ?? ctx.config.resolveSessionVersion;
    if (resolver) {
      const current = asNumber(await resolver(user.id));
      if (current === undefined) throw new SessionCheckUnavailableError("`resolveSessionVersion` did not return the current session version.");

      return user.sessionVersion === current;
    }

    if (options.token) {
      if (looksLikeMachineToken(options.token)) throw new MachineTokenNotAllowedError("A client_credentials token has no user and therefore no `session_version` to check. Machine tokens " + "cannot be revoked at all - the grant issues no refresh token - so a short lifetime is the only " + "control. Do not gate machine callers on this check.");

      const introspection = await ctx.introspect(options.token);
      if (!introspection.active) return false;

      const current = asNumber(introspection.session_version);
      if (current === undefined) throw new SessionCheckUnavailableError("The introspection response carried no `session_version`.");

      return user.sessionVersion === current;
    }

    throw new SessionCheckUnavailableError();
  };

  const liveAccess = async (token: string): Promise<LiveAccess> => {
    if (!asString(token)) throw new NoTokenError("No token was provided.");

    const cacheSeconds = settings.liveAccessCacheSeconds ?? 0;
    if (cacheSeconds > 0) {
      const cached = live.get(token);
      if (cached) return cached;
    }

    const pending = liveInFlight.get(token);
    if (pending) return pending;

    const request = ctx
      .introspect(token)
      .then((result) => {
        const answer: LiveAccess = result.active ? { active: true, ...(Array.isArray(result.permissions) ? { permissions: asStringArray(result.permissions) } : {}), ...(asString(result.sid) ? { sid: asString(result.sid) } : {}) } : { active: false };
        if (cacheSeconds > 0) live.set(token, answer, cacheSeconds, unverifiedExpiry(token));
        return answer;
      })
      .finally(() => liveInFlight.delete(token));

    liveInFlight.set(token, request);
    return request;
  };

  return {
    verifyPlatformSession,
    resolveSession: (tokens, options) => ctx.client.resolveSession(tokens, options),
    isSessionCurrent,
    liveAccess,
  };
}

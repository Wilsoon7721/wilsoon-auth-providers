// 2.x @wilsoon/auth-core suite, run through the wilsoon() profile: only client construction differs from 2.3.0.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AMR, assertAmr, AuthClient, AuthError, AuthorizationResponseError, ClaimValidationError, MemoryStorage, NonceMismatchError, NoTokenError, satisfiesAmr, SessionCheckUnavailableError, StateMismatchError, STORAGE_KEYS, StorageUnavailableError, TokenRefreshError, TokenVerificationError, UserInfoError, generateCodeChallenge, type AuthConfig } from "@wilsoon/auth-core";
import { wilsoon } from "../../src/index";
import { API_AUDIENCE, CLIENT_ID, OTHER_CLIENT_ID, attackerKeys, startFakeIdp, unsignedToken, type FakeIdp } from "../fake-idp";

let idp: FakeIdp;

const config = (overrides: Partial<AuthConfig> = {}): AuthConfig => ({
  profile: wilsoon(),
  clientId: CLIENT_ID,
  issuer: idp.issuer,
  redirectUri: "http://localhost:3000/callback",
  apiAudience: API_AUDIENCE,
  ...overrides,
});

const withStorage = (overrides: Partial<AuthConfig> = {}) => {
  const storage = new MemoryStorage();
  return { storage, client: new AuthClient(config(overrides), storage) };
};

beforeAll(async () => {
  idp = await startFakeIdp();
});

afterAll(async () => {
  await idp.close();
});

afterEach(() => {
  idp.setTokenHandler(null);
});

describe("createAuthorizeUrl", () => {
  it("binds state, nonce and a correct S256 PKCE challenge to the request", async () => {
    const { client } = withStorage();
    const request = await client.createAuthorizeUrl();
    const params = new URL(request.url).searchParams;

    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("redirect_uri")).toBe("http://localhost:3000/callback");
    expect(params.get("response_type")).toBe("code");
    expect(params.get("scope")).toBe("openid profile email");
    expect(params.get("state")).toBe(request.state);
    expect(params.get("nonce")).toBe(request.nonce);
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toBe(await generateCodeChallenge(request.codeVerifier));
    expect(request.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(request.codeVerifier.length).toBeLessThanOrEqual(128);
  });

  it("persists state, nonce and verifier so the callback can be validated", async () => {
    const { client, storage } = withStorage();
    const request = await client.createAuthorizeUrl();

    expect(storage.getItem(STORAGE_KEYS.state)).toBe(request.state);
    expect(storage.getItem(STORAGE_KEYS.nonce)).toBe(request.nonce);
    expect(storage.getItem(STORAGE_KEYS.codeVerifier)).toBe(request.codeVerifier);
  });

  it("passes through prompt, acr_values and login_hint", async () => {
    const { client } = withStorage();
    const request = await client.createAuthorizeUrl({
      prompt: "consent",
      acrValues: ["mfa", "hw"],
      loginHint: "ada@example.com",
      scope: ["openid"],
    });
    const params = new URL(request.url).searchParams;

    expect(params.get("prompt")).toBe("consent");
    expect(params.get("acr_values")).toBe("mfa hw");
    expect(params.get("login_hint")).toBe("ada@example.com");
    expect(params.get("scope")).toBe("openid");
  });

  it("refuses to let extraParams override the security parameters", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { client } = withStorage();

    const request = await client.createAuthorizeUrl({
      extraParams: { state: "attacker-state", code_challenge: "attacker-challenge", ui_locales: "en" },
    });
    const params = new URL(request.url).searchParams;

    expect(params.get("state")).toBe(request.state);
    expect(params.get("code_challenge")).not.toBe("attacker-challenge");
    expect(params.get("ui_locales")).toBe("en");
    warn.mockRestore();
  });

  it("warns instead of silently losing state when no storage is configured", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = new AuthClient(config());

    const request = await client.createAuthorizeUrl();

    expect(request.state).toBeTruthy();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("did not persist"));
    await expect(client.createAuthorizeUrl({ persist: true })).rejects.toThrow(StorageUnavailableError);
    warn.mockRestore();
  });
});

describe("handleCallback", () => {
  const startFlow = async (overrides: Partial<AuthConfig> = {}) => {
    const { client, storage } = withStorage(overrides);
    const request = await client.createAuthorizeUrl();
    return { client, storage, request };
  };

  const respondWith = (idToken: () => Promise<string>) => {
    idp.setTokenHandler(async () => ({
      body: {
        access_token: await idp.mintAccessToken(),
        id_token: await idToken(),
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile email",
        refresh_token: "rotated-refresh-token",
      },
    }));
  };

  it("validates state, exchanges the code with PKCE and returns a verified user", async () => {
    const { client, storage, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const result = await client.handleCallback(`http://localhost:3000/callback?code=the-code&state=${request.state}`);

    expect(result.user?.role).toBe("admin");
    expect(result.user?.authMethods).toContain(AMR.FIDO);
    expect(result.state).toBe(request.state);
    expect(result.tokens.access_token).toBeTruthy();

    const sent = idp.tokenRequests.at(-1)!;
    expect(sent.get("grant_type")).toBe("authorization_code");
    expect(sent.get("code")).toBe("the-code");
    expect(sent.get("code_verifier")).toBe(request.codeVerifier);

    // Single-use values are cleared so the callback cannot be replayed.
    expect(storage.getItem(STORAGE_KEYS.state)).toBeNull();
    expect(storage.getItem(STORAGE_KEYS.nonce)).toBeNull();
    expect(storage.getItem(STORAGE_KEYS.codeVerifier)).toBeNull();
  });

  it("rejects a mismatched state without touching the token endpoint", async () => {
    const { client } = await startFlow();
    const before = idp.tokenHits;

    await expect(client.handleCallback("http://localhost:3000/callback?code=c&state=not-the-state")).rejects.toThrow(StateMismatchError);
    expect(idp.tokenHits).toBe(before);
  });

  it("rejects a callback with no state at all", async () => {
    const { client } = await startFlow();

    await expect(client.handleCallback("http://localhost:3000/callback?code=c")).rejects.toThrow(StateMismatchError);
  });

  it("cannot be replayed once the transient state is consumed", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const callbackUrl = `http://localhost:3000/callback?code=the-code&state=${request.state}`;
    await client.handleCallback(callbackUrl);

    await expect(client.handleCallback(callbackUrl)).rejects.toThrow(StateMismatchError);
  });

  it("surfaces a provider error response", async () => {
    const { client, storage, request } = await startFlow();

    await expect(client.handleCallback(`http://localhost:3000/callback?error=access_denied&error_description=User+said+no&state=${request.state}`)).rejects.toThrow(AuthorizationResponseError);
    expect(storage.getItem(STORAGE_KEYS.state)).toBeNull();
  });

  it("requires an authorization code", async () => {
    const { client, request } = await startFlow();

    await expect(client.handleCallback(`http://localhost:3000/callback?state=${request.state}`)).rejects.toThrow(AuthError);
  });

  it("rejects an ID token bound to a different authorization request", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: "someone-elses-nonce" }));

    await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`)).rejects.toThrow(NonceMismatchError);
  });

  it("rejects an ID token minted for another application", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }, { audience: OTHER_CLIENT_ID }));

    await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`)).rejects.toThrow(TokenVerificationError);
  });

  it("fails when the provider returns no ID token for an OpenID request", async () => {
    const { client, request } = await startFlow();
    idp.setTokenHandler(async () => ({ body: { access_token: await idp.mintAccessToken(), token_type: "Bearer" } }));

    await expect(client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`)).rejects.toThrow(NoTokenError);
  });

  it("accepts caller-managed state for server-side flows", async () => {
    const client = new AuthClient(config());
    const request = await client.createAuthorizeUrl({ persist: false });
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const result = await client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`, {
      expected: { state: request.state, nonce: request.nonce, codeVerifier: request.codeVerifier },
    });

    expect(result.user?.id).toBe("user-1");
  });

  it("refuses to run blind when there is neither storage nor supplied expectations", async () => {
    const client = new AuthClient(config());

    await expect(client.handleCallback("http://localhost:3000/callback?code=c&state=s")).rejects.toThrow(StorageUnavailableError);
  });

  it("optionally persists the token response", async () => {
    const { client, storage, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    await client.handleCallback(`http://localhost:3000/callback?code=c&state=${request.state}`, { persistTokens: true });

    expect(client.getStoredTokens()?.refresh_token).toBe("rotated-refresh-token");
    expect(storage.getItem(STORAGE_KEYS.tokens)).toBeTruthy();
  });

  it("accepts URLSearchParams as well as a URL", async () => {
    const { client, request } = await startFlow();
    respondWith(() => idp.mintIdToken({ nonce: request.nonce }));

    const params = new URLSearchParams({ code: "c", state: request.state });
    await expect(client.handleCallback(params)).resolves.toMatchObject({ state: request.state });
  });
});

describe("refreshAccessToken", () => {
  it("collapses concurrent refreshes into a single request", async () => {
    const { client } = withStorage();
    idp.setTokenHandler(async () => ({
      body: { access_token: await idp.mintAccessToken(), refresh_token: "next-refresh", token_type: "Bearer", expires_in: 3600 },
    }));
    const before = idp.tokenHits;

    const [a, b, c] = await Promise.all([client.refreshAccessToken("rt-1"), client.refreshAccessToken("rt-1"), client.refreshAccessToken("rt-1")]);

    expect(idp.tokenHits - before).toBe(1);
    expect(a.access_token).toBe(b.access_token);
    expect(b.access_token).toBe(c.access_token);
  });

  it("writes the rotated tokens back when the library is managing storage", async () => {
    const { client } = withStorage();
    client.saveTokens({ access_token: "old-access", refresh_token: "rt-1" });
    idp.setTokenHandler(async () => ({
      body: { access_token: await idp.mintAccessToken(), refresh_token: "rt-2", token_type: "Bearer", expires_in: 3600 },
    }));

    await client.refreshAccessToken("rt-1");

    expect(client.getStoredTokens()?.refresh_token).toBe("rt-2");
  });

  it("leaves storage alone when the caller manages tokens itself", async () => {
    const { client, storage } = withStorage();
    idp.setTokenHandler(async () => ({
      body: { access_token: await idp.mintAccessToken(), refresh_token: "rt-2", token_type: "Bearer" },
    }));

    await client.refreshAccessToken("rt-1");

    expect(storage.getItem(STORAGE_KEYS.tokens)).toBeNull();
  });

  it("reports refresh failures and requires a token", async () => {
    const { client } = withStorage();
    idp.setTokenHandler(() => ({ status: 400, body: { error: "invalid_grant" } }));

    await expect(client.refreshAccessToken("rt-1")).rejects.toThrow(TokenRefreshError);
    await expect(client.refreshAccessToken("")).rejects.toThrow(NoTokenError);
  });

  it("does not reuse a settled in-flight request", async () => {
    const { client } = withStorage();
    idp.setTokenHandler(async () => ({ body: { access_token: await idp.mintAccessToken(), token_type: "Bearer" } }));
    const before = idp.tokenHits;

    await client.refreshAccessToken("rt-1");
    await client.refreshAccessToken("rt-1");

    expect(idp.tokenHits - before).toBe(2);
  });
});

describe("expiry hints", () => {
  it("treats a token with no exp claim as expired rather than valid forever", async () => {
    const { client } = withStorage();
    const eternal = unsignedToken({ sub: "user-1", role: "admin" });
    expect(client.isTokenNearExpiry(eternal)).toBe(true);
  });

  it("treats an unparseable token as expired", () => {
    const { client } = withStorage();

    expect(client.isTokenNearExpiry("garbage")).toBe(true);
    expect(client.isTokenNearExpiry("")).toBe(true);
  });

  it("reports live and near-expiry tokens correctly", async () => {
    const { client } = withStorage();

    expect(client.isTokenNearExpiry(await idp.mintAccessToken())).toBe(false);
    expect(client.isTokenNearExpiry(await idp.mintAccessToken({}, { expiresInSeconds: -1 }))).toBe(true);
    expect(client.isTokenNearExpiry(await idp.mintAccessToken({}, { expiresInSeconds: 30 }), 60)).toBe(true);
    expect(client.isTokenNearExpiry(await idp.mintAccessToken({}, { expiresInSeconds: 30 }), 10)).toBe(false);
  });
});

describe("storage handling", () => {
  it("fails with a descriptive error instead of a TypeError when no storage exists", () => {
    const client = new AuthClient(config());

    expect(client.hasStorage()).toBe(false);
    expect(() => client.saveTokens({ access_token: "a" })).toThrow(StorageUnavailableError);
    expect(() => client.saveTokens({ access_token: "a" })).toThrow(/requires a storage implementation/);
    expect(client.getStoredTokens()).toBeNull();
    expect(() => client.clearStorage()).not.toThrow();
  });

  it("round-trips tokens and clears them", () => {
    const { client, storage } = withStorage();

    client.saveTokens({ access_token: "a", refresh_token: "r" });
    expect(client.getStoredTokens()).toEqual({ access_token: "a", refresh_token: "r" });

    client.clearStorage();
    expect(storage.getItem(STORAGE_KEYS.tokens)).toBeNull();
  });

  it("reads the URI-encoded cookie form the identity provider writes", () => {
    const { client, storage } = withStorage();
    storage.setItem(STORAGE_KEYS.tokens, encodeURIComponent(JSON.stringify({ access_token: "a", id_token: "b" })));

    expect(client.getStoredTokens()).toEqual({ access_token: "a", id_token: "b" });
  });

  it("returns null for junk in storage rather than throwing", () => {
    const { client, storage } = withStorage();

    storage.setItem(STORAGE_KEYS.tokens, "not json");
    expect(client.getStoredTokens()).toBeNull();

    storage.setItem(STORAGE_KEYS.tokens, JSON.stringify({ nothing: true }));
    expect(client.getStoredTokens()).toBeNull();
  });
});

describe("profile fetching", () => {
  it("returns display claims only from userinfo", async () => {
    const { client } = withStorage();

    const profile = await client.getUser(await idp.mintAccessToken());

    expect(profile).toEqual({ id: "user-1", name: "Ada Lovelace", email: "ada@example.com", emailVerified: true, picture: undefined });
    expect("role" in profile).toBe(false);
    expect("authMethods" in profile).toBe(false);
    expect("sessionVersion" in profile).toBe(false);
  });

  it("reports userinfo failures and requires a token", async () => {
    const { client } = withStorage();
    idp.setUserinfo({ error: "invalid_token" }, 401);

    await expect(client.getUser(await idp.mintAccessToken())).rejects.toThrow(UserInfoError);
    await expect(client.hydrateSession()).resolves.toBeNull();
    await expect(client.getUser("")).rejects.toThrow(NoTokenError);

    idp.setUserinfo({ sub: "user-1", name: "Ada Lovelace", email: "ada@example.com", email_verified: true }, 200);
  });

  it("rejects a userinfo payload with no subject", async () => {
    const { client } = withStorage();
    idp.setUserinfo({ name: "nobody" }, 200);

    await expect(client.getUser(await idp.mintAccessToken())).rejects.toThrow(ClaimValidationError);

    idp.setUserinfo({ sub: "user-1", name: "Ada Lovelace", email: "ada@example.com", email_verified: true }, 200);
  });
});

describe("session_version enforcement", () => {
  const verified = async (client: AuthClient, sessionVersion?: number) => client.verifyIdToken(await idp.mintIdToken({ session_version: sessionVersion }));

  it("fails closed when no resolver is configured", async () => {
    const { client } = withStorage();
    const user = await verified(client, 3);

    await expect(client.isSessionCurrent(user)).rejects.toThrow(SessionCheckUnavailableError);
  });

  it("compares the token version against the live version", async () => {
    const current = { value: 3 as number | null };
    const { client } = withStorage({ resolveSessionVersion: () => current.value });
    const user = await verified(client, 3);

    await expect(client.isSessionCurrent(user)).resolves.toBe(true);

    current.value = 4; // the user revoked all sessions
    await expect(client.isSessionCurrent(user)).resolves.toBe(false);

    current.value = null;
    await expect(client.isSessionCurrent(user)).rejects.toThrow(SessionCheckUnavailableError);
  });

  it("fails closed when the token asserts no version", async () => {
    const { client } = withStorage({ resolveSessionVersion: () => 3 });
    const user = await verified(client, undefined);

    expect(user.sessionVersion).toBeUndefined();
    await expect(client.isSessionCurrent(user)).rejects.toThrow(SessionCheckUnavailableError);
  });
});

describe("introspection", () => {
  const confidential = () => {
    const storage = new MemoryStorage();
    return new AuthClient(config({ clientSecret: "shh" }), storage);
  };

  it("posts the token with client credentials and returns the response", async () => {
    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
    const client = confidential();

    const result = await client.introspectToken(await idp.mintAccessToken());

    expect(result.active).toBe(true);
    expect(result.session_version).toBe(3);

    const sent = idp.introspectionRequests.at(-1)!;
    expect(sent.get("client_id")).toBe(CLIENT_ID);
    expect(sent.get("client_secret")).toBe("shh");
    expect(sent.get("token")).toBeTruthy();
  });

  it("refuses to introspect from a public client", async () => {
    const { client } = withStorage();

    await expect(client.introspectToken(await idp.mintAccessToken())).rejects.toThrow(/requires a `clientSecret`/);
  });

  it("reports a provider that advertises no introspection endpoint", async () => {
    idp.setIntrospection({ active: true }, { advertise: false });
    try {
      await expect(confidential().introspectToken(await idp.mintAccessToken())).rejects.toThrow(/introspection_endpoint/);
    } finally {
      idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
    }
  });

  it("rejects a failed or malformed introspection response", async () => {
    idp.setIntrospection({ error: "invalid_client" }, { status: 401 });
    await expect(confidential().introspectToken(await idp.mintAccessToken())).rejects.toThrow(/status 401/);

    idp.setIntrospection({ not: "an introspection response" });
    await expect(confidential().introspectToken(await idp.mintAccessToken())).rejects.toThrow(/unexpected payload/);

    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
  });

  it("enforces session_version through introspection when no resolver is configured", async () => {
    const client = confidential();
    const token = await idp.mintIdToken({ session_version: 3 });
    const user = await client.verifyIdToken(token);

    idp.setIntrospection({ active: true, sub: "user-1", session_version: 3 });
    await expect(client.isSessionCurrent(user, { token })).resolves.toBe(true);

    idp.setIntrospection({ active: true, sub: "user-1", session_version: 4 });
    await expect(client.isSessionCurrent(user, { token })).resolves.toBe(false);

    // The provider itself refuses a token from a superseded session.
    idp.setIntrospection({ active: false });
    await expect(client.isSessionCurrent(user, { token })).resolves.toBe(false);

    idp.setIntrospection({ active: true, sub: "user-1", session_version: 3 });
  });

  it("prefers a configured resolver over introspection", async () => {
    const client = new AuthClient(config({ clientSecret: "shh", resolveSessionVersion: () => 9 }), new MemoryStorage());
    const token = await idp.mintIdToken({ session_version: 3 });
    const user = await client.verifyIdToken(token);
    const before = idp.introspectionRequests.length;

    await expect(client.isSessionCurrent(user, { token })).resolves.toBe(false);
    expect(idp.introspectionRequests.length).toBe(before);
  });

  it("fails closed when introspection cannot answer", async () => {
    const client = confidential();
    const token = await idp.mintIdToken({ session_version: 3 });
    const user = await client.verifyIdToken(token);

    idp.setIntrospection({ active: true, sub: "user-1" });
    await expect(client.isSessionCurrent(user, { token })).rejects.toThrow(SessionCheckUnavailableError);

    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", session_version: 3 });
  });
});

describe("platform sessions (shared cookie across services)", () => {
  /** A sibling first-party service: different client_id, same platform access token. */
  const sibling = (overrides: Partial<AuthConfig> = {}) => new AuthClient(config({ clientId: "dash-service", clientSecret: "shh", ...overrides }), new MemoryStorage());

  const platformIntrospection = (extra: Record<string, unknown> = {}) =>
    idp.setIntrospection({
      active: true,
      sub: "user-1",
      role: "admin",
      amr: ["mfa", "fido", "hw"],
      session_version: 3,
      name: "Ada Lovelace",
      email: "ada@example.com",
      email_verified: true,
      auth_time: Math.floor(Date.now() / 1000),
      ...extra,
    });

  it("resolves a verified user from an access token minted for another service", async () => {
    platformIntrospection();
    // The token was issued to `go-service`; `dash-service` receives it via the shared cookie.
    const accessToken = await idp.mintAccessToken({ client_id: "go-service" });

    const user = await sibling().verifyPlatformSession(accessToken);

    expect(user.id).toBe("user-1");
    expect(user.role).toBe("admin");
    expect(user.authMethods).toEqual(["mfa", "fido", "hw"]);
    expect(user.sessionVersion).toBe(3);
    expect(user.name).toBe("Ada Lovelace");
    expect(user.email).toBe("ada@example.com");
    expect(user.source).toBe("access_token");
    expect(user.audience).toBe(API_AUDIENCE);
  });

  it("marks an ID-token identity with its own source", async () => {
    const user = await sibling({ clientId: CLIENT_ID }).verifyIdToken(await idp.mintIdToken());

    expect(user.source).toBe("id_token");
  });

  it("refuses a session the provider reports as inactive", async () => {
    idp.setIntrospection({ active: false });

    await expect(sibling().verifyPlatformSession(await idp.mintAccessToken())).rejects.toThrow(/no longer active/);
  });

  it("still rejects a token that fails cryptographic verification", async () => {
    platformIntrospection();
    const { privateKey } = await attackerKeys();

    await expect(sibling().verifyPlatformSession(await idp.mintAccessToken({}, { key: privateKey }))).rejects.toThrow(TokenVerificationError);
    await expect(sibling().verifyPlatformSession(await idp.mintAccessToken({}, { expiresInSeconds: -60 }))).rejects.toThrow(TokenVerificationError);
  });

  it("rejects an audience that is not the platform API", async () => {
    platformIntrospection();
    const other = await idp.mintAccessToken({}, { audience: "https://someone-elses-api.example.com" });

    await expect(sibling().verifyPlatformSession(other)).rejects.toThrow(TokenVerificationError);
  });

  it("refuses when introspection disagrees about the subject", async () => {
    platformIntrospection({ sub: "somebody-else" });

    await expect(sibling().verifyPlatformSession(await idp.mintAccessToken())).rejects.toThrow(/different subject/);
  });

  it("requires a confidential client and a pinned audience", async () => {
    platformIntrospection();
    const token = await idp.mintAccessToken();

    await expect(sibling({ clientSecret: undefined }).verifyPlatformSession(token)).rejects.toThrow(/clientSecret/);
    // 3.0: the profile pins https://api.wilsoon.dev when the config does not, so only a wrong pin is refused.
    await expect(sibling({ apiAudience: "https://someone-elses-api.example.com" }).verifyPlatformSession(token)).rejects.toThrow(TokenVerificationError);
  });

  it("validates the live role rather than asserting it", async () => {
    platformIntrospection({ role: "superuser" });

    // 3.0: an unknown role no longer fails the session; it is carried in `roles` and never maps onto a known `role`.
    const user = await sibling().verifyPlatformSession(await idp.mintAccessToken());
    expect(user.role).toBeUndefined();
    expect(user.roles).toEqual(["superuser"]);
  });

  it("caches within the configured window and re-checks after it", async () => {
    platformIntrospection();
    const client = sibling({ platformSessionCacheSeconds: 60 });
    const token = await idp.mintAccessToken();
    const before = idp.introspectionRequests.length;

    await client.verifyPlatformSession(token);
    await client.verifyPlatformSession(token);
    await client.verifyPlatformSession(token);
    expect(idp.introspectionRequests.length - before).toBe(1);

    // A revocation is picked up once the window passes...
    idp.setIntrospection({ active: false });
    await expect(client.verifyPlatformSession(token, { cacheSeconds: 0 })).rejects.toThrow(/no longer active/);

    // ...and `force` bypasses the cache immediately.
    platformIntrospection();
    await expect(client.verifyPlatformSession(token, { force: true })).resolves.toBeDefined();
  });

  it("does not cache when no window is configured", async () => {
    platformIntrospection();
    const client = sibling();
    const token = await idp.mintAccessToken();
    const before = idp.introspectionRequests.length;

    await client.verifyPlatformSession(token);
    await client.verifyPlatformSession(token);

    expect(idp.introspectionRequests.length - before).toBe(2);
  });

  it("never caches past the token expiry", async () => {
    platformIntrospection();
    const client = sibling({ platformSessionCacheSeconds: 3600 });
    const token = await idp.mintAccessToken({}, { expiresInSeconds: 65 });
    const before = idp.introspectionRequests.length;

    await client.verifyPlatformSession(token);
    await client.verifyPlatformSession(token);

    // 65s of validity, so the 3600s window is clamped and the entry is still live here.
    expect(idp.introspectionRequests.length - before).toBe(1);
  });
});

describe("resolveSession (framework-agnostic routing)", () => {
  const dash = (overrides: Partial<AuthConfig> = {}) => new AuthClient(config({ clientId: "dash-service", clientSecret: "shh", ...overrides }), new MemoryStorage());

  beforeEach(() => {
    idp.setIntrospection({ active: true, sub: "user-1", role: "admin", amr: ["mfa", "fido", "hw"], session_version: 3 });
  });

  it("verifies our own ID token without introspecting", async () => {
    const before = idp.introspectionRequests.length;

    const user = await dash().resolveSession({
      id_token: await idp.mintIdToken({}, { audience: "dash-service" }),
      access_token: await idp.mintAccessToken(),
    });

    expect(user.source).toBe("id_token");
    expect(idp.introspectionRequests.length).toBe(before);
  });

  it("falls back to the platform session for a sibling service cookie", async () => {
    const user = await dash().resolveSession({
      id_token: await idp.mintIdToken({}, { audience: "go-service" }),
      access_token: await idp.mintAccessToken({ client_id: "go-service" }),
    });

    expect(user.source).toBe("access_token");
    expect(user.role).toBe("admin");
  });

  it("uses the access token when there is no ID token at all", async () => {
    const user = await dash().resolveSession({ access_token: await idp.mintAccessToken() });

    expect(user.source).toBe("access_token");
  });

  it("explains a foreign session when platform mode is not configured", async () => {
    const notConfigured = dash({ apiAudience: undefined, clientSecret: undefined });

    await expect(
      notConfigured.resolveSession({
        id_token: await idp.mintIdToken({}, { audience: "go-service" }),
        access_token: await idp.mintAccessToken(),
      }),
    ).rejects.toThrow(/established by another application/);
  });

  it("requires something to verify", async () => {
    await expect(dash().resolveSession({})).rejects.toThrow(NoTokenError);
  });

  it("does not let a forged audience skip verification", async () => {
    // Claims to be ours, so routing picks the ID token path - where it fails properly.
    const forged = unsignedToken({
      sub: "attacker",
      role: "admin",
      aud: "dash-service",
      iss: idp.issuer,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    await expect(dash().resolveSession({ id_token: forged, access_token: await idp.mintAccessToken() })).rejects.toThrow(TokenVerificationError);
  });
});

describe("amr helpers", () => {
  it("requires every listed method by default", () => {
    const user = { authMethods: ["mfa", "fido", "hw"] };

    expect(satisfiesAmr(user, [AMR.MFA, AMR.FIDO])).toBe(true);
    expect(satisfiesAmr(user, [AMR.OTP])).toBe(false);
    expect(satisfiesAmr(user, [AMR.MFA, AMR.OTP])).toBe(false);
    expect(satisfiesAmr(user, [AMR.MFA, AMR.OTP], { mode: "any" })).toBe(true);
  });

  it("does not treat a social login as multi-factor", () => {
    const social = { authMethods: ["ext", "social"] };

    expect(satisfiesAmr(social, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr(social, [AMR.HARDWARE])).toBe(false);
  });

  it("fails closed on missing or empty methods", () => {
    expect(satisfiesAmr(undefined, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr({ authMethods: [] }, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr({}, [AMR.MFA])).toBe(false);
    expect(satisfiesAmr(undefined, [])).toBe(true);
  });

  it("asserts with a descriptive error", () => {
    expect(() => assertAmr({ authMethods: ["ext", "social"] }, [AMR.FIDO])).toThrow(ClaimValidationError);
    expect(() => assertAmr({ authMethods: ["mfa"] }, [AMR.MFA])).not.toThrow();
  });
});

describe("configuration validation", () => {
  it("rejects incomplete configuration at construction", () => {
    expect(() => new AuthClient({ profile: wilsoon(), issuer: "https://id.wilsoon.dev", redirectUri: "x" } as unknown as AuthConfig)).toThrow(AuthError);
    expect(() => new AuthClient({ profile: wilsoon(), clientId: "c", redirectUri: "x" } as unknown as AuthConfig)).toThrow(AuthError);
    expect(() => new AuthClient({ profile: wilsoon(), clientId: "c", issuer: "not-a-url", redirectUri: "x" })).toThrow(/absolute URL/);
  });

  it("lets a verify-only client omit the redirectUri", async () => {
    const verifier = new AuthClient({ profile: wilsoon(), clientId: CLIENT_ID, issuer: idp.issuer, apiAudience: API_AUDIENCE });

    await expect(verifier.verifyIdToken(await idp.mintIdToken())).resolves.toMatchObject({ id: "user-1" });
    await expect(verifier.verifyAccessToken(await idp.mintAccessToken())).resolves.toMatchObject({ subject: "user-1" });

    // ...but it cannot start a login.
    await expect(verifier.createAuthorizeUrl()).rejects.toThrow(/redirectUri/);
    await expect(verifier.exchangeCodeForToken("c", "v")).rejects.toThrow(/redirectUri/);
  });

  it("warns when the issuer is not HTTPS", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    new AuthClient({ profile: wilsoon(), clientId: "c", issuer: "http://id.example.com", redirectUri: "http://localhost/cb" });

    expect(warn).toHaveBeenCalledWith(expect.stringContaining("not HTTPS"));
    warn.mockRestore();
  });
});

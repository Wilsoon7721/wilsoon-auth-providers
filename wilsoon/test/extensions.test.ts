import { afterAll, beforeAll, describe, expect, expectTypeOf, it, vi } from "vitest";
import { AuthClient, AuthError, createAuthClient, hasPermission, MemoryStorage, requirePermission, type AuthConfig } from "@wilsoon/auth-core";
import { ACR, definePermissionSet, PermissionRegistryError, wilsoon, WILSOON_STORAGE_KEYS, type WilsoonExtensions } from "../src/index";
import { API_AUDIENCE, CLIENT_ID, startFakeIdp, type FakeIdp } from "./fake-idp";

let idp: FakeIdp;

// Spreading a `Partial<AuthConfig>` would widen `profile` and lose the "wilsoon" name, so the profile is set last.
const config = (overrides: Omit<Partial<AuthConfig>, "profile"> = {}, profile = wilsoon()) => ({
  clientId: CLIENT_ID,
  issuer: idp.issuer,
  redirectUri: "http://localhost:3000/callback",
  clientSecret: "s3cret+/%",
  ...overrides,
  profile,
});

beforeAll(async () => {
  idp = await startFakeIdp();
});

afterAll(async () => {
  await idp.close();
});

describe("createAuthClient", () => {
  it("exposes the extensions under client.wilsoon, typed from the profile", () => {
    const client = createAuthClient(config(), new MemoryStorage());

    expectTypeOf(client.wilsoon).toEqualTypeOf<WilsoonExtensions>();
    expect(typeof client.wilsoon.reauthorize).toBe("function");
    expect(client.wilsoon.ACR).toBe(ACR);
    expect(client.profileName).toBe("wilsoon");
  });

  it("keeps the 2.x storage names, so nobody is signed out by the upgrade", () => {
    const client = new AuthClient(config(), new MemoryStorage());
    expect(client.storageKeys).toEqual(WILSOON_STORAGE_KEYS);
  });

  it("lets an explicit storagePrefix win over the profile's legacy names", () => {
    const client = new AuthClient(config({ storagePrefix: "games_" }), new MemoryStorage());
    expect(client.storageKeys.tokens).toBe("games_tokens");
  });

  it("gives each client its own extension state", async () => {
    const a = createAuthClient(config(), new MemoryStorage());
    const b = createAuthClient(config(), new MemoryStorage());
    expect(a.wilsoon).not.toBe(b.wilsoon);
  });

  it("keeps the 2.x methods callable as forwarders that warn once", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = new AuthClient(config(), new MemoryStorage());
    const user = { id: "user-1", sessionVersion: 3 };
    idp.setIntrospection({ active: true, sub: "user-1", session_version: 3 });
    const token = await idp.mintIdToken();

    await expect(client.isSessionCurrent(user, { token })).resolves.toBe(true);
    await expect(client.isSessionCurrent(user, { token })).resolves.toBe(true);

    expect(warn.mock.calls.filter(([message]) => String(message).includes("isSessionCurrent() is deprecated"))).toHaveLength(1);
    warn.mockRestore();
  });
});

describe("mapUser", () => {
  it("reads permissions, sid and the legacy role into the generic model", async () => {
    const client = new AuthClient(config(), new MemoryStorage());
    const user = await client.verifyIdToken(await idp.mintIdToken({ sid: "sess-1", permissions: ["games_portal.access"] }));

    expect(user.roles).toEqual(["admin"]);
    expect(user.role).toBe("admin");
    expect(user.permissions).toEqual(["games_portal.access"]);
    expect(user.sid).toBe("sess-1");
    expect(user.sessionVersion).toBe(3);
  });

  it("merges the session access token's permissions, which is the only place the provider puts them", async () => {
    const client = new AuthClient(config(), new MemoryStorage());
    const user = await client.resolveSession({
      id_token: await idp.mintIdToken(),
      access_token: await idp.mintAccessToken({ permissions: ["games_portal.access", "games_portal.rooms.create"], sid: "sess-1" }),
    });

    expect(user.source).toBe("id_token");
    expect(user.permissions).toEqual(["games_portal.access", "games_portal.rooms.create"]);
    expect(user.sid).toBe("sess-1");
  });

  it("ignores an access token issued to another client or another user", async () => {
    const client = new AuthClient(config(), new MemoryStorage());
    const idToken = await idp.mintIdToken();

    const otherClient = await client.resolveSession({ id_token: idToken, access_token: await idp.mintAccessToken({ client_id: "someone-else", permissions: ["x.admin"] }) });
    const otherUser = await client.resolveSession({ id_token: idToken, access_token: await idp.mintAccessToken({ sub: "user-2", permissions: ["x.admin"] }) });

    expect(otherClient.permissions).toEqual([]);
    expect(otherUser.permissions).toEqual([]);
  });

  it("reads permissions off a verified access token for resource servers", async () => {
    const client = new AuthClient(config(), new MemoryStorage());
    const claims = await client.verifyAccessToken(await idp.mintAccessToken({ permissions: ["games_portal.leaderboard.edit"] }));

    expect(claims.audience).toEqual([API_AUDIENCE]);
    expect(hasPermission(claims, "games_portal.leaderboard.edit")).toBe(true);
  });
});

describe("definePermissionSet", () => {
  const permissions = definePermissionSet("games_portal", {
    "leaderboard.edit": "Edit the leaderboard",
    "rooms.create": "Create rooms",
  });

  it("builds full nodes from keys, typed so typos fail to compile", () => {
    expect(permissions.node("leaderboard.edit")).toBe("games_portal.leaderboard.edit");
    expect(permissions.access).toBe("games_portal.access");
    expect(permissions.nodes).toEqual([
      { node: "games_portal.leaderboard.edit", description: "Edit the leaderboard" },
      { node: "games_portal.rooms.create", description: "Create rooms" },
    ]);

    expectTypeOf(permissions.node("rooms.create")).toEqualTypeOf<"games_portal.rooms.create">();
    // @ts-expect-error - not a declared key
    permissions.node("leaderbord.edit");
  });

  it("guards on declared keys", () => {
    const user = { permissions: ["games_portal.access", "games_portal.rooms.create"] };

    expect(permissions.has(user, "rooms.create")).toBe(true);
    expect(permissions.has(user, ["access", "leaderboard.edit"])).toBe(false);
    expect(() => permissions.require(user, "leaderboard.edit")).toThrow(/games_portal.leaderboard.edit/);
    expect(() => requirePermission(user, permissions.node("rooms.create"))).not.toThrow();
  });

  it("rejects what the provider would reject, at definition time", () => {
    expect(() => definePermissionSet("Games", { a: "x" })).toThrow(AuthError);
    expect(() => definePermissionSet("games", { "Leaderboard.Edit": "x" })).toThrow(/valid node/);
    expect(() => definePermissionSet("games", { edit: "" })).toThrow(/1 to 120/);
    expect(() => definePermissionSet("games", { edit: "x".repeat(121) })).toThrow(/1 to 120/);
  });
});

describe("definePermissions / listPermissions", () => {
  const permissions = definePermissionSet("games_portal", { "leaderboard.edit": "Edit the leaderboard" });

  it("POSTs the nodes with HTTP Basic client authentication and returns the provider's verdict", async () => {
    idp.setAppPermissions({ post: { body: { created: ["games_portal.leaderboard.edit"], updated: [], unchanged: [], unlisted: ["games_portal.old"] } } });
    const client = createAuthClient(config(), new MemoryStorage());

    const result = await client.wilsoon.definePermissions(permissions);

    expect(result).toEqual({ created: ["games_portal.leaderboard.edit"], updated: [], unchanged: [], unlisted: ["games_portal.old"] });

    const sent = idp.appPermissionRequests.at(-1)!;
    expect(sent.method).toBe("POST");
    expect(sent.body).toEqual({ permissions: [{ node: "games_portal.leaderboard.edit", description: "Edit the leaderboard" }] });
    // Both halves URL-encoded first, as the provider's readClientCredentials expects.
    const decoded = Buffer.from(sent.authorization!.replace(/^Basic /, ""), "base64").toString();
    expect(decoded).toBe(`${CLIENT_ID}:${encodeURIComponent("s3cret+/%")}`);
    expect(JSON.stringify(sent.body)).not.toContain("s3cret");
  });

  it("refuses from a public client before making a request", async () => {
    const client = createAuthClient(config({ clientSecret: undefined }), new MemoryStorage());
    const before = idp.appPermissionRequests.length;

    await expect(client.wilsoon.definePermissions(permissions)).rejects.toMatchObject({ code: "CONFIDENTIAL_CLIENT_REQUIRED" });
    await expect(client.wilsoon.listPermissions()).rejects.toMatchObject({ code: "CONFIDENTIAL_CLIENT_REQUIRED" });
    expect(idp.appPermissionRequests.length).toBe(before);
  });

  it("surfaces the provider's refusal with its code", async () => {
    idp.setAppPermissions({ post: { status: 400, body: { error: "invalid_request", error_description: 'permissions[0]: "x.y" must start with this app\'s prefix "games_portal.".' } } });
    const client = createAuthClient(config(), new MemoryStorage());

    const error = await client.wilsoon.definePermissions([{ node: "x.y", description: "nope" }]).then(() => null, (e: PermissionRegistryError) => e);
    expect(error).toBeInstanceOf(PermissionRegistryError);
    if (!error) return;
    expect(error.error).toBe("invalid_request");
    expect(error.status).toBe(400);
    expect(error.message).toMatch(/prefix/);
  });

  it("lists the registered nodes", async () => {
    idp.setAppPermissions({});
    const client = createAuthClient(config(), new MemoryStorage());

    await expect(client.wilsoon.listPermissions()).resolves.toEqual([{ node: "games_portal.access", description: "Sign in", builtIn: true }]);
    expect(idp.appPermissionRequests.at(-1)!.method).toBe("GET");
  });
});

describe("liveAccess", () => {
  it("maps introspection to active, live permissions and sid", async () => {
    idp.setIntrospection({ active: true, sub: "user-1", permissions: ["games_portal.access"], sid: "sess-1" });
    const client = createAuthClient(config(), new MemoryStorage());

    await expect(client.wilsoon.liveAccess(await idp.mintAccessToken())).resolves.toEqual({ active: true, permissions: ["games_portal.access"], sid: "sess-1" });
    // The generic core entry point goes through the same hook.
    await expect(client.liveAccess(await idp.mintAccessToken())).resolves.toMatchObject({ active: true });
  });

  it("reports a signed-out session or lost access as inactive", async () => {
    idp.setIntrospection({ active: false });
    const client = createAuthClient(config(), new MemoryStorage());

    await expect(client.wilsoon.liveAccess(await idp.mintAccessToken())).resolves.toEqual({ active: false });
  });

  it("does not cache by default, and caches within a configured window", async () => {
    idp.setIntrospection({ active: true, sub: "user-1", permissions: [] });
    const token = await idp.mintAccessToken();

    const uncached = createAuthClient(config(), new MemoryStorage());
    let before = idp.introspectionRequests.length;
    await uncached.wilsoon.liveAccess(token);
    await uncached.wilsoon.liveAccess(token);
    expect(idp.introspectionRequests.length - before).toBe(2);

    const cached = createAuthClient(config({}, wilsoon({ liveAccessCacheSeconds: 5 })), new MemoryStorage());
    before = idp.introspectionRequests.length;
    await Promise.all([cached.wilsoon.liveAccess(token), cached.wilsoon.liveAccess(token)]);
    await cached.wilsoon.liveAccess(token);
    expect(idp.introspectionRequests.length - before).toBe(1);
  });
});

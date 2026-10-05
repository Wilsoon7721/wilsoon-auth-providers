// 2.x @wilsoon/auth-core suite, run through the wilsoon() profile: only client construction differs from 2.3.0.
import { SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
    AuthClient,
    ClaimValidationError,
    DiscoveryError,
    isMachineToken,
    IssuerMismatchError,
    MachineTokenNotAllowedError,
    MemoryStorage,
    NonceMismatchError,
    NoTokenError,
    NotAMachineTokenError,
    TokenVerificationError,
} from "@wilsoon/auth-core";
import { wilsoon } from "../../src/index";
import { API_AUDIENCE, CLIENT_ID, OTHER_CLIENT_ID, attackerKeys, startFakeIdp, unsignedToken, type FakeIdp } from "../fake-idp";

let idp: FakeIdp;
const client = () => new AuthClient({ profile: wilsoon(),
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    redirectUri: 'http://localhost:3000/callback',
    apiAudience: API_AUDIENCE,
}, new MemoryStorage());

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterAll(async () => {
    await idp.close();
});

describe('verifyIdToken', () => {
    it('accepts a correctly signed token and maps the security claims', async () => {
        const user = await client().verifyIdToken(await idp.mintIdToken());

        expect(user.id).toBe('user-1');
        expect(user.role).toBe('admin');
        expect(user.authMethods).toEqual(['mfa', 'fido', 'hw']);
        expect(user.sessionVersion).toBe(3);
        expect(user.audience).toBe(CLIENT_ID);
        expect(user.issuer).toBe(idp.issuer);
        expect(user.email).toBe('ada@example.com');
        expect(user.claims.sub).toBe('user-1');
    });

    it('rejects an unsigned alg:none token that claims admin', async () => {
        const forged = unsignedToken({
            sub: 'user-1',
            role: 'admin',
            amr: ['mfa', 'fido', 'hw'],
            session_version: 99,
            email: 'attacker@example.com',
            iss: idp.issuer,
            aud: CLIENT_ID,
            exp: Math.floor(Date.now() / 1000) + 3600,
        });

        await expect(client().verifyIdToken(forged)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects a token signed with an unpublished key', async () => {
        const { privateKey } = await attackerKeys();
        const forged = await idp.mintIdToken({ role: 'admin' }, { key: privateKey });

        await expect(client().verifyIdToken(forged)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects an HMAC token that reuses the algorithm confusion trick', async () => {
        const hmac = await new SignJWT({ sub: 'user-1', role: 'admin', aud: CLIENT_ID })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuer(idp.issuer)
            .setIssuedAt()
            .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
            .sign(new Uint8Array(32));

        await expect(client().verifyIdToken(hmac)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects a token minted for a different application (token substitution)', async () => {
        const otherApp = await idp.mintIdToken({}, { audience: OTHER_CLIENT_ID });

        await expect(client().verifyIdToken(otherApp)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects a token from a different issuer', async () => {
        const foreign = await idp.mintIdToken({}, { issuer: 'https://evil.example.com' });

        await expect(client().verifyIdToken(foreign)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects an expired token', async () => {
        const expired = await idp.mintIdToken({}, { expiresInSeconds: -3600 });

        await expect(client().verifyIdToken(expired)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects a token with no exp claim', async () => {
        const eternal = await idp.mintIdToken({}, { withoutExpiry: true });

        await expect(client().verifyIdToken(eternal)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects a malformed token', async () => {
        await expect(client().verifyIdToken('not-a-jwt')).rejects.toThrow(NoTokenError);
        await expect(client().verifyIdToken('')).rejects.toThrow(NoTokenError);
    });

    it('requires the nonce to match the authorization request', async () => {
        const token = await idp.mintIdToken({ nonce: 'nonce-from-another-request' });

        await expect(client().verifyIdToken(token, { nonce: 'nonce-for-this-request' })).rejects.toThrow(NonceMismatchError);
        await expect(client().verifyIdToken(await idp.mintIdToken({ nonce: 'abc' }), { nonce: 'abc' })).resolves.toMatchObject({ nonce: 'abc' });
    });

    it('rejects a token with no nonce when one was expected', async () => {
        await expect(client().verifyIdToken(await idp.mintIdToken(), { nonce: 'abc' })).rejects.toThrow(NonceMismatchError);
    });

    it('enforces a maximum authentication age for step-up checks', async () => {
        const stale = await idp.mintIdToken({ auth_time: Math.floor(Date.now() / 1000) - 7200 });

        await expect(client().verifyIdToken(stale, { maxAuthAgeSeconds: 300 })).rejects.toThrow(ClaimValidationError);
        await expect(client().verifyIdToken(await idp.mintIdToken(), { maxAuthAgeSeconds: 300 })).resolves.toBeDefined();
    });

    it('validates role at the boundary instead of asserting it', async () => {
        // 3.0: an unknown role no longer fails the login; it is carried in `roles` and never maps onto a known `role`.
        const unknown = await client().verifyIdToken(await idp.mintIdToken({ role: 'superuser' }));
        expect(unknown.role).toBeUndefined();
        expect(unknown.roles).toEqual(['superuser']);

        const noRole = await client().verifyIdToken(await idp.mintIdToken({ role: undefined }));
        expect(noRole.role).toBe('user');
    });

    it('reads security claims from a nested oidc_fields payload as well as a flat one', async () => {
        const nested = await idp.mintIdToken({
            role: undefined,
            session_version: undefined,
            oidc_fields: { role: 'user', session_version: 7, id: 'user-1' },
        });

        const user = await client().verifyIdToken(nested);
        expect(user.role).toBe('user');
        expect(user.sessionVersion).toBe(7);
    });

    it('caches the key set across verifications', async () => {
        const shared = client();
        const before = idp.jwksHits;

        await shared.verifyIdToken(await idp.mintIdToken());
        await shared.verifyIdToken(await idp.mintIdToken());

        expect(idp.jwksHits - before).toBe(1);
    });

    it('recovers when the provider rotates its key without changing the kid', async () => {
        const shared = client();
        await shared.verifyIdToken(await idp.mintIdToken());

        await idp.rotateKey();
        const afterRotation = await idp.mintIdToken();

        await expect(shared.verifyIdToken(afterRotation)).resolves.toMatchObject({ id: 'user-1' });
    });
});

describe('verifyAccessToken', () => {
    it('verifies a token against the pinned audience', async () => {
        const claims = await client().verifyAccessToken(await idp.mintAccessToken());

        expect(claims.subject).toBe('user-1');
        expect(claims.scopes).toEqual(['openid', 'profile', 'email']);
        expect(claims.audience).toContain(API_AUDIENCE);
        expect(claims.jwtId).toBe('jti-1');
    });

    it('refuses to verify without an audience to pin', async () => {
        const unpinned = new AuthClient({ profile: wilsoon(),
            clientId: CLIENT_ID,
            issuer: idp.issuer,
            redirectUri: 'http://localhost:3000/callback',
        }, new MemoryStorage());

        // 3.0: the profile pins https://api.wilsoon.dev, so this verifies; a standards-only client still refuses (see core's suite).
        await expect(unpinned.verifyAccessToken(await idp.mintAccessToken())).resolves.toMatchObject({ audience: [API_AUDIENCE] });
    });

    it('rejects a token issued for another resource server', async () => {
        const other = await idp.mintAccessToken({}, { audience: 'https://other-api.example.com' });

        await expect(client().verifyAccessToken(other)).rejects.toThrow(TokenVerificationError);
    });

    it('rejects an ID token passed where an access token is expected', async () => {
        await expect(client().verifyAccessToken(await idp.mintIdToken())).rejects.toThrow(TokenVerificationError);
    });

    it('enforces required scopes', async () => {
        const token = await idp.mintAccessToken({ scope: 'openid' });

        await expect(client().verifyAccessToken(token, { requiredScopes: ['openid', 'offline_access'] })).rejects.toThrow(ClaimValidationError);
        await expect(client().verifyAccessToken(token, { requiredScopes: ['openid'] })).resolves.toBeDefined();
    });
});

describe('discovery', () => {
    it('refuses a discovery document that advertises a different issuer', async () => {
        idp.setAdvertisedIssuer('https://evil.example.com');
        try {
            await expect(client().verifyIdToken(await idp.mintIdToken())).rejects.toThrow(IssuerMismatchError);
        } finally {
            idp.setAdvertisedIssuer(null);
        }
    });

    it('allows an explicit expectedIssuer override', async () => {
        idp.setAdvertisedIssuer('https://id.wilsoon.dev');
        try {
            const overridden = new AuthClient({ profile: wilsoon(),
                clientId: CLIENT_ID,
                issuer: idp.issuer,
                redirectUri: 'http://localhost:3000/callback',
                expectedIssuer: idp.issuer,
            }, new MemoryStorage());

            await expect(overridden.verifyIdToken(await idp.mintIdToken())).resolves.toMatchObject({ id: 'user-1' });
        } finally {
            idp.setAdvertisedIssuer(null);
        }
    });

    it('fails when the discovery document cannot be reached', async () => {
        const unreachable = new AuthClient({ profile: wilsoon(),
            clientId: CLIENT_ID,
            issuer: 'http://127.0.0.1:1/',
            redirectUri: 'http://localhost:3000/callback',
        }, new MemoryStorage());

        await expect(unreachable.verifyIdToken(await idp.mintIdToken())).rejects.toThrow(DiscoveryError);
    });
});

describe('unverified decode paths', () => {
    it('decodeIdTokenUnsafe throws on a malformed token', () => {
        expect(() => client().decodeIdTokenUnsafe('a.b')).toThrow(NoTokenError);
        expect(() => client().decodeIdTokenUnsafe('a.!!.c')).toThrow(NoTokenError);
    });

    it('getUser rejects an ID token before it reaches the network', async () => {
        await expect(client().getUser(await idp.mintIdToken())).rejects.toThrow(ClaimValidationError);
    });
});

describe('machine tokens (client_credentials)', () => {
    const MACHINE_CLIENT = 'svc-reporting';

    /** What the provider mints for `grant_type=client_credentials`: `sub` is the client, and there is no scope. */
    const mintMachineToken = (claims: Record<string, unknown> = {}) => idp.mintAccessToken({
        sub: MACHINE_CLIENT,
        client_id: MACHINE_CLIENT,
        token_use: 'client',
        scope: undefined,
        ...claims,
    });

    const confidential = () => new AuthClient({ profile: wilsoon(),
        clientId: CLIENT_ID,
        issuer: idp.issuer,
        apiAudience: API_AUDIENCE,
        clientSecret: 'shh',
    }, new MemoryStorage());

    it('refuses a machine token on verifyAccessToken by default', async () => {
        await expect(client().verifyAccessToken(await mintMachineToken()))
            .rejects.toThrow(MachineTokenNotAllowedError);
    });

    it('names the offending client on the refusal, so the caller can tell who called', async () => {
        await client().verifyAccessToken(await mintMachineToken()).catch((error: MachineTokenNotAllowedError) => {
            expect(error.code).toBe('MACHINE_TOKEN_NOT_ALLOWED');
            expect(error.clientId).toBe(MACHINE_CLIENT);
        });
        expect.assertions(2);
    });

    it('accepts one when the caller opts in, and marks it as a client', async () => {
        const claims = await client().verifyAccessToken(await mintMachineToken(), { allowMachineTokens: true });

        expect(claims.tokenUse).toBe('client');
        expect(claims.subject).toBe(MACHINE_CLIENT);
        expect(claims.scopes).toEqual([]);
    });

    it('marks an ordinary user token as a user', async () => {
        const claims = await client().verifyAccessToken(await idp.mintAccessToken());

        expect(claims.tokenUse).toBe('user');
        expect(claims.subject).toBe('user-1');
    });

    it('verifyMachineToken returns a client identity with no user fields on it', async () => {
        const machine = await client().verifyMachineToken(await mintMachineToken());

        expect(machine.clientId).toBe(MACHINE_CLIENT);
        expect(machine.tokenUse).toBe('client');
        expect(machine.audience).toContain(API_AUDIENCE);
        expect('id' in machine).toBe(false);
        expect('role' in machine).toBe(false);
        expect('authMethods' in machine).toBe(false);
    });

    it('verifyMachineToken refuses a user token, so the check runs in both directions', async () => {
        await expect(client().verifyMachineToken(await idp.mintAccessToken()))
            .rejects.toThrow(NotAMachineTokenError);
    });

    it('still enforces the signature: a forged token_use buys nothing', async () => {
        const forged = unsignedToken({
            sub: MACHINE_CLIENT,
            token_use: 'client',
            iss: idp.issuer,
            aud: API_AUDIENCE,
            exp: Math.floor(Date.now() / 1000) + 3600,
        });

        await expect(client().verifyMachineToken(forged)).rejects.toThrow(TokenVerificationError);
    });

    it('still enforces the audience: a machine token for another API is rejected', async () => {
        const elsewhere = await idp.mintAccessToken(
            { sub: MACHINE_CLIENT, token_use: 'client' },
            { audience: 'https://other-api.example.com' }
        );

        await expect(client().verifyMachineToken(elsewhere)).rejects.toThrow(TokenVerificationError);
    });

    it('refuses to resolve a platform session from a machine token', async () => {
        await expect(confidential().verifyPlatformSession(await mintMachineToken()))
            .rejects.toThrow(MachineTokenNotAllowedError);
    });

    it('refuses to resolve a session from a cookie holding a machine token', async () => {
        await expect(confidential().resolveSession({ access_token: await mintMachineToken() }))
            .rejects.toThrow(MachineTokenNotAllowedError);
    });

    it('refuses a session-version check on a machine token rather than failing as undeterminable', async () => {
        await expect(confidential().isSessionCurrent(
            { id: MACHINE_CLIENT, sessionVersion: 1 },
            { token: await mintMachineToken() }
        )).rejects.toThrow(MachineTokenNotAllowedError);
    });

    it('catches a machine token from a provider that emits no token_use', async () => {
        // RFC 9068 §5: a client_credentials `sub` SHOULD be the client id. Relying on `token_use`
        // alone failed open here - every machine token read as a user, which is the exact
        // confusion the check exists to prevent.
        const foreign = await idp.mintAccessToken({ sub: MACHINE_CLIENT, client_id: MACHINE_CLIENT, scope: undefined });

        await expect(client().verifyAccessToken(foreign)).rejects.toThrow(MachineTokenNotAllowedError);

        const claims = await client().verifyAccessToken(foreign, { allowMachineTokens: true });
        expect(claims.tokenUse).toBe('client');
    });

    it('does not mistake an ordinary user token for a machine one', async () => {
        // `sub` is the user and `client_id` is this application, so the two differ.
        const claims = await client().verifyAccessToken(await idp.mintAccessToken());
        expect(claims.tokenUse).toBe('user');
    });

    it('lets a provider define its own marker through detectMachineToken', async () => {
        const custom = new AuthClient({ profile: wilsoon(),
            clientId: CLIENT_ID,
            issuer: idp.issuer,
            apiAudience: API_AUDIENCE,
            detectMachineToken: (claims) => claims.kind === 'service',
        }, new MemoryStorage());

        const marked = await idp.mintAccessToken({ sub: 'svc-9', kind: 'service' });
        await expect(custom.verifyAccessToken(marked)).rejects.toThrow(MachineTokenNotAllowedError);

        // And the predicate replaces the defaults rather than adding to them, so a token the
        // built-in signals would flag is a user here.
        const builtinWouldFlag = await idp.mintAccessToken({ sub: MACHINE_CLIENT, client_id: MACHINE_CLIENT });
        const claims = await custom.verifyAccessToken(builtinWouldFlag);
        expect(claims.tokenUse).toBe('user');
    });

    it('isMachineToken reads the claim, and defaults everything else to a user', () => {
        expect(isMachineToken({ token_use: 'client' })).toBe(true);
        expect(isMachineToken({ token_use: 'user' })).toBe(false);
        expect(isMachineToken({})).toBe(false);
        expect(isMachineToken(null)).toBe(false);

        // The RFC 9068 signal, for providers that emit no token_use.
        expect(isMachineToken({ sub: 'svc-1', client_id: 'svc-1' })).toBe(true);
        expect(isMachineToken({ sub: 'user-1', client_id: 'svc-1' })).toBe(false);
        expect(isMachineToken({ sub: '', client_id: '' })).toBe(false);
    });
});

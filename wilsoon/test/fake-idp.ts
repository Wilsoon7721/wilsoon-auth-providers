import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

export const CLIENT_ID = 'test-client';
export const OTHER_CLIENT_ID = 'someone-elses-client';
export const API_AUDIENCE = 'https://api.wilsoon.dev';

/** The identity provider serves a hardcoded `kid`, so the fakes do too. */
export const KID = '5c6a00b46f1e4505b2391ddce28d0b34';

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

export interface TokenEndpointResult {
    status?: number;
    body: unknown;
}

/**
 * A minimal stand-in for a real identity provider: it publishes the same discovery
 * document and JWKS shape, and signs tokens with the same claim layout.
 *
 * A real HTTP server rather than a `fetch` mock, because jose fetches the JWKS through
 * `node:http` on the server runtime.
 */
export interface FakeIdp {
    issuer: string;
    /** Number of times the JWKS endpoint has been read, for cache assertions. */
    jwksHits: number;
    /** Form bodies received by the token endpoint. */
    tokenRequests: URLSearchParams[];
    /** Number of times the token endpoint has been called. */
    tokenHits: number;
    setTokenHandler(handler: ((params: URLSearchParams) => Promise<TokenEndpointResult> | TokenEndpointResult) | null): void;
    setUserinfo(body: unknown, status?: number): void;
    /** Makes the discovery document advertise an issuer other than its own URL. */
    setAdvertisedIssuer(value: string | null): void;
    /** Overrides the introspection response, or drops the endpoint from discovery. */
    setIntrospection(body: unknown, options?: { status?: number; advertise?: boolean }): void;
    /** Form bodies received by the introspection endpoint. */
    introspectionRequests: URLSearchParams[];
    /** Scripts the escalation endpoints: one create response, then a queue of poll responses. */
    setEscalation(script: EscalationScript): void;
    /** Form bodies received by the escalation create endpoint. */
    escalationRequests: URLSearchParams[];
    /** Form bodies received by the escalation poll endpoint. */
    escalationPolls: URLSearchParams[];
    /** Scripts /api/apps/permissions: the next response for each method. */
    setAppPermissions(script: { get?: { status?: number; body: unknown }; post?: { status?: number; body: unknown } }): void;
    /** Requests received by /api/apps/permissions: method, Authorization header and parsed JSON body. */
    appPermissionRequests: Array<{ method: string; authorization?: string; body: unknown }>;
    /** Scripts the device authorization endpoint, or drops it from discovery. */
    setDeviceCode(body: unknown, options?: { status?: number; advertise?: boolean }): void;
    /** Form bodies received by the device authorization endpoint. */
    deviceCodeRequests: URLSearchParams[];
    mintIdToken(claims?: Record<string, unknown>, options?: MintOptions): Promise<string>;
    mintAccessToken(claims?: Record<string, unknown>, options?: MintOptions): Promise<string>;
    /** Mints a step-up proof token, `evt: "escalation"` by default. */
    mintEscalationToken(claims?: Record<string, unknown>, options?: MintOptions): Promise<string>;
    /** Replaces the signing key while keeping the same `kid`, as a key rotation would. */
    rotateKey(): Promise<void>;
    close(): Promise<void>;
}

/**
 * How the fake provider should answer an escalation.
 *
 * `polls` is consumed in order and the last entry repeats, so a test can say "pending,
 * pending, then done" without counting requests.
 */
export interface EscalationScript {
    create?: { status?: number; body: unknown };
    polls?: Array<{ status?: number; body: unknown }>;
}

export interface MintOptions {
    /** Sign with a key the provider does not publish (a forgery). */
    key?: KeyPair['privateKey'];
    /** Override the protected header. */
    header?: Record<string, unknown>;
    /** Omit `exp`. */
    withoutExpiry?: boolean;
    /** Seconds until expiry (default 3600; negative values are already expired). */
    expiresInSeconds?: number;
    /** Override the audience. */
    audience?: string | string[];
    /** Override the issuer. */
    issuer?: string;
}

const base64Url = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');

/** Builds an `alg: none` token: a payload with an empty signature. */
export function unsignedToken(payload: Record<string, unknown>): string {
    return `${base64Url({ alg: 'none', typ: 'JWT' })}.${base64Url(payload)}.`;
}

/** Starts the fake IdP: real RS256-signed tokens and discovery, nothing over the network. */
export async function startFakeIdp(): Promise<FakeIdp> {
    let keys = await generateKeyPair('RS256', { extractable: true });

    const publishedJwks = async () => ({
        keys: [{ ...(await exportJWK(keys.publicKey)), kid: KID, alg: 'RS256', use: 'sig', kty: 'RSA' }],
    });

    const state = {
        jwksHits: 0,
        tokenHits: 0,
        tokenRequests: [] as URLSearchParams[],
        tokenHandler: null as null | ((params: URLSearchParams) => Promise<TokenEndpointResult> | TokenEndpointResult),
        userinfo: { sub: 'user-1', name: 'Ada Lovelace', email: 'ada@example.com', email_verified: true } as unknown,
        userinfoStatus: 200,
        advertisedIssuer: null as string | null,
        introspection: { active: true, sub: 'user-1', role: 'admin', session_version: 3 } as unknown,
        introspectionStatus: 200,
        advertiseIntrospection: true,
        introspectionRequests: [] as URLSearchParams[],
        escalation: {} as EscalationScript,
        escalationRequests: [] as URLSearchParams[],
        escalationPolls: [] as URLSearchParams[],
        pollCursor: 0,
        deviceCode: null as unknown,
        deviceCodeStatus: 200,
        advertiseDeviceGrant: true,
        deviceCodeRequests: [] as URLSearchParams[],
        appPermissions: {} as { get?: { status?: number; body: unknown }; post?: { status?: number; body: unknown } },
        appPermissionRequests: [] as Array<{ method: string; authorization?: string; body: unknown }>,
    };

    let issuer = '';

    const sign = async (claims: Record<string, unknown>, options: MintOptions = {}) => {
        const jwt = new SignJWT(claims)
            .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: KID, ...(options.header || {}) })
            .setIssuer(options.issuer ?? issuer)
            .setIssuedAt();

        if (!options.withoutExpiry) jwt.setExpirationTime(Math.floor(Date.now() / 1000) + (options.expiresInSeconds ?? 3600));

        return jwt.sign(options.key ?? keys.privateKey);
    };

    const mintIdToken = (claims: Record<string, unknown> = {}, options: MintOptions = {}) =>
        sign({
            sub: 'user-1',
            id: 'user-1',
            email: 'ada@example.com',
            name: 'Ada Lovelace',
            role: 'admin',
            amr: ['mfa', 'fido', 'hw'],
            session_version: 3,
            auth_time: Math.floor(Date.now() / 1000),
            aud: options.audience ?? CLIENT_ID,
            ...claims,
        }, options);

    const mintAccessToken = (claims: Record<string, unknown> = {}, options: MintOptions = {}) =>
        sign({
            sub: 'user-1',
            scope: 'openid profile email',
            client_id: CLIENT_ID,
            jti: 'jti-1',
            aud: options.audience ?? API_AUDIENCE,
            ...claims,
        }, options);

    const mintEscalationToken = (claims: Record<string, unknown> = {}, options: MintOptions = {}) =>
        sign({
            sub: 'user-1',
            evt: 'escalation',
            satisfied_by: 'passkey',
            already_satisfied: false,
            amr: ['mfa', 'fido', 'hw'],
            acr: 'urn:wilsoon:acr:passkey',
            auth_time: Math.floor(Date.now() / 1000),
            aud: options.audience ?? CLIENT_ID,
            ...claims,
        }, options);

    const server: Server = createServer((req, res) => {
        void (async () => {
            const url = new URL(req.url || '/', issuer || 'http://127.0.0.1');
            const json = (status: number, body: unknown) => {
                res.writeHead(status, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(body));
            };

            if (url.pathname === '/.well-known/openid-configuration') {
                return json(200, {
                    issuer: state.advertisedIssuer ?? issuer,
                    authorization_endpoint: `${issuer}/authorize`,
                    token_endpoint: `${issuer}/api/token`,
                    userinfo_endpoint: `${issuer}/api/userinfo`,
                    end_session_endpoint: `${issuer}/api/logout`,
                    jwks_uri: `${issuer}/api/jwks`,
                    ...(state.advertiseIntrospection ? { introspection_endpoint: `${issuer}/api/introspect` } : {}),
                    ...(state.advertiseDeviceGrant ? { device_authorization_endpoint: `${issuer}/api/device/code` } : {}),
                    grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
                    response_types_supported: ['code'],
                    id_token_signing_alg_values_supported: ['RS256'],
                    code_challenge_methods_supported: ['S256'],
                });
            }

            if (url.pathname === '/api/jwks') {
                state.jwksHits += 1;
                return json(200, await publishedJwks());
            }

            if (url.pathname === '/api/token') {
                const chunks: Buffer[] = [];
                for await (const chunk of req) chunks.push(chunk as Buffer);
                const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));

                state.tokenHits += 1;
                state.tokenRequests.push(params);

                if (state.tokenHandler) {
                    const result = await state.tokenHandler(params);
                    return json(result.status ?? 200, result.body);
                }

                return json(200, {
                    access_token: await mintAccessToken(),
                    id_token: await mintIdToken({ nonce: params.get('nonce') || undefined }),
                    token_type: 'Bearer',
                    expires_in: 3600,
                    scope: 'openid profile email',
                });
            }

            if (url.pathname === '/api/introspect') {
                const chunks: Buffer[] = [];
                for await (const chunk of req) chunks.push(chunk as Buffer);
                state.introspectionRequests.push(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));

                return json(state.introspectionStatus, state.introspection);
            }

            const readForm = async () => {
                const chunks: Buffer[] = [];
                for await (const chunk of req) chunks.push(chunk as Buffer);
                return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
            };

            if (url.pathname === '/api/escalate') {
                state.escalationRequests.push(await readForm());
                state.pollCursor = 0;

                const scripted = state.escalation.create;
                if (scripted) return json(scripted.status ?? 200, scripted.body);

                const expiresAt = Math.floor(Date.now() / 1000) + 300;
                return json(200, {
                    escalation_id: 'esc-1',
                    escalation_url: `${issuer}/2fa/escalate?escalation_id=esc-1&signature=abc`,
                    strategies: ['passkey'],
                    force: false,
                    poll_token: 'poll-secret',
                    expires_in: 300,
                    expires_at: expiresAt,
                    interval: 1,
                });
            }

            if (url.pathname === '/api/escalate/poll') {
                state.escalationPolls.push(await readForm());

                const queue = state.escalation.polls ?? [];
                const scripted = queue[Math.min(state.pollCursor, queue.length - 1)];
                state.pollCursor += 1;

                if (scripted) return json(scripted.status ?? 200, scripted.body);

                return json(200, {
                    status: 'completed',
                    escalation_id: 'esc-1',
                    already_satisfied: false,
                    satisfied_by: 'passkey',
                    amr: ['mfa', 'fido', 'hw'],
                    acr: 'urn:wilsoon:acr:passkey',
                    auth_time: Math.floor(Date.now() / 1000),
                    escalation_token: await mintEscalationToken(),
                });
            }

            if (url.pathname === '/api/device/code') {
                state.deviceCodeRequests.push(await readForm());

                if (state.deviceCode !== null) return json(state.deviceCodeStatus, state.deviceCode);

                return json(200, {
                    device_code: 'dev-code-1',
                    user_code: 'BCDF-GHJK',
                    verification_uri: `${issuer}/device`,
                    verification_uri_complete: `${issuer}/device?user_code=BCDF-GHJK`,
                    expires_in: 600,
                    interval: 1,
                });
            }

            if (url.pathname === '/api/apps/permissions') {
                const chunks: Buffer[] = [];
                for await (const chunk of req) chunks.push(chunk as Buffer);
                const text = Buffer.concat(chunks).toString('utf8');
                state.appPermissionRequests.push({ method: req.method || 'GET', authorization: req.headers.authorization, body: text ? JSON.parse(text) : null });

                const scripted = req.method === 'POST' ? state.appPermissions.post : state.appPermissions.get;
                if (scripted) return json(scripted.status ?? 200, scripted.body);
                return req.method === 'POST'
                    ? json(200, { created: [], updated: [], unchanged: [], unlisted: [] })
                    : json(200, { permissions: [{ node: 'games_portal.access', description: 'Sign in', built_in: true }] });
            }

            if (url.pathname === '/api/userinfo') {
                return json(state.userinfoStatus, state.userinfo);
            }

            return json(404, { error: 'not_found' });
        })();
    });

    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    return {
        issuer,
        get jwksHits() { return state.jwksHits; },
        get tokenHits() { return state.tokenHits; },
        get tokenRequests() { return state.tokenRequests; },
        setTokenHandler(handler) { state.tokenHandler = handler; },
        setUserinfo(body, status = 200) { state.userinfo = body; state.userinfoStatus = status; },
        setAdvertisedIssuer(value) { state.advertisedIssuer = value; },
        setIntrospection(body, options = {}) {
            state.introspection = body;
            state.introspectionStatus = options.status ?? 200;
            state.advertiseIntrospection = options.advertise ?? true;
        },
        get introspectionRequests() { return state.introspectionRequests; },
        setEscalation(script) { state.escalation = script; state.pollCursor = 0; },
        get escalationRequests() { return state.escalationRequests; },
        get escalationPolls() { return state.escalationPolls; },
        setDeviceCode(body, options = {}) {
            state.deviceCode = body;
            state.deviceCodeStatus = options.status ?? 200;
            state.advertiseDeviceGrant = options.advertise ?? true;
        },
        get deviceCodeRequests() { return state.deviceCodeRequests; },
        setAppPermissions(script) { state.appPermissions = script; },
        get appPermissionRequests() { return state.appPermissionRequests; },
        mintIdToken,
        mintAccessToken,
        mintEscalationToken,
        async rotateKey() { keys = await generateKeyPair('RS256', { extractable: true }); },
        close: () => new Promise<void>((resolve, reject) => server.close(error => (error ? reject(error) : resolve()))),
    };
}

/** A key pair the provider never publishes, for forging signatures. */
export const attackerKeys = () => generateKeyPair('RS256', { extractable: true });

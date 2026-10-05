// 2.x @wilsoon/auth-core suite, run through the wilsoon() profile: only client construction differs from 2.3.0.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
    AuthClient,
    AuthorizationDeniedError,
    AuthorizationExpiredError,
    EscalationError,
    MemoryStorage,
    pollUntilResolved,
    TokenVerificationError,
    type PollClock,
} from "@wilsoon/auth-core";
import { wilsoon } from "../../src/index";
import { API_AUDIENCE, CLIENT_ID, OTHER_CLIENT_ID, startFakeIdp, type FakeIdp } from "../fake-idp";

let idp: FakeIdp;

const client = (overrides: Record<string, unknown> = {}) => new AuthClient({ profile: wilsoon(),
    clientId: CLIENT_ID,
    issuer: idp.issuer,
    apiAudience: API_AUDIENCE,
    ...overrides,
}, new MemoryStorage());

/** Polls resolve instantly, so a test that scripts three rounds still runs in milliseconds. */
const instantClock: PollClock = { now: () => Date.now(), sleep: () => Promise.resolve() };

const pending = (extra: Record<string, unknown> = {}) => ({
    status: 400,
    body: { error: 'authorization_pending', error_description: 'Not yet.', interval: 1, ...extra },
});

beforeAll(async () => {
    idp = await startFakeIdp();
});

afterAll(async () => {
    idp.setEscalation({});
    await idp.close();
});

describe('createEscalation', () => {
    it('sends the subject as id_token_hint and the methods as a space-delimited `use`', async () => {
        idp.setEscalation({});
        const before = idp.escalationRequests.length;

        const request = await client().createEscalation({
            use: ['passkey', 'fido'],
            force: true,
            idTokenHint: await idp.mintIdToken(),
        });

        const sent = idp.escalationRequests[before];
        expect(sent.get('use')).toBe('passkey fido');
        expect(sent.get('force')).toBe('true');
        expect(sent.get('id_token_hint')).toBeTruthy();
        expect(sent.get('sub')).toBeNull();
        expect(request.escalationId).toBe('esc-1');
        expect(request.pollToken).toBe('poll-secret');
    });

    it('sends `sub` only when there is no id_token_hint to prefer', async () => {
        idp.setEscalation({});
        const before = idp.escalationRequests.length;

        await client({ clientSecret: 'shh' }).createEscalation({ use: 'passkey', subject: 'user-1' });

        const sent = idp.escalationRequests[before];
        expect(sent.get('sub')).toBe('user-1');
        expect(sent.get('client_secret')).toBe('shh');
    });

    it('omits the client secret for a public client', async () => {
        idp.setEscalation({});
        const before = idp.escalationRequests.length;

        await client().createEscalation({ use: 'passkey', idTokenHint: await idp.mintIdToken() });

        expect(idp.escalationRequests[before].get('client_secret')).toBeNull();
    });

    it('refuses to send a request that names no subject', async () => {
        await expect(client().createEscalation({ use: 'passkey' })).rejects.toThrow(EscalationError);
    });

    it('refuses to send a request that names no method', async () => {
        await expect(client().createEscalation({ use: '', subject: 'user-1' })).rejects.toThrow(EscalationError);
    });

    it("surfaces the provider's error code, so invalid_use is distinguishable", async () => {
        idp.setEscalation({ create: { status: 400, body: { error: 'invalid_use', error_description: 'Unknown method "telepathy".' } } });

        await client().createEscalation({ use: 'telepathy', subject: 'user-1' }).catch((error: EscalationError) => {
            expect(error.error).toBe('invalid_use');
            expect(error.message).toContain('telepathy');
        });
        expect.assertions(2);
    });
});

describe('pollEscalation', () => {
    it('reports pending without throwing, and adopts the interval the provider named', async () => {
        idp.setEscalation({ polls: [pending({ interval: 7 })] });

        const step = await client().pollEscalation({ escalationId: 'esc-1', pollToken: 'poll-secret', interval: 1 });

        expect(step.state).toBe('pending');
        if (step.state === 'pending') {
            expect(step.interval).toBe(7);
            expect(step.slowDown).toBe(false);
        }
    });

    it('flags slow_down as pending rather than an error, and takes the raised interval', async () => {
        idp.setEscalation({ polls: [{ status: 400, body: { error: 'slow_down', interval: 10 } }] });

        const step = await client().pollEscalation({ escalationId: 'esc-1', pollToken: 'poll-secret', interval: 1 });

        expect(step.state).toBe('pending');
        if (step.state === 'pending') {
            expect(step.slowDown).toBe(true);
            expect(step.interval).toBe(10);
        }
    });

    it('throws a denial as its own error, carrying the reason', async () => {
        idp.setEscalation({ polls: [{ status: 400, body: { error: 'access_denied', error_description: 'The user refused.', reason: 'user_cancelled' } }] });

        await client().pollEscalation({ escalationId: 'esc-1', pollToken: 'poll-secret', interval: 1 })
            .catch((error: AuthorizationDeniedError) => {
                expect(error).toBeInstanceOf(AuthorizationDeniedError);
                expect(error.reason).toBe('user_cancelled');
            });
        expect.assertions(2);
    });

    it('throws an expiry as its own error, distinct from a denial', async () => {
        idp.setEscalation({ polls: [{ status: 400, body: { error: 'expired_token', error_description: 'Too late.', expires_at: 1700000000 } }] });

        await client().pollEscalation({ escalationId: 'esc-1', pollToken: 'poll-secret', interval: 1 })
            .catch((error: AuthorizationExpiredError) => {
                expect(error).toBeInstanceOf(AuthorizationExpiredError);
                expect(error.expiresAt).toBe(1700000000);
            });
        expect.assertions(2);
    });

    it('sends the poll token and the escalation id together', async () => {
        idp.setEscalation({});
        const before = idp.escalationPolls.length;

        await client().pollEscalation({ escalationId: 'esc-1', pollToken: 'poll-secret', interval: 1 });

        const sent = idp.escalationPolls[before];
        expect(sent.get('escalation_id')).toBe('esc-1');
        expect(sent.get('poll_token')).toBe('poll-secret');
    });
});

describe('reauthorize', () => {
    it('completes without ever showing the user a URL when the session already qualifies', async () => {
        idp.setEscalation({
            polls: [{
                body: {
                    status: 'completed',
                    escalation_id: 'esc-1',
                    already_satisfied: true,
                    satisfied_by: 'passkey',
                    acr: 'urn:wilsoon:acr:passkey',
                    escalation_token: await idp.mintEscalationToken({ already_satisfied: true }),
                },
            }],
        });
        const openUrl = vi.fn();

        const result = await client().reauthorize(['passkey'], false, { subject: 'user-1', openUrl });

        expect(result.alreadySatisfied).toBe(true);
        expect(result.satisfiedBy).toBe('passkey');
        expect(openUrl).not.toHaveBeenCalled();
    });

    it('shows the URL once, then polls to completion', async () => {
        idp.setEscalation({
            polls: [
                pending(),
                pending(),
                {
                    body: {
                        status: 'completed',
                        escalation_id: 'esc-1',
                        already_satisfied: false,
                        satisfied_by: 'passkey',
                        amr: ['mfa', 'fido', 'hw'],
                        acr: 'urn:wilsoon:acr:passkey',
                        escalation_token: await idp.mintEscalationToken(),
                    },
                },
            ],
        });
        const openUrl = vi.fn();
        const onPending = vi.fn();

        const result = await client().reauthorize(['passkey'], true, {
            subject: 'user-1',
            openUrl,
            onPending,
        });

        expect(openUrl).toHaveBeenCalledTimes(1);
        expect(openUrl.mock.calls[0][0]).toContain('/2fa/escalate');
        expect(result.alreadySatisfied).toBe(false);
        expect(result.authMethods).toEqual(['mfa', 'fido', 'hw']);
        expect(onPending).toHaveBeenCalled();
    }, 20000);

    it('propagates a denial rather than treating it as "keep waiting"', async () => {
        idp.setEscalation({ polls: [{ status: 400, body: { error: 'access_denied', error_description: 'No.' } }] });

        await expect(client().reauthorize('passkey', true, { subject: 'user-1' }))
            .rejects.toThrow(AuthorizationDeniedError);
    });

    it('rejects a completion whose escalation token does not verify', async () => {
        idp.setEscalation({
            polls: [{
                body: {
                    status: 'completed',
                    escalation_id: 'esc-1',
                    already_satisfied: true,
                    // Minted for a different application: a step-up proof addressed elsewhere.
                    escalation_token: await idp.mintEscalationToken({}, { audience: OTHER_CLIENT_ID }),
                },
            }],
        });

        await expect(client().reauthorize('passkey', false, { subject: 'user-1' }))
            .rejects.toThrow(TokenVerificationError);
    });

    it('can be told not to verify, for a caller that forwards the token untouched', async () => {
        idp.setEscalation({
            polls: [{
                body: {
                    status: 'completed',
                    escalation_id: 'esc-1',
                    already_satisfied: true,
                    escalation_token: await idp.mintEscalationToken({}, { audience: OTHER_CLIENT_ID }),
                },
            }],
        });

        const result = await client().reauthorize('passkey', false, { subject: 'user-1', verifyToken: false });
        expect(result.escalationToken).toBeTruthy();
    });
});

describe('verifyEscalationToken', () => {
    it('accepts a genuine escalation token and maps the outcome', async () => {
        const verified = await client().verifyEscalationToken(await idp.mintEscalationToken());

        expect(verified.subject).toBe('user-1');
        expect(verified.satisfiedBy).toBe('passkey');
        expect(verified.acr).toBe('urn:wilsoon:acr:passkey');
        expect(verified.authMethods).toEqual(['mfa', 'fido', 'hw']);
        expect(verified.alreadySatisfied).toBe(false);
    });

    it('refuses an ID token, which is otherwise identically shaped', async () => {
        await expect(client().verifyEscalationToken(await idp.mintIdToken()))
            .rejects.toThrow(EscalationError);
    });

    it('refuses a token minted for another application', async () => {
        const elsewhere = await idp.mintEscalationToken({}, { audience: OTHER_CLIENT_ID });

        await expect(client().verifyEscalationToken(elsewhere)).rejects.toThrow(TokenVerificationError);
    });

    it('refuses an expired token', async () => {
        const stale = await idp.mintEscalationToken({}, { expiresInSeconds: -60 });

        await expect(client().verifyEscalationToken(stale)).rejects.toThrow(TokenVerificationError);
    });

    it('and verifyIdToken refuses an escalation token, so the check runs both ways', async () => {
        // The reverse direction. Both tokens are RS256, from this issuer, audienced to this
        // client - `evt` is the only thing separating "signed in" from "just proved one
        // thing", so a step-up proof must not verify as a login.
        await expect(client().verifyIdToken(await idp.mintEscalationToken()))
            .rejects.toThrow(/not an ID token/);
    });
});

describe('pollUntilResolved', () => {
    it('honours the provider interval and never lowers it', async () => {
        const waits: number[] = [];
        const clock: PollClock = { now: () => 0, sleep: (ms) => { waits.push(ms); return Promise.resolve(); } };
        let attempts = 0;

        const value = await pollUntilResolved<string>(
            () => {
                attempts += 1;
                if (attempts === 1) return Promise.resolve({ state: 'pending', interval: 5, slowDown: false });
                if (attempts === 2) return Promise.resolve({ state: 'pending', interval: 2, slowDown: false });
                return Promise.resolve({ state: 'done', value: 'ok' });
            },
            1,
            {},
            clock
        );

        expect(value).toBe('ok');
        // 5s was requested, then 2s - the loop keeps 5, because backing off is one-way.
        expect(waits).toEqual([5000, 5000]);
    });

    it('stops immediately when the signal is already aborted', async () => {
        const controller = new AbortController();
        controller.abort(new Error('cancelled'));

        await expect(pollUntilResolved(
            () => Promise.resolve({ state: 'pending', interval: 1, slowDown: false }),
            1,
            { signal: controller.signal },
            instantClock
        )).rejects.toThrow('cancelled');
    });

    it('gives up on maxWaitSeconds rather than polling a hung request forever', async () => {
        let now = 0;
        const clock: PollClock = { now: () => now, sleep: (ms) => { now += ms; return Promise.resolve(); } };

        await expect(pollUntilResolved(
            () => Promise.resolve({ state: 'pending', interval: 5, slowDown: false }),
            5,
            { maxWaitSeconds: 12 },
            clock
        )).rejects.toThrow(/Gave up waiting/);
    });

    it('lets a throwing onPending cancel the loop', async () => {
        await expect(pollUntilResolved(
            () => Promise.resolve({ state: 'pending', interval: 1, slowDown: false }),
            1,
            { onPending: () => { throw new Error('user cancelled'); } },
            instantClock
        )).rejects.toThrow('user cancelled');
    });
});

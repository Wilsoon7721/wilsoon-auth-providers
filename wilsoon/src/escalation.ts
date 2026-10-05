import { ACCESS_DENIED, AUTHORIZATION_PENDING, AuthorizationDeniedError, AuthorizationExpiredError, ClaimValidationError, CreateEscalationOptions, ESCALATION_TOKEN_TYPE, EscalationError, EscalationRequest, EscalationResult, EXPIRED_TOKEN, normalizeIssuer, NoTokenError, PollStep, pollUntilResolved, ProfileContext, ReauthorizeOptions, SLOW_DOWN, VerifiedEscalation } from "@wilsoon/auth-core";
import { asNumber, asString, asStringArray, DEFAULT_POLL_INTERVAL_SECONDS, isRecord } from "./util";

export interface EscalationExtensions {
  /**
   * Creates a method escalation request: asks the provider to require a stronger authentication method from a user who is already signed in.
   * See {@link EscalationExtensions.reauthorize} for the whole exchange as one call.
   *
   * @throws {EscalationError} If the provider refuses the request - an unknown method (`invalid_use`), an unusable `id_token_hint`, or an unknown subject.
   */
  createEscalation(options: CreateEscalationOptions): Promise<EscalationRequest>;
  /**
   * Polls an escalation once: `pending` while the provider is still waiting, and a throw for every terminal outcome.
   *
   * @throws {AuthorizationDeniedError} If the user refused.
   * @throws {AuthorizationExpiredError} If the provider says the request expired.
   * @throws {EscalationError} If the request is unknown, or the poll token does not match.
   */
  pollEscalation(request: Pick<EscalationRequest, "escalationId" | "pollToken" | "interval">): Promise<PollStep<EscalationResult>>;
  /**
   * Requires a stronger authentication method from the signed-in user, and waits for the answer.
   * With `force: false` a session that already qualifies completes on the first poll, and `openUrl` is never called.
   *
   * @throws {AuthorizationDeniedError} If the user refused.
   * @throws {AuthorizationExpiredError} If the request expired before it was completed.
   * @throws {EscalationError} If the provider refuses the request, or returns a token that fails verification.
   */
  reauthorize(use: string | string[], force?: boolean, options?: Omit<ReauthorizeOptions, "use" | "force">): Promise<EscalationResult>;
  /**
   * Verifies an escalation token, including that `evt` is `escalation`, which is the only thing that tells it apart from an ID token.
   *
   * @throws {EscalationError} If the token is not an escalation token.
   * @throws {TokenVerificationError} If the signature, issuer, audience or expiry fails.
   */
  verifyEscalationToken(escalationToken: string): Promise<VerifiedEscalation>;
}

/**
 * Builds the escalation functions for a client.
 * Not part of standard OIDC discovery - location is assumed at `https://id.wilsoon.dev/api/escalate` until overridden.
 */
export function escalationExtensions(ctx: ProfileContext, endpoint: string | undefined): EscalationExtensions {
  const base = (asString(endpoint) || asString(ctx.config.escalationEndpoint) || `${normalizeIssuer(ctx.config.issuer)}/api/escalate`).replace(/\/+$/, "");
  const endpoints = { create: base, poll: `${base}/poll` };

  // A client with a secret must present, a public client doesn't need one
  const clientAuth = (): Record<string, string> => {
    const secret = asString(ctx.config.clientSecret);
    return { client_id: ctx.config.clientId, ...(secret ? { client_secret: secret } : {}) };
  };

  const createEscalation = async (options: CreateEscalationOptions): Promise<EscalationRequest> => {
    const use = Array.isArray(options.use) ? options.use.join(" ") : asString(options.use);
    if (!use) throw new EscalationError("`use` is required: an escalation must say which methods would satisfy it.");

    const idTokenHint = asString(options.idTokenHint);
    const subject = asString(options.subject);
    if (!idTokenHint && !subject) throw new EscalationError("An escalation must name its subject. Pass `idTokenHint` (preferred, and the only option for a public " + "client) or `subject` from a confidential client.");

    const response = await fetch(endpoints.create, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        ...clientAuth(),
        use,
        force: options.force ? "true" : "false",
        ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
        ...(!idTokenHint && subject ? { sub: subject } : {}),
        ...(options.expiresInSeconds !== undefined ? { expires_in: String(options.expiresInSeconds) } : {}),
      }),
    });

    const body = await response.json().catch(() => null);
    if (!response.ok || !isRecord(body)) {
      const error = isRecord(body) ? asString(body.error) : undefined;
      const description = isRecord(body) ? asString(body.error_description) : undefined;
      throw new EscalationError(description || `The escalation request was refused (status ${response.status}).`, error);
    }

    const escalationId = asString(body.escalation_id);
    const escalationUrl = asString(body.escalation_url);
    const pollToken = asString(body.poll_token);
    if (!escalationId || !escalationUrl || !pollToken) throw new EscalationError("The provider returned an escalation without an id, URL or poll token.");

    return {
      escalationId,
      escalationUrl,
      strategies: asStringArray(body.strategies),
      force: body.force === true,
      pollToken,
      expiresIn: asNumber(body.expires_in) ?? 0,
      expiresAt: asNumber(body.expires_at) ?? 0,
      interval: asNumber(body.interval) ?? DEFAULT_POLL_INTERVAL_SECONDS,
    };
  };

  const pollEscalation = async (request: Pick<EscalationRequest, "escalationId" | "pollToken" | "interval">): Promise<PollStep<EscalationResult>> => {
    const response = await fetch(endpoints.poll, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        ...clientAuth(),
        escalation_id: request.escalationId,
        poll_token: request.pollToken,
      }),
    });

    const body = await response.json().catch(() => null);
    if (!isRecord(body)) throw new EscalationError(`The escalation poll returned an unreadable response (status ${response.status}).`);

    if (!response.ok) {
      const error = asString(body.error) || "invalid_grant";
      const description = asString(body.error_description) || "The escalation poll was refused.";

      // Adopts the provider's interval on `slow_down`
      if (error === AUTHORIZATION_PENDING || error === SLOW_DOWN) {
        return {
          state: "pending",
          interval: asNumber(body.interval) ?? request.interval,
          slowDown: error === SLOW_DOWN,
          expiresAt: asNumber(body.expires_at),
        };
      }

      if (error === EXPIRED_TOKEN) throw new AuthorizationExpiredError(description, asNumber(body.expires_at));
      if (error === ACCESS_DENIED) throw new AuthorizationDeniedError(description, asString(body.reason));

      throw new EscalationError(description, error);
    }

    return {
      state: "done",
      value: {
        escalationId: asString(body.escalation_id) || request.escalationId,
        alreadySatisfied: body.already_satisfied === true,
        satisfiedBy: asString(body.satisfied_by),
        authMethods: asStringArray(body.amr),
        acr: asString(body.acr),
        authTime: asNumber(body.auth_time),
        escalationToken: asString(body.escalation_token),
      },
    };
  };

  const verifyEscalationToken = async (escalationToken: string): Promise<VerifiedEscalation> => {
    if (!asString(escalationToken)) throw new NoTokenError("No escalation token was provided.");

    const claims = await ctx.verifyJwt(escalationToken);

    const eventType = asString(claims.evt);
    if (eventType !== ESCALATION_TOKEN_TYPE) throw new EscalationError(`Expected an escalation token (evt: "${ESCALATION_TOKEN_TYPE}") but this one carries evt: ` + `"${eventType || "none"}". An ID token is not proof of a step-up, and refusing it here is what keeps ` + "the two from being interchangeable.");

    const subject = asString(claims.sub);
    if (!subject) throw new ClaimValidationError("The escalation token is missing the `sub` claim.");

    const expiresAt = asNumber(claims.exp);
    if (expiresAt === undefined) throw new ClaimValidationError("The escalation token is missing the `exp` claim.");

    return {
      subject,
      satisfiedBy: asString(claims.satisfied_by),
      alreadySatisfied: claims.already_satisfied === true,
      authMethods: asStringArray(claims.amr),
      acr: asString(claims.acr),
      authTime: asNumber(claims.auth_time),
      issuer: asString(claims.iss) || "",
      audience: ctx.config.clientId,
      expiresAt,
      claims: Object.freeze({ ...claims }),
    };
  };

  const reauthorize = async (use: string | string[], force = false, options: Omit<ReauthorizeOptions, "use" | "force"> = {}): Promise<EscalationResult> => {
    const request = await createEscalation({ ...options, use, force });
    // If `force` is `false` and the user already qualifies, it's not necessary to show the user anything
    const first = await pollEscalation(request);

    let result: EscalationResult;
    if (first.state === "done") {
      result = first.value;
    } else {
      await options.openUrl?.(request.escalationUrl, request);
      result = await pollUntilResolved(() => pollEscalation(request), first.interval, options);
    }

    if (options.verifyToken !== false && result.escalationToken) await verifyEscalationToken(result.escalationToken);

    return result;
  };

  return { createEscalation, pollEscalation, reauthorize, verifyEscalationToken };
}

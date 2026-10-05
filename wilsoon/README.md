# @wilsoon/auth-provider-wilsoon

The WilsoonID (`id.wilsoon.dev`) provider profile for `@wilsoon/auth-core` 3.x. It brings back 2.x behaviour and storage names, and adds the provider's own functions under `client.wilsoon`.

```ts
import { createAuthClient } from "@wilsoon/auth-core";
import { wilsoon, WILSOON_ISSUER } from "@wilsoon/auth-provider-wilsoon";

const client = createAuthClient({ issuer: WILSOON_ISSUER, clientId, clientSecret, profile: wilsoon() });
```

`new AuthClient({ ...config, profile: wilsoon() })` behaves the same at runtime, and keeps the
deprecated 2.x methods (`client.reauthorize()` and so on) working until 4.0. Only
`createAuthClient` types `client.wilsoon`. Do not annotate the config as `AuthConfig`, because
that widens `profile` and loses the name.

## What the profile sets

|                 |                                                                                                                                                                          |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Storage names   | `wilsoon_id_tokens`, `wilsoon_auth_state` / `_nonce` / `_verifier`, so nobody is signed out by the upgrade                                                               |
| `apiAudience`   | `https://api.wilsoon.dev` unless the config sets one; needed to read `permissions`, which only access tokens carry                                                       |
| `mapUser`       | `permissions` (`<slug>.<key>`), `sid`, `roles` from the legacy `role`, plus deprecated `role` and `sessionVersion`. An unknown role goes to `roles` and never to `role`. |
| Machine tokens  | `token_use: "client"`, then RFC 9068 `sub === client_id`                                                                                                                 |
| Session restore | the 2.x `hydrateSession` (cookie). Deprecated, and only a fallback after `silentAuthorize()`                                                                             |
| Shared sessions | sibling first-party cookies, resolved through introspection (`resolveSession()` routes to it)                                                                            |

## Extensions (`client.wilsoon`)

- **Escalation** (moved from 2.x unchanged): `createEscalation`, `pollEscalation`,
  `reauthorize`, `verifyEscalationToken`, `ACR`.
- **Sessions**: `verifyPlatformSession`, `resolveSession`, `isSessionCurrent`.
- **`liveAccess(token)`** returns `{ active, permissions, sid }` from the live introspection
  endpoint. The middleware's `enforce: "live"` uses it.
- **`definePermissions(nodes)`** / **`listPermissions()`** register and list the app's
  permission nodes at `/api/apps/permissions`, with HTTP Basic client auth. Confidential
  clients only. Registration never deletes; `unlisted` names the nodes the app stopped sending.

```ts
export const permissions = definePermissionSet("games_portal", {
  "leaderboard.edit": "Edit the leaderboard",
  "rooms.create": "Create rooms",
});

await client.wilsoon.definePermissions(permissions); // at boot or in a deploy step; idempotent
permissions.require(user, "leaderboard.edit"); // a typo here fails to compile
requirePermission(user, permissions.node("rooms.create"));
```

## Options

`wilsoon({ escalationEndpoint, permissionsEndpoint, apiAudience, platformSessionCacheSeconds, liveAccessCacheSeconds, resolveSessionVersion })`.
All are optional. `liveAccessCacheSeconds` defaults to 0, because the provider already caches
and invalidates on every admin change.

## Provider changes this depends on

These belong in `FederatedIdentityProvider`, not here:

1. **Allow `/v2/authorize` to be framed by first-party origins** for `prompt=none`.
   `src/proxy.js` sends `X-Frame-Options: DENY` and `frame-ancestors 'none'` on every
   response. If browsers apply that to the redirect, silent restore in the iframe falls back
   to the cookie path, which fails fast without hanging. Safer still is
   `frame-ancestors https://*.wilsoon.dev` on that route only.
2. Discovery's `prompt_values_supported` still lists `none, reauthenticate, consent`, while
   `/v2/authorize` also takes `login` and `select_account`.
3. Once apps restore with `silentAuthorize`, stop writing `wilsoon_id_tokens`. Then remove
   `restoreSession` from this profile.

## Development

`pnpm install`, then `pnpm build`, `pnpm typecheck`, `pnpm lint` and `pnpm test` from the repository
root. `pnpm lint` fixes and formats in place with `@wilsoon/eslint-config`; CI fails if it would change
anything.

`test/compat` holds the 2.3.0 core suites, run through this profile. Only client construction
differs, plus 4 assertions marked `3.0:` for the two intended changes: unknown roles no longer
throw, and the profile pins the API audience.

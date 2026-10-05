import { AuthError, hasPermission, normalizeIssuer, PermissionCarrier, ProfileContext, requirePermission } from "@wilsoon/auth-core";
import { asString, asStringArray, isRecord } from "./util";

/** The most nodes accepted in one registration. */
export const MAX_PERMISSION_NODES = 150;

/** The longest description the provider accepts. */
export const MAX_PERMISSION_DESCRIPTION = 120;

/** The provider's rule for a key after the slug: dot-separated parts of lowercase letters, digits and underscores, each starting with a letter. */
const KEY = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;

/** One permission node, in full (`<slug>.<key>`) */
export interface PermissionNode<Node extends string = string> {
  node: Node;
  description: string;
}

/** What the provider did with a registration. Nodes are never deleted - `unlisted` names the ones the app stopped sending. */
export interface PermissionRegistration {
  created: string[];
  updated: string[];
  unchanged: string[];
  unlisted: string[];
}

/** A node as the provider lists it. `builtIn` marks `<slug>.access`, which every app gets by default. */
export interface RegisteredPermission {
  node: string;
  description: string;
  builtIn: boolean;
}

/**
 * An app's permission nodes, declared once and reused for registration and for typed guards.
 * Unknown keys fail to compile, so a typo in a guard won't silently deny everyone.
 */
export interface PermissionSet<Slug extends string, Key extends string> {
  /** The app's immutable slug, the prefix of every node. */
  readonly slug: Slug;
  /** The nodes to register, built-in `access` excluded. */
  readonly nodes: readonly PermissionNode<`${Slug}.${Key}`>[];
  /** The built-in node that means "may sign in", `<slug>.access`. */
  readonly access: `${Slug}.access`;
  /** The full node for a key. */
  node<K extends Key | "access">(key: K): `${Slug}.${K}`;
  /** Whether the subject holds every listed key. */
  has(subject: PermissionCarrier | null | undefined, key: Key | "access" | readonly (Key | "access")[]): boolean;
  /** {@link PermissionSet.has} that throws `ClaimValidationError` instead of returning `false`. */
  require(subject: PermissionCarrier | null | undefined, key: Key | "access" | readonly (Key | "access")[]): void;
}

/**
 * Declares an app's permission nodes from `{ key: description }`, validated against provider rules.
 *
 * ```ts
 * export const permissions = definePermissionSet("games_portal", { "leaderboard.edit": "Edit the leaderboard" });
 * requirePermission(user, permissions.node("leaderboard.edit"));
 * ```
 *
 * @throws {AuthError} With code `INVALID_PERMISSION` for a malformed slug, key or description.
 */
export function definePermissionSet<const Slug extends string, const Map extends Record<string, string>>(slug: Slug, nodes: Map): PermissionSet<Slug, Extract<keyof Map, string>> {
  type Key = Extract<keyof Map, string>;

  if (!KEY.test(slug) || slug.includes(".")) throw new AuthError(`"${slug}" is not a valid app slug: use lowercase letters, digits and underscores, starting with a letter.`, "INVALID_PERMISSION");

  const entries = Object.entries(nodes).filter(([key]) => key !== "access");
  if (entries.length > MAX_PERMISSION_NODES) throw new AuthError(`At most ${MAX_PERMISSION_NODES} permissions can be registered at once; this set has ${entries.length}.`, "INVALID_PERMISSION");

  const list = entries.map(([key, description]) => {
    if (!KEY.test(key) || key.length > 100) throw new AuthError(`"${slug}.${key}" is not a valid node. After the prefix, use lowercase letters, digits and underscores in dot-separated parts that each start with a letter.`, "INVALID_PERMISSION");
    const text = typeof description === "string" ? description.trim() : "";
    if (!text || text.length > MAX_PERMISSION_DESCRIPTION) throw new AuthError(`Give "${slug}.${key}" a description of 1 to ${MAX_PERMISSION_DESCRIPTION} characters.`, "INVALID_PERMISSION");
    return Object.freeze({ node: `${slug}.${key}` as `${Slug}.${Key}`, description: text });
  });

  const full = (key: string) => `${slug}.${key}`;
  const toNodes = (key: string | readonly string[]) => (typeof key === "string" ? [full(key)] : key.map(full));

  return Object.freeze({
    slug,
    nodes: Object.freeze(list),
    access: `${slug}.access` as `${Slug}.access`,
    node: <K extends Key | "access">(key: K) => full(key) as `${Slug}.${K}`,
    has: (subject: PermissionCarrier | null | undefined, key: Key | "access" | readonly (Key | "access")[]) => hasPermission(subject, toNodes(key)),
    require: (subject: PermissionCarrier | null | undefined, key: Key | "access" | readonly (Key | "access")[]) => requirePermission(subject, toNodes(key)),
  });
}

/** Thrown when `/api/apps/permissions` refuses a request. `error` is the provider's code, e.g. `unauthorized_client`. */
export class PermissionRegistryError extends AuthError {
  constructor(
    message: string,
    public error?: string,
    public status?: number,
  ) {
    super(message, "PERMISSION_REGISTRY_FAILED");
    this.name = "PermissionRegistryError";
  }
}

/** The permission-registry half of the `wilsoon()` extensions. */
export interface PermissionExtensions {
  /**
   * Registers the app's permission nodes with the provider: adds new ones, updates changed descriptions, never deletes.
   * This is idempotent so calling it on every boot is fine. For confidential clients only.
   *
   * @throws {AuthError} With code `CONFIDENTIAL_CLIENT_REQUIRED` from a public client, before any request.
   * @throws {PermissionRegistryError} If the provider refuses the nodes or the credentials.
   */
  definePermissions(nodes: readonly PermissionNode[] | Pick<PermissionSet<string, string>, "nodes">): Promise<PermissionRegistration>;
  /** Lists the app's registered nodes, built-in `access` included. Confidential clients only. */
  listPermissions(): Promise<RegisteredPermission[]>;
}

/** Builds the permission-registry functions for one client, at `https://id.wilsoon.dev/api/apps/permissions` unless overridden. */
export function permissionExtensions(ctx: ProfileContext, endpoint: string | undefined): PermissionExtensions {
  const url = () => asString(endpoint) ?? `${normalizeIssuer(ctx.config.issuer)}/api/apps/permissions`;

  const requireConfidential = (operation: string) => {
    if (!asString(ctx.config.clientSecret)) throw new AuthError(`${operation} needs a confidential client: the provider authenticates the app by its \`clientSecret\`, because a public client's id is not a secret. Call it from a server or deploy step.`, "CONFIDENTIAL_CLIENT_REQUIRED");
  };

  const read = async (response: Response, operation: string): Promise<Record<string, unknown>> => {
    const body = await response.json().catch(() => null);
    if (!response.ok || !isRecord(body)) {
      const error = isRecord(body) ? asString(body.error) : undefined;
      const description = isRecord(body) ? asString(body.error_description) : undefined;
      throw new PermissionRegistryError(description || `${operation} failed with status ${response.status}.`, error, response.status);
    }
    return body;
  };

  const definePermissions = async (nodes: readonly PermissionNode[] | Pick<PermissionSet<string, string>, "nodes">): Promise<PermissionRegistration> => {
    requireConfidential("definePermissions()");

    const list = Array.isArray(nodes) ? (nodes as readonly PermissionNode[]) : (nodes as Pick<PermissionSet<string, string>, "nodes">).nodes;
    if (list.length === 0) throw new PermissionRegistryError("definePermissions() needs at least one node.");
    if (list.length > MAX_PERMISSION_NODES) throw new PermissionRegistryError(`At most ${MAX_PERMISSION_NODES} permissions per request; got ${list.length}.`);

    const response = await ctx.clientFetch(url(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ permissions: list.map(({ node, description }) => ({ node, description })) }),
    });
    const body = await read(response, "Registering permissions");

    return {
      created: asStringArray(body.created),
      updated: asStringArray(body.updated),
      unchanged: asStringArray(body.unchanged),
      unlisted: asStringArray(body.unlisted),
    };
  };

  const listPermissions = async (): Promise<RegisteredPermission[]> => {
    requireConfidential("listPermissions()");

    const body = await read(await ctx.clientFetch(url(), { method: "GET" }), "Listing permissions");
    const rows = Array.isArray(body.permissions) ? body.permissions : [];
    return rows.filter(isRecord).map((row) => ({ node: asString(row.node) ?? "", description: asString(row.description) ?? "", builtIn: row.built_in === true }));
  };

  return { definePermissions, listPermissions };
}

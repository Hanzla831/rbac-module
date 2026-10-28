import { PermissionSyntaxError } from './errors.js';
import { GLOBAL_SCOPE, type PermissionString, type Scope } from './types.js';

const WILDCARD = '*';
const SEGMENT = /^(?:[a-z0-9][a-z0-9_-]*|\*)$/i;

export interface ParsedPermission {
  resource: string;
  action: string;
}

const cache = new Map<string, ParsedPermission>();

/** Parses and validates `resource:action`, memoised — this is the hot path. */
export function parsePermission(value: PermissionString): ParsedPermission {
  const cached = cache.get(value);
  if (cached) return cached;

  const parts = value.split(':');
  if (parts.length !== 2) {
    throw new PermissionSyntaxError(`Permission must be "resource:action", got "${value}"`);
  }
  const [resource, action] = parts as [string, string];
  if (!SEGMENT.test(resource) || !SEGMENT.test(action)) {
    throw new PermissionSyntaxError(`Invalid permission segment in "${value}"`);
  }

  const parsed = { resource, action };
  cache.set(value, parsed);
  return parsed;
}

/**
 * Does a grant cover a requested permission?
 *
 * The request must name a concrete resource and action. Allowing `*` on the
 * asking side would let a caller probe with `*:*` and match every wildcard
 * grant in the system — a check that reads as correct but authorizes
 * everything.
 */
export function permissionMatches(grant: PermissionString, requested: PermissionString): boolean {
  const g = parsePermission(grant);
  const r = parsePermission(requested);

  if (r.resource === WILDCARD || r.action === WILDCARD) {
    throw new PermissionSyntaxError(
      `A request must name a concrete resource and action, got "${requested}"`,
    );
  }

  return (
    (g.resource === WILDCARD || g.resource === r.resource) &&
    (g.action === WILDCARD || g.action === r.action)
  );
}

/**
 * Pattern-to-pattern containment: does `held` cover everything `target` does?
 *
 * Distinct from `permissionMatches`, which answers a live request and so
 * forbids wildcards on the asking side. Comparing two *policies* — "does this
 * role hand out more than the actor holds?" — legitimately has wildcards on
 * both sides, and `document:read` must not be treated as covering
 * `document:*`.
 */
export function permissionCovers(held: PermissionString, target: PermissionString): boolean {
  const h = parsePermission(held);
  const t = parsePermission(target);
  return (
    (h.resource === WILDCARD || h.resource === t.resource) &&
    (h.action === WILDCARD || h.action === t.action)
  );
}

/** 2 = exact, 1 = one wildcard, 0 = `*:*`. Used to pick the closest allow. */
export function specificity(grant: PermissionString): number {
  const { resource, action } = parsePermission(grant);
  return (resource === WILDCARD ? 0 : 1) + (action === WILDCARD ? 0 : 1);
}

/**
 * Scope matching. A global assignment covers everything; an exact path covers
 * itself; a path ending in `/*` covers its descendants.
 *
 * `tenant:acme` deliberately does NOT cover `tenant:acme-corp` — prefix
 * comparison without a separator check is a classic scope-escape bug.
 */
export function scopeCovers(assigned: Scope, requested: Scope): boolean {
  if (assigned === GLOBAL_SCOPE) return true;
  if (assigned === requested) return true;

  if (assigned.endsWith('/*')) {
    const prefix = assigned.slice(0, -1); // keep the trailing '/'
    return requested.startsWith(prefix);
  }
  return false;
}

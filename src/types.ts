/**
 * Core RBAC domain types.
 *
 * The model is role-based at its centre with two deliberate extensions that
 * pure RBAC cannot express on its own:
 *
 *   - scoped assignments, so "admin of tenant A" is not "admin everywhere";
 *   - conditional grants, so a permission can depend on the record being
 *     touched (ownership, tenancy) rather than only on the caller role.
 *
 * Without those, real systems end up encoding `admin_tenant_a_billing` style
 * role names, which stops being maintainable almost immediately.
 */

export type Effect = 'allow' | 'deny';

/** `resource:action`; either segment may be the wildcard `*`. */
export type PermissionString = string;

export interface Grant {
  permission: PermissionString;
  effect: Effect;
  /** Name of a registered condition that must hold for this grant to apply. */
  when?: string;
  description?: string;
}

export interface RoleDefinition {
  name: string;
  description?: string;
  grants: Grant[];
  /** Roles whose grants this role also receives. */
  inherits?: string[];
}

/**
 * Where an assignment applies: `*` is global, otherwise a path such as
 * `tenant:acme` or `tenant:acme/project:apollo`. A trailing `/*` covers every
 * descendant of that path.
 */
export type Scope = string;
export const GLOBAL_SCOPE = '*';

export interface RoleAssignment {
  subjectId: string;
  role: string;
  scope: Scope;
  grantedBy?: string;
  grantedAt: Date;
  /** Null means permanent. Time-boxed elevation is the safer default. */
  expiresAt?: Date | null;
}

/** Whoever is asking — a user, service account, or API key. */
export interface Subject {
  id: string;
  attributes?: Record<string, unknown>;
}

export interface AccessRequest {
  subject: Subject;
  resource: string;
  action: string;
  scope?: Scope;
  /** The specific record being acted on, for ownership/tenancy conditions. */
  resourceAttributes?: Record<string, unknown>;
}

export type DecisionReason =
  | 'allowed'
  | 'explicit_deny'
  | 'no_roles_in_scope'
  | 'no_matching_grant'
  | 'condition_failed';

/** One grant that matched the requested permission, and how it fared. */
export interface MatchTrace {
  role: string;
  grant: Grant;
  /** 2 = exact `resource:action`, 1 = one wildcard, 0 = `*:*`. */
  specificity: number;
  conditionPassed: boolean;
}

/**
 * Every decision carries its full reasoning. An authorization layer that can
 * only answer yes/no is impossible to debug in production and impossible to
 * audit after an incident.
 */
export interface Decision {
  allowed: boolean;
  reason: DecisionReason;
  permission: string;
  scope: Scope;
  /** Effective roles after inheritance, in resolution order. */
  roles: string[];
  matched: MatchTrace | null;
  evaluated: MatchTrace[];
}

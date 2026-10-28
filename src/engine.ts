import type { AuditSink } from './audit.js';
import { ConditionRegistry } from './conditions.js';
import { AccessDeniedError, UnknownConditionError } from './errors.js';
import { permissionMatches, scopeCovers, specificity } from './permission.js';
import type { RoleRegistry } from './roleRegistry.js';
import { isActive, type AssignmentStore } from './store.js';
import {
  GLOBAL_SCOPE,
  type AccessRequest,
  type Decision,
  type Grant,
  type MatchTrace,
  type Scope,
  type Subject,
} from './types.js';

export interface AccessControlOptions {
  conditions?: ConditionRegistry;
  audit?: AuditSink;
  /** Audit allows as well as denials (denials only by default). */
  auditAllows?: boolean;
}

interface CachedRoles {
  roles: readonly string[];
  storeVersion: number;
  registryVersion: number;
}

/**
 * The policy decision point.
 *
 * Evaluation order, fixed and deliberate:
 *   1. Collect assignments that are unexpired and in scope.
 *   2. Expand them through role inheritance.
 *   3. Keep the grants matching the requested permission.
 *   4. Drop grants whose condition fails.
 *   5. Any surviving DENY wins outright.
 *   6. Otherwise the most specific ALLOW wins.
 *   7. Otherwise deny.
 *
 * Deny-overrides is the only safe precedence: if a deny could be outvoted by a
 * broader allow, revoking a capability from one role would silently do nothing
 * whenever the subject held any wildcard grant. Default-deny at the end means
 * a resource nobody wrote a policy for is closed, not open.
 */
export class AccessControl {
  private readonly conditions: ConditionRegistry;
  private readonly audit?: AuditSink;
  private readonly auditAllows: boolean;
  private readonly roleCache = new Map<string, CachedRoles>();

  constructor(
    private readonly registry: RoleRegistry,
    private readonly store: AssignmentStore,
    options: AccessControlOptions = {},
  ) {
    this.conditions = options.conditions ?? new ConditionRegistry();
    this.audit = options.audit;
    this.auditAllows = options.auditAllows ?? false;

    // Fail fast: a grant referencing a condition nobody registered would
    // otherwise throw on the first request that happens to match it.
    for (const name of this.registry.referencedConditions()) {
      if (!this.conditions.has(name)) throw new UnknownConditionError(name);
    }
  }

  /** Full decision with trace. */
  async decide(request: AccessRequest): Promise<Decision> {
    const scope = request.scope ?? GLOBAL_SCOPE;
    const permission = `${request.resource}:${request.action}`;
    const roles = await this.rolesFor(request.subject.id, scope);

    const decision = this.evaluate(request, permission, scope, roles);
    this.recordAudit(request.subject.id, decision);
    return decision;
  }

  /** Boolean form for call sites that do not need the reasoning. */
  async can(request: AccessRequest): Promise<boolean> {
    return (await this.decide(request)).allowed;
  }

  /** Throwing form, for use inside a service method. */
  async check(request: AccessRequest): Promise<Decision> {
    const decision = await this.decide(request);
    if (!decision.allowed) throw new AccessDeniedError(decision);
    return decision;
  }

  /**
   * Effective grants for a subject in a scope — what a settings screen would
   * render. Conditional grants are reported separately: whether they apply
   * cannot be known without a specific record.
   */
  async grantsFor(
    subject: Subject,
    scope: Scope = GLOBAL_SCOPE,
  ): Promise<{ roles: string[]; allowed: string[]; denied: string[]; conditional: string[] }> {
    const roles = await this.rolesFor(subject.id, scope);
    const allowed = new Set<string>();
    const denied = new Set<string>();
    const conditional = new Set<string>();

    for (const role of roles) {
      for (const grant of this.registry.get(role).grants) {
        if (grant.when) conditional.add(`${grant.permission} when ${grant.when}`);
        else if (grant.effect === 'deny') denied.add(grant.permission);
        else allowed.add(grant.permission);
      }
    }
    return {
      roles: [...roles],
      allowed: [...allowed].sort(),
      denied: [...denied].sort(),
      conditional: [...conditional].sort(),
    };
  }

  /**
   * Every grant a subject holds in a scope, with its defining role and its
   * condition intact.
   *
   * `grantsFor` flattens grants into display strings, which loses the
   * distinction between "may update any document" and "may update documents
   * they own". Comparing one subject authority against another needs that
   * distinction, so the escalation check uses this instead.
   */
  async effectiveGrants(
    subject: Subject,
    scope: Scope = GLOBAL_SCOPE,
  ): Promise<Array<{ role: string; grant: Grant }>> {
    const roles = await this.rolesFor(subject.id, scope);
    return roles.flatMap((role) =>
      this.registry.get(role).grants.map((grant) => ({ role, grant })),
    );
  }

  /** Effective roles for a subject in a scope, inheritance expanded. */
  async rolesFor(subjectId: string, scope: Scope = GLOBAL_SCOPE): Promise<readonly string[]> {
    const cacheKey = `${subjectId}|${scope}`;
    const cached = this.roleCache.get(cacheKey);
    if (
      cached &&
      cached.storeVersion === this.store.version() &&
      cached.registryVersion === this.registry.version
    ) {
      return cached.roles;
    }

    const assignments = await this.store.listForSubject(subjectId);
    const now = new Date();
    const roles: string[] = [];
    const seen = new Set<string>();

    for (const assignment of assignments) {
      if (!isActive(assignment, now)) continue;
      if (!scopeCovers(assignment.scope, scope)) continue;
      if (!this.registry.has(assignment.role)) continue; // role deleted since

      for (const role of this.registry.closure(assignment.role)) {
        if (!seen.has(role)) {
          seen.add(role);
          roles.push(role);
        }
      }
    }

    // Time-limited assignments must not be cached past their expiry.
    const hasExpiring = assignments.some((assignment) => assignment.expiresAt);
    if (!hasExpiring) {
      this.roleCache.set(cacheKey, {
        roles,
        storeVersion: this.store.version(),
        registryVersion: this.registry.version,
      });
    }
    return roles;
  }

  clearCache(): void {
    this.roleCache.clear();
  }

  private evaluate(
    request: AccessRequest,
    permission: string,
    scope: Scope,
    roles: readonly string[],
  ): Decision {
    const base = { permission, scope, roles: [...roles] };

    if (roles.length === 0) {
      return { ...base, allowed: false, reason: 'no_roles_in_scope', matched: null, evaluated: [] };
    }

    const evaluated: MatchTrace[] = [];
    for (const role of roles) {
      // `roles` is already the expanded closure, so each role contributes only
      // the grants it defines itself. Using `grantsOf` here would re-expand
      // inheritance, evaluating shared ancestors once per descendant and
      // crediting an inherited grant to the wrong role in the trace.
      for (const grant of this.registry.get(role).grants) {
        if (!permissionMatches(grant.permission, permission)) continue;
        evaluated.push({
          role,
          grant,
          specificity: specificity(grant.permission),
          conditionPassed: grant.when ? this.conditions.evaluate(grant.when, request) : true,
        });
      }
    }

    const applicable = evaluated.filter((trace) => trace.conditionPassed);

    // Step 5: an explicit deny ends it, however specific the competing allow.
    const deny = applicable.find((trace) => trace.grant.effect === 'deny');
    if (deny) {
      return { ...base, allowed: false, reason: 'explicit_deny', matched: deny, evaluated };
    }

    // Step 6: most specific allow, so `document:read` beats `*:*`.
    const allow = applicable
      .filter((trace) => trace.grant.effect === 'allow')
      .sort((a, b) => b.specificity - a.specificity)[0];
    if (allow) {
      return { ...base, allowed: true, reason: 'allowed', matched: allow, evaluated };
    }

    // Distinguish "no policy covers this" from "a policy covered it but the
    // record did not qualify" — very different things when debugging.
    return {
      ...base,
      allowed: false,
      reason: evaluated.length > 0 ? 'condition_failed' : 'no_matching_grant',
      matched: null,
      evaluated,
    };
  }

  private recordAudit(subjectId: string, decision: Decision): void {
    if (!this.audit) return;
    if (decision.allowed && !this.auditAllows) return;

    this.audit.record({
      at: new Date(),
      subjectId,
      permission: decision.permission,
      scope: decision.scope,
      allowed: decision.allowed,
      reason: decision.reason,
      matchedRole: decision.matched?.role ?? null,
      roles: decision.roles,
    });
  }
}

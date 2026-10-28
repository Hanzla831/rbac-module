import type { AccessControl } from './engine.js';
import { AccessDeniedError, PrivilegeEscalationError, UnknownRoleError } from './errors.js';
import { permissionCovers } from './permission.js';
import type { RoleRegistry } from './roleRegistry.js';
import type { AssignmentStore } from './store.js';
import { GLOBAL_SCOPE, type RoleAssignment, type Scope, type Subject } from './types.js';

/**
 * Administration of role assignments.
 *
 * The interesting part is not granting a role — it is refusing to grant one.
 * An actor holding `role:assign` can otherwise assign themselves `admin` and
 * walk straight out of the permission model, which makes every other check in
 * the system decorative. Two rules prevent that:
 *
 *   1. No granting a role whose permissions exceed your own.
 *   2. No granting outside the scope you administer.
 */
export class RoleAdminService {
  constructor(
    private readonly registry: RoleRegistry,
    private readonly store: AssignmentStore,
    private readonly ac: AccessControl,
  ) {}

  async assignRole(params: {
    actor: Subject;
    subjectId: string;
    role: string;
    scope?: Scope;
    expiresAt?: Date | null;
  }): Promise<RoleAssignment> {
    const scope = params.scope ?? GLOBAL_SCOPE;
    if (!this.registry.has(params.role)) throw new UnknownRoleError(params.role);

    // Rule 2: the actor must hold `role:assign` *in the target scope*, so a
    // tenant admin cannot grant roles inside another tenant.
    await this.ac.check({
      subject: params.actor,
      resource: 'role',
      action: 'assign',
      scope,
    });

    // Rule 1: no handing out more than you hold.
    const missing = await this.permissionsBeyond(params.actor, params.role, scope);
    if (missing.length > 0) throw new PrivilegeEscalationError(params.role, missing);

    const assignment: RoleAssignment = {
      subjectId: params.subjectId,
      role: params.role,
      scope,
      grantedBy: params.actor.id,
      grantedAt: new Date(),
      expiresAt: params.expiresAt ?? null,
    };
    await this.store.assign(assignment);
    return assignment;
  }

  async revokeRole(params: {
    actor: Subject;
    subjectId: string;
    role: string;
    scope?: Scope;
  }): Promise<boolean> {
    const scope = params.scope ?? GLOBAL_SCOPE;
    await this.ac.check({
      subject: params.actor,
      resource: 'role',
      action: 'revoke',
      scope,
    });
    // Revocation is not escalation, so it needs no subset check — taking
    // permissions away can never grant any.
    return this.store.revoke(params.subjectId, params.role, scope);
  }

  /** Which roles this actor is actually able to hand out. */
  async assignableRoles(actor: Subject, scope: Scope = GLOBAL_SCOPE): Promise<string[]> {
    try {
      await this.ac.check({ subject: actor, resource: 'role', action: 'assign', scope });
    } catch (error) {
      if (error instanceof AccessDeniedError) return [];
      throw error;
    }

    const assignable: string[] = [];
    for (const role of this.registry.list()) {
      if ((await this.permissionsBeyond(actor, role.name, scope)).length === 0) {
        assignable.push(role.name);
      }
    }
    return assignable;
  }

  /**
   * Permissions the role carries that the actor does not hold.
   *
   * Comparison happens on the static grant sets, because "does this role hand
   * out more authority than the actor has?" is a question about policy, not
   * about any one record. Two rules, both erring toward refusal:
   *
   *   - An UNCONDITIONAL grant in the role needs an unconditional allow from
   *     the actor. Someone who may only edit their own documents cannot hand
   *     out the right to edit everyone documents.
   *   - A CONDITIONAL grant needs any covering allow, conditional or not,
   *     since it is the narrower of the two.
   *
   * Only unconditional denies block delegation: a deny that applies to some
   * records is not grounds to refuse the whole permission.
   */
  private async permissionsBeyond(
    actor: Subject,
    role: string,
    scope: Scope,
  ): Promise<string[]> {
    const actorGrants = await this.ac.effectiveGrants(actor, scope);
    const actorAllows = actorGrants.filter(({ grant }) => grant.effect === 'allow');
    const actorDenies = actorGrants.filter(({ grant }) => grant.effect === 'deny');

    const missing: string[] = [];
    for (const grant of this.registry.grantsOf(role)) {
      if (grant.effect === 'deny') continue; // a deny never widens anyone

      const covered = actorAllows.some(
        ({ grant: held }) =>
          permissionCovers(held.permission, grant.permission) &&
          (grant.when ? true : !held.when),
      );
      const blocked = actorDenies.some(
        ({ grant: denied }) => !denied.when && permissionCovers(denied.permission, grant.permission),
      );

      if (!covered || blocked) missing.push(grant.permission);
    }
    return [...new Set(missing)];
  }
}

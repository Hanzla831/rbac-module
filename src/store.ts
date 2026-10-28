import { GLOBAL_SCOPE, type RoleAssignment, type Scope } from './types.js';

/**
 * Persistence boundary for role assignments. The engine depends only on this
 * interface, so the in-memory implementation below can be replaced with SQL
 * without touching any policy logic.
 */
export interface AssignmentStore {
  listForSubject(subjectId: string): Promise<RoleAssignment[]>;
  listForRole(role: string): Promise<RoleAssignment[]>;
  assign(assignment: RoleAssignment): Promise<void>;
  revoke(subjectId: string, role: string, scope: Scope): Promise<boolean>;
  /** Removes expired rows; returns how many. */
  purgeExpired(now?: Date): Promise<number>;
  /**
   * Monotonic write counter. The engine caches resolved roles against this, so
   * any assignment change invalidates the cache immediately rather than after
   * a TTL — a revoked role must stop working on the very next request.
   */
  version(): number;
}

const key = (subjectId: string, role: string, scope: Scope): string =>
  `${subjectId}|${role}|${scope}`;

export class InMemoryAssignmentStore implements AssignmentStore {
  private readonly assignments = new Map<string, RoleAssignment>();
  private revision = 0;

  constructor(seed: readonly RoleAssignment[] = []) {
    for (const assignment of seed) {
      this.assignments.set(key(assignment.subjectId, assignment.role, assignment.scope), {
        ...assignment,
      });
    }
  }

  async listForSubject(subjectId: string): Promise<RoleAssignment[]> {
    return [...this.assignments.values()]
      .filter((assignment) => assignment.subjectId === subjectId)
      .map((assignment) => ({ ...assignment }));
  }

  async listForRole(role: string): Promise<RoleAssignment[]> {
    return [...this.assignments.values()]
      .filter((assignment) => assignment.role === role)
      .map((assignment) => ({ ...assignment }));
  }

  async assign(assignment: RoleAssignment): Promise<void> {
    this.assignments.set(key(assignment.subjectId, assignment.role, assignment.scope), {
      ...assignment,
    });
    this.revision += 1;
  }

  async revoke(subjectId: string, role: string, scope: Scope = GLOBAL_SCOPE): Promise<boolean> {
    const removed = this.assignments.delete(key(subjectId, role, scope));
    if (removed) this.revision += 1;
    return removed;
  }

  async purgeExpired(now = new Date()): Promise<number> {
    let purged = 0;
    for (const [id, assignment] of this.assignments) {
      if (assignment.expiresAt && assignment.expiresAt.getTime() <= now.getTime()) {
        this.assignments.delete(id);
        purged += 1;
      }
    }
    if (purged) this.revision += 1;
    return purged;
  }

  version(): number {
    return this.revision;
  }
}

/** An assignment is live if it has not expired. */
export function isActive(assignment: RoleAssignment, now = new Date()): boolean {
  return !assignment.expiresAt || assignment.expiresAt.getTime() > now.getTime();
}

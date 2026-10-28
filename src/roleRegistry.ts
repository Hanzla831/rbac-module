import { RoleCycleError, UnknownRoleError } from './errors.js';
import { parsePermission } from './permission.js';
import type { Grant, RoleDefinition } from './types.js';

/**
 * The role catalogue: definitions, inheritance, and the resolved closure of
 * each role.
 *
 * Roles are validated eagerly — unknown parents, bad permission strings and
 * inheritance cycles all fail at construction. A misconfigured role graph is a
 * deployment error, not something to discover when a request is denied.
 */
export class RoleRegistry {
  private readonly roles = new Map<string, RoleDefinition>();
  private readonly closureCache = new Map<string, readonly string[]>();
  private readonly grantCache = new Map<string, readonly Grant[]>();
  /** Bumped on mutation so dependent caches can invalidate. */
  private revision = 0;

  constructor(definitions: readonly RoleDefinition[] = []) {
    for (const definition of definitions) this.define(definition);
    this.validate();
  }

  define(definition: RoleDefinition): this {
    if (!definition.name.trim()) throw new UnknownRoleError(definition.name);
    // Surface malformed permissions here rather than at evaluation time.
    for (const grant of definition.grants) parsePermission(grant.permission);

    this.roles.set(definition.name, definition);
    this.invalidate();
    return this;
  }

  has(name: string): boolean {
    return this.roles.has(name);
  }

  get(name: string): RoleDefinition {
    const role = this.roles.get(name);
    if (!role) throw new UnknownRoleError(name);
    return role;
  }

  list(): RoleDefinition[] {
    return [...this.roles.values()];
  }

  get version(): number {
    return this.revision;
  }

  /**
   * A role plus every role it inherits, depth-first and deduplicated.
   * Order matters: it is the order grants are reported in a decision trace.
   */
  closure(name: string): readonly string[] {
    const cached = this.closureCache.get(name);
    if (cached) return cached;

    const resolved: string[] = [];
    const visited = new Set<string>();
    const path: string[] = [];

    const visit = (current: string): void => {
      // The active path is what detects a cycle; `visited` only prevents
      // re-walking a diamond, which is legitimate.
      if (path.includes(current)) throw new RoleCycleError([...path, current]);
      if (visited.has(current)) return;

      path.push(current);
      visited.add(current);
      resolved.push(current);
      for (const parent of this.get(current).inherits ?? []) visit(parent);
      path.pop();
    };

    visit(name);
    this.closureCache.set(name, resolved);
    return resolved;
  }

  /** Every grant a role confers, its inherited ones included. */
  grantsOf(name: string): readonly Grant[] {
    const cached = this.grantCache.get(name);
    if (cached) return cached;

    const grants = this.closure(name).flatMap((role) => this.get(role).grants);
    this.grantCache.set(name, grants);
    return grants;
  }

  /** Condition names referenced anywhere, so the engine can verify them. */
  referencedConditions(): Set<string> {
    const names = new Set<string>();
    for (const role of this.roles.values()) {
      for (const grant of role.grants) if (grant.when) names.add(grant.when);
    }
    return names;
  }

  /** Checks every parent resolves and no cycle exists. */
  validate(): void {
    for (const [name, definition] of this.roles) {
      for (const parent of definition.inherits ?? []) {
        if (!this.roles.has(parent)) {
          throw new UnknownRoleError(`${parent}" (inherited by "${name}`);
        }
      }
    }
    for (const name of this.roles.keys()) this.closure(name);
  }

  private invalidate(): void {
    this.closureCache.clear();
    this.grantCache.clear();
    this.revision += 1;
  }
}

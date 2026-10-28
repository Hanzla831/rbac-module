import { describe, expect, it } from 'vitest';
import { RoleRegistry } from '../src/roleRegistry.js';
import { PermissionSyntaxError, RoleCycleError, UnknownRoleError } from '../src/errors.js';
import { examplePolicy } from '../src/policy.js';

describe('role inheritance', () => {
  it('resolves a role to itself plus its ancestors', () => {
    const registry = new RoleRegistry(examplePolicy);
    expect(registry.closure('member')).toEqual(['member', 'guest']);
    expect(registry.closure('editor')).toEqual(['editor', 'member', 'guest']);
    expect(registry.closure('tenant-admin')).toEqual([
      'tenant-admin',
      'editor',
      'member',
      'guest',
    ]);
  });

  it('collects grants from the whole chain', () => {
    const registry = new RoleRegistry(examplePolicy);
    const permissions = registry.grantsOf('editor').map((grant) => grant.permission);
    expect(permissions).toContain('document:publish'); // own
    expect(permissions).toContain('document:create'); // from member
    expect(permissions).toContain('document:read'); // from guest
  });

  it('visits a diamond only once', () => {
    const registry = new RoleRegistry([
      { name: 'base', grants: [{ permission: 'a:read', effect: 'allow' }] },
      { name: 'left', inherits: ['base'], grants: [] },
      { name: 'right', inherits: ['base'], grants: [] },
      { name: 'top', inherits: ['left', 'right'], grants: [] },
    ]);
    expect(registry.closure('top')).toEqual(['top', 'left', 'base', 'right']);
    expect(registry.grantsOf('top').filter((g) => g.permission === 'a:read')).toHaveLength(1);
  });

  it('rejects an inheritance cycle at construction', () => {
    expect(
      () =>
        new RoleRegistry([
          { name: 'a', inherits: ['b'], grants: [] },
          { name: 'b', inherits: ['a'], grants: [] },
        ]),
    ).toThrow(RoleCycleError);
  });

  it('rejects a self-inheriting role', () => {
    expect(
      () => new RoleRegistry([{ name: 'loop', inherits: ['loop'], grants: [] }]),
    ).toThrow(RoleCycleError);
  });

  it('rejects inheriting an undefined role', () => {
    expect(
      () => new RoleRegistry([{ name: 'orphan', inherits: ['ghost'], grants: [] }]),
    ).toThrow(UnknownRoleError);
  });

  it('rejects a malformed permission when the role is defined', () => {
    expect(
      () => new RoleRegistry([{ name: 'bad', grants: [{ permission: 'nope', effect: 'allow' }] }]),
    ).toThrow(PermissionSyntaxError);
  });

  it('invalidates caches and bumps the version when a role changes', () => {
    const registry = new RoleRegistry([
      { name: 'base', grants: [{ permission: 'a:read', effect: 'allow' }] },
    ]);
    const before = registry.version;
    expect(registry.grantsOf('base')).toHaveLength(1);

    registry.define({
      name: 'base',
      grants: [
        { permission: 'a:read', effect: 'allow' },
        { permission: 'a:write', effect: 'allow' },
      ],
    });

    expect(registry.version).toBeGreaterThan(before);
    expect(registry.grantsOf('base')).toHaveLength(2);
  });

  it('reports the conditions its grants reference', () => {
    const registry = new RoleRegistry(examplePolicy);
    expect(registry.referencedConditions()).toEqual(
      new Set(['isNotArchived', 'isOwner', 'isSelf', 'sameTenant']),
    );
  });
});

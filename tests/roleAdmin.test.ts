import { beforeEach, describe, expect, it } from 'vitest';
import { AccessControl } from '../src/engine.js';
import { RoleRegistry } from '../src/roleRegistry.js';
import { InMemoryAssignmentStore } from '../src/store.js';
import { RoleAdminService } from '../src/roleAdmin.js';
import { AccessDeniedError, PrivilegeEscalationError, UnknownRoleError } from '../src/errors.js';
import { examplePolicy } from '../src/policy.js';
import type { RoleAssignment, Subject } from '../src/types.js';

const assignment = (subjectId: string, role: string, scope = '*'): RoleAssignment => ({
  subjectId,
  role,
  scope,
  grantedAt: new Date(),
  expiresAt: null,
});

const subject = (id: string, attributes: Record<string, unknown> = {}): Subject => ({
  id,
  attributes,
});

describe('role administration', () => {
  let store: InMemoryAssignmentStore;
  let admin: RoleAdminService;

  beforeEach(() => {
    const registry = new RoleRegistry(examplePolicy);
    store = new InMemoryAssignmentStore();
    const ac = new AccessControl(registry, store);
    admin = new RoleAdminService(registry, store, ac);
  });

  it('refuses to assign roles without role:assign', async () => {
    await store.assign(assignment('m', 'member'));
    await expect(
      admin.assignRole({ actor: subject('m'), subjectId: 'target', role: 'member' }),
    ).rejects.toBeInstanceOf(AccessDeniedError);
  });

  it('refuses an unknown role', async () => {
    await store.assign(assignment('root', 'superadmin'));
    await expect(
      admin.assignRole({ actor: subject('root'), subjectId: 't', role: 'ghost' }),
    ).rejects.toBeInstanceOf(UnknownRoleError);
  });

  it('lets a superadmin assign any role', async () => {
    await store.assign(assignment('root', 'superadmin'));
    const created = await admin.assignRole({
      actor: subject('root'),
      subjectId: 'newbie',
      role: 'tenant-admin',
      scope: 'tenant:acme',
    });

    expect(created.grantedBy).toBe('root');
    expect(await store.listForSubject('newbie')).toHaveLength(1);
  });

  it('blocks granting a role that carries more than the actor holds', async () => {
    // A tenant-admin has role:assign but not `*:*`, so handing out superadmin
    // is exactly the escalation that must fail.
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));

    await expect(
      admin.assignRole({
        actor: subject('ta'),
        subjectId: 'accomplice',
        role: 'superadmin',
        scope: 'tenant:acme',
      }),
    ).rejects.toBeInstanceOf(PrivilegeEscalationError);
  });

  it('blocks self-escalation', async () => {
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));
    await expect(
      admin.assignRole({
        actor: subject('ta'),
        subjectId: 'ta',
        role: 'superadmin',
        scope: 'tenant:acme',
      }),
    ).rejects.toBeInstanceOf(PrivilegeEscalationError);
  });

  it('allows granting a role at or below the actor own level', async () => {
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));
    const created = await admin.assignRole({
      actor: subject('ta'),
      subjectId: 'staff',
      role: 'member',
      scope: 'tenant:acme',
    });
    expect(created.role).toBe('member');
  });

  it('confines a tenant admin to their own scope', async () => {
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));
    await expect(
      admin.assignRole({
        actor: subject('ta'),
        subjectId: 'outsider',
        role: 'member',
        scope: 'tenant:globex',
      }),
    ).rejects.toBeInstanceOf(AccessDeniedError);
  });

  it('lists only the roles an actor can actually hand out', async () => {
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));
    const assignable = await admin.assignableRoles(subject('ta'), 'tenant:acme');

    expect(assignable).toContain('member');
    expect(assignable).not.toContain('superadmin');
    // auditor carries explicit denies the tenant-admin does not hold, and its
    // `*:read` is broader than anything they can grant.
    expect(assignable).not.toContain('auditor');
  });

  it('returns nothing assignable for an actor without role:assign', async () => {
    await store.assign(assignment('m', 'member'));
    expect(await admin.assignableRoles(subject('m'))).toEqual([]);
  });

  it('supports time-boxed elevation', async () => {
    await store.assign(assignment('root', 'superadmin'));
    const expiresAt = new Date(Date.now() + 3600_000);
    const created = await admin.assignRole({
      actor: subject('root'),
      subjectId: 'oncall',
      role: 'tenant-admin',
      scope: 'tenant:acme',
      expiresAt,
    });
    expect(created.expiresAt).toEqual(expiresAt);
  });

  it('revokes a role', async () => {
    await store.assign(assignment('root', 'superadmin'));
    await admin.assignRole({ actor: subject('root'), subjectId: 'u', role: 'member' });

    expect(
      await admin.revokeRole({ actor: subject('root'), subjectId: 'u', role: 'member' }),
    ).toBe(true);
    expect(await store.listForSubject('u')).toHaveLength(0);
  });

  it('requires role:revoke to revoke', async () => {
    await store.assign(assignment('m', 'member'));
    await expect(
      admin.revokeRole({ actor: subject('m'), subjectId: 'x', role: 'member' }),
    ).rejects.toBeInstanceOf(AccessDeniedError);
  });
});

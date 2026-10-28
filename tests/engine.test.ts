import { beforeEach, describe, expect, it } from 'vitest';
import { AccessControl } from '../src/engine.js';
import { RoleRegistry } from '../src/roleRegistry.js';
import { InMemoryAssignmentStore } from '../src/store.js';
import { InMemoryAuditLog } from '../src/audit.js';
import { ConditionRegistry } from '../src/conditions.js';
import { AccessDeniedError, UnknownConditionError } from '../src/errors.js';
import { examplePolicy } from '../src/policy.js';
import type { RoleAssignment, Subject } from '../src/types.js';

const assignment = (
  subjectId: string,
  role: string,
  scope = '*',
  expiresAt: Date | null = null,
): RoleAssignment => ({ subjectId, role, scope, grantedAt: new Date(), expiresAt });

const subject = (id: string, attributes: Record<string, unknown> = {}): Subject => ({
  id,
  attributes,
});

describe('decision engine', () => {
  let registry: RoleRegistry;
  let store: InMemoryAssignmentStore;
  let ac: AccessControl;

  beforeEach(() => {
    registry = new RoleRegistry(examplePolicy);
    store = new InMemoryAssignmentStore();
    ac = new AccessControl(registry, store);
  });

  it('denies by default when the subject has no roles', async () => {
    const decision = await ac.decide({
      subject: subject('nobody'),
      resource: 'document',
      action: 'read',
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('no_roles_in_scope');
  });

  it('allows a permission granted directly', async () => {
    await store.assign(assignment('u1', 'member'));
    expect(
      await ac.can({ subject: subject('u1'), resource: 'document', action: 'create' }),
    ).toBe(true);
  });

  it('allows a permission inherited from a parent role', async () => {
    await store.assign(assignment('u1', 'editor'));
    // `document:read` comes from guest, two levels up, and is conditional.
    const decision = await ac.decide({
      subject: subject('u1'),
      resource: 'document',
      action: 'read',
      resourceAttributes: { archivedAt: null },
    });
    expect(decision.allowed).toBe(true);
    expect(decision.matched?.role).toBe('guest');
  });

  it('denies a permission no role grants', async () => {
    await store.assign(assignment('u1', 'member'));
    const decision = await ac.decide({
      subject: subject('u1'),
      resource: 'billing',
      action: 'read',
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('no_matching_grant');
  });

  it('matches a wildcard grant', async () => {
    await store.assign(assignment('root', 'superadmin'));
    expect(
      await ac.can({ subject: subject('root'), resource: 'anything', action: 'destroy' }),
    ).toBe(true);
  });

  it('lets an explicit deny beat a broader allow', async () => {
    // auditor holds `*:read` (allow) and `*:update` (deny).
    await store.assign(assignment('a1', 'auditor'));

    expect(await ac.can({ subject: subject('a1'), resource: 'document', action: 'read' })).toBe(
      true,
    );

    const decision = await ac.decide({
      subject: subject('a1'),
      resource: 'document',
      action: 'update',
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('explicit_deny');
  });

  it('lets a deny from one role override an allow from another', async () => {
    // Holding both roles must not let the allow win: deny-overrides is what
    // makes a revocation role actually revoke.
    await store.assign(assignment('mixed', 'editor'));
    await store.assign(assignment('mixed', 'auditor'));

    const decision = await ac.decide({
      subject: subject('mixed', { tenantId: 't1' }),
      resource: 'document',
      action: 'update',
      resourceAttributes: { tenantId: 't1' },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('explicit_deny');
  });

  it('prefers the most specific allow', async () => {
    const custom = new RoleRegistry([
      {
        name: 'mixed',
        grants: [
          { permission: '*:*', effect: 'allow', description: 'broad' },
          { permission: 'document:read', effect: 'allow', description: 'exact' },
        ],
      },
    ]);
    const localStore = new InMemoryAssignmentStore([assignment('u', 'mixed')]);
    const engine = new AccessControl(custom, localStore);

    const decision = await engine.decide({
      subject: subject('u'),
      resource: 'document',
      action: 'read',
    });
    expect(decision.matched?.grant.description).toBe('exact');
    expect(decision.matched?.specificity).toBe(2);
  });
});

describe('conditional grants', () => {
  let store: InMemoryAssignmentStore;
  let ac: AccessControl;

  beforeEach(() => {
    store = new InMemoryAssignmentStore([assignment('alice', 'member')]);
    ac = new AccessControl(new RoleRegistry(examplePolicy), store);
  });

  it('allows updating a document the caller owns', async () => {
    const decision = await ac.decide({
      subject: subject('alice'),
      resource: 'document',
      action: 'update',
      resourceAttributes: { ownerId: 'alice' },
    });
    expect(decision.allowed).toBe(true);
  });

  it('denies updating someone else document despite holding the permission', async () => {
    const decision = await ac.decide({
      subject: subject('alice'),
      resource: 'document',
      action: 'update',
      resourceAttributes: { ownerId: 'bob' },
    });
    expect(decision.allowed).toBe(false);
    // The grant matched but the record did not qualify — distinct from having
    // no permission at all.
    expect(decision.reason).toBe('condition_failed');
    expect(decision.evaluated.length).toBeGreaterThan(0);
  });

  it('denies when no record is supplied for a conditional grant', async () => {
    const decision = await ac.decide({
      subject: subject('alice'),
      resource: 'document',
      action: 'update',
    });
    expect(decision.allowed).toBe(false);
  });

  it('applies tenant conditions', async () => {
    await store.assign(assignment('ed', 'editor'));
    const sameTenant = await ac.decide({
      subject: subject('ed', { tenantId: 'acme' }),
      resource: 'document',
      action: 'publish',
      resourceAttributes: { tenantId: 'acme' },
    });
    const crossTenant = await ac.decide({
      subject: subject('ed', { tenantId: 'acme' }),
      resource: 'document',
      action: 'publish',
      resourceAttributes: { tenantId: 'globex' },
    });
    expect(sameTenant.allowed).toBe(true);
    expect(crossTenant.allowed).toBe(false);
  });

  it('fails closed when a condition throws', async () => {
    const conditions = new ConditionRegistry().register('explodes', () => {
      throw new Error('bug in predicate');
    });
    const registry = new RoleRegistry([
      { name: 'risky', grants: [{ permission: 'document:read', effect: 'allow', when: 'explodes' }] },
    ]);
    const engine = new AccessControl(
      registry,
      new InMemoryAssignmentStore([assignment('u', 'risky')]),
      { conditions },
    );

    const decision = await engine.decide({
      subject: subject('u'),
      resource: 'document',
      action: 'read',
    });
    expect(decision.allowed).toBe(false);
  });

  it('refuses to construct when a grant names an unregistered condition', () => {
    const registry = new RoleRegistry([
      { name: 'broken', grants: [{ permission: 'a:read', effect: 'allow', when: 'nope' }] },
    ]);
    expect(() => new AccessControl(registry, new InMemoryAssignmentStore())).toThrow(
      UnknownConditionError,
    );
  });
});

describe('scoped assignments', () => {
  let store: InMemoryAssignmentStore;
  let ac: AccessControl;

  beforeEach(() => {
    store = new InMemoryAssignmentStore();
    ac = new AccessControl(new RoleRegistry(examplePolicy), store);
  });

  it('confines a role to the scope it was granted in', async () => {
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));

    expect(
      await ac.can({
        subject: subject('ta'),
        resource: 'user',
        action: 'invite',
        scope: 'tenant:acme',
      }),
    ).toBe(true);

    expect(
      await ac.can({
        subject: subject('ta'),
        resource: 'user',
        action: 'invite',
        scope: 'tenant:globex',
      }),
    ).toBe(false);
  });

  it('applies a global assignment in every scope', async () => {
    await store.assign(assignment('root', 'superadmin', '*'));
    expect(
      await ac.can({
        subject: subject('root'),
        resource: 'user',
        action: 'invite',
        scope: 'tenant:globex',
      }),
    ).toBe(true);
  });

  it('covers descendant scopes with a wildcard suffix', async () => {
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme/*'));
    expect(
      await ac.can({
        subject: subject('ta'),
        resource: 'user',
        action: 'invite',
        scope: 'tenant:acme/project:apollo',
      }),
    ).toBe(true);
  });
});

describe('assignment lifetime and caching', () => {
  it('ignores an expired assignment', async () => {
    const store = new InMemoryAssignmentStore([
      assignment('temp', 'tenant-admin', '*', new Date(Date.now() - 1000)),
    ]);
    const ac = new AccessControl(new RoleRegistry(examplePolicy), store);

    expect(
      await ac.can({ subject: subject('temp'), resource: 'user', action: 'invite' }),
    ).toBe(false);
    expect(await store.purgeExpired()).toBe(1);
  });

  it('honours an assignment that has not expired yet', async () => {
    const store = new InMemoryAssignmentStore([
      assignment('temp', 'tenant-admin', '*', new Date(Date.now() + 60_000)),
    ]);
    const ac = new AccessControl(new RoleRegistry(examplePolicy), store);
    expect(
      await ac.can({ subject: subject('temp'), resource: 'user', action: 'invite' }),
    ).toBe(true);
  });

  it('stops honouring a revoked role immediately, not after a TTL', async () => {
    const store = new InMemoryAssignmentStore([assignment('u1', 'tenant-admin')]);
    const ac = new AccessControl(new RoleRegistry(examplePolicy), store);

    expect(await ac.can({ subject: subject('u1'), resource: 'user', action: 'invite' })).toBe(
      true,
    );

    await store.revoke('u1', 'tenant-admin', '*');

    // The cache keys on the store write counter, so this is a fresh resolve.
    expect(await ac.can({ subject: subject('u1'), resource: 'user', action: 'invite' })).toBe(
      false,
    );
  });

  it('picks up a role definition change without an explicit cache clear', async () => {
    const registry = new RoleRegistry([
      { name: 'basic', grants: [{ permission: 'document:read', effect: 'allow' }] },
    ]);
    const store = new InMemoryAssignmentStore([assignment('u1', 'basic')]);
    const ac = new AccessControl(registry, store);

    expect(await ac.can({ subject: subject('u1'), resource: 'document', action: 'write' })).toBe(
      false,
    );

    registry.define({
      name: 'basic',
      grants: [
        { permission: 'document:read', effect: 'allow' },
        { permission: 'document:write', effect: 'allow' },
      ],
    });

    expect(await ac.can({ subject: subject('u1'), resource: 'document', action: 'write' })).toBe(
      true,
    );
  });

  it('ignores an assignment to a role that no longer exists', async () => {
    const store = new InMemoryAssignmentStore([assignment('u1', 'deleted-role')]);
    const ac = new AccessControl(new RoleRegistry(examplePolicy), store);
    const decision = await ac.decide({
      subject: subject('u1'),
      resource: 'document',
      action: 'read',
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('no_roles_in_scope');
  });
});

describe('reporting and auditing', () => {
  it('check() throws with the decision attached', async () => {
    const ac = new AccessControl(new RoleRegistry(examplePolicy), new InMemoryAssignmentStore());
    await expect(
      ac.check({ subject: subject('u'), resource: 'document', action: 'read' }),
    ).rejects.toBeInstanceOf(AccessDeniedError);
  });

  it('summarises effective grants for a subject', async () => {
    const store = new InMemoryAssignmentStore([assignment('a1', 'auditor')]);
    const ac = new AccessControl(new RoleRegistry(examplePolicy), store);

    const grants = await ac.grantsFor(subject('a1'));
    expect(grants.roles).toEqual(['auditor']);
    expect(grants.allowed).toContain('*:read');
    expect(grants.denied).toContain('*:update');
  });

  it('separates conditional grants, which need a record to resolve', async () => {
    const store = new InMemoryAssignmentStore([assignment('m', 'member')]);
    const ac = new AccessControl(new RoleRegistry(examplePolicy), store);

    const grants = await ac.grantsFor(subject('m'));
    expect(grants.conditional).toContain('document:update when isOwner');
    expect(grants.allowed).not.toContain('document:update');
  });

  it('records denials to the audit sink', async () => {
    const audit = new InMemoryAuditLog();
    const ac = new AccessControl(
      new RoleRegistry(examplePolicy),
      new InMemoryAssignmentStore([assignment('a1', 'auditor')]),
      { audit },
    );

    await ac.can({ subject: subject('a1'), resource: 'document', action: 'read' }); // allow
    await ac.can({ subject: subject('a1'), resource: 'document', action: 'delete' }); // deny

    expect(audit.entries).toHaveLength(1); // denials only by default
    expect(audit.denials()[0]).toMatchObject({
      subjectId: 'a1',
      permission: 'document:delete',
      allowed: false,
      reason: 'explicit_deny',
    });
  });

  it('records allows too when asked', async () => {
    const audit = new InMemoryAuditLog();
    const ac = new AccessControl(
      new RoleRegistry(examplePolicy),
      new InMemoryAssignmentStore([assignment('root', 'superadmin')]),
      { audit, auditAllows: true },
    );

    await ac.can({ subject: subject('root'), resource: 'document', action: 'delete' });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.allowed).toBe(true);
  });
});

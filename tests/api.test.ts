import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../src/app.js';
import { InMemoryAssignmentStore } from '../src/store.js';
import { GLOBAL_SCOPE, type RoleAssignment } from '../src/types.js';

const assignment = (subjectId: string, role: string, scope = GLOBAL_SCOPE): RoleAssignment => ({
  subjectId,
  role,
  scope,
  grantedAt: new Date(),
  expiresAt: null,
});

describe('RBAC HTTP API', () => {
  let app: Express;
  let store: InMemoryAssignmentStore;

  beforeEach(async () => {
    store = new InMemoryAssignmentStore();
    ({ app } = createApp({ store }));
    await store.assign(assignment('root', 'superadmin'));
    await store.assign(assignment('ta', 'tenant-admin', 'tenant:acme'));
    await store.assign(assignment('member', 'member'));
  });

  const as = (subject: string) => ({ 'x-subject-id': subject });

  it('reports health with the loaded policy', async () => {
    const response = await request(app).get('/health').expect(200);
    expect(response.body.status).toBe('ok');
    expect(response.body.roles).toBeGreaterThan(0);
  });

  it('lists the role catalogue with resolved permissions', async () => {
    const response = await request(app).get('/rbac/roles').expect(200);
    const editor = response.body.roles.find((role: { name: string }) => role.name === 'editor');

    expect(editor.inherits).toContain('member');
    // Inherited grants are resolved, not just the ones declared on the role.
    expect(editor.permissions.map((g: { permission: string }) => g.permission)).toContain(
      'document:read',
    );
  });

  it('requires authentication for caller-scoped routes', async () => {
    const response = await request(app).get('/rbac/me/permissions').expect(401);
    expect(response.body.error.code).toBe('authentication_required');
  });

  it('returns the caller effective permissions', async () => {
    const response = await request(app)
      .get('/rbac/me/permissions')
      .set(as('member'))
      .expect(200);

    expect(response.body.roles).toContain('member');
    expect(response.body.allowed).toContain('document:create');
    // Conditional grants are reported separately: they need a record to resolve.
    expect(response.body.conditional.join(' ')).toContain('isOwner');
  });

  it('answers an access check with its reasoning', async () => {
    const allowed = await request(app)
      .post('/rbac/access/check')
      .set(as('member'))
      .send({
        resource: 'document',
        action: 'update',
        resourceAttributes: { ownerId: 'member' },
      })
      .expect(200);

    const denied = await request(app)
      .post('/rbac/access/check')
      .set(as('member'))
      .send({
        resource: 'document',
        action: 'update',
        resourceAttributes: { ownerId: 'someone-else' },
      })
      .expect(200);

    expect(allowed.body.allowed).toBe(true);
    expect(denied.body.allowed).toBe(false);
    // "covered by a policy but this record did not qualify" is a different
    // answer from "no permission at all".
    expect(denied.body.reason).toBe('condition_failed');
  });

  it('validates the access-check body', async () => {
    await request(app).post('/rbac/access/check').set(as('member')).send({}).expect(400);
  });

  it('lets an admin assign a role', async () => {
    const response = await request(app)
      .post('/rbac/subjects/newbie/roles')
      .set(as('root'))
      .send({ role: 'member' })
      .expect(201);

    expect(response.body.assignment.role).toBe('member');
    expect(await store.listForSubject('newbie')).toHaveLength(1);
  });

  it('blocks privilege escalation with 403', async () => {
    const response = await request(app)
      .post('/rbac/subjects/accomplice/roles')
      .set(as('ta'))
      .send({ role: 'superadmin', scope: 'tenant:acme' })
      .expect(403);

    expect(response.body.error.code).toBe('privilege_escalation');
  });

  it('blocks assigning outside the actor scope', async () => {
    await request(app)
      .post('/rbac/subjects/outsider/roles')
      .set(as('ta'))
      .send({ role: 'member', scope: 'tenant:globex' })
      .expect(403);
  });

  it('refuses role assignment from someone without role:assign', async () => {
    const response = await request(app)
      .post('/rbac/subjects/x/roles')
      .set(as('member'))
      .send({ role: 'member' })
      .expect(403);

    // The body names the required permission and nothing about roles or rules.
    expect(response.body.error.requiredPermission).toBe('role:assign');
    expect(JSON.stringify(response.body)).not.toContain('superadmin');
  });

  it('404s an unknown role', async () => {
    await request(app)
      .post('/rbac/subjects/x/roles')
      .set(as('root'))
      .send({ role: 'wizard' })
      .expect(404);
  });

  it('rejects a malformed expiry', async () => {
    await request(app)
      .post('/rbac/subjects/x/roles')
      .set(as('root'))
      .send({ role: 'member', expiresAt: 'next tuesday' })
      .expect(400);
  });

  it('supports time-boxed elevation', async () => {
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const response = await request(app)
      .post('/rbac/subjects/oncall/roles')
      .set(as('root'))
      .send({ role: 'tenant-admin', scope: 'tenant:acme', expiresAt })
      .expect(201);

    expect(response.body.assignment.expiresAt).toBe(expiresAt);
  });

  it('lists only the roles the caller can hand out', async () => {
    const response = await request(app)
      .get('/rbac/roles/assignable?scope=tenant:acme')
      .set(as('ta'))
      .expect(200);

    expect(response.body.roles).toContain('member');
    expect(response.body.roles).not.toContain('superadmin');
  });

  it('revokes a role, idempotently', async () => {
    await request(app)
      .delete('/rbac/subjects/member/roles/member')
      .set(as('root'))
      .expect(204);

    // Revoking again is a 404, not an error state.
    await request(app)
      .delete('/rbac/subjects/member/roles/member')
      .set(as('root'))
      .expect(404);
  });

  it('gates reading another subject roles', async () => {
    await request(app).get('/rbac/subjects/member/roles').set(as('member')).expect(403);
    await request(app).get('/rbac/subjects/member/roles').set(as('root')).expect(200);
  });

  it('404s an unknown endpoint', async () => {
    await request(app).get('/rbac/nope').set(as('root')).expect(404);
  });
});

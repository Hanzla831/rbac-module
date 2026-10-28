import { describe, expect, it } from 'vitest';
import express, { type Express } from 'express';
import request from 'supertest';
import { AccessControl } from '../src/engine.js';
import { RoleRegistry } from '../src/roleRegistry.js';
import { InMemoryAssignmentStore } from '../src/store.js';
import { attachSubject, authorize, authorizeAny, rbacErrorHandler } from '../src/middleware.js';
import { examplePolicy } from '../src/policy.js';
import type { RoleAssignment } from '../src/types.js';

const DOCUMENTS: Record<string, { ownerId: string; tenantId: string; archivedAt: Date | null }> = {
  d1: { ownerId: 'alice', tenantId: 'acme', archivedAt: null },
  d2: { ownerId: 'bob', tenantId: 'acme', archivedAt: null },
};

const assignment = (subjectId: string, role: string, scope = '*'): RoleAssignment => ({
  subjectId,
  role,
  scope,
  grantedAt: new Date(),
  expiresAt: null,
});

/**
 * A miniature app wired the way a real one would be: authentication puts a
 * subject on the request, then each route declares the permission it needs.
 */
function buildApp(assignments: RoleAssignment[]): Express {
  const ac = new AccessControl(
    new RoleRegistry(examplePolicy),
    new InMemoryAssignmentStore(assignments),
  );
  const app = express();
  app.use(express.json());

  // Stands in for JWT or session authentication.
  app.use(
    attachSubject((req) => {
      const id = req.header('x-user-id');
      const tenantId = req.header('x-tenant-id') ?? 'acme';
      return id ? { id, attributes: { tenantId } } : null;
    }),
  );

  app.get(
    '/documents',
    authorize(ac, { resource: 'document', action: 'read' }),
    (_req, res) => {
      res.json({ documents: Object.keys(DOCUMENTS) });
    },
  );

  app.patch(
    '/documents/:id',
    authorize(ac, {
      resource: 'document',
      action: 'update',
      // Loading the record is what turns "may update documents" into
      // "may update this document".
      loadResource: async (req) => DOCUMENTS[req.params.id as string] ?? null,
    }),
    (req, res) => {
      res.json({ updated: req.params.id, reason: req.authDecision?.reason });
    },
  );

  app.get(
    '/tenants/:tenantId/users',
    authorize(ac, {
      resource: 'user',
      action: 'read',
      scope: (req) => `tenant:${req.params.tenantId}`,
    }),
    (_req, res) => {
      res.json({ users: [] });
    },
  );

  app.get(
    '/reports',
    authorizeAny(ac, [
      { resource: 'auditlog', action: 'read' },
      { resource: 'billing', action: 'read' },
    ]),
    (_req, res) => {
      res.json({ ok: true });
    },
  );

  app.use(rbacErrorHandler);
  return app;
}

describe('express integration', () => {
  it('returns 401 when there is no subject', async () => {
    const response = await request(buildApp([])).get('/documents').expect(401);
    expect(response.body.error.code).toBe('authentication_required');
  });

  it('returns 403 when authenticated but unauthorized', async () => {
    const response = await request(buildApp([]))
      .get('/documents')
      .set('x-user-id', 'nobody')
      .expect(403);

    expect(response.body.error.code).toBe('forbidden');
    expect(response.body.error.requiredPermission).toBe('document:read');
  });

  it('does not leak which role or rule would have granted access', async () => {
    const response = await request(buildApp([assignment('alice', 'member')]))
      .patch('/documents/d2')
      .set('x-user-id', 'alice')
      .expect(403);

    const body = JSON.stringify(response.body);
    expect(body).not.toContain('member');
    expect(body).not.toContain('isOwner');
    expect(body).not.toContain('role');
  });

  it('allows a permitted request', async () => {
    await request(buildApp([assignment('alice', 'member')]))
      .get('/documents')
      .set('x-user-id', 'alice')
      .expect(200);
  });

  it('enforces ownership on the specific record', async () => {
    const app = buildApp([assignment('alice', 'member')]);

    await request(app).patch('/documents/d1').set('x-user-id', 'alice').expect(200);
    // Same permission, different record — the IDOR is closed by the policy.
    await request(app).patch('/documents/d2').set('x-user-id', 'alice').expect(403);
  });

  it('denies rather than allows when the record does not exist', async () => {
    await request(buildApp([assignment('alice', 'member')]))
      .patch('/documents/missing')
      .set('x-user-id', 'alice')
      .expect(403);
  });

  it('lets an editor update a document they do not own, in their tenant', async () => {
    await request(buildApp([assignment('ed', 'editor')]))
      .patch('/documents/d2')
      .set('x-user-id', 'ed')
      .set('x-tenant-id', 'acme')
      .expect(200);
  });

  it('blocks the same editor across a tenant boundary', async () => {
    await request(buildApp([assignment('ed', 'editor')]))
      .patch('/documents/d2')
      .set('x-user-id', 'ed')
      .set('x-tenant-id', 'globex')
      .expect(403);
  });

  it('derives the scope from the route', async () => {
    const app = buildApp([assignment('ta', 'tenant-admin', 'tenant:acme')]);

    await request(app).get('/tenants/acme/users').set('x-user-id', 'ta').expect(200);
    await request(app).get('/tenants/globex/users').set('x-user-id', 'ta').expect(403);
  });

  it('passes when any one of several permissions is held', async () => {
    await request(buildApp([assignment('a1', 'auditor')]))
      .get('/reports')
      .set('x-user-id', 'a1')
      .expect(200);

    await request(buildApp([assignment('m', 'member')]))
      .get('/reports')
      .set('x-user-id', 'm')
      .expect(403);
  });
});

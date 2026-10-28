import express, { type Express, type Request } from 'express';
import { AccessControl } from './engine.js';
import { RoleRegistry } from './roleRegistry.js';
import { RoleAdminService } from './roleAdmin.js';
import { InMemoryAssignmentStore, type AssignmentStore } from './store.js';
import { ConditionRegistry } from './conditions.js';
import { InMemoryAuditLog, type AuditSink } from './audit.js';
import { attachSubject, rbacErrorHandler } from './middleware.js';
import { createRbacRouter, rbacRouteErrorHandler } from './routes.js';
import { examplePolicy } from './policy.js';
import type { RoleDefinition, Subject } from './types.js';

export interface AppDependencies {
  policy?: readonly RoleDefinition[];
  store?: AssignmentStore;
  conditions?: ConditionRegistry;
  audit?: AuditSink;
  /**
   * Bridges the host application authentication to this module. The engine has
   * no opinion about JWTs, sessions or API keys — it needs only a subject id
   * and attributes.
   */
  resolveSubject?: (req: Request) => Subject | null | Promise<Subject | null>;
}

export interface BuiltApp {
  app: Express;
  ac: AccessControl;
  admin: RoleAdminService;
  registry: RoleRegistry;
  store: AssignmentStore;
  audit: InMemoryAuditLog;
}

/**
 * Builds the Express application from explicit dependencies.
 *
 * Nothing is constructed at import time, so tests spin up isolated instances
 * and production swaps the in-memory store for a database without touching
 * this file. The role graph is validated during construction, so a bad policy
 * fails at boot rather than on the first denied request.
 */
export function createApp(deps: AppDependencies = {}): BuiltApp {
  const registry = new RoleRegistry(deps.policy ?? examplePolicy);
  const store = deps.store ?? new InMemoryAssignmentStore();
  const audit = deps.audit instanceof InMemoryAuditLog ? deps.audit : new InMemoryAuditLog();

  const ac = new AccessControl(registry, store, {
    conditions: deps.conditions ?? new ConditionRegistry(),
    audit: deps.audit ?? audit,
  });
  const admin = new RoleAdminService(registry, store, ac);

  const app = express();
  app.disable('x-powered-by');
  // Required for a correct `req.ip` behind a proxy; trusting one hop rather
  // than `true` stops clients spoofing X-Forwarded-For.
  app.set('trust proxy', 1);

  app.use(express.json({ limit: '16kb' }));

  app.use(
    attachSubject(
      deps.resolveSubject ??
        ((req) => {
          // Development fallback. A real deployment verifies a JWT or session
          // here and must never trust a plain header.
          const id = req.header('x-subject-id');
          const tenantId = req.header('x-tenant-id');
          return id ? { id, attributes: tenantId ? { tenantId } : {} } : null;
        }),
    ),
  );

  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      roles: registry.list().length,
      policyRevision: registry.version,
      uptime: process.uptime(),
    });
  });

  app.use('/rbac', createRbacRouter({ ac, admin, registry, store }));

  // Route-level handler first (it knows about escalation and unknown roles),
  // then the generic guard handler for anything raised by middleware.
  app.use(rbacRouteErrorHandler);
  app.use(rbacErrorHandler);

  app.use((_req, res) => {
    res.status(404).json({ error: { code: 'not_found', message: 'Endpoint not found' } });
  });

  return { app, ac, admin, registry, store, audit };
}

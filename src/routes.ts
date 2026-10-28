import { Router, type NextFunction, type Request, type Response } from 'express';
import type { AccessControl } from './engine.js';
import {
  AccessDeniedError,
  AuthenticationRequiredError,
  PrivilegeEscalationError,
  UnknownRoleError,
} from './errors.js';
import type { RoleAdminService } from './roleAdmin.js';
import type { RoleRegistry } from './roleRegistry.js';
import type { AssignmentStore } from './store.js';
import { GLOBAL_SCOPE, type Scope } from './types.js';
import { authorize } from './middleware.js';

/**
 * HTTP surface for role-based access control.
 *
 * Two distinct audiences share this router, and the difference matters:
 * a normal user may read their *own* effective permissions, while assigning
 * and revoking roles is itself a permission-gated administrative action
 * (`role:assign` / `role:revoke`) enforced in the target scope.
 */
export interface RbacRouterDeps {
  ac: AccessControl;
  admin: RoleAdminService;
  registry: RoleRegistry;
  store: AssignmentStore;
}

const asyncRoute =
  (handler: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => {
    void Promise.resolve(handler(req, res)).catch(next);
  };

function requireSubject(req: Request) {
  if (!req.subject) throw new AuthenticationRequiredError();
  return req.subject;
}

/** Scope from the query string, defaulting to global. */
const scopeOf = (req: Request): Scope =>
  typeof req.query.scope === 'string' && req.query.scope ? req.query.scope : GLOBAL_SCOPE;

function badRequest(res: Response, message: string): void {
  res.status(400).json({ error: { code: 'invalid_request', message } });
}

export function createRbacRouter(deps: RbacRouterDeps): Router {
  const router = Router();

  /** The catalogue itself — useful for rendering an admin UI. */
  router.get(
    '/roles',
    asyncRoute(async (_req, res) => {
      res.json({
        roles: deps.registry.list().map((role) => ({
          name: role.name,
          description: role.description ?? null,
          inherits: role.inherits ?? [],
          // The resolved closure, not just the declared grants.
          permissions: deps.registry.grantsOf(role.name).map((grant) => ({
            permission: grant.permission,
            effect: grant.effect,
            when: grant.when ?? null,
          })),
        })),
      });
    }),
  );

  /** What the caller can do right now, in a given scope. */
  router.get(
    '/me/permissions',
    asyncRoute(async (req, res) => {
      const subject = requireSubject(req);
      res.json(await deps.ac.grantsFor(subject, scopeOf(req)));
    }),
  );

  /**
   * Policy decision point over HTTP, for services that cannot import this
   * module directly. Returns the full reasoning, not just a boolean — a
   * caller that only learns "no" cannot tell a missing role from a failed
   * ownership check.
   */
  router.post(
    '/access/check',
    asyncRoute(async (req, res) => {
      const subject = requireSubject(req);
      const { resource, action, scope, resourceAttributes } = req.body ?? {};

      if (typeof resource !== 'string' || typeof action !== 'string') {
        return badRequest(res, '"resource" and "action" are required strings');
      }

      const decision = await deps.ac.decide({
        subject,
        resource,
        action,
        scope: typeof scope === 'string' ? scope : GLOBAL_SCOPE,
        ...(resourceAttributes && typeof resourceAttributes === 'object'
          ? { resourceAttributes: resourceAttributes as Record<string, unknown> }
          : {}),
      });

      res.json({
        allowed: decision.allowed,
        reason: decision.reason,
        permission: decision.permission,
        scope: decision.scope,
        matchedRole: decision.matched?.role ?? null,
      });
    }),
  );

  /** Roles this caller is actually allowed to hand out, for a picker UI. */
  router.get(
    '/roles/assignable',
    asyncRoute(async (req, res) => {
      const subject = requireSubject(req);
      res.json({ roles: await deps.admin.assignableRoles(subject, scopeOf(req)) });
    }),
  );

  router.get(
    '/subjects/:id/roles',
    authorize(deps.ac, {
      resource: 'user',
      action: 'read',
      scope: (req) => scopeOf(req),
    }),
    asyncRoute(async (req, res) => {
      const assignments = await deps.store.listForSubject(String(req.params.id));
      res.json({
        assignments: assignments.map((assignment) => ({
          role: assignment.role,
          scope: assignment.scope,
          grantedBy: assignment.grantedBy ?? null,
          grantedAt: assignment.grantedAt.toISOString(),
          expiresAt: assignment.expiresAt?.toISOString() ?? null,
        })),
      });
    }),
  );

  /**
   * Assigns a role. The escalation rules live in `RoleAdminService`, not here:
   * holding `role:assign` is not enough to grant a role carrying permissions
   * the actor does not have.
   */
  router.post(
    '/subjects/:id/roles',
    asyncRoute(async (req, res) => {
      const actor = requireSubject(req);
      const { role, scope, expiresAt } = req.body ?? {};

      if (typeof role !== 'string' || !role) {
        return badRequest(res, '"role" is required');
      }
      if (expiresAt !== undefined && Number.isNaN(Date.parse(String(expiresAt)))) {
        return badRequest(res, '"expiresAt" must be an ISO-8601 timestamp');
      }

      const assignment = await deps.admin.assignRole({
        actor,
        subjectId: String(req.params.id),
        role,
        ...(typeof scope === 'string' ? { scope } : {}),
        // Time-boxed elevation is safer than a permanent grant.
        ...(expiresAt ? { expiresAt: new Date(String(expiresAt)) } : {}),
      });

      res.status(201).json({
        assignment: {
          subjectId: assignment.subjectId,
          role: assignment.role,
          scope: assignment.scope,
          expiresAt: assignment.expiresAt?.toISOString() ?? null,
        },
      });
    }),
  );

  router.delete(
    '/subjects/:id/roles/:role',
    asyncRoute(async (req, res) => {
      const actor = requireSubject(req);
      const revoked = await deps.admin.revokeRole({
        actor,
        subjectId: String(req.params.id),
        role: String(req.params.role),
        scope: scopeOf(req),
      });
      // Idempotent: revoking a role nobody holds is not an error.
      res.status(revoked ? 204 : 404).end();
    }),
  );

  return router;
}

/**
 * Translates RBAC errors to status codes.
 *
 * A 403 body names only the permission that was required — never the role that
 * would have granted it or the rule that matched, since that maps out the
 * policy for whoever is probing.
 */
export const rbacRouteErrorHandler = (
  error: unknown,
  _req: Request,
  res: Response,
  next: NextFunction,
): void => {
  if (res.headersSent) return next(error);

  if (error instanceof AuthenticationRequiredError) {
    res.status(401).json({ error: { code: 'authentication_required', message: error.message } });
    return;
  }
  if (error instanceof PrivilegeEscalationError) {
    res.status(403).json({
      error: {
        code: 'privilege_escalation',
        message: 'You cannot grant a role that exceeds your own permissions',
        role: error.role,
      },
    });
    return;
  }
  if (error instanceof AccessDeniedError) {
    res.status(403).json({
      error: {
        code: 'forbidden',
        message: 'You do not have permission to perform this action',
        requiredPermission: error.decision.permission,
      },
    });
    return;
  }
  if (error instanceof UnknownRoleError) {
    res.status(404).json({ error: { code: 'unknown_role', message: error.message } });
    return;
  }
  next(error);
};

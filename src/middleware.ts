import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AccessControl } from './engine.js';
import { AccessDeniedError, AuthenticationRequiredError } from './errors.js';
import { GLOBAL_SCOPE, type Scope, type Subject } from './types.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      subject?: Subject;
      /** Populated by `authorize` so handlers can log or inspect the reason. */
      authDecision?: Awaited<ReturnType<AccessControl['decide']>>;
    }
  }
}

/**
 * Bridges whatever authentication the app uses to this module. Keeping the
 * resolver injectable means the engine has no opinion about JWTs, sessions or
 * API keys — it only needs a subject id and attributes.
 */
export function attachSubject(
  resolve: (req: Request) => Subject | null | Promise<Subject | null>,
): RequestHandler {
  return async (req, _res, next) => {
    try {
      req.subject = (await resolve(req)) ?? undefined;
      next();
    } catch (error) {
      next(error);
    }
  };
}

export interface AuthorizeOptions {
  resource: string;
  action: string;
  /** Derives the scope from the request, e.g. from `/tenants/:tenantId`. */
  scope?: (req: Request) => Scope;
  /**
   * Loads the record being acted on, for conditional grants.
   *
   * This is what closes the IDOR gap: holding `document:update` is not the
   * same as being allowed to update *this* document. Returning null means the
   * record does not exist, which is denied rather than allowed by default.
   */
  loadResource?: (req: Request) => Promise<Record<string, unknown> | null>;
}

/**
 * Route guard. Authentication and authorization stay separate: a missing
 * subject is 401 (who are you?), a failed policy check is 403 (you may not).
 * Collapsing the two hides misconfigured authentication behind a permissions
 * error.
 */
export function authorize(ac: AccessControl, options: AuthorizeOptions): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const subject = req.subject;
      if (!subject) throw new AuthenticationRequiredError();

      const resourceAttributes = options.loadResource
        ? await options.loadResource(req)
        : undefined;

      // A resource that could not be loaded must not fall through to a
      // permission that would otherwise pass unconditionally.
      if (options.loadResource && resourceAttributes === null) {
        throw new AccessDeniedError({
          allowed: false,
          reason: 'condition_failed',
          permission: `${options.resource}:${options.action}`,
          scope: options.scope?.(req) ?? GLOBAL_SCOPE,
          roles: [],
          matched: null,
          evaluated: [],
        });
      }

      const decision = await ac.decide({
        subject,
        resource: options.resource,
        action: options.action,
        scope: options.scope?.(req) ?? GLOBAL_SCOPE,
        ...(resourceAttributes ? { resourceAttributes } : {}),
      });

      req.authDecision = decision;
      if (!decision.allowed) throw new AccessDeniedError(decision);
      next();
    } catch (error) {
      next(error);
    }
  };
}

/** Passes when any one of several permissions is granted. */
export function authorizeAny(
  ac: AccessControl,
  permissions: ReadonlyArray<{ resource: string; action: string }>,
  scope?: (req: Request) => Scope,
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const subject = req.subject;
      if (!subject) throw new AuthenticationRequiredError();

      let last = null;
      for (const permission of permissions) {
        const decision = await ac.decide({
          subject,
          ...permission,
          scope: scope?.(req) ?? GLOBAL_SCOPE,
        });
        last = decision;
        if (decision.allowed) {
          req.authDecision = decision;
          return next();
        }
      }
      throw new AccessDeniedError(last!);
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Error translator. The client is told only the permission that was required —
 * never which role would have granted it or which rule matched, since that
 * maps out the policy for an attacker. The full trace goes to the audit log.
 */
export const rbacErrorHandler = (
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
  next(error);
};

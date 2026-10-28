import type { Decision } from './types.js';

export class RbacError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Error.captureStackTrace?.(this, new.target);
  }
}

/** A malformed permission string, caught at definition time wherever possible. */
export class PermissionSyntaxError extends RbacError {}

export class UnknownRoleError extends RbacError {
  constructor(readonly role: string) {
    super(`Unknown role "${role}"`);
  }
}

export class UnknownConditionError extends RbacError {
  constructor(readonly condition: string) {
    super(`Unknown condition "${condition}"`);
  }
}

/**
 * Inheritance cycles make the effective permission set undefined, so they are
 * rejected at construction rather than discovered under load.
 */
export class RoleCycleError extends RbacError {
  constructor(readonly path: string[]) {
    super(`Role inheritance cycle: ${path.join(' -> ')}`);
  }
}

/** Thrown by `AccessControl.check`; carries the trace for logging. */
export class AccessDeniedError extends RbacError {
  readonly status = 403;
  constructor(readonly decision: Decision) {
    super(`Access denied: ${decision.permission} (${decision.reason})`);
  }
}

export class AuthenticationRequiredError extends RbacError {
  readonly status = 401;
  constructor(message = 'Authentication required') {
    super(message);
  }
}

/**
 * Raised when an actor tries to grant a role carrying permissions they do not
 * themselves hold — the most common way an RBAC system is escalated.
 */
export class PrivilegeEscalationError extends RbacError {
  readonly status = 403;
  constructor(
    readonly role: string,
    readonly missing: string[],
  ) {
    super(
      `Cannot grant "${role}": it carries permissions you do not hold (${missing.join(', ')})`,
    );
  }
}

import { UnknownConditionError } from './errors.js';
import type { AccessRequest } from './types.js';

/**
 * A condition narrows a grant to the records it should actually cover.
 *
 * `document:update` on its own means "may update documents" — every document
 * in the system. Attaching `isOwner` turns it into "may update documents they
 * own", which is what almost every product actually means. Without this the
 * only alternatives are a role per resource or an ownership check copy-pasted
 * into every handler, and the second one always gets forgotten somewhere.
 */
export type Condition = (request: AccessRequest) => boolean;

/** Reads a value that may live on the resource or on the subject. */
const attr = (bag: Record<string, unknown> | undefined, key: string): unknown =>
  bag ? bag[key] : undefined;

export const builtInConditions: Record<string, Condition> = {
  /** The caller owns the record. */
  isOwner: (request) => {
    const owner = attr(request.resourceAttributes, 'ownerId');
    return typeof owner === 'string' && owner === request.subject.id;
  },

  /** The record is the caller own user record. */
  isSelf: (request) => {
    const target = attr(request.resourceAttributes, 'userId');
    return typeof target === 'string' && target === request.subject.id;
  },

  /** Caller and record belong to the same tenant. */
  sameTenant: (request) => {
    const subjectTenant = attr(request.subject.attributes, 'tenantId');
    const resourceTenant = attr(request.resourceAttributes, 'tenantId');
    return (
      typeof subjectTenant === 'string' &&
      subjectTenant.length > 0 &&
      subjectTenant === resourceTenant
    );
  },

  /** The record is not archived or soft-deleted. */
  isNotArchived: (request) => attr(request.resourceAttributes, 'archivedAt') == null,
};

export class ConditionRegistry {
  private readonly conditions = new Map<string, Condition>();

  constructor(includeBuiltIns = true) {
    if (includeBuiltIns) {
      for (const [name, fn] of Object.entries(builtInConditions)) this.register(name, fn);
    }
  }

  register(name: string, condition: Condition): this {
    this.conditions.set(name, condition);
    return this;
  }

  has(name: string): boolean {
    return this.conditions.has(name);
  }

  /**
   * Evaluates a condition, failing closed: a condition that throws denies the
   * grant instead of propagating. A bug in a predicate must not become an
   * unhandled 500 that a caller can trigger with crafted input.
   */
  evaluate(name: string, request: AccessRequest): boolean {
    const condition = this.conditions.get(name);
    if (!condition) throw new UnknownConditionError(name);
    try {
      return condition(request) === true;
    } catch {
      return false;
    }
  }
}

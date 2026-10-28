/**
 * Public surface of the RBAC module.
 *
 * The engine (registry, store, conditions, decisions) has no framework
 * dependency at all; only `middleware.ts` imports Express. That split keeps
 * the policy logic testable in isolation and reusable from a worker, a CLI or
 * a GraphQL resolver.
 */
export * from './types.js';
export * from './errors.js';
export { parsePermission, permissionMatches, permissionCovers, specificity, scopeCovers } from './permission.js';
export { RoleRegistry } from './roleRegistry.js';
export { ConditionRegistry, builtInConditions, type Condition } from './conditions.js';
export { InMemoryAssignmentStore, isActive, type AssignmentStore } from './store.js';
export { AccessControl, type AccessControlOptions } from './engine.js';
export { RoleAdminService } from './roleAdmin.js';
export { InMemoryAuditLog, ConsoleAuditSink, type AuditEntry, type AuditSink } from './audit.js';
export { attachSubject, authorize, authorizeAny, rbacErrorHandler, type AuthorizeOptions } from './middleware.js';
export { examplePolicy } from './policy.js';
export { createRbacRouter, rbacRouteErrorHandler, type RbacRouterDeps } from './routes.js';
export { createApp, type AppDependencies, type BuiltApp } from './app.js';

import type { RoleDefinition } from './types.js';

/**
 * A worked example policy for a multi-tenant document product.
 *
 * Read it as documentation of the model rather than as defaults to ship:
 * inheritance, wildcards, conditional grants, and an explicit deny that
 * overrides an inherited allow all appear here.
 */
export const examplePolicy: RoleDefinition[] = [
  {
    name: 'guest',
    description: 'Unauthenticated or invited read-only visitor',
    grants: [
      { permission: 'document:read', effect: 'allow', when: 'isNotArchived' },
    ],
  },
  {
    name: 'member',
    description: 'Standard signed-in user within a tenant',
    inherits: ['guest'],
    grants: [
      { permission: 'document:create', effect: 'allow' },
      // Ownership is enforced by the policy, not by each route handler.
      { permission: 'document:update', effect: 'allow', when: 'isOwner' },
      { permission: 'document:delete', effect: 'allow', when: 'isOwner' },
      { permission: 'comment:create', effect: 'allow' },
      { permission: 'profile:read', effect: 'allow' },
      { permission: 'profile:update', effect: 'allow', when: 'isSelf' },
    ],
  },
  {
    name: 'editor',
    description: 'May edit any document in the tenant',
    inherits: ['member'],
    grants: [
      { permission: 'document:update', effect: 'allow', when: 'sameTenant' },
      { permission: 'document:publish', effect: 'allow', when: 'sameTenant' },
    ],
  },
  {
    name: 'auditor',
    description: 'Reads everything, changes nothing',
    grants: [
      { permission: '*:read', effect: 'allow' },
      { permission: 'auditlog:read', effect: 'allow' },
      // Deny-overrides makes this hold even if another role is added later
      // that grants writes — the intent survives future policy edits.
      { permission: '*:update', effect: 'deny' },
      { permission: '*:delete', effect: 'deny' },
      { permission: '*:create', effect: 'deny' },
    ],
  },
  {
    name: 'tenant-admin',
    description: 'Full control within an assigned tenant scope',
    inherits: ['editor'],
    grants: [
      { permission: 'document:delete', effect: 'allow', when: 'sameTenant' },
      { permission: 'user:read', effect: 'allow' },
      { permission: 'user:invite', effect: 'allow' },
      { permission: 'role:assign', effect: 'allow' },
      { permission: 'role:revoke', effect: 'allow' },
      { permission: 'auditlog:read', effect: 'allow' },
    ],
  },
  {
    name: 'superadmin',
    description: 'Unrestricted; assign globally and sparingly',
    grants: [{ permission: '*:*', effect: 'allow' }],
  },
];

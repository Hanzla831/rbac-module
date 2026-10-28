# Role-Based Access Control

A policy engine for RBAC in Node.js / TypeScript: role hierarchies, scoped
assignments, conditional grants, deny-overrides evaluation, Express route
guards, and privilege-escalation prevention on role administration.

The engine has **no framework dependency**. Only `middleware.ts` imports
Express, so the policy logic is equally usable from a worker, a CLI, or a
GraphQL resolver — and is testable without HTTP.

```
src/
  types.ts          Domain model: roles, grants, assignments, decisions
  permission.ts     resource:action parsing, wildcard and scope matching
  roleRegistry.ts   Role catalogue, inheritance closure, cycle detection
  conditions.ts     Predicates that narrow a grant to specific records
  store.ts          Assignment persistence boundary (+ in-memory impl)
  engine.ts         AccessControl — the policy decision point
  roleAdmin.ts      Assignment administration with escalation prevention
  audit.ts          Decision audit trail
  middleware.ts     Express guards and error translation
  policy.ts         A worked example policy
```

## The model

Pure RBAC — users get roles, roles get permissions — breaks down on two things
every real product needs. This module addresses both without abandoning roles.

**Scoped assignments.** "Admin of tenant A" is not "admin everywhere". A role
is assigned within a scope (`*`, `tenant:acme`, or `tenant:acme/*` for
descendants), so the same `tenant-admin` definition serves every tenant.
Without this you end up with `admin_tenant_a_billing` style role names.

**Conditional grants.** `document:update` alone means "may update *any*
document". Attaching `when: 'isOwner'` makes it "may update documents they
own", which is what products usually mean. The alternative is an ownership
check copy-pasted into every handler — and it always gets forgotten somewhere.

```ts
const registry = new RoleRegistry([
  { name: 'member', inherits: ['guest'], grants: [
    { permission: 'document:create', effect: 'allow' },
    { permission: 'document:update', effect: 'allow', when: 'isOwner' },
  ]},
  { name: 'auditor', grants: [
    { permission: '*:read',   effect: 'allow' },
    { permission: '*:update', effect: 'deny'  },
  ]},
]);

const ac = new AccessControl(registry, new InMemoryAssignmentStore());

await ac.can({
  subject: { id: 'alice' },
  resource: 'document',
  action: 'update',
  resourceAttributes: { ownerId: 'alice' },
});
```

## Evaluation order

1. Collect assignments that are unexpired and in scope.
2. Expand them through role inheritance.
3. Keep grants matching the requested permission.
4. Drop grants whose condition fails.
5. **Any surviving DENY wins outright.**
6. Otherwise the **most specific ALLOW** wins (`document:read` beats `*:*`).
7. Otherwise **deny**.

Deny-overrides is the only safe precedence. If a broader allow could outvote a
deny, then revoking a capability from one role would silently do nothing for
any subject who also held a wildcard grant. Default-deny at step 7 means a
resource nobody wrote a policy for is closed rather than open.

## Design decisions worth calling out

**Requests may not contain wildcards.** `permissionMatches` throws if the
*requested* permission contains `*`. Without that guard, a caller probing with
`*:*` matches every wildcard grant in the system — a check that reads as
correct while authorizing everything.

**Scope prefixes respect separators.** `tenant:acme` does not cover
`tenant:acme-corp`. Naive `startsWith` comparison is a scope-escape bug.

**Misconfiguration fails at boot, not at request time.** Unknown parent roles,
inheritance cycles, malformed permission strings, and grants referencing an
unregistered condition all throw during construction. A broken role graph is a
deployment error; discovering it when a user is denied is far too late.

**Conditions fail closed.** A predicate that throws denies the grant rather
than propagating, so a bug in a predicate cannot become an unhandled 500 that
a caller triggers with crafted input.

**Revocation takes effect immediately.** Resolved roles are cached against the
store write counter and the registry revision, so a revoked role stops working
on the very next request instead of after a TTL. Assignments with an expiry are
never cached.

**Every decision carries its reasoning.** A `Decision` includes the effective
roles, every grant evaluated, and which one decided it — and distinguishes
`no_matching_grant` ("no policy covers this") from `condition_failed` ("a
policy covered it but the record did not qualify"). An authorization layer that
answers only yes/no cannot be debugged or audited after an incident.

**Clients are told nothing.** The 403 body names the required permission and
nothing else — never which role would have granted it or which rule matched,
since that maps out the policy. The full trace goes to the audit log.

## Privilege-escalation prevention

Holding `role:assign` is not enough to grant a role. `RoleAdminService`
enforces:

1. **No granting beyond your own authority.** An unconditional grant in the
   target role requires an unconditional allow from the actor; a conditional
   grant requires any covering allow, being the narrower of the two. So a
   tenant-admin may grant `member`, but not `superadmin` — and not to
   themselves.
2. **No granting outside your scope.** The actor must hold `role:assign` *in
   the target scope*, so a tenant admin cannot reach into another tenant.

`assignableRoles()` applies the same rules to render a UI that only offers what
the actor can actually give.

## Running it

```bash
npm test        # 68 tests
npm run typecheck
```

Tests cover the semantics and the attack cases: wildcard-probe requests, scope
escape via prefix, cross-tenant access, IDOR on a specific record, deny beating
an inherited allow, stale permissions after revocation, and both escalation
paths above.

## Using a real database

Implement `AssignmentStore` (six methods) and pass it to `AccessControl`. The
only requirement beyond the obvious is `version()`: a counter that increases on
every write, which is what makes cache invalidation immediate. A single row
holding a sequence value, or `max(updated_at)`, both work.

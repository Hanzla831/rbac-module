import { describe, expect, it } from 'vitest';
import {
  parsePermission,
  permissionCovers,
  permissionMatches,
  scopeCovers,
  specificity,
} from '../src/permission.js';
import { PermissionSyntaxError } from '../src/errors.js';

describe('permission parsing', () => {
  it('accepts resource:action and wildcards', () => {
    expect(parsePermission('document:read')).toEqual({ resource: 'document', action: 'read' });
    expect(parsePermission('*:read')).toEqual({ resource: '*', action: 'read' });
    expect(parsePermission('*:*')).toEqual({ resource: '*', action: '*' });
  });

  it('rejects malformed permission strings', () => {
    for (const bad of ['document', 'a:b:c', ':read', 'document:', 'doc ument:read', '']) {
      expect(() => parsePermission(bad)).toThrow(PermissionSyntaxError);
    }
  });
});

describe('grant matching', () => {
  it('matches exact and wildcard grants', () => {
    expect(permissionMatches('document:read', 'document:read')).toBe(true);
    expect(permissionMatches('document:*', 'document:read')).toBe(true);
    expect(permissionMatches('*:read', 'document:read')).toBe(true);
    expect(permissionMatches('*:*', 'document:read')).toBe(true);
    expect(permissionMatches('document:read', 'document:update')).toBe(false);
    expect(permissionMatches('comment:*', 'document:read')).toBe(false);
  });

  it('refuses a wildcard on the requested side', () => {
    // Probing with `*:*` would otherwise match every wildcard grant and
    // silently authorize everything.
    expect(() => permissionMatches('document:read', '*:*')).toThrow(PermissionSyntaxError);
    expect(() => permissionMatches('document:read', 'document:*')).toThrow(PermissionSyntaxError);
  });

  it('ranks specificity so the closest grant wins', () => {
    expect(specificity('document:read')).toBe(2);
    expect(specificity('document:*')).toBe(1);
    expect(specificity('*:read')).toBe(1);
    expect(specificity('*:*')).toBe(0);
  });
});

describe('pattern containment', () => {
  it('compares two patterns without treating narrow as covering broad', () => {
    expect(permissionCovers('document:*', 'document:read')).toBe(true);
    expect(permissionCovers('document:*', 'document:*')).toBe(true);
    expect(permissionCovers('*:*', 'document:*')).toBe(true);
    // The important direction: holding only `document:read` does not let you
    // hand out `document:*`.
    expect(permissionCovers('document:read', 'document:*')).toBe(false);
    expect(permissionCovers('document:read', '*:read')).toBe(false);
  });
});

describe('scope matching', () => {
  it('treats * as global', () => {
    expect(scopeCovers('*', 'tenant:acme')).toBe(true);
    expect(scopeCovers('*', '*')).toBe(true);
  });

  it('matches an exact scope only', () => {
    expect(scopeCovers('tenant:acme', 'tenant:acme')).toBe(true);
    expect(scopeCovers('tenant:acme', 'tenant:globex')).toBe(false);
    expect(scopeCovers('tenant:acme', '*')).toBe(false);
  });

  it('covers descendants with a trailing /*', () => {
    expect(scopeCovers('tenant:acme/*', 'tenant:acme/project:apollo')).toBe(true);
    expect(scopeCovers('tenant:acme/*', 'tenant:globex/project:x')).toBe(false);
  });

  it('does not let a prefix escape into a sibling scope', () => {
    // `tenant:acme` must never cover `tenant:acme-corp`.
    expect(scopeCovers('tenant:acme', 'tenant:acme-corp')).toBe(false);
    expect(scopeCovers('tenant:acme/*', 'tenant:acme-corp/project:x')).toBe(false);
  });
});

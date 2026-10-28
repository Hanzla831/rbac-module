import type { Decision, Scope } from './types.js';

/**
 * Authorization decisions are security events. Denials in particular are the
 * signal that someone is probing, and "who could have done this?" after an
 * incident is unanswerable without a record of the allows too.
 */
export interface AuditEntry {
  at: Date;
  subjectId: string;
  permission: string;
  scope: Scope;
  allowed: boolean;
  reason: Decision['reason'];
  /** The role whose grant decided it, when one did. */
  matchedRole: string | null;
  roles: string[];
}

export interface AuditSink {
  record(entry: AuditEntry): void;
}

/** Bounded ring buffer — useful in tests and as a local diagnostic. */
export class InMemoryAuditLog implements AuditSink {
  readonly entries: AuditEntry[] = [];

  constructor(private readonly limit = 1000) {}

  record(entry: AuditEntry): void {
    this.entries.push(entry);
    if (this.entries.length > this.limit) this.entries.shift();
  }

  denials(): AuditEntry[] {
    return this.entries.filter((entry) => !entry.allowed);
  }

  forSubject(subjectId: string): AuditEntry[] {
    return this.entries.filter((entry) => entry.subjectId === subjectId);
  }

  clear(): void {
    this.entries.length = 0;
  }
}

/** Emits one structured line per decision, ready for a log pipeline. */
export class ConsoleAuditSink implements AuditSink {
  constructor(private readonly onlyDenials = true) {}

  record(entry: AuditEntry): void {
    if (this.onlyDenials && entry.allowed) return;
    console.log(
      JSON.stringify({
        event: 'authorization_decision',
        at: entry.at.toISOString(),
        subject: entry.subjectId,
        permission: entry.permission,
        scope: entry.scope,
        allowed: entry.allowed,
        reason: entry.reason,
        matchedRole: entry.matchedRole,
      }),
    );
  }
}

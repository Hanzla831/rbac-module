import { createApp } from './app.js';
import { InMemoryAssignmentStore } from './store.js';
import { GLOBAL_SCOPE } from './types.js';

/**
 * Node.js process entry point: configuration, startup, background maintenance
 * and graceful shutdown.
 *
 * Kept apart from `app.ts` so tests can import the application without binding
 * a port or starting timers.
 */
const PORT = Number(process.env.PORT ?? 3000);
const NODE_ENV = process.env.NODE_ENV ?? 'development';

async function main(): Promise<void> {
  const store = new InMemoryAssignmentStore();
  const { app, registry } = createApp({ store });

  if (NODE_ENV === 'development') {
    // A first administrator has to exist, or nobody can ever grant a role:
    // `role:assign` is itself permission-gated, so an empty system is a
    // locked system. Real deployments seed this in a migration.
    await store.assign({
      subjectId: process.env.BOOTSTRAP_ADMIN_ID ?? 'admin',
      role: 'superadmin',
      scope: GLOBAL_SCOPE,
      grantedBy: 'bootstrap',
      grantedAt: new Date(),
      expiresAt: null,
    });
    console.log('[rbac] seeded bootstrap superadmin');
  }

  const server = app.listen(PORT, () => {
    console.log(`[rbac] listening on http://localhost:${PORT} (${NODE_ENV})`);
    console.log(`[rbac] ${registry.list().length} roles loaded`);
  });

  // Expired assignments are dead weight and a liability: a time-boxed
  // elevation that is never cleaned up still shows in audit exports.
  const cleanup = setInterval(
    () => {
      void store
        .purgeExpired()
        .then((count) => count > 0 && console.log(`[rbac] purged ${count} expired assignments`))
        .catch((error) => console.error('[rbac] purge failed', error));
    },
    15 * 60_000,
  );
  cleanup.unref();

  // Drain in-flight requests before exiting so a deploy does not drop
  // authorization decisions mid-flight.
  const shutdown = (signal: string): void => {
    console.log(`[rbac] ${signal} received, shutting down`);
    clearInterval(cleanup);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => {
    console.error('[rbac] unhandled rejection', reason);
    shutdown('unhandledRejection');
  });
}

main().catch((error) => {
  console.error('[rbac] failed to start:', error instanceof Error ? error.message : error);
  process.exit(1);
});

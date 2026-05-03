// Minimal init/context pattern so the package's helpers can be used
// with bare imports (`import { createSession } from "@anthonyotte/auth-kit/server"`)
// rather than requiring callers to thread a config object through every
// call site. The host calls `initAuthKit({ ... })` once at startup;
// every helper reads from this context lazily.

// Auth tables are typed permissively because their concrete column
// shape varies per host — the host's `users` table carries arbitrary
// extra columns, and the FK-bearing factories return tables that
// reference the host's own users instance. The package accesses
// columns dynamically (e.g. tables.users.id) which means a strict
// PgTable<...> generic would block legitimate property access. The
// loose typing here is a library-boundary concern; nothing in the
// host code uses `as any` to satisfy this interface.
export interface AuthKitTables {
  users: any;
  sessions: any;
  passwordResetTokens: any;
  emailVerificationTokens: any;
  oauthAccounts: any;
  auditLog: any;
}

export interface AuthKitConfig {
  // Brand label baked into the QR code seen by users in their TOTP app.
  // Defaults to "App". Set this to your product name (e.g. "Acme.app").
  totpIssuer?: string;
  // The single privileged email allowed to perform super-admin actions.
  // null disables the super-admin gate entirely.
  superAdminEmail?: string | null;
  // Absolute http(s) URL the app is served from. Used to build emailed
  // links (verify-email, reset-password). In production this MUST be
  // set or link-builders throw.
  appUrl?: string | null;
  // Bcrypt cost factor. Defaults to 12.
  bcryptRounds?: number;
}

export interface AuthKitContext {
  db: any;
  tables: AuthKitTables;
  config: Required<Omit<AuthKitConfig, "superAdminEmail" | "appUrl">> & {
    superAdminEmail: string | null;
    appUrl: string | null;
  };
}

let _ctx: AuthKitContext | null = null;

export function initAuthKit(input: {
  db: any;
  tables: AuthKitTables;
  config?: AuthKitConfig;
}): void {
  const cfg = input.config ?? {};
  _ctx = {
    db: input.db,
    tables: input.tables,
    config: {
      totpIssuer: cfg.totpIssuer ?? "App",
      superAdminEmail: cfg.superAdminEmail ?? null,
      appUrl: cfg.appUrl ?? null,
      bcryptRounds: cfg.bcryptRounds ?? 12,
    },
  };
}

export function ctx(): AuthKitContext {
  if (!_ctx) {
    throw new Error(
      "auth-kit: not initialized. Call initAuthKit({ db, tables, config }) before using any helpers.",
    );
  }
  return _ctx;
}

// Test-only escape hatch.
export function __resetAuthKitForTests(): void {
  if (process.env.NODE_ENV === "production") return;
  _ctx = null;
}

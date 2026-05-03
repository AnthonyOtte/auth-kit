// Minimal init/context pattern so the package's helpers can be used
// with bare imports (`import { createSession } from "@anthonyotte/auth-kit/server"`)
// rather than requiring callers to thread a config object through every
// call site. The host calls `initAuthKit({ ... })` once at startup;
// every helper reads from this context lazily.

import type { sessions, passwordResetTokens, emailVerificationTokens, oauthAccounts, auditLog } from "../shared/schema";

// `users` is host-defined via createUsersTable() — its column shape
// varies per app, so we keep it loosely typed here. Helpers that touch
// users use drizzle's parametric query API and don't depend on extra
// columns.
export interface AuthKitTables {
  users: any;
  sessions: typeof sessions;
  passwordResetTokens: typeof passwordResetTokens;
  emailVerificationTokens: typeof emailVerificationTokens;
  oauthAccounts: typeof oauthAccounts;
  auditLog: typeof auditLog;
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

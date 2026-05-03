// Drizzle table definitions for the auth subsystem.
//
// `createUsersTable(extraColumns)` returns a `users` table whose
// canonical auth columns are baked in (email, passwordHash, role,
// totp_*, recovery_codes, locked_until, email_verified_at, etc.) and
// whose host-specific columns (e.g. credit balances, subscription
// state, team labels) come from the caller. The host then wires that
// `users` table into auth-kit via `initAuthKit({ tables: { users, ... } })`.
//
// All other auth tables (`sessions`, `password_reset_tokens`,
// `email_verification_tokens`, `oauth_accounts`, `audit_log`) are
// fully owned by the package and exported as concrete drizzle tables.

import {
  pgTable,
  text,
  varchar,
  timestamp,
  integer,
  pgEnum,
  boolean,
  jsonb,
  unique,
  type AnyPgColumn,
  type PgColumnBuilderBase,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { z } from "zod";

// Reusable enum for user roles. Keep this exported so the host can
// reuse it when its own queries reference role values.
export const userRoleEnum = pgEnum("user_role", ["admin", "user"]);

// Auth-canonical columns. Host extends with extraColumns at definition
// time. We deliberately don't expose this object directly — callers go
// through `createUsersTable()` so we can validate / future-proof the
// shape.
function authUserColumns() {
  return {
    id: varchar("id", { length: 36 }).primaryKey(),
    email: varchar("email", { length: 255 }).notNull().unique(),
    passwordHash: text("password_hash"),
    role: userRoleEnum("role").notNull().default("user"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    isActive: boolean("is_active").notNull().default(true),
    lastLoginAt: timestamp("last_login_at"),
    failedLoginCount: integer("failed_login_count").notNull().default(0),
    lockedUntil: timestamp("locked_until"),
    totpSecret: text("totp_secret"),
    totpEnabledAt: timestamp("totp_enabled_at"),
    totpIssuer: text("totp_issuer"),
    recoveryCodeHashes: text("recovery_code_hashes")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    emailVerifiedAt: timestamp("email_verified_at"),
  };
}

export type AuthUserColumns = ReturnType<typeof authUserColumns>;

// Build the host's `users` table by merging auth-canonical columns with
// the host's extra columns. Column names cannot collide with the
// canonical names (TS will complain at compile time).
export function createUsersTable<
  TExtra extends Record<string, PgColumnBuilderBase>,
>(extraColumns: TExtra = {} as TExtra) {
  const base = authUserColumns();
  for (const k of Object.keys(extraColumns)) {
    if (k in base) {
      throw new Error(
        `auth-kit: extra column "${k}" collides with a built-in auth column`,
      );
    }
  }
  return pgTable("users", { ...base, ...extraColumns });
}

// Sessions ─ owned by the package.
export const sessions = pgTable("sessions", {
  id: varchar("id", { length: 36 }).primaryKey(),
  userId: varchar("user_id", { length: 36 }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
export type SessionDb = typeof sessions.$inferSelect;

// Password-reset tokens.
export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: varchar("id", { length: 36 }).primaryKey(),
  userId: varchar("user_id", { length: 36 }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  usedAt: timestamp("used_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
export type PasswordResetTokenDb = typeof passwordResetTokens.$inferSelect;

// Email-verification tokens.
export const emailVerificationTokens = pgTable("email_verification_tokens", {
  id: varchar("id", { length: 36 }).primaryKey(),
  userId: varchar("user_id", { length: 36 }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  usedAt: timestamp("used_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
export type EmailVerificationTokenDb = typeof emailVerificationTokens.$inferSelect;

// OAuth account links.
export const oauthAccounts = pgTable(
  "oauth_accounts",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    provider: varchar("provider", { length: 32 }).notNull(),
    providerSubject: varchar("provider_subject", { length: 255 }).notNull(),
    email: varchar("email", { length: 255 }),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (t) => ({
    providerSubjectUnique: unique("oauth_accounts_provider_subject_unique").on(
      t.provider,
      t.providerSubject,
    ),
  }),
);
export type OAuthAccountDb = typeof oauthAccounts.$inferSelect;

// Audit log. Host-defined event strings allowed — just a varchar.
export const auditLog = pgTable("audit_log", {
  id: varchar("id", { length: 36 }).primaryKey(),
  userId: varchar("user_id", { length: 36 }),
  event: varchar("event", { length: 64 }).notNull(),
  ip: varchar("ip", { length: 64 }),
  userAgent: text("user_agent"),
  meta: jsonb("meta"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
export type AuditLogDb = typeof auditLog.$inferSelect;

// Zod schemas for API payloads.
export const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required"),
});
export type LoginInput = z.infer<typeof loginSchema>;

export const loginWith2faSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  totpCode: z.string().regex(/^\d{6}$/).optional(),
  recoveryCode: z.string().min(8).optional(),
});
export type LoginWith2faInput = z.infer<typeof loginWith2faSchema>;

export const resetPasswordSchema = z.object({
  token: z.string().min(1, "Token is required"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

export const totpVerifySchema = z.object({
  code: z.string().regex(/^\d{6}$/, "Code must be 6 digits"),
});
export const recoveryCodeSchema = z.object({
  recoveryCode: z.string().min(8, "Recovery code is required"),
});

// Minimal "auth-only" view of a user — what the package's helpers
// guarantee will exist. Host's full UserDb extends this with extra
// columns it defined when it called createUsersTable().
export interface BaseUserAuthFields {
  id: string;
  email: string;
  passwordHash: string | null;
  role: "admin" | "user";
  createdAt: Date;
  isActive: boolean;
  lastLoginAt: Date | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  totpSecret: string | null;
  totpEnabledAt: Date | null;
  totpIssuer: string | null;
  recoveryCodeHashes: string[];
  emailVerifiedAt: Date | null;
}

// ─────────────────────────────────────────────────────────────────────
// Table factories with FK references — for hosts that want their auth
// tables to physically reference the users table they declared via
// createUsersTable(). Mirrors the column shape of the standalone
// `sessions` / `passwordResetTokens` / `emailVerificationTokens` /
// `oauthAccounts` / `auditLog` exports above, but each ROW gets a
// foreign-key constraint pointing at `users.id`.

export function createSessionsTable(users: { id: AnyPgColumn }) {
  return pgTable("sessions", {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 })
      .notNull()
      .references(() => users.id as any, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  });
}

export function createPasswordResetTokensTable(users: { id: AnyPgColumn }) {
  return pgTable("password_reset_tokens", {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 })
      .notNull()
      .references(() => users.id as any, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  });
}

export function createEmailVerificationTokensTable(users: { id: AnyPgColumn }) {
  return pgTable("email_verification_tokens", {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 })
      .notNull()
      .references(() => users.id as any, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  });
}

export function createOAuthAccountsTable(users: { id: AnyPgColumn }) {
  return pgTable(
    "oauth_accounts",
    {
      id: varchar("id", { length: 36 }).primaryKey(),
      userId: varchar("user_id", { length: 36 })
        .notNull()
        .references(() => users.id as any, { onDelete: "cascade" }),
      provider: varchar("provider", { length: 32 }).notNull(),
      providerSubject: varchar("provider_subject", { length: 255 }).notNull(),
      email: varchar("email", { length: 255 }),
      createdAt: timestamp("created_at").defaultNow().notNull(),
    },
    (t) => ({
      providerSubjectUnique: unique("oauth_accounts_provider_subject_unique").on(
        t.provider,
        t.providerSubject,
      ),
    }),
  );
}

export function createAuditLogTable(users: { id: AnyPgColumn }) {
  return pgTable("audit_log", {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 }).references(
      () => users.id as any,
      { onDelete: "set null" },
    ),
    event: varchar("event", { length: 64 }).notNull(),
    ip: varchar("ip", { length: 64 }),
    userAgent: text("user_agent"),
    meta: jsonb("meta"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  });
}

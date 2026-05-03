// Pure-auth helpers: sessions, password reset tokens, email verification
// tokens, user CRUD, lockout tracking, TOTP storage. Credit/billing
// concerns live in the consuming app.

import bcrypt from "bcrypt";
import crypto from "crypto";
import { eq, and, gt, sql, isNull } from "drizzle-orm";
import { ctx } from "./context";
import type { BaseUserAuthFields } from "../shared/schema";

const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const RESET_TOKEN_DURATION_MS = 60 * 60 * 1000; // 1 hour
const VERIFICATION_TOKEN_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

const MAX_FAILED_LOGINS = 10;
const LOCKOUT_MS = 30 * 60 * 1000;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, ctx().config.bcryptRounds);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export async function createSession(userId: string): Promise<string> {
  const { db, tables } = ctx();
  const token = generateToken();
  const tokenHash = hashToken(token);
  const id = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

  await db.insert(tables.sessions).values({ id, userId, tokenHash, expiresAt });

  return token;
}

// Validate a session token. Returns the host's full user row (whatever
// shape it has) or null if invalid/expired/inactive.
export async function validateSession<U = any>(token: string): Promise<U | null> {
  const { db, tables } = ctx();
  const tokenHash = hashToken(token);

  const result = await db
    .select()
    .from(tables.sessions)
    .innerJoin(tables.users, eq(tables.sessions.userId, tables.users.id))
    .where(
      and(
        eq(tables.sessions.tokenHash, tokenHash),
        gt(tables.sessions.expiresAt, new Date()),
      ),
    )
    .limit(1);

  if (result.length === 0) return null;
  // drizzle returns { sessions: ..., users: ... } when joining two tables.
  const row = result[0] as { users?: U & { isActive?: boolean } };
  const user = row.users;
  if (!user) return null;
  if (user.isActive === false) return null;
  return user as U;
}

export async function deleteSession(token: string): Promise<void> {
  const { db, tables } = ctx();
  await db.delete(tables.sessions).where(eq(tables.sessions.tokenHash, hashToken(token)));
}

export async function getSessionByToken(
  token: string,
): Promise<{ userId: string } | null> {
  const { db, tables } = ctx();
  const result = await db
    .select({ userId: tables.sessions.userId })
    .from(tables.sessions)
    .where(eq(tables.sessions.tokenHash, hashToken(token)))
    .limit(1);
  return result[0] ?? null;
}

export async function deleteAllUserSessions(userId: string): Promise<void> {
  const { db, tables } = ctx();
  await db.delete(tables.sessions).where(eq(tables.sessions.userId, userId));
}

// Revoke every session for a user except the supplied caller token.
// Returns the count of deleted rows.
export async function revokeOtherSessions(
  userId: string,
  exceptToken: string | null,
): Promise<number> {
  const { db, tables } = ctx();
  if (!exceptToken) {
    const result = await db
      .delete(tables.sessions)
      .where(eq(tables.sessions.userId, userId))
      .returning({ id: tables.sessions.id });
    return result.length;
  }
  const exceptHash = hashToken(exceptToken);
  const result = await db
    .delete(tables.sessions)
    .where(
      and(
        eq(tables.sessions.userId, userId),
        sql`${tables.sessions.tokenHash} <> ${exceptHash}`,
      ),
    )
    .returning({ id: tables.sessions.id });
  return result.length;
}

// ─── Password-reset tokens ────────────────────────────────────────────

export async function createPasswordResetToken(userId: string): Promise<string> {
  const { db, tables } = ctx();
  const token = generateToken();
  const tokenHash = hashToken(token);
  const id = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + RESET_TOKEN_DURATION_MS);

  await db
    .insert(tables.passwordResetTokens)
    .values({ id, userId, tokenHash, expiresAt });

  return token;
}

export async function validatePasswordResetToken(
  token: string,
): Promise<string | null> {
  const { db, tables } = ctx();
  const tokenHash = hashToken(token);
  const result = await db
    .select()
    .from(tables.passwordResetTokens)
    .where(
      and(
        eq(tables.passwordResetTokens.tokenHash, tokenHash),
        gt(tables.passwordResetTokens.expiresAt, new Date()),
      ),
    )
    .limit(1);

  if (result.length === 0) return null;
  const row = result[0];
  if (row.usedAt) return null;
  return row.userId;
}

export async function markPasswordResetTokenUsed(token: string): Promise<void> {
  const { db, tables } = ctx();
  await db
    .update(tables.passwordResetTokens)
    .set({ usedAt: new Date() })
    .where(eq(tables.passwordResetTokens.tokenHash, hashToken(token)));
}

// ─── Email-verification tokens ────────────────────────────────────────

export async function createEmailVerificationToken(userId: string): Promise<string> {
  const { db, tables } = ctx();
  await db
    .delete(tables.emailVerificationTokens)
    .where(
      and(
        eq(tables.emailVerificationTokens.userId, userId),
        isNull(tables.emailVerificationTokens.usedAt),
      ),
    );

  const token = generateToken();
  const tokenHash = hashToken(token);
  const id = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + VERIFICATION_TOKEN_DURATION_MS);

  await db
    .insert(tables.emailVerificationTokens)
    .values({ id, userId, tokenHash, expiresAt });

  return token;
}

export async function validateEmailVerificationToken(
  token: string,
): Promise<string | null> {
  const { db, tables } = ctx();
  const tokenHash = hashToken(token);
  const result = await db
    .select()
    .from(tables.emailVerificationTokens)
    .where(
      and(
        eq(tables.emailVerificationTokens.tokenHash, tokenHash),
        gt(tables.emailVerificationTokens.expiresAt, new Date()),
      ),
    )
    .limit(1);
  if (result.length === 0) return null;
  if (result[0].usedAt) return null;
  return result[0].userId;
}

export async function consumeEmailVerificationToken(
  token: string,
): Promise<{ verified: boolean; userId: string | null }> {
  const { db, tables } = ctx();
  const tokenHash = hashToken(token);
  return db.transaction(async (tx: any) => {
    const rows = await tx
      .select()
      .from(tables.emailVerificationTokens)
      .where(
        and(
          eq(tables.emailVerificationTokens.tokenHash, tokenHash),
          gt(tables.emailVerificationTokens.expiresAt, new Date()),
        ),
      )
      .limit(1);
    if (rows.length === 0) return { verified: false, userId: null };
    const row = rows[0];
    if (row.usedAt) return { verified: false, userId: row.userId };

    await tx
      .update(tables.emailVerificationTokens)
      .set({ usedAt: new Date() })
      .where(eq(tables.emailVerificationTokens.id, row.id));

    await tx
      .update(tables.users)
      .set({ emailVerifiedAt: new Date() })
      .where(
        and(
          eq(tables.users.id, row.userId),
          isNull(tables.users.emailVerifiedAt),
        ),
      );

    return { verified: true, userId: row.userId };
  });
}

// One-shot startup migration: stamp emailVerifiedAt = createdAt for
// every existing user that doesn't have it set yet.
export async function backfillEmailVerified(): Promise<number> {
  const { db } = ctx();
  // @ts-ignore - drizzle execute generics on untyped db
  const result = await (db as any).execute<{ id: string }>(sql`
    UPDATE users
    SET email_verified_at = created_at
    WHERE email_verified_at IS NULL
    RETURNING id
  `);
  return result.rows.length;
}

// ─── Users ────────────────────────────────────────────────────────────

export async function getUserByEmail<U = any>(email: string): Promise<U | null> {
  const { db, tables } = ctx();
  const result = await db
    .select()
    .from(tables.users)
    .where(eq(tables.users.email, email.toLowerCase()))
    .limit(1);
  return result.length > 0 ? (result[0] as U) : null;
}

export async function getUserById<U = any>(id: string): Promise<U | null> {
  const { db, tables } = ctx();
  const result = await db
    .select()
    .from(tables.users)
    .where(eq(tables.users.id, id))
    .limit(1);
  return result.length > 0 ? (result[0] as U) : null;
}

// Create a new user. Extra columns (creditBalance, etc.) default to
// whatever the host's `users` table specifies — we only set the auth
// columns here. Returns the inserted user row.
export async function createUser<U = any>(
  email: string,
  role: "admin" | "user" = "user",
  passwordHash?: string,
  extraColumns: Record<string, unknown> = {},
): Promise<U> {
  const { db, tables } = ctx();
  const id = crypto.randomUUID();

  await db.insert(tables.users).values({
    id,
    email: email.toLowerCase(),
    passwordHash: passwordHash || null,
    role,
    isActive: true,
    ...extraColumns,
  });

  const user = await getUserById<U>(id);
  if (!user) throw new Error("Failed to create user");
  return user;
}

export async function updateUserPassword(
  userId: string,
  password: string,
): Promise<void> {
  const { db, tables } = ctx();
  const passwordHash = await hashPassword(password);
  await db
    .update(tables.users)
    .set({ passwordHash })
    .where(eq(tables.users.id, userId));
}

export async function deleteUser(userId: string): Promise<void> {
  const { db, tables } = ctx();
  await db.delete(tables.users).where(eq(tables.users.id, userId));
}

export async function getAllUsers<U = any>(): Promise<U[]> {
  const { db, tables } = ctx();
  return db.select().from(tables.users).orderBy(tables.users.createdAt);
}

export async function updateUserLastLogin(userId: string): Promise<void> {
  const { db, tables } = ctx();
  await db
    .update(tables.users)
    .set({ lastLoginAt: new Date(), failedLoginCount: 0, lockedUntil: null })
    .where(eq(tables.users.id, userId));
}

// ─── Lockout ──────────────────────────────────────────────────────────

export function isUserLocked(user: BaseUserAuthFields): boolean {
  return !!user.lockedUntil && user.lockedUntil.getTime() > Date.now();
}

export async function recordFailedLogin(
  userId: string,
): Promise<{ locked: boolean; failedCount: number }> {
  const { db } = ctx();
  const lockoutMs = LOCKOUT_MS;
  const maxFails = MAX_FAILED_LOGINS;
  // @ts-ignore - drizzle execute generics on untyped db
  const result = await (db as any).execute<{
    failed_login_count: number;
    locked_until: Date | null;
  }>(sql`
    UPDATE users
    SET
      failed_login_count = failed_login_count + 1,
      locked_until = CASE
        WHEN failed_login_count + 1 >= ${maxFails}
          THEN NOW() + (${lockoutMs} || ' milliseconds')::interval
        ELSE locked_until
      END
    WHERE id = ${userId}
    RETURNING failed_login_count, locked_until
  `);
  const row = result.rows[0];
  if (!row) return { locked: false, failedCount: 0 };
  const failedCount = Number(row.failed_login_count ?? 0);
  const locked = !!row.locked_until && new Date(row.locked_until).getTime() > Date.now();
  return { locked, failedCount };
}

export async function clearFailedLogins(userId: string): Promise<void> {
  const { db, tables } = ctx();
  await db
    .update(tables.users)
    .set({ failedLoginCount: 0, lockedUntil: null })
    .where(eq(tables.users.id, userId));
}

// ─── TOTP ─────────────────────────────────────────────────────────────

export async function setUserTotp(
  userId: string,
  totpSecret: string,
  recoveryCodeHashes: string[],
  totpIssuer: string,
): Promise<void> {
  const { db, tables } = ctx();
  await db
    .update(tables.users)
    .set({ totpSecret, totpEnabledAt: new Date(), recoveryCodeHashes, totpIssuer })
    .where(eq(tables.users.id, userId));
}

export async function rotateUserTotp(
  userId: string,
  totpSecret: string,
  recoveryCodeHashes: string[],
  totpIssuer: string,
): Promise<void> {
  const { db, tables } = ctx();
  await db
    .update(tables.users)
    .set({ totpSecret, recoveryCodeHashes, totpIssuer, totpEnabledAt: new Date() })
    .where(eq(tables.users.id, userId));
}

export async function disableUserTotp(userId: string): Promise<void> {
  const { db, tables } = ctx();
  await db
    .update(tables.users)
    .set({
      totpSecret: null,
      totpEnabledAt: null,
      totpIssuer: null,
      recoveryCodeHashes: [],
    })
    .where(eq(tables.users.id, userId));
}

export async function setUserRecoveryCodes(
  userId: string,
  recoveryCodeHashes: string[],
): Promise<void> {
  const { db, tables } = ctx();
  await db.update(tables.users).set({ recoveryCodeHashes }).where(eq(tables.users.id, userId));
}

// Atomic verify-and-consume of a single recovery code under FOR UPDATE
// row-lock. Two concurrent logins cannot both spend the same code.
export async function tryConsumeRecoveryCode(
  userId: string,
  candidate: string,
  verifyFn: (
    hashes: string[],
  ) => Promise<{ remaining: string[]; matched: boolean }>,
): Promise<{ matched: boolean; remaining: number }> {
  const { db, tables } = ctx();
  return db.transaction(async (tx: any) => {
    // @ts-ignore - drizzle execute generics on untyped db
    const result = await (tx as any).execute<{ recovery_code_hashes: string[] | null }>(sql`
      SELECT recovery_code_hashes FROM users WHERE id = ${userId} FOR UPDATE
    `);
    const row = result.rows[0];
    const current: string[] = row?.recovery_code_hashes ?? [];
    const { remaining, matched } = await verifyFn(current);
    if (!matched) return { matched: false, remaining: current.length };
    await tx
      .update(tables.users)
      .set({ recoveryCodeHashes: remaining })
      .where(eq(tables.users.id, userId));
    return { matched: true, remaining: remaining.length };
  });
}

// Idempotent admin seeder: creates the user if they don't exist yet,
// otherwise updates the password + role to admin. Useful for bootstrapping
// the first admin via an env var.
export async function seedAdminUser(
  email: string,
  password: string,
): Promise<void> {
  const { db, tables } = ctx();
  const existing = await getUserByEmail<{ id: string }>(email);
  const passwordHash = await hashPassword(password);

  if (existing) {
    await db
      .update(tables.users)
      .set({ passwordHash, role: "admin" })
      .where(eq(tables.users.id, existing.id));
  } else {
    await createUser(email, "admin", passwordHash);
  }
}

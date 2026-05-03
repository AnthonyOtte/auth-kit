// Crypto / TOTP / password-strength / audit-log helpers.
import otplib from "otplib";
const { authenticator } = otplib;
import QRCode from "qrcode";
import zxcvbn from "zxcvbn";
import bcrypt from "bcrypt";
import { randomBytes, randomUUID, timingSafeEqual } from "crypto";
import type { Request } from "express";
import { ctx } from "./context";
import { isSuperAdminEmail as isSuperAdminEmailRaw } from "../shared/super-admin";

export function generateTotpSecret(): string {
  return authenticator.generateSecret();
}

export function buildTotpUri(email: string, secret: string): string {
  const issuer = ctx().config.totpIssuer;
  return authenticator.keyuri(email, issuer, secret);
}

export async function buildTotpQrDataUrl(
  email: string,
  secret: string,
): Promise<string> {
  const uri = buildTotpUri(email, secret);
  return QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 1, scale: 6 });
}

export function verifyTotpToken(secret: string, token: string): boolean {
  if (!/^\d{6}$/.test(token)) return false;
  try {
    authenticator.options = { window: 1 };
    return authenticator.check(token, secret);
  } catch {
    return false;
  }
}

export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString("hex").toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}

export async function hashRecoveryCodes(codes: string[]): Promise<string[]> {
  return Promise.all(
    codes.map((c) => bcrypt.hash(c.toUpperCase().replace(/[^A-F0-9]/g, ""), 10)),
  );
}

export async function consumeRecoveryCode(
  hashes: string[],
  candidate: string,
): Promise<{ remaining: string[]; matched: boolean }> {
  const normalized = candidate.toUpperCase().replace(/[^A-F0-9]/g, "");
  if (normalized.length < 8) return { remaining: hashes, matched: false };
  for (let i = 0; i < hashes.length; i++) {
    const ok = await bcrypt.compare(normalized, hashes[i]);
    if (ok) {
      const remaining = [...hashes.slice(0, i), ...hashes.slice(i + 1)];
      return { remaining, matched: true };
    }
  }
  return { remaining: hashes, matched: false };
}

export interface PasswordStrengthResult {
  ok: boolean;
  score: number;
  feedback: string;
}

const MIN_PASSWORD_SCORE = 3;

export function checkPasswordStrength(
  password: string,
  userInputs: string[] = [],
): PasswordStrengthResult {
  const result = zxcvbn(password, userInputs);
  if (password.length < 10) {
    return {
      ok: false,
      score: result.score,
      feedback: "Password must be at least 10 characters.",
    };
  }
  if (result.score < MIN_PASSWORD_SCORE) {
    const warning = result.feedback.warning || "Password is too weak.";
    const suggestion =
      result.feedback.suggestions?.[0] ||
      "Try a longer mix of words, numbers, and symbols.";
    return {
      ok: false,
      score: result.score,
      feedback: `${warning} ${suggestion}`.trim(),
    };
  }
  return { ok: true, score: result.score, feedback: "Strong password." };
}

export function getRequestIp(req: Request): string {
  const xff = (req.headers["x-forwarded-for"] as string | undefined)
    ?.split(",")[0]
    ?.trim();
  return xff || req.ip || "unknown";
}

export function getRequestUserAgent(req: Request): string | null {
  const ua = req.get("user-agent");
  return ua ? ua.slice(0, 1024) : null;
}

// Audit-log event type. We accept any string so host apps can add their
// own event names without forking the package. The exported union below
// lists the canonical events written by the package itself.
export type AuthKitAuditEvent =
  | "login.success"
  | "login.failure"
  | "login.locked"
  | "login.totp_required"
  | "login.totp_failure"
  | "login.recovery_used"
  | "logout"
  | "password.reset_requested"
  | "password.reset_completed"
  | "password.weak_rejected"
  | "password.changed"
  | "totp.enabled"
  | "totp.disabled"
  | "totp.reenrolled"
  | "totp.recovery_regenerated"
  | "email.verification_sent"
  | "email.verified"
  | "email.verification_failed"
  | "oauth.signin"
  | "oauth.signin_failed"
  | "user.registered"
  | "register.duplicate";

export async function writeAuditLog(params: {
  userId?: string | null;
  event: AuthKitAuditEvent | (string & {});
  ip?: string | null;
  userAgent?: string | null;
  meta?: Record<string, unknown> | null;
}): Promise<void> {
  const { db, tables } = ctx();
  try {
    await db.insert(tables.auditLog).values({
      id: randomUUID(),
      userId: params.userId ?? null,
      event: params.event,
      ip: params.ip ?? null,
      userAgent: params.userAgent ?? null,
      meta: (params.meta ?? null) as any,
    });
  } catch (err) {
    console.error("[auth-kit:audit] failed to write event", params.event, err);
  }
}

export function safeStrEq(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Configured super-admin email (read from context). Returns true iff
// the supplied email matches the host-configured super-admin.
export function isConfiguredSuperAdmin(email: string | null | undefined): boolean {
  return isSuperAdminEmailRaw(email, ctx().config.superAdminEmail);
}

// Re-export for consumer convenience.
export { isSuperAdminEmailRaw as isSuperAdminEmail };

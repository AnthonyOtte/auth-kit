// CSRF protection for the OAuth code flow.
//
// Both the `state` (round-trip CSRF token) and the `nonce` (binding the
// id_token to this browser session) are signed with HMAC-SHA256 using
// SESSION_SECRET so the callback can verify them without a server-side
// store. Each is delivered to the browser as a short-lived, secure,
// httpOnly cookie scoped to the OAuth callback paths.

import crypto from "crypto";
import type { Request, Response } from "express";

const STATE_COOKIE = "oauth_state";
const NONCE_COOKIE = "oauth_nonce";
const RETURN_COOKIE = "oauth_return";
const COOKIE_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes

function getSecret(): string {
  const s = process.env.SESSION_SECRET;
  if (!s) {
    throw new Error(
      "SESSION_SECRET is required to sign OAuth state cookies. Set it as an environment secret.",
    );
  }
  return s;
}

function sign(value: string): string {
  return crypto.createHmac("sha256", getSecret()).update(value).digest("hex");
}

function makeSigned(): { raw: string; signed: string } {
  const raw = crypto.randomBytes(24).toString("hex");
  return { raw, signed: `${raw}.${sign(raw)}` };
}

function verifySigned(signed: string): string | null {
  if (!signed || typeof signed !== "string") return null;
  const idx = signed.lastIndexOf(".");
  if (idx <= 0) return null;
  const raw = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expected = sign(raw);
  if (
    sig.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
  ) {
    return null;
  }
  return raw;
}

export interface OAuthStartCookies {
  state: string;
  nonce: string;
}

export function issueOAuthCookies(
  res: Response,
  options: { provider: string; returnTo?: string | null } = { provider: "" },
): OAuthStartCookies {
  const { signed: stateSigned, raw: stateRaw } = makeSigned();
  const { signed: nonceSigned, raw: nonceRaw } = makeSigned();
  const cookieBase = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: COOKIE_MAX_AGE_MS,
    path: "/api/auth/oauth",
  };
  res.cookie(STATE_COOKIE, stateSigned, cookieBase);
  res.cookie(NONCE_COOKIE, nonceSigned, cookieBase);
  if (options.returnTo) {
    const safe = sanitizeReturnTo(options.returnTo);
    if (safe) res.cookie(RETURN_COOKIE, safe, cookieBase);
  }
  return { state: stateRaw, nonce: nonceRaw };
}

function clearCookies(res: Response): void {
  const opts = { path: "/api/auth/oauth" };
  res.clearCookie(STATE_COOKIE, opts);
  res.clearCookie(NONCE_COOKIE, opts);
  res.clearCookie(RETURN_COOKIE, opts);
}

export interface OAuthVerifiedState {
  expectedNonce: string;
  returnTo: string;
}

export function verifyOAuthState(
  req: Request,
  res: Response,
  receivedState: string | undefined | null,
  defaultReturnTo: string = "/",
): OAuthVerifiedState | null {
  const stateCookie = (req as any).cookies?.[STATE_COOKIE] as string | undefined;
  const nonceCookie = (req as any).cookies?.[NONCE_COOKIE] as string | undefined;
  const returnCookie = (req as any).cookies?.[RETURN_COOKIE] as string | undefined;
  clearCookies(res);

  if (!receivedState || typeof receivedState !== "string") return null;
  if (!stateCookie || !nonceCookie) return null;

  const expectedState = verifySigned(stateCookie);
  const expectedNonce = verifySigned(nonceCookie);
  if (!expectedState || !expectedNonce) return null;

  if (
    receivedState.length !== expectedState.length ||
    !crypto.timingSafeEqual(Buffer.from(receivedState), Buffer.from(expectedState))
  ) {
    return null;
  }

  return {
    expectedNonce,
    returnTo: sanitizeReturnTo(returnCookie ?? null) ?? defaultReturnTo,
  };
}

export function sanitizeReturnTo(value: string | null | undefined): string | null {
  if (!value || typeof value !== "string") return null;
  if (!value.startsWith("/")) return null;
  if (value.startsWith("//")) return null;
  if (value.length > 512) return null;
  return value;
}

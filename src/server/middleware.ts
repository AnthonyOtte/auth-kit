// Session-cookie middleware. Cookie name is fixed at "session_token";
// override only if you really need to (e.g. running two auth-kit-backed
// apps on the same parent domain).

import type { Request, Response, NextFunction } from "express";
import { validateSession } from "./auth";
import { isConfiguredSuperAdmin } from "./security";

const SESSION_COOKIE_NAME = "session_token";

declare global {
  namespace Express {
    interface Request {
      // Host augments this with their full UserDb shape.
      user?: any;
    }
  }
}

export function getSessionToken(req: Request): string | null {
  return (req as any).cookies?.[SESSION_COOKIE_NAME] || null;
}

export function setSessionCookie(res: Response, token: string): void {
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = getSessionToken(req);
  if (!token) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  const user = await validateSession(token);
  if (!user) {
    clearSessionCookie(res);
    res.status(401).json({ error: "Invalid or expired session" });
    return;
  }
  req.user = user;
  next();
}

export async function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = getSessionToken(req);
  if (!token) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  const user = await validateSession<{ role?: string }>(token);
  if (!user) {
    clearSessionCookie(res);
    res.status(401).json({ error: "Invalid or expired session" });
    return;
  }
  if (user.role !== "admin") {
    res.status(403).json({ error: "Admin access required" });
    return;
  }
  req.user = user;
  next();
}

export async function requireSuperAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = getSessionToken(req);
  if (!token) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  const user = await validateSession<{ role?: string; email?: string }>(token);
  if (!user) {
    clearSessionCookie(res);
    res.status(401).json({ error: "Invalid or expired session" });
    return;
  }
  if (user.role !== "admin" || !isConfiguredSuperAdmin(user.email)) {
    res.status(403).json({ error: "Super-admin access required" });
    return;
  }
  req.user = user;
  next();
}

export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = getSessionToken(req);
  if (token) {
    const user = await validateSession(token);
    if (user) req.user = user;
  }
  next();
}

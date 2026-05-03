// A single super-admin email is allowed to perform privileged actions
// (mint credits, etc.). The host configures this via initAuthKit().
//
// Compare case-insensitively. Empty/null is never a super-admin.
export function isSuperAdminEmail(
  email: string | null | undefined,
  configured: string | null | undefined,
): boolean {
  if (!email || !configured) return false;
  return email.toLowerCase() === configured.toLowerCase();
}

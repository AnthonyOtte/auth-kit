// Per-provider OIDC config + token exchange + id_token verification.
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from "jose";

export type OAuthProviderId = "google" | "microsoft";

export interface OAuthIdentity {
  provider: OAuthProviderId;
  subject: string;
  email: string;
  emailVerified: boolean;
  name?: string | null;
}

export interface ProviderConfig {
  id: OAuthProviderId;
  label: string;
  scopes: string[];
  authorizeUrl: () => string;
  tokenUrl: () => string;
  issuer: () => string | string[];
  jwksUri: () => string;
  isConfigured: () => boolean;
  clientId: () => string;
  clientSecret: () => string;
}

const google: ProviderConfig = {
  id: "google",
  label: "Google",
  scopes: ["openid", "email", "profile"],
  authorizeUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUrl: () => "https://oauth2.googleapis.com/token",
  issuer: () => ["https://accounts.google.com", "accounts.google.com"],
  jwksUri: () => "https://www.googleapis.com/oauth2/v3/certs",
  isConfigured: () =>
    !!process.env.GOOGLE_OAUTH_CLIENT_ID &&
    !!process.env.GOOGLE_OAUTH_CLIENT_SECRET,
  clientId: () => process.env.GOOGLE_OAUTH_CLIENT_ID ?? "",
  clientSecret: () => process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? "",
};

function msTenant(): string {
  const t = process.env.MICROSOFT_OAUTH_TENANT_ID?.trim();
  return t || "common";
}

const microsoft: ProviderConfig = {
  id: "microsoft",
  label: "Microsoft",
  scopes: ["openid", "email", "profile"],
  authorizeUrl: () =>
    `https://login.microsoftonline.com/${msTenant()}/oauth2/v2.0/authorize`,
  tokenUrl: () =>
    `https://login.microsoftonline.com/${msTenant()}/oauth2/v2.0/token`,
  issuer: () => `https://login.microsoftonline.com/${msTenant()}/v2.0`,
  jwksUri: () =>
    `https://login.microsoftonline.com/${msTenant()}/discovery/v2.0/keys`,
  isConfigured: () =>
    !!process.env.MICROSOFT_OAUTH_CLIENT_ID &&
    !!process.env.MICROSOFT_OAUTH_CLIENT_SECRET,
  clientId: () => process.env.MICROSOFT_OAUTH_CLIENT_ID ?? "",
  clientSecret: () => process.env.MICROSOFT_OAUTH_CLIENT_SECRET ?? "",
};

const PROVIDERS: Record<OAuthProviderId, ProviderConfig> = { google, microsoft };

export function getProvider(id: string): ProviderConfig | null {
  if (id !== "google" && id !== "microsoft") return null;
  return PROVIDERS[id];
}

export function listConfiguredProviders(): Record<OAuthProviderId, boolean> {
  return {
    google: google.isConfigured(),
    microsoft: microsoft.isConfigured(),
  };
}

export function buildAuthorizeUrl(
  provider: ProviderConfig,
  args: { redirectUri: string; state: string; nonce: string },
): string {
  const params = new URLSearchParams({
    client_id: provider.clientId(),
    response_type: "code",
    redirect_uri: args.redirectUri,
    scope: provider.scopes.join(" "),
    state: args.state,
    nonce: args.nonce,
    prompt: "select_account",
  });
  if (provider.id === "microsoft") {
    params.set("response_mode", "query");
  }
  return `${provider.authorizeUrl()}?${params.toString()}`;
}

const JWKS_CACHE: Partial<Record<OAuthProviderId, ReturnType<typeof createRemoteJWKSet>>> = {};

function getJwks(provider: ProviderConfig) {
  const cached = JWKS_CACHE[provider.id];
  if (cached) return cached;
  const jwks = createRemoteJWKSet(new URL(provider.jwksUri()));
  JWKS_CACHE[provider.id] = jwks;
  return jwks;
}

export async function exchangeCodeAndVerify(
  provider: ProviderConfig,
  args: { code: string; redirectUri: string; expectedNonce: string },
): Promise<OAuthIdentity> {
  const body = new URLSearchParams({
    code: args.code,
    client_id: provider.clientId(),
    client_secret: provider.clientSecret(),
    redirect_uri: args.redirectUri,
    grant_type: "authorization_code",
  });

  const tokenRes = await fetch(provider.tokenUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });

  if (!tokenRes.ok) {
    const errText = await tokenRes.text().catch(() => "(no body)");
    throw new Error(
      `OAuth token exchange failed (${provider.id}): ${tokenRes.status} ${errText.slice(0, 200)}`,
    );
  }

  const tokenJson = (await tokenRes.json()) as { id_token?: string };
  const idToken = tokenJson.id_token;
  if (!idToken) {
    throw new Error(`OAuth provider ${provider.id} did not return an id_token`);
  }

  const jwks = getJwks(provider);
  const issuer = provider.issuer();
  let payload: JWTPayload;
  try {
    if (provider.id === "microsoft") {
      const verified = await jwtVerify(idToken, jwks, { audience: provider.clientId() });
      payload = verified.payload;
      const iss = String(payload.iss ?? "");
      const validPrefix = "https://login.microsoftonline.com/";
      const validSuffix = "/v2.0";
      if (!iss.startsWith(validPrefix) || !iss.endsWith(validSuffix)) {
        throw new Error(`Unexpected Microsoft issuer: ${iss}`);
      }
    } else {
      const verified = await jwtVerify(idToken, jwks, {
        issuer,
        audience: provider.clientId(),
      });
      payload = verified.payload;
    }
  } catch (err: any) {
    throw new Error(
      `OAuth id_token verification failed (${provider.id}): ${err?.message ?? err}`,
    );
  }

  if (payload.nonce !== args.expectedNonce) {
    throw new Error(`OAuth id_token nonce mismatch (${provider.id})`);
  }

  const sub = String(payload.sub ?? "");
  const email = String(payload.email ?? "");
  if (!sub) throw new Error(`OAuth id_token missing sub claim (${provider.id})`);
  if (!email) throw new Error(`OAuth id_token missing email claim (${provider.id})`);

  let emailVerified = false;
  if (provider.id === "google") {
    emailVerified = payload.email_verified === true;
  } else {
    emailVerified =
      payload.email_verified === true || payload.email_verified === undefined;
  }

  const name =
    typeof payload.name === "string"
      ? payload.name
      : typeof (payload as any).given_name === "string"
        ? ((payload as any).given_name as string)
        : null;

  return { provider: provider.id, subject: sub, email, emailVerified, name };
}

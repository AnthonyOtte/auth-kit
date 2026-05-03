// Server-side surface of @anthonyotte/auth-kit.
//
// Call `initAuthKit({ db, tables, config })` once at app startup before
// using any of the helpers below. After that, every helper reads the
// configured db / tables / brand info lazily, so the call style mirrors
// what you'd write inline in your own app.

export {
  initAuthKit,
  ctx,
  __resetAuthKitForTests,
  type AuthKitTables,
  type AuthKitConfig,
  type AuthKitContext,
} from "./context";

export * from "./security";
export * from "./auth";
export * from "./middleware";
export * as oauth from "./oauth";
export {
  // Convenience top-level re-exports for the common OAuth helpers.
  issueOAuthCookies,
  verifyOAuthState,
  sanitizeReturnTo,
  getProvider,
  listConfiguredProviders,
  buildAuthorizeUrl,
  exchangeCodeAndVerify,
  type OAuthProviderId,
  type OAuthIdentity,
  type ProviderConfig,
} from "./oauth";

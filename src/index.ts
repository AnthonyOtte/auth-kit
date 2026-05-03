// Top-level barrel — re-exports the shared schema/types only. Server
// code is reached via "@anthonyotte/auth-kit/server" and client code
// via "@anthonyotte/auth-kit/client" so importing the top-level entry
// from the browser doesn't drag node-only deps (bcrypt, jose, etc.)
// into the bundle.
export * from "./shared";

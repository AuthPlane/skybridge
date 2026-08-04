import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { JwksVerifyConfig } from "./verify.js";

/**
 * An {@link OAuthConfig} whose `verify` is JWKS-config-shaped. This is what
 * the bundled providers return: the framework performs the JWT verification,
 * and callers can still read and tweak `verify.issuer` / `verify.audience`.
 */
export type JwksOAuthConfig = OAuthConfig & { verify: JwksVerifyConfig };

/** Resource-server OAuth config for `SkybridgeServerOptions.oauth`. */
export type OAuthConfig = {
  /**
   * Public URL of this server; sets `resourceServerUrl` and the
   * `resource_metadata` URL. When omitted, it is inferred per request from
   * `x-forwarded-host`/`origin`/`host` headers.
   */
  baseUrl?: string;
  /** AS metadata served at `/.well-known/oauth-authorization-server`. */
  oauthMetadata: OAuthMetadata;
  /**
   * How `/mcp` bearer tokens are verified: either a `JwksVerifyConfig`
   * describing a JWKS endpoint (JWT verification handled by the framework),
   * or a caller-supplied `OAuthTokenVerifier` for anything the JWKS path
   * cannot express — token introspection, revocation checks, custom claim
   * mapping, or an identity provider's own SDK. A custom verifier resolves
   * with `AuthInfo` or throws `InvalidTokenError`/`InsufficientScopeError`
   * from `@modelcontextprotocol/sdk`, exactly as with `requireBearerAuth`.
   */
  verify: JwksVerifyConfig | OAuthTokenVerifier;
  /** Scopes advertised in protected-resource metadata. */
  scopesSupported?: string[];
  /** Server-wide required-scope floor. */
  requiredScopes?: string[];
};

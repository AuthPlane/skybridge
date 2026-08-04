import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { JwksVerifyConfig } from "./verify.js";

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
  verify: JwksVerifyConfig;
  /**
   * Creates the token verifier for this config. When omitted, Skybridge's
   * built-in JWKS verifier, configured by `verify`, is used.
   */
  createVerifier?: (config: OAuthConfig) => OAuthTokenVerifier;
  /** Scopes advertised in protected-resource metadata. */
  scopesSupported?: string[];
  /** Server-wide required-scope floor. */
  requiredScopes?: string[];
};

import { authplaneMcpAuth } from "@authplane/mcp";
import { type AuthInfo, authplaneProvider, McpServer } from "skybridge/server";
import * as z from "zod";
import { env } from "./env.js";

/**
 * Auth Example - Authplane SDK verifier through `createVerifier`
 *
 * Same shape as the `auth-authplane` example, but token verification is done
 * by the Authplane SDK (`@authplane/mcp`) instead of Skybridge's built-in
 * JWKS verifier: `authplaneProvider` still supplies the discovery metadata
 * config, and `createVerifier` hands Skybridge the SDK's `tokenVerifier`.
 *
 * What the SDK adds over the built-in path: hardened JWT validation
 * (algorithm pinning, mandatory audience binding, `typ` checking), RFC 8414
 * metadata and JWKS caches with stale-while-revalidate background refresh,
 * and a circuit breaker on authorization-server calls. The refresh windows
 * here are deliberately short so the background refreshes are observable —
 * see `smoke/run.mjs`, which exercises all of it end to end.
 *
 * Scope enforcement stays entirely with Skybridge: the `requiredScopes`
 * floor plus per-tool scopes declared in each tool's `auth` shorthand.
 */

const scopesSupported = ["profile", "report:read", "report:admin"];

// The SDK client does its own RFC 8414 discovery and JWKS priming at boot
// (providers are async), then `createVerifier` below hands Skybridge the
// prepared verifier synchronously.
const auth = await authplaneMcpAuth({
  issuer: env.AUTHPLANE_ISSUER,
  resource: env.SERVER_URL,
  scopes: scopesSupported,
  requiredScopes: [],
  jwksRefreshSeconds: env.JWKS_REFRESH_SECONDS,
  metadataRefreshSeconds: env.METADATA_REFRESH_SECONDS,
  // Allows http:// issuers for local development against a local
  // authorization server; harmless for https deployments.
  devMode: env.AUTHPLANE_ISSUER.startsWith("http://"),
});

const oauth = await authplaneProvider({
  issuer: env.AUTHPLANE_ISSUER,
  resource: env.SERVER_URL,
  scopes: scopesSupported,
  requiredScopes: ["profile"],
});
oauth.createVerifier = () => auth.tokenVerifier;

const server = new McpServer(
  {
    name: "auth-sdk-reports",
    version: "0.0.1",
  },
  { capabilities: {} },
  { oauth },
)
  .registerTool(
    {
      name: "whoami",
      description:
        "Returns the authenticated caller's identity as seen by the Authplane SDK verifier. Requires authentication.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
      auth: {},
    },
    (_args, extra) => {
      const info = extra.authInfo as AuthInfo;
      return {
        structuredContent: {
          clientId: info.clientId,
          scopes: info.scopes,
          subject: (info.extra?.subject as string | undefined) ?? null,
        },
        content: [
          {
            type: "text",
            text: `client=${info.clientId} scopes=${info.scopes.join(" ")}`,
          },
        ],
      };
    },
  )
  .registerTool(
    {
      name: "read-report",
      description: "Reads a report. Requires the report:read scope.",
      inputSchema: {
        id: z.string().describe("Report identifier"),
      },
      annotations: { readOnlyHint: true },
      auth: { scopes: ["report:read"] },
    },
    ({ id }) => ({
      structuredContent: { id, status: "ok" },
      content: [{ type: "text", text: `report ${id}: all systems nominal` }],
    }),
  )
  .registerTool(
    {
      name: "admin-report",
      description:
        "Rebuilds the report index. Requires the report:admin scope.",
      inputSchema: {},
      auth: { scopes: ["report:admin"] },
    },
    () => ({
      structuredContent: { rebuilt: true },
      content: [{ type: "text", text: "report index rebuilt" }],
    }),
  );

export default await server.run();

export type AppType = typeof server;

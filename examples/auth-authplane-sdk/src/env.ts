import "dotenv/config";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got ${raw}`);
  }
  return parsed;
}

export const env = {
  NODE_ENV:
    (process.env.NODE_ENV as "development" | "production") || "development",
  /** Authplane authorization server URL. */
  AUTHPLANE_ISSUER: requireEnv("AUTHPLANE_ISSUER"),
  /**
   * Public URL of this MCP server — its resource identifier and expected
   * token audience. Must match the string registered in Authplane.
   */
  SERVER_URL: process.env.SERVER_URL || "http://localhost:3000/mcp",
  /**
   * Short refresh windows so the SDK's stale-while-revalidate refresh of
   * JWKS and AS metadata is observable while exercising the server.
   */
  JWKS_REFRESH_SECONDS: intEnv("JWKS_REFRESH_SECONDS", 5),
  METADATA_REFRESH_SECONDS: intEnv("METADATA_REFRESH_SECONDS", 5),
};

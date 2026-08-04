# Auth Example — Authplane SDK verifier via `createVerifier`

Same deployment shape as the `auth-authplane` example, but token verification
is performed by the Authplane SDK (`@authplane/mcp`) instead of Skybridge's
built-in JWKS verifier: `authplaneProvider` still supplies the discovery
metadata config, and `createVerifier` hands Skybridge the SDK's
`tokenVerifier`.

What the SDK path adds over the built-in verifier:

- hardened JWT validation (algorithm pinning, mandatory audience binding,
  `typ`/`jti` checks),
- RFC 8414 metadata + JWKS caches with stale-while-revalidate background
  refresh (`jwksRefreshSeconds` / `metadataRefreshSeconds`),
- a circuit breaker on authorization-server calls.

Scope enforcement stays entirely with Skybridge: the `requiredScopes` floor
(`profile`) plus per-tool scopes (`report:read`, `report:admin`) declared in
each tool's `auth` shorthand.

> The `@authplane/mcp` / `@authplane/sdk` dependencies are linked from a
> local checkout (`file:`) until the error-bridge release ships on npm.

## Smoke test

`pnpm smoke` boots a fake authorization server (rotatable keys, fetch
counters) plus this example, and asserts the full matrix: challenge shapes
(401/403 with `resource_metadata`), per-tool scope enforcement, happy path
through a real MCP client, JWKS background refresh under traffic, and key
rotation (new key accepted, withdrawn key rejected).

## Running against a real Authplane server

```sh
docker run -d -p 9000:9000 -p 9001:9001 \
  -e AUTHPLANE_SERVER_ISSUER=http://localhost:9000 \
  -e AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true \
  -e AUTHPLANE_ADMIN_ENABLED=true -e AUTHPLANE_ADMIN_ADDRESS=:9001 \
  -e AUTHPLANE_ADMIN_API_KEY=<admin-key> \
  --name authserver authplane/authserver:latest
```

1. Register the resource (Admin API): `POST /admin/resources` with
   `uri = SERVER_URL` and the three scopes above.
2. Create a client with scopes: `POST /admin/clients` with
   `"scope": "profile report:read report:admin"` and the
   `client_credentials` grant. (Open DCR registers clients but does not
   grant scopes, and the token endpoint fails closed on scope requests
   exceeding the client's registration.)
3. Start this server:
   `AUTHPLANE_ISSUER=http://localhost:9000 SERVER_URL=http://localhost:3000/mcp pnpm start`
4. Mint tokens with `grant_type=client_credentials`, a `scope`, and
   `resource=<SERVER_URL>` — the token `aud` is bound to the resource and
   verified by the SDK.

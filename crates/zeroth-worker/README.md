# zeroth-worker

Cloudflare Worker deployment surface for Zeroth.

This crate is intentionally separate from `zeroth-server` so Cloudflare-specific
bindings, Wrangler config, D1 migrations, and Worker runtime APIs do not leak
into the generic server/domain crates.

## Bindings

```toml
[[d1_databases]]
binding = "ZEROTH_DB"
database_name = "zeroth"
database_id = "..."
```

`PRODUCT_NAME` optionally brands the hosted Leptos UI without changing generic
code. `PUBLIC_BASE_URL` must be the deployed issuer origin because the Worker
uses it for provider callbacks, discovery metadata, and same-origin UI API
requests.

`DEFAULT_LOGIN_CLIENT_ID` optionally selects the registered client used by hosted
browser login URLs that omit `client_id`, for example `/login?return_to=...`.

`APPLE_APP_SITE_ASSOCIATION_JSON` optionally serves the public Apple App Site
Association payload at `/.well-known/apple-app-site-association`.

`ADMIN_TOKEN` or `ADMIN_TOKEN_SHA256` enables the minimal management APIs and
schema bootstrap endpoint. `ADMIN_TOKEN` is the plaintext bearer token stored as
a Wrangler secret. `ADMIN_TOKEN_SHA256` is the SHA-256 hex digest of that token,
optionally prefixed with `sha256:`. If both are present, the hash setting wins.
After the first admin user has logged in through Zeroth, `ADMIN_USER_IDS` and
`ADMIN_EMAILS` can allow that first-party browser session to call the same admin
APIs. `ADMIN_EMAILS` only matches verified primary emails.

`POST /__zeroth/db/ensure` creates the generic migration ledger, applies
embedded migrations that are not yet recorded in `zeroth_schema_migrations`, and
repairs compatibility columns exported by `zeroth-storage` when the request
includes `Authorization: Bearer <ADMIN_TOKEN>`. The JSON response reports
`migrationsApplied` and `migrationsSkipped`. Registered clients live in
`zeroth_clients`; `/authorize` will not redirect to an upstream provider until
the `client_id` and `redirect_uri` match a non-disabled row.

The same generic D1 SQL can be inspected or used by deployment scripts through
the CLI:

```sh
cargo run -p zeroth-cli -- schema
cargo run -p zeroth-cli -- schema --only compatibility --format lines
```

The CLI also validates locally supplied secret material without printing it:

```sh
printf "%s" "$JWT_ES256_PRIVATE_KEY" \
  | cargo run -p zeroth-cli -- validate-secret es256-private-key
printf "%s" "$APPLE_PRIVATE_KEY" \
  | cargo run -p zeroth-cli -- validate-secret apple-private-key
printf "%s" "$JWT_PREVIOUS_PUBLIC_JWKS_JSON" \
  | cargo run -p zeroth-cli -- validate-secret previous-public-jwks
```

Example public iOS client:

```sql
INSERT INTO zeroth_clients (
  id, name, confidential, redirect_uris_json, allowed_origins_json,
  allowed_email_domains_json, created_at, updated_at
) VALUES (
  'wavey-ios',
  'Wavey iOS',
  0,
  '["wavey://auth/callback"]',
  '[]',
  '[]',
  strftime('%s','now'),
  strftime('%s','now')
);
```

Example native loopback client:

```sql
INSERT INTO zeroth_clients (
  id, name, confidential, redirect_uris_json, allowed_origins_json,
  allowed_email_domains_json, created_at, updated_at
) VALUES (
  'infidelity-macos',
  'Infidelity macOS',
  0,
  '["http://localhost/oidc-callback"]',
  '[]',
  '[]',
  strftime('%s','now'),
  strftime('%s','now')
);
```

An unported loopback redirect such as `http://localhost/oidc-callback` allows
authorization requests with an ephemeral port on the same loopback host and
path, for example `http://localhost:49231/oidc-callback`. Custom-scheme and web
redirects still require exact registered URI matches.

Example web client:

```sql
INSERT INTO zeroth_clients (
  id, name, secret_hash, confidential, redirect_uris_json, allowed_origins_json,
  allowed_email_domains_json, created_at, updated_at
) VALUES (
  'wavey-web',
  'Wavey Web',
  'sha256:<sha256-hex-client-secret>',
  1,
  '["https://app.example.com/auth/callback"]',
  '["https://app.example.com"]',
  '["example.com"]',
  strftime('%s','now'),
  strftime('%s','now')
);
```

`allowed_email_domains_json` is optional client policy. Leave it as `[]` for
public clients that can accept any provider account, or set domains such as
`["example.com"]` to require a verified provider email whose domain matches the
client allowlist before Zeroth issues a session or authorization code.

For confidential clients, `secret_hash` is the SHA-256 hex digest of the client
secret, optionally prefixed with `sha256:`. `/oauth/token` accepts
`client_secret_post` and `client_secret_basic`.

The same rows can be managed through `/clients` without direct SQL:

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/clients"

curl -X POST "https://id.example.com/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "id": "wavey-ios",
    "name": "Wavey iOS",
    "redirectUris": ["wavey://auth/callback"],
    "allowedOrigins": [],
    "allowedEmailDomains": [],
    "confidential": false
  }'

curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/clients?client_id=old-client"
```

`GET /clients?client_id=...` returns one client; `GET /clients` returns at most
256 clients. `POST /clients` creates or updates a client. Confidential clients
may send `clientSecret` to have Zeroth hash it, or `secretHash` when the hash is
already produced outside the Worker. `allowedEmailDomains` accepts up to 32
ASCII domains and requires provider emails to be verified before matching.
`DELETE /clients?client_id=...` disables the client instead of deleting the row.

`GET /ready` is the public deployment preflight endpoint. It returns `200` only
when the issuer URL is HTTPS, Zeroth signing material is present and parseable,
and Apple, Google, and Spotify provider credentials are configured. Empty values
and scaffold placeholders such as `replace-with-*`, `changeme`, or `<...>` are
treated as unconfigured so local templates cannot accidentally pass a live
readiness check. It also reports Apple App Site Association JSON status without
making that optional file block readiness.

`GET /admin` and `GET /admin/clients` serve the Leptos management UI for the
same APIs. The page can use the current Zeroth session when the user is
allowlisted by `ADMIN_USER_IDS` or `ADMIN_EMAILS`; it also accepts the bootstrap
admin bearer token in the browser and stores that token only in `sessionStorage`
for the current tab session. The admin page includes a first-party sign-in link
to `/login?return_to=<issuer>/admin`; issuer-origin `/admin` and
`/admin/clients` returns are allowed only for the hosted management UI. The UI
also renders the admin-only D1 schema status from `/__zeroth/db/status` before
loading D1-backed users, events, and clients, so an incomplete database shows
actionable missing-table or pending-migration rows. API writes still go through
`/clients`, `/users`, `/events`, and `/providers/status`, so direct JSON and the
UI share validation and D1 persistence.

The embedded schema bootstrap endpoint is admin-only:

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/__zeroth/db/status"

curl -X POST "https://id.example.com/__zeroth/db/ensure" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

`GET /__zeroth/db/status` is read-only and reports whether required D1 tables,
embedded migrations, compatibility columns, and any registered clients are
present. It is separate from public `/ready` so launch checks can verify D1
persistence without adding D1 reads to the fast public readiness path.

User and provider management are also exposed as bounded JSON APIs:

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/providers/status"

curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/users"

curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/users?user_id=usr_123"

curl -X PATCH "https://id.example.com/users?user_id=usr_123" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"disabled":true}'

curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://id.example.com/events"
```

`GET /users` returns at most 100 users ordered by recent update time.
`GET /users?user_id=...` returns a single user with linked identities and active
sessions. `PATCH /users?user_id=...` reversibly disables or enables the user;
disabling also revokes active browser sessions and active refresh tokens, but it
does not delete the user or identity rows.

`GET /events` returns at most 100 recent audit events. It accepts exact-match
filters for `event_type`, `user_id`, `client_id`, and `provider_id`. Events
store event metadata, hashed IP, user agent, and a small details JSON object;
Zeroth does not write provider secrets, access tokens, refresh tokens, auth
codes, or session cookie values into audit details. The hosted admin UI exposes
the same event filters and sends them directly to `/events`.

Browser calls use `allowed_origins_json` for CORS. Zeroth answers preflight for
`/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/userinfo`, `/session`,
`/sessions`, `/profile`, `/identities/link`, `/identities`, `/validate`, and
`/logout` only when the `Origin` exactly matches a non-disabled registered
client's allowed origin.

## Secrets

Provider secrets should be configured with Wrangler secrets:

```sh
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put APPLE_CLIENT_ID
wrangler secret put APPLE_CLIENT_SECRET # or APPLE_TEAM_ID/APPLE_KEY_ID/APPLE_PRIVATE_KEY
wrangler secret put SPOTIFY_CLIENT_ID
wrangler secret put SPOTIFY_CLIENT_SECRET
wrangler secret put JWT_ES256_PRIVATE_KEY
wrangler secret put JWT_KEY_ID
wrangler secret put JWT_PREVIOUS_PUBLIC_JWKS_JSON # optional rotation-only public JWKS
wrangler secret put ADMIN_TOKEN # or ADMIN_TOKEN_SHA256
wrangler secret put ADMIN_USER_IDS # optional first-party admin session allowlist
wrangler secret put ADMIN_EMAILS # optional verified primary-email allowlist
wrangler secret put APPLE_APP_SITE_ASSOCIATION_JSON # optional public AASA payload
```

Non-secret deployment vars include `PUBLIC_BASE_URL`, `SESSION_COOKIE_NAME`,
`TX_COOKIE_NAME`, and optional `SESSION_COOKIE_DOMAIN`. Leave
`SESSION_COOKIE_DOMAIN` unset for a host-only Zeroth session cookie, or set it
to a parent domain such as `.example.com` when one first-party registrable
domain owns multiple subdomain apps. This is the Zeroth-native equivalent of
the useful shared-cookie behavior from a deployment-specific identity broker;
unrelated domains still need OIDC redirects and app-local sessions.

Apple can be configured in either of two ways:

- `APPLE_CLIENT_SECRET`: a pre-minted Sign in with Apple client-secret JWT.
- `APPLE_TEAM_ID`, `APPLE_KEY_ID`, and `APPLE_PRIVATE_KEY`: Zeroth mints and
  caches the client-secret JWT at runtime. `APPLE_PRIVATE_KEY` is the `.p8` PKCS
  #8 PEM content; escaped `\n` newlines are accepted. `APPLE_CLIENT_SECRET_TTL_SECONDS`
  optionally sets the JWT TTL and is capped at Apple's 180-day maximum.

A test `APPLE_CLIENT_SECRET` can still be minted locally without changing Apple
Developer records:

```sh
cargo run -p zeroth-cli -- apple-client-secret \
  --team-id "$APPLE_TEAM_ID" \
  --key-id "$APPLE_KEY_ID" \
  --client-id "$APPLE_CLIENT_ID" \
  --private-key "$APPLE_PRIVATE_KEY_PATH"
```

For Zeroth-owned tokens, `JWT_ES256_PRIVATE_KEY` is a 32-byte P-256 private
scalar encoded as base64url, base64, hex, or a private JWK with `d`.
`JWT_KEY_ID` is published in `/.well-known/jwks.json`. Generate a fresh issuer
signing key locally with:

```sh
cargo run -p zeroth-cli -- signing-key --kid zeroth-es256-1
```

Use `--format json` when you want to retain the public JWKS record alongside the
secret value for future rotation notes.
`JWT_PREVIOUS_PUBLIC_JWKS_JSON` optionally publishes retired ES256 public keys
alongside the active key during signing-key rotation. It must be a JWKS object
with public `EC`/`P-256`/`ES256` signing keys only. The active `JWT_KEY_ID`
key is always emitted first and wins duplicate `kid` values. Zeroth also uses
those configured public keys to verify access tokens, introspection requests,
and logout `id_token_hint` values during the rotation window.

## CPU Budget

Zeroth is intended to stay inside the Workers Free 10 ms CPU budget for normal
API calls. Network and D1 wait time are wall time, not CPU time, but local JSON,
hashing, JWT signing/verification, and loops count.

Current guardrails:

- ES256 signing material, derived JWKS, and derived verification keys are parsed
  once per isolate and reused until `JWT_KEY_ID`, `JWT_ES256_PRIVATE_KEY`, or
  `JWT_PREVIOUS_PUBLIC_JWKS_JSON` changes.
- Apple client-secret JWTs can be minted from deployment key material and cached
  per isolate until one hour before expiry, avoiding per-request PEM parsing.
- Apple/Google provider JWKS responses are cached per isolate with a short TTL,
  so repeated provider callbacks do not refetch and reparse the same key set.
- Apple/Google provider ID-token signatures are verified with Workers WebCrypto
  on the wasm Worker path instead of pure Rust RSA.
- Token issuance performs a single compact D1 user-claims lookup before signing
  so disabled users are rejected and scoped ID-token claims do not require
  unbounded identity scans.
- Token introspection verifies Zeroth access tokens locally before D1 checks,
  requires confidential client authentication, and returns the compact inactive
  RFC7662 response for invalid, disabled-user, disabled-client, or revoked
  session-bound tokens.
- Session-bound access and ID tokens include the standard `sid` claim, and
  token validation/introspection require the referenced D1 session to still be
  active before exposing that same session id to relying services.
- Auth-code consumption and refresh-token rotation use conditional indexed D1
  updates and `changes` metadata, avoiding extra post-write scans on the token
  endpoint.
- Provider callback state consumption uses the same conditional D1 metadata
  check before upstream token exchange, profile upsert, session creation, or
  Zeroth code issuance.
- Provider callbacks must also match a short-lived HttpOnly transaction cookie
  scoped to `/oauth2/callback`; it uses `SameSite=None` so Apple's cross-site
  `form_post` callback can still carry it.
- List endpoints are bounded: `/sessions` returns at most 100 active sessions,
  `/identities` returns at most 16 linked provider identities, `/clients`
  returns at most 256 registered clients, `/users` returns at most 100 users,
  and `/events` returns at most 100 audit events.
- List queries use D1 indexes that match the bounded lookup shape so Worker code
  does not sort or scan unbounded rows.
- Event inspection stays bounded even when filtered because `/events` uses
  exact-match query parameters with indexed lookups and a fixed 100-row limit.
- Management writes are bounded: `POST /clients` accepts only JSON bodies up to
  8 KiB, validates at most 32 redirect URIs, 32 allowed origins, and 32 allowed
  email domains, and uses a single D1 upsert. `PATCH /users` accepts only a 1
  KiB JSON body for the reversible disabled state.
- Audit details are bounded to 1 KiB and oversized details are replaced with a
  small truncation marker before they are inserted into D1.
- Profile writes are bounded: `PATCH /profile` accepts only JSON bodies up to 4
  KiB and validates the two mutable local profile fields before writing D1.
- Identity unlinking is guarded: `DELETE /identities` uses exact provider
  identity keys and will not remove the user's last linked identity.
- Identity linking is session-bound: `GET /identities/link` requires an active
  browser session, stores the target user/session on the provider transaction,
  and refuses callback completion if the identity belongs to another user.
- Request-path maintenance is bounded: `/authorize` and provider-selected
  `/login` delete at most 64 expired provider transactions before inserting the
  next one.
- Hosted UI rendering is server-side Leptos with inline CSS and a tiny inline
  form handler. `/login`, `/account`, `/admin`, and `/admin/clients` perform
  only bounded D1 reads already used by the API paths, and API endpoints do not
  render the UI.
- Anonymous CORS preflight scans at most 256 registered clients and skips JSON
  parsing for origin rows that cannot contain the request origin.
- Provider callback routes still perform provider token exchange and D1 writes.
  They should be measured in Workers Logs before relying on the Free plan for
  production traffic.

## Current Flow

- `GET /login` renders the hosted Leptos provider picker for either a valid OIDC
  authorization-code request or a browser-session login request such as
  `/login?client_id=wavey-web&return_to=https%3A%2F%2Fapp.example.com%2F`.
  If `client_id` is omitted, the Worker uses `DEFAULT_LOGIN_CLIENT_ID`. Browser
  login return URLs are validated against the selected client's registered
  redirect URIs or allowed origins.
- `GET /account` renders the hosted Leptos account UI for the current browser
  session, including local profile edits, linked identities, and active
  sessions. Identity-link returns to `/account` are allowed only on Zeroth's own
  issuer origin.
- `GET /admin` and `GET /admin/clients` render the hosted Leptos management UI
  for database status, providers, users, and registered clients. It can SSR
  bounded rows when the request includes a valid admin bearer token or an
  allowlisted Zeroth browser session. Without either, the page still loads and
  lets an operator enter the bootstrap token for the current browser tab or sign
  in through Zeroth. The client script also retries the same APIs with
  same-origin credentials so an allowlisted Zeroth session can administer the
  issuer without a bearer token in browser storage.
- `GET|POST|DELETE /clients` exposes registered-client management. It requires
  the admin bearer token or an allowlisted Zeroth browser session, returns safe
  client metadata without secret hashes, creates or updates clients with bounded
  JSON, hashes `clientSecret` when supplied, preserves an existing confidential
  secret when omitted, and disables clients instead of deleting rows. Disabled
  clients are hidden from authorization, token, resource, validation, and CORS
  checks.
- `GET|PATCH /users` exposes bounded user inspection and reversible disable or
  enable. Disabling revokes active sessions and active refresh tokens.
- `GET /ready` reports public launch readiness without D1 reads or secret
  values. It returns `503` until issuer, signing, and Apple/Google/Spotify
  provider configuration are ready.
- `GET /providers/status` reports Apple, Google, and Spotify readiness booleans
  to admins without returning configured secret values.
- `GET /__zeroth/db/status` reports admin-only D1 schema readiness and
  registered-client count without mutating the database.
- `GET /events` exposes recent audit events for admin troubleshooting. It is
  bounded to 100 rows and can filter by event type, user, client, or provider.
- `GET /authorize` parses an OIDC authorization-code request, requires `openid`
  scope, supports only query-mode downstream code responses, validates the
  registered client redirect URI, requires S256 PKCE for public clients, and
  renders the hosted provider picker when `provider` is omitted. When `provider`
  is Apple, Google, or Spotify, it stores a provider transaction in D1 and
  redirects upstream using Zeroth's `/oauth2/callback`.
  When the validated request uses `prompt=none` and no provider selection is
  required, Zeroth checks the existing browser session directly; an active
  session that satisfies `max_age` receives a Zeroth authorization code on the
  registered redirect URI, while a missing or too-old session redirects back
  with `login_required`, original `state`, and Zeroth's `iss` parameter.
  `prompt=login` and failed `max_age` checks suppress current-session reuse in
  the hosted provider picker. After the client and redirect URI are validated,
  authorization errors such as unsupported or unconfigured providers also
  redirect to the registered client with `error`, `error_description`, original
  `state`, and `iss` instead of returning JSON.
- `GET|POST /oauth2/callback` supports normal query callbacks and Apple's
  `form_post`, resolves the stored D1 transaction, requires the callback
  `state` to match the short-lived browser transaction cookie, requires the
  conditional D1 update that consumes the one-time provider state to report
  exactly one changed row, exchanges the provider code for upstream tokens,
  verifies Google/Apple RS256 ID tokens against provider JWKS and a
  Zeroth-owned provider nonce separate from the downstream app nonce, persists
  Google/Apple users/identities from verified claims, preserves Apple's
  first-consent `user` JSON for display-name capture, persists Spotify
  users/identities from Spotify's profile API, creates a D1-backed browser
  session, sets the secure session cookie, clears the transaction cookie, and
  then either redirects to the browser login `return_to` URL or issues a Zeroth
  authorization code and redirects to the registered OIDC
  client with query response parameters `code`, `state` when supplied, and
  `iss` set to Zeroth's issuer. Provider-side authorization errors such as user
  cancellation are also resolved through the stored D1 transaction, consume the
  one-time provider state, and redirect back with `error`,
  `error_description`, original app `state`, and `iss` for OIDC authorization
  responses instead of returning a generic JSON response.
- `POST /oauth/token` validates authorization-code exchanges, checks S256 PKCE
  for codes that were issued with a challenge, authenticates confidential
  clients with `client_secret_post` or `client_secret_basic`, and requires the
  conditional D1 update that consumes the Zeroth auth code to report exactly one
  changed row before credentials are minted. It reloads the D1 user before
  signing so missing/disabled users are rejected, optionally persists a hashed
  refresh token bound to the auth code's browser session and original
  `auth_time` when `offline_access` was requested, and returns ES256 access and
  ID tokens. ID tokens include standard `email`, `email_verified`, `name`, and
  `picture` claims only when the authorization scope requested `email` and/or
  `profile`; access and ID tokens include `sid` when they are tied to a browser
  session. The same endpoint also accepts
  `grant_type=refresh_token`, rejects expired/revoked/rotated refresh tokens,
  and requires the conditional D1 rotation update to report exactly one changed
  row before it stores and returns a replacement refresh token. If a rotated
  refresh token is presented again by the same client, or if the conditional
  rotation loses a race, Zeroth treats it as replay and revokes the active
  session-scoped refresh-token family before returning `invalid_grant`. Legacy
  refresh-token rows without a stored session id are still accepted and
  replay-revoked within their null-session user/client family.
- `GET /.well-known/openid-configuration` advertises the authorization,
  token, revocation, introspection, userinfo, JWKS, and end-session endpoints,
  ES256 token signing, `query` response mode, supported prompt values, and
  `authorization_response_iss_parameter_supported: true`. `prompt=none`
  performs silent SSO only with a fresh active session, `prompt=login` and
  `prompt=select_account` force the hosted picker to ignore the current session,
  and `prompt=consent` is parsed explicitly while remaining a no-op until
  consent records exist.
- `GET /.well-known/oauth-authorization-server` serves the same issuer-derived
  endpoint metadata for OAuth-only resource servers and advertises revocation
  and introspection client-auth methods.
- `POST /oauth/revoke` authenticates the registered client and revokes a matching
  Zeroth refresh token for that client. Unknown tokens, access-token hints, and
  tokens owned by another client are treated as successful no-ops.
- `POST /oauth/introspect` authenticates a confidential registered client and
  returns RFC7662-style metadata for active Zeroth access tokens. Refresh tokens
  introspect as active only for their owning client; invalid, expired, rotated,
  revoked, disabled-user, disabled-client, or revoked session-bound tokens
  return `{"active":false}`.
- `OPTIONS /oauth/token|/oauth/revoke|/oauth/introspect|/userinfo|/session|/sessions|/profile|/identities/link|/identities|/validate|/logout`
  handles browser CORS preflight for exact registered origins. Actual token,
  revocation, introspection, userinfo, session, sessions, profile, identities,
  validate, and logout responses include credentialed CORS headers only for
  origins allowed by the identified client or active session.
- `GET /.well-known/jwks.json` publishes the active ES256 public signing key
  plus optional previous public keys configured for rotation.
- `GET /.well-known/apple-app-site-association` serves the configured
  `APPLE_APP_SITE_ASSOCIATION_JSON` payload for deployments that use Apple
  associated domains.
- `GET /userinfo` verifies a Zeroth ES256 bearer access token, loads the user
  and active token client from D1, rejects disabled users or disabled/missing
  clients, rejects session-bound tokens whose D1 session is no longer active,
  and returns profile fields allowed by the token scope.
- `GET /session` reads the secure session cookie and returns authenticated
  browser-session state without treating an anonymous request as an error.
- `GET /sessions` lists the current user's active browser sessions. `DELETE
  /sessions?session_id=...` revokes a session owned by the current user, revokes
  that session's refresh-token family, and also clears the browser cookie when
  the current session is revoked.
- `GET /profile` requires an active browser session and returns the user's basic
  profile fields.
- `PATCH /profile` requires an active browser session and accepts a bounded
  `application/json` body with `name` or `displayName` and `picture` or
  `pictureUrl`. String values update local profile fields; `null` clears them.
- `GET /identities` requires an active browser session and returns the current
  user's linked Apple, Google, and Spotify provider identities without raw
  provider profile JSON.
- `GET /identities/link?provider=...&return_to=...` requires an active browser
  session, validates `return_to` against the session client's registered
  redirect URIs or allowed origins, starts an upstream Apple, Google, or Spotify
  authorization flow, and completes by linking the provider identity back to the
  current user.
- `DELETE /identities?provider_id=...&provider_subject=...` requires an active
  browser session and unlinks that provider identity only when it belongs to the
  current user and at least one other login identity remains.
- `GET /validate` verifies a Zeroth ES256 bearer access token or active browser
  session cookie, requires the referenced D1 user and client to still be active,
  requires session-bound access tokens to reference an active D1 session, and
  returns the validated subject, client, expiry, session id, and scoped profile
  payload.
- `GET|POST /logout` revokes the current browser session row and its
  refresh-token family when present, then clears the session cookie. It is also
  advertised as the OIDC
  `end_session_endpoint`: when `post_logout_redirect_uri` or `return_to` is
  present, Zeroth resolves the client from the active session, `client_id`, or a
  valid `id_token_hint`, validates the redirect against registered redirect URIs
  or allowed origins, appends `state` when present, and redirects after clearing
  the cookie.

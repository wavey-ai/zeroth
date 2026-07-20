# Zeroth

Zeroth is a minimal first-party identity provider and social login broker.

Designed for free-tier Cloudflare worker deployment.

It is intended to cover the Auth0-shaped role for owned products:

- hosted login
- upstream provider brokering
- OIDC authorization-code flow with PKCE
- browser sessions
- native app login for Swift/iOS clients

## Workspace

```text
zeroth
crates/zeroth-core
crates/zeroth-oidc
crates/zeroth-providers
crates/zeroth-storage
crates/zeroth-server
crates/zeroth-cli
crates/zeroth-ui
crates/zeroth-worker
```

The facade crate keeps the Leptos UI behind the optional `ui` feature so API and
Worker consumers do not pull UI dependencies by default.

`zeroth-worker` follows the existing Rust Cloudflare Worker shape in this repo:
`worker-build` produces `build/worker/shim.mjs`, and D1 is exposed through a
`ZEROTH_DB` binding.

## UI Screenshots

| Hosted login | Account management |
| --- | --- |
| <img src="docs/screenshots/zeroth-login.png" alt="Zeroth hosted login with Apple, Google, wallet, and password options" width="520"> | <img src="docs/screenshots/zeroth-account.png" alt="Zeroth account page showing profile, linked identities, sessions, and applications" width="520"> |

| Admin overview | Provider and system detail |
| --- | --- |
| <img src="docs/screenshots/zeroth-admin-overview.png" alt="Zeroth admin overview with tenant metrics, admin access, passkey registration, schema status, and client editor" width="520"> | <img src="docs/screenshots/zeroth-admin-system.png" alt="Zeroth admin provider detail with configured providers, setup evidence, disabled Spotify notes, and last failure text" width="520"> |

| Application management |
| --- |
| <img src="docs/screenshots/zeroth-admin-applications.png" alt="Zeroth admin application table showing clients, redirect URIs, origins, account sharing, login visibility, and actions" width="1040"> |

## Current Status

Implemented so far:

- provider presets for Apple, Google, and Spotify
- OIDC authorization request parsing and registered-client validation
- native loopback redirect validation for Swift clients that use an ephemeral
  localhost callback port
- D1 schema for users, identities, clients, provider auth transactions, auth
  codes, refresh tokens, sessions, signing keys, and audit events
- Worker `/authorize` flow that stores provider transaction state in D1 before
  redirecting upstream, plus `prompt=none` silent SSO from an active Zeroth
  browser session
- Worker hosted Leptos `/login` and `/account` pages. `/login` supports browser
  sessions with client-bounded `return_to`. `/authorize` renders the provider
  picker when the OIDC request omits `provider`
- discoverable WebAuthn passkeys with opaque user handles, required user
  verification, conditional-mediation autofill, stored transport/backup
  metadata, and synced-passkey-aware signature-counter handling
- password and scanner-safe magic-link sign-in with layered D1 rate limits,
  generic public responses, one-time POST confirmation, and one-time
  cross-device polling credentials
- Worker hosted Leptos `/admin` and `/admin/clients` pages for provider and D1
  readiness, users, audit events, and registered clients. The pages use the
  generic management APIs. They include Zeroth sign-in for allowlisted admin
  sessions

- Worker Apple App Site Association endpoint backed by deployment-provided JSON
- Worker `/ready` public launch preflight for HTTPS issuer, parseable signing
  material, and Apple/Google/Spotify provider configuration without D1 reads or
  secret disclosure
- Worker JWKS publishing and token verification for the active ES256 signing
  key plus optional previous public ES256 keys during signing-key rotation
- CLI `signing-key` generator for fresh Zeroth issuer keys and public JWKS
  rotation records
- CLI `schema` exporter for generic D1 migrations and compatibility repair SQL,
  so deployments do not copy `zeroth-storage` schema details by hand
- CLI `validate-secret` checks for Zeroth ES256 private keys, Apple PKCS #8
  private keys, and previous public JWKS rotation JSON without printing secret
  material
- Worker `/clients` management API as the minimal Auth0-management replacement.
  It creates, updates, lists, and disables registered clients in D1. A deployment
  admin token or allowlisted Zeroth browser session protects it
- Worker `/tokens` and `/api/tokens` short-lived ES256 bearer-token minting for
  client-configured downstream issuers such as `yl-record-issuer`, with the
  audience and TTL editable through the client admin UI
- Worker `POST /__zeroth/db/ensure` schema bootstrap endpoint. The same admin gate
  protects it. It applies unrecorded generic migrations and stores migration
  history in D1. It repairs compatibility columns from `zeroth-storage`
- Worker `GET /__zeroth/db/status` read-only persistence preflight. The same
  admin gate protects it. It reports D1 tables, migrations, compatibility
  columns, and registered-client count without slowing public `/ready`
- Worker `/users` and `/providers/status` management APIs for bounded user
  inspection and provider readiness. User disable and enable are reversible.
  Disable also revokes sessions and refresh tokens. The APIs do not expose secrets
- Worker `/events` management API, D1 audit persistence, and hosted admin
  filters for bounded Auth0-style event inspection without storing token values
  or provider secrets
- Worker `/oauth2/callback` parsing for query callbacks and Apple `form_post`.
  It looks up the D1 transaction and binds the browser transaction cookie. It
  consumes the transaction before provider token exchange and rejects replays
- Zeroth-owned upstream OIDC provider nonces for Apple/Google callbacks,
  separate from downstream app nonces that are preserved only for Zeroth-issued
  ID tokens
- Apple `form_post` callback `user` JSON preservation for first-consent name
  capture, merged with verified Apple ID-token claims before D1 user/identity
  upsert
- Provider-side callback errors such as user cancellation redirect back to the
  stored OIDC, browser-login, or identity-link return URL with error details and
  original app state
- Spotify profile fetch and D1 user/identity upsert using Spotify `account_id`
  as the stable account-linking subject when present, with legacy `id` fallback
- Google/Apple RS256 ID-token verification against provider JWKS and D1
  user/identity upsert from verified OIDC claims
- provider callback completion for hosted login or registered OIDC clients. It
  can create a D1-backed browser session and use the hosted-login `return_to` URL.
  It can issue a hashed Zeroth code and redirect to the registered client. The
  response includes original app state and Zeroth's `iss` parameter
- client-bound authorization error redirects after redirect URI validation.
  Relying apps receive an OIDC error response instead of JSON. It contains
  `error`, original app state, and `iss` for failures that are safe to redirect.
- Worker `/oauth/token` authorization-code validation for public PKCE and
  confidential clients. It verifies the registered client, secret, code,
  expiry, reuse state, and redirect URI. It validates the S256 `code_verifier`
  when the code used PKCE. It consumes the D1 code before it mints credentials
- Worker `/oauth/token` native provider token exchange for Swift and mobile apps.
  It verifies Apple and Google ID tokens against provider JWKS and native client
  ID allowlists. It validates Spotify access tokens through the profile endpoint.
  It uses Spotify `account_id` as the stable linking subject when present. Each
  provider flow stores the identity in D1 and applies the client's email-domain
  policy. It returns Zeroth-owned access and ID tokens
- registered-client CORS/preflight support for browser calls to token,
  revocation, introspection, userinfo, session, sessions, profile, identities,
  validate, and logout
  endpoints
- ES256 Zeroth-owned access and ID token issuance. ID tokens contain standard
  scoped `email` and `profile` claims. Conservative `roles` claims use `user`
  and add `admin` for active admin memberships. The tokens support session-bound
  `sid`, refresh tokens for `offline_access`, and Worker JWKS
- `zeroth-oidc` relying-party helpers for sub-10 ms product gating. They match
  exact and prefix protected paths locally. They verify Zeroth access tokens from
  cached JWKS and check role and scope claims without calling Zeroth each time.

- OIDC discovery metadata for query-mode code responses and rejection of
  unsupported `response_mode` values. It advertises the response `iss` flag and
  Zeroth issuer and JWKS endpoints. It includes OAuth Authorization Server
  metadata and explicit `prompt` values. Clients that use `max_age` receive
  `auth_time` claims
- refresh-token grant exchange with rotation and fresh Zeroth token issuance.
  Authorization-code refresh tokens bind to the browser session that created the
  code. They preserve original `auth_time`. Conditional D1 rotation must win
  before replacement. They support `prompt=none` SSO with `max_age` checks
- refresh-token replay detection that revokes the active session-scoped token
  family when a rotated token is presented again by the same client
- Worker `/oauth/revoke` refresh-token revocation for registered clients
- Worker `/oauth/introspect` for RFC7662-style access-token and same-client
  refresh-token introspection by confidential clients, returning inactive
  responses without exposing token values. Session-bound access tokens
  introspect as inactive when their D1 session is missing, revoked, expired, or
  mismatched.

- Worker `/userinfo` with ES256 bearer-token verification and a D1-backed scoped
  profile. It rejects disabled users and disabled or missing token clients before
  it returns profile data. Session-bound access tokens require an active browser
  session
- Worker browser sessions with D1 persistence, secure session cookies,
  optional deployment-controlled parent-domain session cookies for same-site SSO
  across first-party subdomains, `/session`, `/sessions`, `/profile`,
  `/identities`, and `/logout`. Session revocation also revokes that session's
  refresh-token family
- Worker OIDC `end_session_endpoint` metadata and bounded post-logout redirects
  through `/logout`
- Worker `PATCH /profile` for bounded local display-name and picture updates
- Worker `/identities/link` for session-bound provider linking through Apple,
  Google, or Spotify, with client-bounded return URLs and callback completion
- Worker `DELETE /identities` for guarded linked-identity unlinking without
  allowing removal of the last login method
- Worker `/validate` for bearer-token and browser-session validation. It checks
  active D1 users and registered clients. When an access token has a `sid`, it
  also checks the active D1 session
- Leptos account/login UI for hosted provider choice, profile management,
  linked identities, sessions, and compact OIDC application inventory
- Worker CPU-budget guardrails for the 10 ms Free-plan target. They cache ES256
  signing material and provider JWKS. They also bound lists, queries,
  request-path cleanup, and CORS origin scans
- CLI minting of Sign in with Apple client-secret JWTs from Apple team/key/client
  configuration without mutating Apple Developer records
- Worker runtime minting and isolate caching of Sign in with Apple
  client-secret JWTs from deployment-provided Apple team/key/private-key secrets

The current UI/security/implementation review and prioritized production gates
are documented in
[`docs/security-technical-feature-audit-2026-07-14.md`](docs/security-technical-feature-audit-2026-07-14.md).

Still required before Auth0 can be removed:

- deployment-specific Wavey/Bitneedle Apple Developer identifier setup
- real Apple, Google, and Spotify OAuth client IDs/secrets in the `wavey-id`
  deployment
- a real Cloudflare D1 database ID, schema application, and Wavey client
  seed or `/clients` management upsert
- relying app cutover to Zeroth issuer, client IDs, redirect URIs, and JWKS
- crates.io ownership for the root `zeroth` crate name. As of 2026-06-04,
  crates.io already has `zeroth = 0.0.0` owned by `jason-yau`. The split crate
  names are not claimed by search. These include `zeroth-core`, `zeroth-oidc`,
  and `zeroth-worker`. The root name needs a transfer or owner invitation before
  publication.

## Crates.io

The root crate should remain named `zeroth`, but the name is currently occupied
on crates.io by an unrelated placeholder. Until ownership is transferred, publish
only the split crates.

Publish order matters because crates.io verifies versioned dependencies against
already-published packages:

```sh
cargo publish -p zeroth-core
cargo publish -p zeroth-providers
cargo publish -p zeroth-oidc
cargo publish -p zeroth-storage
cargo publish -p zeroth-server
cargo publish -p zeroth-ui
cargo publish -p zeroth-cli
cargo publish -p zeroth-worker
```

After the root name is transferred:

```sh
cargo publish -p zeroth
```

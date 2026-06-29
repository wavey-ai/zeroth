# Zeroth Security and Feature TODO

## Purpose

This document turns the Zeroth security and feature audit into an implementation plan for the current Rust and Cloudflare Workers/D1 codebase.

The priorities are:

1. Prevent account takeover, credential abuse, cross-site request forgery, and administrative compromise.
2. Keep authentication latency and D1 usage practical on Cloudflare's free plan.
3. Avoid adding Durable Objects, Queues, KV, or paid services unless a simpler D1 or edge-based design would materially prejudice security.
4. Preserve the existing strong parts of the implementation, including hashed bearer credentials, one-time challenge consumption, authorization-code consumption, refresh-token rotation, refresh-token-family revocation, audit events, account namespaces, and existing origin checks.
5. Prefer one canonical implementation path over compatibility aliases and duplicated policy.

## Repository areas

The uploaded snapshot contains these principal implementation surfaces:

- `crates/zeroth-core/src/lib.rs`
- `crates/zeroth-storage/src/lib.rs`
- `crates/zeroth-server/src/lib.rs`
- `crates/zeroth-worker/src/lib.rs`
- `crates/zeroth-oidc/src/lib.rs`
- `crates/zeroth-providers/src/lib.rs`
- `crates/zeroth-ui/src/lib.rs`
- `crates/zeroth-cli/src/main.rs`
- `src/lib.rs`
- SQL migrations included by `zeroth-storage`

Most production changes belong in `crates/zeroth-worker/src/lib.rs`, with policy and domain types moved into `zeroth-core` or `zeroth-oidc` where they can be tested without a Worker runtime.

---

# Delivery rules

## Security invariants

- Never reduce password, token, challenge, signature, or WebAuthn verification work merely to save Worker CPU.
- Optimise successful common paths by reducing D1 round trips and avoiding broad scans.
- Do not use eventual consistency for one-time credential consumption or privilege changes.
- Store only hashes of bearer credentials.
- Make every one-time credential transition atomic.
- Do not expose whether an account, email, wallet, passkey, or identity exists.
- Require recent authentication for high-impact account and administrative mutations.
- Keep browser-session authentication and bearer-token authentication as separate route policies.
- Prefer exact allowlists over permissive parsing followed by downstream filtering.

## Cloudflare free-plan implementation preferences

- Use indexed D1 point lookups and conditional updates.
- Use a single D1 batch only when all statements belong to one logical operation.
- Avoid a database write on every ordinary authenticated request.
- Perform cleanup probabilistically or in bounded batches rather than on every request.
- Avoid introducing Durable Objects for rate limiting until edge rate limiting plus compact D1 counters proves insufficient.
- Do not use KV for one-time security state because its consistency model is unsuitable.
- Keep audit writes non-blocking only for low-severity events. Authentication success, failure, privilege change, credential change, and replay detection must remain durable enough to investigate.
- Return small JSON error bodies and avoid rendering full HTML for API failures.
- Add covering indexes before adding caches around security records.

---

# P0 — block unrestricted production exposure

## TODO P0.1 — Replace the current password hashing policy

**Risk:** Critical  
**Status:** Required before public password authentication  
**Primary files:** `crates/zeroth-worker/src/lib.rs`, password migration SQL, `crates/zeroth-storage/src/lib.rs`, `crates/zeroth-cli/src/main.rs`

### Current state

The Worker stores a password hash, salt, and `password_iterations`. The snapshot uses PBKDF2-HMAC-SHA-256 and exposes an environment-controlled iteration count. The observed default is too low, and the configured ceiling prevents a suitably strong PBKDF2 setting.

### Implementation

1. Add a self-describing credential scheme.

   Add columns to `zeroth_local_credentials`:

   ```sql
   password_scheme TEXT NOT NULL DEFAULT 'pbkdf2-sha256',
   password_params_json TEXT NOT NULL DEFAULT '{}',
   password_version INTEGER NOT NULL DEFAULT 1
   ```

   Keep existing `password_hash`, `password_salt`, and `password_iterations` during migration.

2. Add a domain type in `zeroth-core`:

   ```rust
   pub enum PasswordScheme {
       Pbkdf2Sha256,
       Argon2id,
   }

   pub struct PasswordHashRecord {
       pub scheme: PasswordScheme,
       pub version: i32,
       pub hash: String,
       pub salt: String,
       pub params_json: String,
   }
   ```

3. Prefer Argon2id only after benchmarking the exact `wasm32-unknown-unknown` build in Cloudflare Workers.

   Target starting parameters:

   - memory: 19–32 MiB
   - iterations: 2
   - parallelism: 1
   - salt: 16 random bytes minimum
   - output: 32 bytes

   If Worker memory or CPU limits make Argon2id unreliable, use PBKDF2-HMAC-SHA-256 at a calibrated cost rather than selecting weak Argon2id parameters.

4. For PBKDF2 fallback:

   - remove the 100,000 maximum;
   - benchmark in production-like Worker execution;
   - target approximately 150–300 ms for an interactive login on the deployed Worker;
   - make the chosen count a versioned server policy, not a freely adjustable per-request parameter.

5. Add a pepper.

   - Bind `PASSWORD_PEPPER` as a Cloudflare secret.
   - Feed it into the password KDF input using an unambiguous construction such as `HMAC-SHA-256(pepper, normalized_password_bytes)` before the slow KDF.
   - Add `PASSWORD_PEPPER_PREVIOUS` for one-step rotation.
   - Never store or log the pepper identifier with user-controlled values.

6. Rehash on successful login.

   After a successful password verification:

   - compare the stored scheme/version/parameters with the current policy;
   - derive a new salt and hash when outdated;
   - update the credential in one indexed `UPDATE`;
   - do not delay the login response if the rehash can be safely completed in the same request budget;
   - if rehashing risks exceeding limits, complete the login and set a bounded `rehash_required` flag for the next successful login. Do not send plaintext passwords to a queue.

7. Add a fake verification path for unknown accounts.

   When an email lookup misses, run one password KDF using a fixed-format, server-generated dummy hash before returning the generic failure. This reduces timing-based enumeration.

8. Add CLI support:

   ```text
   zeroth password-policy benchmark
   zeroth password-policy validate
   ```

   The benchmark should output the algorithm, parameters, and observed duration without printing secret values.

### Free-plan considerations

- Password verification is deliberately CPU-expensive. Do not weaken it to save CPU.
- Rate limiting must prevent attackers from turning the KDF into a denial-of-service amplifier.
- Rehash only after successful authentication.
- Never perform multiple current-policy KDFs during one request.

### Tests

- verifies every legacy PBKDF2 record;
- rejects malformed hashes and unreasonable stored parameters;
- upgrades a legacy record after successful login;
- does not upgrade after a failed login;
- verifies with current and previous pepper during rotation;
- returns equivalent public failure responses for missing and incorrect accounts;
- enforces maximum password input byte length before running the KDF.

### Acceptance criteria

- No newly created credential uses the legacy weak setting.
- Existing users can sign in and migrate without a password reset.
- Unknown-account and wrong-password requests execute comparable work.
- The selected policy is documented with an actual Worker benchmark.

---

## TODO P0.2 — Add layered rate limiting and abuse controls

**Risk:** Critical  
**Status:** Required before public password, magic-link, wallet, passkey, token, or admin endpoints  
**Primary files:** `crates/zeroth-worker/src/lib.rs`, new migration, `wrangler.toml` or deployment configuration

### Design

Use three layers:

1. Cloudflare edge/WAF rate limits for high-volume IP abuse.
2. Application-level D1 counters for account/client/credential-specific limits.
3. Per-record outstanding-challenge limits to prevent table growth.

Do not start with Durable Objects. D1 is sufficient at expected free-plan scale if counters are compact, indexed, and bucketed.

### Schema

Add:

```sql
CREATE TABLE zeroth_rate_limits (
    scope TEXT NOT NULL,
    subject_hash TEXT NOT NULL,
    bucket_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    blocked_until INTEGER,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, subject_hash, bucket_start)
);

CREATE INDEX zeroth_rate_limits_expiry_idx
ON zeroth_rate_limits(updated_at);
```

Never store raw email, IP, wallet address, credential ID, or user agent. Compute:

```text
subject_hash = HMAC-SHA-256(RATE_LIMIT_KEY, canonical_subject)
```

Bind `RATE_LIMIT_KEY` as a secret distinct from other peppers and signing keys.

### Atomic increment

Use a single D1 upsert:

```sql
INSERT INTO zeroth_rate_limits (
    scope, subject_hash, bucket_start, count, blocked_until, updated_at
)
VALUES (?, ?, ?, 1, NULL, ?)
ON CONFLICT(scope, subject_hash, bucket_start)
DO UPDATE SET
    count = count + 1,
    updated_at = excluded.updated_at
RETURNING count, blocked_until;
```

If D1 support for `RETURNING` is unavailable in the deployed compatibility date, perform the upsert and point lookup in a D1 batch.

### Limit keys

Apply at least:

| Endpoint family | Keys |
|---|---|
| Password login | IP, normalized email, IP+email |
| Password registration | IP, normalized email |
| Magic-link request | IP, normalized email, client |
| Magic-link consume | IP, token hash prefix |
| Passkey options | IP, client, user/email when supplied |
| Passkey verify | IP, credential ID hash |
| Wallet challenge | IP, wallet address, client |
| Wallet verify | IP, wallet address, challenge |
| OAuth token | IP, client ID, grant type |
| Token introspection | IP, confidential client |
| Admin bearer auth | IP, credential ID |
| Identity link/unlink | session/user |
| Database ensure | IP, deployment credential |

### Initial policy

Use configuration defaults rather than hard-coded permanent values:

- password login: 5 failures per account per 15 minutes; 20 per IP per 15 minutes;
- magic-link request: 3 per email per hour; 20 per IP per hour;
- passkey/wallet verify: 10 failures per credential/address per 15 minutes;
- OAuth token failures: 30 per client per 5 minutes;
- admin authentication failures: 5 per credential/IP per 15 minutes.

Successful authentication may clear or soften the account-specific failure counter, but should not erase an IP abuse history.

### Backoff

Store `blocked_until` only after thresholds are crossed. Use bounded exponential backoff:

```text
1 minute, 5 minutes, 15 minutes, 1 hour
```

Do not create permanent lockouts from unauthenticated traffic.

### Response

Return:

- HTTP `429`;
- `Retry-After`;
- OAuth-compatible `temporarily_unavailable` where required;
- the same body whether an account exists or not.

### Cleanup

Do not run a full cleanup on each request.

- On approximately 1 in 100 relevant requests, delete at most 100 rows older than 48 hours.
- Alternatively run a scheduled Worker once daily if Cron Triggers are available in the chosen plan.
- Always bound the delete.

### Audit

Record an event only when a request first becomes blocked or a block duration escalates. Do not write one audit row for every rejected bot request.

### Tests

- concurrent increments cannot undercount;
- account and IP limits operate independently;
- rate-limit keys never contain plaintext identifiers;
- aliases hit the same limiter;
- success does not remove unrelated IP throttling;
- cleanup is bounded;
- throttled requests do not execute password KDF or signature verification.

---

## TODO P0.3 — Enforce server-side CSRF protection for session-authenticated mutations

**Risk:** Critical  
**Status:** UI renders `_csrf` fields, but the Worker must centrally validate them  
**Primary files:** `crates/zeroth-worker/src/lib.rs`, `crates/zeroth-ui/src/lib.rs`, `crates/zeroth-core/src/lib.rs`

### Route authentication policy

Introduce:

```rust
enum RouteAuth {
    Public,
    BrowserSessionRead,
    BrowserSessionMutation,
    OAuthBearer,
    ConfidentialClient,
    AdminSession,
    BootstrapDeployment,
}
```

Every route match arm must declare one policy. The dispatcher should reject a route whose policy is not satisfied before entering its handler.

### CSRF token design

Use a stateless token tied to the browser session:

```text
token = base64url(
    version || issued_bucket || HMAC-SHA-256(
        CSRF_SECRET,
        session_id || 0x00 || issued_bucket || 0x00 || route_family
    )
)
```

- `CSRF_SECRET` is a Cloudflare secret.
- `issued_bucket` can be a UTC day number.
- accept the current and previous day to avoid forced refresh at midnight;
- compare MACs in constant time;
- do not store one CSRF row per session.

This avoids a D1 read solely for CSRF beyond the session lookup already required.

### Browser submission

For HTML forms, continue using `_csrf`.

For JavaScript/API calls, require:

```text
X-Zeroth-CSRF: <token>
```

Do not accept CSRF tokens in query strings.

### Origin validation

For every `BrowserSessionMutation`:

1. Require `Origin`.
2. Parse it as an origin, not a general URL.
3. Accept only:
   - the Zeroth hosted UI origin; or
   - an explicitly registered first-party origin for the current session/client.
4. Reject `null`, opaque, malformed, or absent origins except for a narrowly documented non-browser client path using bearer authentication rather than cookies.

Validate both Origin and token. Neither replaces the other.

### Mutating routes to cover

At minimum:

- profile update;
- session deletion;
- logout POST;
- identity linking initiation;
- identity deletion;
- passkey registration options and finish when using a session;
- passkey rename/delete;
- password change;
- email changes;
- client administration through hosted UI;
- user administration;
- admin membership changes;
- database ensure;
- any future account recovery mutation.

### Free-plan considerations

A stateless HMAC token is faster and cheaper than a CSRF table. Session lookup is already needed, so no additional D1 request is required.

### Tests

- valid token + valid Origin succeeds;
- missing token fails;
- token for another session fails;
- token for another route family fails if route binding is enabled;
- valid token + malicious Origin fails;
- stale token fails after the allowed overlap;
- bearer-only API calls do not require CSRF;
- GET requests never mutate state.

---

## TODO P0.4 — Remove all state-changing GET behaviour

**Risk:** Critical for magic links; High for logout  
**Primary files:** `crates/zeroth-server/src/lib.rs`, `crates/zeroth-worker/src/lib.rs`, `crates/zeroth-ui/src/lib.rs`

### Magic links

Current route aliases include GET and POST consumption, and the Worker can consume on GET before redirecting.

Replace this with:

1. GET `/magic-link/confirm?token=...`
   - hash and locate the token;
   - do not mark it consumed;
   - render a no-store confirmation page;
   - place the raw token only in a hidden POST field;
   - set `Referrer-Policy: no-referrer`;
   - prevent framing;
   - do not load third-party resources.

2. POST `/magic-link/consume`
   - validate Origin;
   - validate a purpose-bound confirmation token or same-site form state;
   - atomically consume the magic-link row;
   - create the session;
   - redirect.

Email scanners and link preview services may still fetch GET, but cannot authenticate the user.

### Logout

- Remove GET mutation.
- GET `/logout` renders confirmation only.
- POST `/logout` requires session CSRF and Origin checks.
- Session-row revocation remains POST/DELETE with CSRF.

### Routing

Delete GET consume/mutate entries from `ROUTES` and the Worker dispatcher. Do not retain behavioural aliases.

### Tests

- two GETs do not consume a magic link;
- scanner-style GET without cookies does not create a session;
- first valid POST consumes it;
- second POST fails generically;
- GET logout preserves the session;
- POST logout revokes it.

---

## TODO P0.5 — Restrict the bootstrap/admin token to deployment bootstrap only

**Risk:** Critical  
**Primary files:** `crates/zeroth-worker/src/lib.rs`, admin UI handlers, deployment docs

### Target model

Use three distinct concepts:

1. Deployment bootstrap credential
2. Human administrator session
3. OAuth confidential-client credential

They must not be interchangeable.

### Changes

1. Replace broad acceptance of `ADMIN_TOKEN` with:

   ```text
   ZEROTH_BOOTSTRAP_TOKEN_SHA256
   ```

   Do not support plaintext `ADMIN_TOKEN` in production mode.

2. Add a bootstrap-state rule:

   - bootstrap credential is valid only when no active admin membership exists; or
   - an explicit `ZEROTH_BOOTSTRAP_ENABLED=true` emergency flag is set.

3. Scope bootstrap routes to:

   - initial schema ensure;
   - creation of the first admin membership;
   - health/config validation required for deployment.

4. Ordinary admin routes must require an authenticated user with active admin membership and recent authentication.

5. Add `credential_id` for rotation:

   ```text
   ZEROTH_BOOTSTRAP_KEY_ID
   ```

   Log only this identifier.

6. Add an emergency mode:

   - requires both token and deployment flag;
   - expires via a configured Unix timestamp;
   - emits a high-severity audit event on every use;
   - readiness warns while enabled.

7. Constant-time compare the presented token hash with the configured digest.

### Free-plan considerations

This requires no new service and only one indexed admin-membership existence query during bootstrap-sensitive operations. Cache the fact only within a single request, never globally across deployments.

### Tests

- token is rejected once an admin exists;
- token cannot access ordinary client/user/event admin APIs;
- human admin cannot call deployment-only schema mutation unless separately authorised;
- emergency mode expires;
- plaintext configuration fails production readiness.

---

## TODO P0.6 — Remove account-enumeration differences

**Risk:** High  
**Primary files:** local-auth handlers in `crates/zeroth-worker/src/lib.rs`, UI copy in `crates/zeroth-ui/src/lib.rs`

### Public response rules

Password login:

```json
{"error":"invalid_grant","error_description":"invalid email or password"}
```

Use the same status, body shape, headers, and approximate work for:

- malformed but plausibly normal email;
- unknown email;
- disabled credential;
- disabled user;
- incorrect password.

Registration and magic-link request:

```json
{"ok":true,"message":"If this account can use this method, the next step has been initiated."}
```

Return the same response when:

- account exists;
- registration is disallowed;
- email domain is not permitted;
- magic-link delivery is suppressed;
- account is disabled.

Where client policy must be exposed to an already trusted first-party UI, expose it through authenticated configuration rather than account-specific error responses.

### Timing

- Run dummy password verification for unknown users.
- Avoid synchronous email provider error details in the public response.
- Do not let rate-limit state reveal existence.
- Add small bounded jitter only if benchmarked and necessary; prefer equivalent code paths over artificial sleeps.

### Internal handling

Keep precise audit reason codes:

- `unknown_account`
- `wrong_password`
- `disabled_credential`
- `disabled_user`
- `domain_disallowed`
- `delivery_suppressed`

Store these only in protected audit data.

### Tests

Snapshot the public response across all failure classes and compare:

- status;
- JSON;
- relevant headers;
- redirect behaviour.

Timing tests should use broad thresholds and repeated samples, not fragile exact durations.

---

## TODO P0.7 — Verify and harden all atomic one-time transitions

**Risk:** High  
**Status:** Much of this is already implemented; this task proves consistency  
**Primary files:** D1 helper functions in `crates/zeroth-worker/src/lib.rs`, migration indexes

### Existing mechanisms to preserve

The snapshot already calls atomic-looking functions such as:

- `consume_auth_transaction`
- `consume_authorization_code`
- `consume_passkey_challenge`
- `consume_wallet_challenge`
- `consume_magic_link`
- `rotate_refresh_token`
- `revoke_refresh_token_family`

### Required implementation form

Each consume function must be one conditional update:

```sql
UPDATE table
SET consumed_at = ?
WHERE key_hash = ?
  AND consumed_at IS NULL
  AND expires_at > ?
```

Return success only when exactly one row changed.

Refresh-token rotation must condition on:

```sql
rotated_at IS NULL
AND revoked_at IS NULL
AND expires_at > ?
```

Then insert the replacement token with the same family ID. If D1 cannot make the update and insert fully transactional in the chosen API, perform the conditional update first; failure revokes the family. A replacement insertion failure must also revoke the family rather than leave an ambiguous usable state.

### Add schema constraints

- primary key or unique index on every challenge/token hash;
- index on expiry for bounded cleanup;
- index on refresh-token family ID;
- index on session ID for family revocation;
- no nullable hash fields.

### Concurrency tests

Issue at least 20 simultaneous attempts against one credential and assert:

- one succeeds;
- all others fail;
- no duplicate session/token is created;
- refresh replay revokes the family;
- audit contains one success and a bounded replay event.

Use integration tests against a real D1-compatible test environment where possible; SQLite tests alone may miss API semantics.

---

# P1 — hardening and core feature completion

## TODO P1.1 — Narrow session and transaction cookies

**Risk:** High  
**Primary files:** cookie helpers in `crates/zeroth-worker/src/lib.rs`, `ZerothServerConfig`

### Changes

- Use host-only cookies by default.
- Prefer `__Host-zeroth_session`:
  - `Secure`
  - `Path=/`
  - no `Domain`
- Keep a parent-domain cookie only behind an explicit deployment option and suffix allowlist.
- Rename transaction cookie to `__Host-zeroth_tx` when host-only.
- Evaluate `SameSite=Lax` for the session cookie.
- Use `SameSite=None` only for flows proven to require cross-site cookie sending.
- Keep `HttpOnly`.
- Add `Priority=High` if supported and useful.
- Rotate session ID after successful authentication, privilege elevation, password change, and identity linking.

### Configuration validation

Fail readiness when:

- production issuer is HTTP;
- `SameSite=None` is configured without `Secure`;
- cookie domain is a public suffix;
- cookie domain does not suffix-match the issuer host;
- parent-domain cookies are enabled without an explicit allowlist.

### Tests

Create a matrix for:

- hosted login;
- OAuth redirect;
- `form_post` provider callback;
- cross-origin first-party app;
- local development;
- sibling subdomain compromise assumptions.

---

## TODO P1.2 — Centralise route authentication and security middleware

**Risk:** High  
**Primary files:** `crates/zeroth-worker/src/lib.rs`, `crates/zeroth-server/src/lib.rs`

The Worker dispatcher currently has a very large route match. Add a static route descriptor:

```rust
struct RouteSpec {
    method: Method,
    canonical_path: &'static str,
    auth: RouteAuth,
    cors: CorsPolicy,
    csrf: CsrfPolicy,
    body_limit: usize,
    rate_limit: Option<RateLimitScope>,
    cache: CachePolicy,
}
```

Resolve the request to one `RouteSpec`, apply middleware in this order:

1. canonical path resolution;
2. request ID;
3. body-size precheck;
4. CORS preflight;
5. rate limit;
6. authentication;
7. Origin validation;
8. CSRF;
9. handler;
10. security headers;
11. audit outcome.

Do not let aliases bypass middleware.

Add a test that iterates every exported route and asserts a complete policy declaration.

---

## TODO P1.3 — Add recent-authentication and step-up policy

**Risk:** High  
**Primary files:** session model, Worker account/admin handlers, UI

### Model

Sessions already carry authentication time in related flows. Add or standardise:

```rust
pub struct AuthenticationContext {
    pub auth_time: i32,
    pub method: String,
    pub strength: AuthenticationStrength,
}
```

Strength examples:

- `Password`
- `MagicLink`
- `PasskeyUserVerification`
- `WalletSignature`
- `ExternalProvider`
- `Recovery`

### Policy

Require authentication within the previous 10 minutes for:

- password change;
- adding/removing passkeys;
- changing primary email;
- unlinking a login identity;
- linking a wallet;
- creating or rotating client secrets;
- granting/removing admin membership;
- disabling or enabling users;
- enabling emergency bootstrap;
- deleting the account.

For high-risk admin actions, require a passkey with user verification when one is registered. Otherwise require re-entry of the active method.

### UX

Return:

```json
{
  "error": "interaction_required",
  "reauthenticate": true,
  "return_to": "..."
}
```

The hosted UI should preserve the intended action and execute it only after reauthentication, using a short-lived, purpose-bound transaction.

### D1 efficiency

Use `auth_time` already associated with the current session; avoid another table lookup. Update session authentication context only on successful step-up.

---

## TODO P1.4 — Complete password change and recovery

**Risk:** High; feature gap  
**Primary files:** Worker, UI, new migration, mail delivery abstraction

### Authenticated password change

Require:

- active session;
- recent authentication;
- current password unless the session was just verified by a strong passkey;
- new password policy validation.

After change:

- rotate the current session ID;
- revoke all other sessions by default;
- revoke all refresh-token families;
- send a notification;
- write a high-severity audit event.

### Forgotten-password recovery

Add a separate table:

```sql
CREATE TABLE zeroth_password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    client_id TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    requested_ip_hash TEXT
);
CREATE INDEX zeroth_password_resets_expiry_idx
ON zeroth_password_resets(expires_at);
```

Do not reuse ordinary magic-link rows because reset tokens have a different purpose and stronger post-consumption effects.

Flow:

1. Generic request response.
2. Send a 20-minute reset link.
3. GET confirmation page does not consume.
4. POST verifies token and accepts new password.
5. Atomic consume.
6. Revoke sessions and refresh-token families.
7. Notify user.

Limit outstanding active resets per user to three. Delete or invalidate older active resets when issuing a new one.

---

## TODO P1.5 — Complete passkey lifecycle management

**Risk:** High; feature gap  
**Primary files:** Worker, UI, passkey migration/helpers

Add authenticated endpoints:

- `GET /account/passkeys`
- `POST /account/passkeys/registration/options`
- `POST /account/passkeys/registration/finish`
- `PATCH /account/passkeys/{credential_id}`
- `DELETE /account/passkeys/{credential_id}`

Store/display:

- credential ID hash or encoded ID as required for WebAuthn;
- user ID;
- public key;
- sign count;
- transports;
- AAGUID;
- backup eligible;
- backup state;
- discoverable/resident-key status;
- user-verification result;
- created at;
- last used at;
- user-facing name;
- disabled at.

### Deletion safety

- require recent authentication;
- prevent removal of the last usable authentication/recovery method;
- revoke sessions created through a credential if policy requires;
- send notification;
- keep a disabled tombstone rather than immediate destructive deletion for audit integrity.

### Counter policy

Do not automatically lock an account solely because a sign counter is zero. Implement:

- counter increased: accept and update;
- both stored/current zero: accept;
- non-zero counter decreases or repeats unexpectedly: record a risk event and apply configured policy;
- backup-enabled multi-device passkeys: use backup state and platform guidance rather than assuming cloning.

### Free-plan considerations

Passkey verification is local cryptography plus indexed D1 reads. No external service is required.

---

## TODO P1.6 — Add explicit user consent and grant storage

**Risk:** High for third-party OAuth clients  
**Primary files:** `zeroth-oidc`, Worker, UI, migration

### Schema

```sql
CREATE TABLE zeroth_user_grants (
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (user_id, client_id)
);
CREATE INDEX zeroth_user_grants_client_idx
ON zeroth_user_grants(client_id, revoked_at);
```

Store scopes in canonical sorted space-separated form or a child table. At free-plan scale, canonical text is cheaper and sufficient if scope count remains small.

### Authorize behaviour

Show consent when:

- no active grant exists;
- requested scope exceeds granted scope;
- `prompt=consent`;
- client policy always requires consent.

Never silently add scopes.

On denial, return OAuth `access_denied` only to a previously validated redirect URI.

### Account UI

List authorised applications with:

- client name;
- granted scopes;
- grant date;
- last token activity if cheaply available;
- revoke action.

Revoking a grant must revoke refresh-token families for that user/client. Existing short-lived access tokens may remain valid until expiry unless token denylisting is introduced.

### Discovery

Advertise `consent` only after this is complete and tested.

---

## TODO P1.7 — Consolidate OAuth client-type enforcement

**Risk:** High  
**Primary files:** `zeroth-oidc`, Worker token and authorize handlers

Create explicit client types:

```rust
pub enum OAuthClientType {
    PublicBrowser,
    PublicNative,
    ConfidentialWeb,
    FirstPartyTrusted,
}
```

Enforce:

- public clients always use PKCE S256;
- `plain` PKCE is rejected;
- confidential clients authenticate at the token endpoint;
- browser public clients use HTTPS redirect URIs;
- native custom schemes use exact registered values;
- loopback redirects, if supported, allow port variance only under a specific native policy;
- redirect URI is byte-for-byte equal after registration-time normalisation;
- refresh tokens are bound to user, client, session/family, and granted scope;
- refresh requests cannot widen scope;
- token exchange cannot silently change account namespace.

Add a table-driven test matrix covering every grant/client combination.

---

## TODO P1.8 — Strengthen refresh-token rotation operations

**Risk:** High  
**Status:** Rotation and replay-family revocation already exist; complete observability and failure handling  
**Primary files:** Worker token helpers, migrations

Ensure the row contains:

- `family_id`
- `parent_token_hash`
- `replaced_by_token_hash`
- `rotated_at`
- `revoked_at`
- `revoke_reason`
- `session_id`
- `auth_time`
- `scope`
- `client_id`
- `expires_at`

On replay:

1. revoke every active row in the family with one indexed update;
2. revoke the associated session when appropriate;
3. record one high-severity audit event;
4. optionally notify the user;
5. return generic `invalid_grant`.

Add a unique index preventing two children for one parent:

```sql
CREATE UNIQUE INDEX zeroth_refresh_tokens_parent_unique
ON zeroth_refresh_tokens(parent_token_hash)
WHERE parent_token_hash IS NOT NULL;
```

If partial indexes are not supported in the target D1 version, enforce uniqueness through a non-null sentinel strategy or transaction logic.

---

## TODO P1.9 — Canonicalise and delete route aliases

**Risk:** Medium to High  
**Primary files:** `crates/zeroth-server/src/lib.rs`, Worker dispatcher, UI

The snapshot exposes many aliases such as:

- `/magic-links`
- `/magic-link`
- `/magic_link`
- `/api/...`
- `/auth/...`
- `/local-auth/...`

Select one canonical API:

```text
/oauth/*
/auth/password/*
/auth/magic-link/*
/auth/passkeys/*
/auth/wallet/*
/account/*
/admin/*
/.well-known/*
```

### Migration strategy

Because the project does not require legacy support:

- delete noncanonical route entries;
- update all hosted UI forms and scripts;
- update tests;
- do not leave duplicate handler match arms;
- return 404 rather than permanent compatibility shims.

Add a test that canonical route paths are unique and that `ROUTES` matches the Worker dispatcher.

This reduces cold-code size, policy drift, and missed protection.

---

## TODO P1.10 — Add comprehensive response security headers

**Risk:** High for hosted UI  
**Primary files:** Worker response helpers, UI asset serving

Create one function applied to every response class.

### HTML

```text
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' <registered first-party origins only where needed>;
  form-action 'self' <validated provider origins where required>;
  frame-ancestors 'none';
  base-uri 'none';
  object-src 'none'

Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cache-Control: no-store
```

Avoid inline scripts/styles so CSP does not require `unsafe-inline`. If generated inline content is unavoidable, use a per-response nonce.

### JSON auth responses

- `Cache-Control: no-store`
- `Pragma: no-cache`
- `X-Content-Type-Options: nosniff`

### Discovery/JWKS/static assets

Allow caching with explicit max age and ETag where content is public and stable. Do not apply `no-store` to JWKS unnecessarily.

Set HSTS at the Cloudflare zone:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Enable `preload` only after confirming every subdomain is HTTPS-only.

---

## TODO P1.11 — Centralise redirect and return target validation

**Risk:** High  
**Primary files:** `zeroth-core`, `zeroth-oidc`, Worker

Add validated types:

```rust
pub struct RegisteredRedirectUri(Url);
pub struct HostedReturnPath(String);
pub struct NativeRedirectUri(String);
pub struct PostLogoutRedirectUri(Url);
```

Parsing rules:

- OAuth redirect must exactly match a registered URI under client-type rules.
- Hosted return must be same-origin or a root-relative path.
- Never allow username/password URL components.
- Reject fragments where not explicitly permitted.
- Reject control characters before and after percent decoding.
- Reject `javascript:`, `data:`, `file:`, and scheme-relative URLs.
- Normalize only at registration; never normalize an incoming authorize redirect into a match.
- Bind every stored `return_to` to client ID and account namespace.

Handlers should receive typed validated values rather than raw strings.

---

## TODO P1.12 — Add audit-event schemas, redaction, retention, and alerts

**Risk:** Medium to High  
**Primary files:** Worker audit helpers, migration, admin UI

### Typed event details

Replace arbitrary JSON construction for sensitive events with typed serializable structures. Create an allowlist of fields per event.

Never include:

- raw tokens;
- authorization codes;
- signatures;
- passkey challenges;
- provider ID/access tokens;
- password input;
- raw IP;
- full cookie values;
- secret-bearing URLs.

Use keyed hashes for identifiers when correlation is needed.

### Severity

Add:

```text
info
warning
high
critical
```

High/critical examples:

- admin privilege change;
- bootstrap credential use;
- refresh-token replay;
- credential deletion;
- password reset;
- user disable/enable;
- repeated account throttling.

### Retention

At free-plan scale:

- keep high/critical events longer;
- delete ordinary events in bounded batches;
- add `(created_at)` and `(severity, created_at)` indexes;
- add pagination by `(created_at, id)`, not OFFSET;
- never load the entire event table in the admin UI.

Optional external export can be added later; do not make it a prerequisite for safe local operation.

---

# P2 — product and operational completion

## TODO P2.1 — Add primary and recovery email lifecycle

**Primary files:** Worker, UI, migration

Add a dedicated email table instead of overloading `primary_email`:

```sql
CREATE TABLE zeroth_user_emails (
    user_id TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    display_email TEXT NOT NULL,
    verified_at INTEGER,
    is_primary INTEGER NOT NULL DEFAULT 0,
    added_at INTEGER NOT NULL,
    removed_at INTEGER,
    PRIMARY KEY (user_id, normalized_email),
    UNIQUE (normalized_email)
);
```

If cross-tenant reuse is allowed, uniqueness must include `account_namespace`.

Features:

- add email;
- send purpose-bound verification link;
- verify;
- promote to primary;
- remove;
- prevent removal of the last recovery identity;
- notify old and new addresses;
- require recent authentication.

Do not automatically treat every provider-returned email as a durable recovery address. Store provider verification provenance.

---

## TODO P2.2 — Define and implement account recovery policy

**Primary files:** architecture document, Worker, UI

Decide the role of each method:

- password;
- magic link;
- passkey;
- wallet;
- physical Bitneedle record credential;
- social/provider identity.

For the physical-record login design:

- do not store a permanent bearer password in readable record metadata;
- prefer a record-held private secret used in a challenge-response protocol;
- bind it to one account namespace;
- support revocation and replacement;
- expose a credential ID, not a sequential account identifier;
- keep the record credential independent of Zeroth's social-provider machinery;
- model it as a first-party authenticator or signed challenge, not as a fake WebAuthn passkey unless it actually implements WebAuthn semantics.

Recovery must not silently weaken the strongest configured authentication method.

---

## TODO P2.3 — Add user security notifications

**Primary files:** Worker, email abstraction, preferences migration

Send notifications for:

- password changed/reset;
- passkey added/removed;
- wallet linked/unlinked;
- primary email changed;
- new login from a new coarse device fingerprint;
- all sessions revoked;
- admin action on account;
- recovery started/completed.

To minimise writes:

- derive a coarse device key from keyed hashes of selected request attributes;
- write only when a device is first seen or materially changes;
- do not create invasive fingerprinting data;
- let users disable informational notifications but not critical security notices.

Email sending failure must not roll back the security mutation. Record delivery failure without leaking provider details to the user.

---

## TODO P2.4 — Improve session management

**Primary files:** session schema/helpers, account UI

Add:

- `last_seen_at`, updated no more than once per 6 hours;
- coarse device label;
- authentication method;
- last IP country if supplied by trusted Cloudflare metadata and acceptable under privacy policy;
- idle expiry;
- absolute expiry;
- session rotation lineage;
- revoked reason.

UI actions:

- revoke one session;
- sign out all other sessions;
- sign out all sessions;
- identify current session.

Free-plan optimisation:

```sql
UPDATE zeroth_sessions
SET last_seen_at = ?
WHERE id = ?
  AND last_seen_at < ?;
```

Run only when the stored value is older than the write interval.

---

## TODO P2.5 — Add confidential-client secret lifecycle

**Primary files:** client schema, Worker admin, CLI, UI

Use generated 256-bit random secrets.

Store:

```sql
CREATE TABLE zeroth_client_secrets (
    secret_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX zeroth_client_secrets_client_idx
ON zeroth_client_secrets(client_id, revoked_at);
```

Display plaintext once.

Hash with HMAC-SHA-256 using a server pepper because generated secrets have full entropy. A slow password hash is unnecessary for truly random 256-bit secrets and would waste Worker CPU.

Support:

- two overlapping active secrets during rotation;
- optional expiry;
- per-secret revocation;
- recent admin authentication;
- audit event;
- last-used update at most once per day to reduce D1 writes.

Remove direct acceptance of arbitrary client-secret hashes from normal UI/API creation paths. Keep any import path deployment-only.

---

## TODO P2.6 — Define identity linking, collision, and account merge rules

**Primary files:** `zeroth-core`, Worker identity helpers, UI

Create explicit decisions for:

- same verified email from two providers;
- provider email changes;
- wallet already linked elsewhere;
- passkey user handle conflict;
- tenant/client namespace conflict;
- linking while authenticated;
- linking initiated without a session;
- merge requests.

Safe default:

- never merge accounts automatically from email alone;
- linking requires an active, recently authenticated session;
- prove control of the new identity;
- reject if that identity belongs to another account;
- provide a separate, heavily audited account-merge operation only if genuinely needed.

Store identity provenance and link method.

---

## TODO P2.7 — Add adversarial account-namespace isolation tests

**Primary files:** Worker integration tests, storage helpers

For every lookup and write involving identity, credential, email, wallet, magic link, passkey, token exchange, or user creation, verify the namespace predicate.

Required scenarios:

- same email in global and tenant namespaces;
- same wallet in two permitted namespaces;
- client-scoped account cannot resolve tenant/global identity;
- magic link issued for client A cannot authenticate client B;
- passkey challenge for namespace A cannot finish in B;
- return target cannot switch namespace;
- changing a client account-sharing mode does not expose old rows;
- admin search intentionally crosses namespaces only with explicit filters.

Add composite indexes matching actual predicates, for example:

```sql
CREATE UNIQUE INDEX zeroth_account_identity_unique
ON zeroth_account_identities(account_namespace, provider_id, provider_subject);
```

---

## TODO P2.8 — Make schema migrations production-safe

**Primary files:** `zeroth-storage`, Worker schema handlers, CLI

Add migration checksum tracking:

```sql
ALTER TABLE zeroth_schema_migrations ADD COLUMN checksum TEXT;
```

For new installations, include it in the initial table.

On startup/ensure:

- compute a stable SHA-256 of each migration;
- reject a recorded version whose name/checksum differs;
- acquire a migration lock using a D1 row with expiration;
- apply one migration at a time;
- record completion only after all statements succeed;
- expose dry-run/status through CLI;
- keep public readiness read-only.

Remove the general production HTTP mutation route or restrict it to deployment bootstrap policy.

Compatibility columns should become explicit numbered migrations. Repeated `ALTER TABLE ... ADD COLUMN` inference is difficult to reason about and audit.

---

## TODO P2.9 — Complete JWT signing-key rotation

**Primary files:** CLI, Worker signing config, JWKS handler

Define key records:

```rust
struct SigningKeyMetadata {
    kid: String,
    active_from: i64,
    sign_until: i64,
    verify_until: i64,
}
```

Requirements:

- exactly one active signing key;
- multiple verification keys;
- reject duplicate `kid`;
- publish old public keys until every signed token must be expired;
- no private key in JWKS;
- startup validation that private key matches active public JWK;
- emergency key retirement;
- documented overlap sequence.

For free-plan simplicity, secrets may remain Worker secret bindings and public metadata may remain JSON configuration. A database-backed HSM-style key service is unnecessary at this scale.

Cache JWKS publicly with a modest max age and ETag. During rotation, publish the new public key before signing with it.

---

## TODO P2.10 — Expand readiness into security readiness

**Primary files:** status/readiness handlers

Return separate states:

```json
{
  "serviceReady": true,
  "securityReady": false,
  "failures": [],
  "warnings": []
}
```

Production security failures:

- weak password policy;
- missing rate-limit key/config;
- plaintext bootstrap token;
- HTTP issuer;
- missing signing key;
- duplicate `kid`;
- invalid cookie domain;
- `SameSite=None` without secure HTTPS deployment;
- wildcard credentialed CORS;
- public password/magic-link auth enabled without application rate limiting;
- migration checksum mismatch;
- emergency bootstrap expired or improperly configured.

Do not expose secret values or detailed infrastructure internals publicly. Full readiness details should require admin/deployment authentication; public readiness returns only pass/fail categories.

---

## TODO P2.11 — Add a formal security integration and fuzz suite

**Primary files:** Worker integration tests, `zeroth-core` property tests, CI

### Integration tests

- authorization-code replay;
- auth-transaction replay;
- refresh-token replay and family revocation;
- simultaneous challenge consumption;
- CSRF;
- malicious Origin;
- CORS preflight parity;
- open redirects;
- tenant crossing;
- disabled-user tokens;
- admin-membership removal;
- stale recent-auth context;
- magic-link scanner GET;
- account enumeration;
- alias/canonical route coverage;
- oversized body rejection before parsing/KDF;
- password KDF rate-limit ordering.

### Fuzz targets

- URL and redirect parser;
- OAuth form parser;
- JWT/JWK parser;
- WebAuthn client data and authenticator data;
- EVM signature/message parser;
- JSON body parsing with nesting and oversized fields.

Keep pure parsing and validation in non-Worker crates so `cargo fuzz` can run natively.

### CI gates

- `cargo test --workspace`
- wasm build
- clippy with warnings denied for security crates
- dependency audit
- migration checksum test
- route-policy completeness test
- secret-pattern scan of fixtures and snapshots

---

# P3 — efficiency, maintainability, and optional upgrades

## TODO P3.1 — Add bounded expiry cleanup

Do not call full cleanup before every challenge issuance.

For each expiring table:

- index `expires_at`;
- delete at most 100 rows per cleanup;
- trigger probabilistically or via daily Cron;
- keep cleanup outside the critical successful-login path where possible.

Tables include:

- auth transactions;
- authorization codes;
- passkey challenges;
- wallet challenges;
- magic links;
- password resets;
- rate-limit buckets;
- expired sessions;
- revoked/expired refresh tokens.

Use:

```sql
DELETE FROM table
WHERE primary_key IN (
    SELECT primary_key
    FROM table
    WHERE expires_at < ?
    LIMIT 100
);
```

Avoid unbounded deletes.

---

## TODO P3.2 — Reduce D1 round trips on authentication paths

Profile each flow and combine only logically related operations.

Target common successful password login:

1. one indexed credential/user join or two point reads;
2. local KDF;
3. one D1 batch for usage update + session insert + essential audit event.

Target passkey/wallet finish:

1. challenge/credential lookup;
2. local verification;
3. conditional consume;
4. batch session insert + usage update + essential audit event.

Do not cache credential or disabled-user state across requests.

Add query plans for critical SQL and indexes based on those plans.

---

## TODO P3.3 — Add request and correlation IDs

Generate a short random request ID for every request.

- Return it in `X-Request-ID`.
- Store it in important audit events.
- Include it in internal error logs.
- Never derive it from user data.
- Do not return stack traces or database errors.

This materially improves debugging without adding D1 operations.

---

## TODO P3.4 — Minimise Worker bundle and hosted UI policy duplication

- Move pure policy and validation into `zeroth-core`/`zeroth-oidc`.
- Keep Worker code focused on HTTP, D1, secret bindings, and response creation.
- Generate route documentation from `RouteSpec`.
- Generate hosted form action paths from canonical route constants.
- Remove unused compatibility aliases and duplicated JavaScript.
- Keep CSP-compatible JavaScript in external static assets.

This reduces both bundle size and the chance that UI and server policy diverge.

---

# Suggested migration sequence

## Milestone 1 — Safe public authentication baseline

Complete:

- P0.1 password hashing;
- P0.2 rate limiting;
- P0.3 CSRF;
- P0.4 POST-only mutations;
- P0.5 bootstrap restriction;
- P0.6 enumeration resistance;
- P0.7 atomic transition verification.

**Release gate:** public password and magic-link authentication remain disabled until this milestone passes.

## Milestone 2 — Browser and account security

Complete:

- P1.1 cookies;
- P1.2 route middleware;
- P1.3 recent authentication;
- P1.4 password recovery;
- P1.5 passkey lifecycle;
- P1.9 route canonicalisation;
- P1.10 headers;
- P1.11 redirect validation.

## Milestone 3 — OAuth and token completeness

Complete:

- P1.6 consent grants;
- P1.7 client-type enforcement;
- P1.8 refresh-token hardening;
- P1.12 audit hardening;
- P2.5 client-secret lifecycle;
- P2.9 signing-key rotation.

## Milestone 4 — Identity and operations

Complete:

- P2.1 email lifecycle;
- P2.2 recovery policy;
- P2.3 notifications;
- P2.4 sessions;
- P2.6 identity collision rules;
- P2.7 namespace tests;
- P2.8 migrations;
- P2.10 readiness;
- P2.11 security suite.

## Milestone 5 — Free-plan optimisation

Complete P3 tasks only after security invariants and tests exist. Measure D1 reads/writes and Worker CPU before introducing new infrastructure.

---

# Initial implementation checklist

- [ ] Add numbered migrations for password metadata, rate limits, grants, reset tokens, email identities, client secrets, and required indexes.
- [ ] Add `RouteSpec` and require every route to declare auth/CORS/CSRF/rate/body/cache policy.
- [ ] Add keyed identifier hashing utility with separate secret purposes.
- [ ] Add application D1 rate limiter before expensive authentication work.
- [ ] Add stateless session-bound CSRF tokens and strict Origin checks.
- [ ] Delete GET mutation routes and compatibility aliases.
- [ ] Restrict bootstrap authentication.
- [ ] Replace password policy and add rehash-on-login.
- [ ] Normalise public authentication errors.
- [ ] Add concurrency tests for every one-time credential.
- [ ] Add recent-auth policy.
- [ ] Complete passkey, password recovery, grant, session, and client-secret lifecycle.
- [ ] Add security headers and typed redirects.
- [ ] Add namespace isolation and replay integration tests.
- [ ] Add security readiness and migration checksum validation.

---

# Definition of done

A task is not complete until:

- its security invariants are represented in tests;
- all canonical routes use the same middleware;
- D1 queries are indexed and bounded;
- no secret or raw bearer credential is logged;
- failure responses do not reveal account existence;
- readiness detects missing production configuration;
- hosted UI and API behaviour agree;
- the implementation has been exercised in a deployed Cloudflare Worker/D1 test environment, not only native Rust unit tests.

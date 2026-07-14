# Zeroth UI, security, technical, and feature audit

Date: 2026-07-14  
Scope: the Rust workspace, Cloudflare Worker/D1 implementation, hosted Leptos UI, gate Worker, migrations, configuration/readiness paths, and dependency lockfile.

## Executive assessment

Zeroth has a stronger security core than its current UI and monolithic Worker suggest. The authorization-code/PKCE flow, exact redirect validation, provider nonce/state binding, hashed bearer credentials, conditional one-time updates, refresh rotation/replay response, session revocation, origin checks, rate limits, audit events, and readiness checks are all meaningful controls rather than placeholders.

This review also implemented a substantial hardening slice: discoverable passkeys, conditional passkey autofill, opaque WebAuthn user handles, authenticator backup/counter handling, response security headers, safer cross-device magic-link polling, a 15-character password floor, session revocation UI, and a navigable admin surface.

The system should still be treated as **limited-production / controlled-audience**, not ready for unrestricted public identity traffic. The main blockers are policy duplication across routes, no recent-authentication/step-up boundary for sensitive changes, incomplete recovery and authenticator lifecycle, an enumerable implicit password-signup mode, bootstrap bearer access to ordinary admin reads, and the absence of deployed Worker/D1 and browser-WebAuthn adversarial tests.

No claim in this document is a deployed-environment penetration-test result. Cloudflare bindings, DNS/TLS, WAF rules, email reputation, secret handling outside the repository, production D1 behavior, and actual browser/authenticator behavior were not dynamically assessed.

## Standards baseline

The passkey review used [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) and the browser conditional-mediation behavior described by [MDN's Web Authentication API reference](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API). OAuth recommendations were checked against [RFC 9700, OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html). Password requirements were checked against [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/). The deployed RSA provider-verification path was checked against [Cloudflare Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/).

## What changed in this review

### Passkeys

- Authentication now uses discoverable credentials: `allowCredentials` is empty instead of listing every tenant credential. This removes an O(n) scan and avoids disclosing credential identifiers.
- Each user gets a stable, random, non-PII WebAuthn user handle. Registration challenges and credentials bind that handle; authentication validates the returned `userHandle`.
- Registration requires resident credentials and user verification. Conditional mediation integrates passkeys into username autofill without breaking the explicit passkey button.
- Credential transports, COSE algorithm, backup eligibility, and backup state are persisted. Stored transports are returned in exclusion descriptors.
- Authenticator flags, reserved bits, CBOR extension structure, trailing bytes, ES256 keys, the full unsigned 32-bit signature counter, user presence, and user verification are checked.
- Backup-eligible/synced authenticators follow WebAuthn's counter model instead of being rejected solely for a non-incrementing counter. Single-device credentials retain the stricter clone signal.
- Migration `0011_passkey_metadata.sql` adds the required user-handle and credential metadata.

### Magic links and sessions

- The email link remains a confirmation GET and the session-creating operation remains a protected POST.
- Cross-device login polling now uses an opaque, hashed, unique token in a same-origin POST body. The token is atomically nulled before it can mint a polling-device session, so it is one-time and no longer appears in URLs.
- Suppressed magic-link requests now return the same public response shape, including a synthetic poll token. Disallowed domains, missing accounts, disabled accounts, and allowed accounts no longer differ by the presence of `pollToken`.
- Signup account creation is deferred until the emailed credential is confirmed.
- Account UI rows can revoke other sessions through the existing CSRF-protected `DELETE /sessions` operation; the current session still uses logout.

### Passwords

- New passwords require at least 15 Unicode characters and remain bounded to 1,024 input bytes. Existing credentials are not invalidated.
- Existing versioned PBKDF2-HMAC-SHA-256 records, a keyed prehash/pepper, pepper rotation, dummy verification, bounded stored parameters, and rehash-on-login remain in place.

### Browser and admin UI

- The admin screen now has hash-addressable, client-side sections rather than one uninterrupted page.
- Keyboard focus indicators, reduced-motion behavior, live status regions, and non-interactive disabled provider controls were added.
- Password, passkey, and wallet methods remain reachable under progressive disclosure; password authentication is no longer accidentally hidden.
- The main sign-in fields advertise `autocomplete="username webauthn"` for conditional passkey discovery.

### Response and dependency hardening

- Responses receive `nosniff`, `no-referrer`, frame denial, HSTS, a restrictive Permissions Policy, and default `no-store` behavior. HTML gets a deny-by-default CSP.
- `anyhow` was raised from 1.0.102 to 1.0.103 to resolve RUSTSEC-2026-0190.

## Security findings

| Priority | Finding | Current exposure | Required action |
| --- | --- | --- | --- |
| P0 | Route policy is duplicated | Dispatch, known-route, method, CORS, auth, CSRF, cache, and rate-limit decisions are spread across large match statements and handlers. The magic-link poll route initially demonstrated how these lists can drift. | Introduce a single `RouteSpec` registry that generates dispatch/method/CORS policy and declares auth mode, mutation status, CSRF/origin policy, rate-limit family, body limit, and cache policy. Add a table-driven invariant test for every route. |
| P0 | No recent-authentication boundary | A stolen active session can register a passkey, unlink identities, and perform allowed admin/client mutations without proving a recently used authenticator. | Store a recent-auth timestamp and AMR/ACR evidence. Require step-up for authenticator changes, recovery changes, identity unlink, password changes, client-secret operations, and privilege mutations. Prefer a UV passkey when available. |
| P0 | Implicit password signup is enumerable | With `PASSWORD_ALLOW_SIGNUP=true`, an unknown email receives `202 {needConfirm:true}` while a known email with a wrong password receives generic 401. | Remove signup from the login endpoint and use the already generic registration endpoint, or make the entire ceremony indistinguishable until control of the email/account is proven. |
| P0 | Password policy is incomplete | The KDF design is materially improved and the new minimum is 15 characters, but there is no compromised/common-password blocklist and no production Worker benchmark documenting the selected 100,000 PBKDF2 iterations. | Add a bounded local blocklist check and benchmark the exact wasm deployment. Keep at least a 64-character accepted maximum; the current 1,024-byte bound is sufficient. |
| P0 | Bootstrap bearer reaches ordinary admin reads | Ordinary writes reject bootstrap access unless explicitly allowed, but `authorize_admin_request` still accepts the bootstrap bearer for client, user, event, provider, and schema-status reads. The UI also retains the bearer in `sessionStorage`. | Make ordinary admin APIs session-only. Limit bootstrap to schema setup, first-admin creation, and explicitly expiring emergency use. Remove routine token persistence from the browser. |
| P0 | One-time flows are not transactionally closed around all side effects | Conditional updates protect the credential record, but some flows can create an orphan session/user before losing a concurrent consume race. This is primarily integrity/cleanup risk, but it complicates incident reasoning. | Claim one-time records before externally useful side effects, or use a D1 batch/transaction-compatible state machine with `pending -> claimed -> completed`. Add concurrent D1 integration tests. |
| P0 | Security verification is mostly native/unit-level | The suite is broad, but it does not execute passkeys in real browsers, run mutations against deployed D1 semantics, or test two-request races and retry behavior. | Add Miniflare/Wrangler integration tests, Playwright with virtual WebAuthn authenticators, magic-link scanner/double-submit tests, and a small deployed smoke suite. |
| P1 | Passkey/recovery lifecycle is incomplete | Registration and authentication are implemented, but users cannot list, rename, or delete passkeys; there is no last-authenticator guard, recovery code, or loss workflow. | Add `/account/passkeys` list/rename/delete, metadata and last-used display, recent-auth enforcement, last-credential protection, recovery codes, and notifications. |
| P1 | Consent is advertised but not implemented | Discovery and parsing accept `prompt=consent`, but there is no grant store, consent screen, scope-delta logic, or account grant revocation. | Do not advertise consent until grant persistence and UI exist. Revoking a grant must revoke the user's refresh-token families for that client. |
| P1 | Email and identity lifecycle is incomplete | Provider linking/unlinking exists, but verified-email changes, password reset/change, provider-removal safety, and notifications are not a complete account-recovery model. | Model email addresses and authenticators explicitly; require verification and recent auth; prevent removal of the last usable authenticator; notify on security changes. |
| P1 | CSP still permits inline script/style | The new CSP is deny-by-default but includes `'unsafe-inline'` because the UI embeds large scripts, style blocks, inline handlers, and SVG markup. | Move scripts/styles into versioned same-origin assets and use nonces or hashes for any unavoidable bootstrap. Remove inline event handlers. |
| P1 | Dependency audit is not clean | `rsa 0.9.10` triggers RUSTSEC-2023-0071 with no patched release. In this repository it is native/dev-only, used for public-key verification and test signing; the production wasm path uses Web Crypto and has no RSA private key. `paste` and `proc-macro-error2` are unmaintained transitive build dependencies; `spin 0.9.8` is yanked. | Replace the native RSA verifier/test dependency or explicitly target-ignore the advisory with the deployment rationale. Track upstream Leptos/Worker dependency upgrades that remove the informational warnings. Keep CI `cargo audit` active. |
| P2 | Audit events are useful but operationally thin | Events are bounded and secret-conscious, but use free-form detail JSON and have no documented retention, export, correlation ID, alerting, or tamper-evident archival. | Add event schemas/severity, request correlation IDs, retention/export policy, and alerts for replay, bootstrap use, credential changes, and privilege changes. |
| P2 | Cookie scope can be broader than necessary | Sessions support a parent-domain cookie and `SameSite=None` to serve cross-product flows. Secure/HttpOnly and mutation CSRF controls reduce risk, but a parent domain expands the subdomain trust boundary. | Default to host-only cookies; enable parent-domain scope only for documented clients that require it. Continue exact Origin and CSRF enforcement. |

## Passkey implementation assessment

The resulting sign-in protocol is an appropriate passkey baseline for controlled production:

1. Registration generates a random server challenge and opaque user handle, requires a discoverable credential and user verification, verifies RP ID/origin/type/challenge, extracts an ES256 COSE key, and conditionally consumes the challenge.
2. Authentication sends no account-wide credential list, allowing the authenticator to select a discoverable credential. It verifies the credential, user handle, signature, flags, backup semantics, and counter before issuing a session.
3. Conditional mediation is additive. Unsupported browsers retain explicit passkey, password, magic-link, wallet, and provider flows.

Before describing passkeys as a complete account feature, Zeroth still needs lifecycle UI, step-up, recovery, notifications, browser integration tests, and an explicit policy for whether ES256-only support is sufficient for its target authenticators. Attestation set to `none` is a valid consumer-passkey choice; enterprise attestation should only be added for a concrete device-trust requirement.

## UI/UX audit

### Direction

The right target is a technical control plane, not a generic consumer dashboard. It should preserve exact identifiers, scopes, timestamps, redirect URIs, provider evidence, and schema state, while reducing the amount a user must parse at once.

The new section navigation is a meaningful improvement, but the next iteration should make each section a real task surface:

- **Overview:** readiness failures and actions only, not every configuration detail.
- **Applications:** searchable clients, compact redirect/origin summaries, explicit secret rotation state, and a dedicated editor route/drawer.
- **Users:** search/filter, authenticator/session summary, disable status, and a user detail route.
- **Events:** saved filters, severity, correlation IDs, expandable structured JSON, and copy/export.
- **System:** migrations, bindings/readiness, provider diagnostics, key rotation, and deployment-only operations.

### Remaining UX issues

- The 5,000-line UI module embeds duplicated account/admin JavaScript and relies on `window.alert` for important failures. Use inline error summaries associated with the triggering control, preserve technical detail behind disclosure, and keep status in the document.
- Dense tables only degrade to horizontal scrolling. At narrow widths, turn rows into labeled key/value cards or allow users to choose columns.
- Hash tabs are an improvement, but dedicated URLs such as `/admin/clients/:id` and `/admin/users/:id` would make state shareable and reduce fragile client-side orchestration.
- Existing screenshots predate this change and should not be treated as current UX evidence.
- Add keyboard-only, high-zoom, reduced-motion, and automated accessibility checks. Passkey conditional UI needs real-browser coverage rather than string assertions alone.
- Technical users benefit from copy controls, stable timestamps plus relative time, unambiguous empty/loading/error states, and request/event correlation IDs more than decorative dashboard metrics.

## Technical implementation audit

### Strengths

- Security-sensitive bearer values are generally hashed at rest.
- Authorization codes, refresh tokens, challenges, magic links, and passkey challenges have bounded lifetimes and conditional state transitions.
- Public clients require S256 PKCE; redirect and return targets are client-bounded.
- Provider ID tokens validate issuer, audience, nonce, algorithm, and JWKS key.
- Refresh rotation preserves family/session context and reacts to replay by revoking the family.
- D1 lookups are predominantly indexed and cleanup is bounded.
- Readiness distinguishes issuer, key, provider, database, rate-limit, CSRF, admin, and local-auth dependencies without exposing secrets.
- Unit tests cover a broad set of protocol parsing, token, policy, migration, and UI-rendering invariants.

### Maintainability and reliability debt

- `crates/zeroth-worker/src/lib.rs` is over 25,000 lines with roughly 650 functions; `crates/zeroth-ui/src/lib.rs` is over 5,000 lines. Auth policy, persistence, HTTP adaptation, provider code, UI assembly, and tests should be split into modules with narrow interfaces.
- Route metadata is duplicated between `zeroth-server`, Worker dispatch, known paths, CORS paths, and per-handler checks. This is a security boundary, not merely code style.
- SQL migrations have ordered history but no checksum/immutability enforcement, transactional rollout contract, or rollback/forward-compatibility playbook.
- The current Clippy run succeeds with warnings, including high-arity functions and smaller mechanical issues. These are not vulnerabilities, but they reinforce the need to extract typed request/context services.
- No CI workflow was found in the audited tree. A required pipeline should run format, tests, wasm check, Clippy policy, dependency audit, migration smoke tests, and browser auth tests.
- The untracked root file `x` appears to be a concatenated source/repository dump. Its ownership is unclear; inspect and remove or ignore it deliberately before release because repository dumps can accidentally retain sensitive material.

## Feature coverage

| Area | Assessment | Important gap |
| --- | --- | --- |
| OIDC authorization code + PKCE | Strong | Consent/grants and broader conformance testing |
| Upstream Apple/Google/Spotify | Strong | Deployed failure/retry tests and operational alerting |
| Sessions and refresh tokens | Strong core | Recent-auth state, user-facing naming/device detail, bulk revoke |
| Password auth | Partial | Blocklist, production KDF benchmark, recovery/change, implicit-signup enumeration |
| Magic links | Strong baseline | Concurrent D1 state-machine tests and security-change notifications |
| Passkeys | Strong protocol baseline | Lifecycle, recovery, step-up, real-browser tests, algorithm policy |
| EVM wallet auth | Partial | Recovery/identity lifecycle and clearer trust/product policy |
| Account profile/identities | Partial | Verified email lifecycle, last-authenticator guard, notifications |
| Client management | Partial | Recent auth, secret rotation lifecycle, consent policy, dedicated detail UX |
| Admin users/events/system | Partial | Session-only admin policy, correlation/alerts/export, scalable navigation |
| Operations/readiness | Good baseline | CI, deployed smoke tests, migration checksums/runbook, backup/restore exercise |
| Recovery codes/password reset | Missing | Required before password/passkey-only users can safely self-recover |
| Consent/grant management | Missing | Required before advertising `prompt=consent` |

## Recommended delivery order

### Gate 1: unrestricted-production blockers

1. Build the single route-policy registry and generated invariant tests.
2. Add recent-auth/step-up and apply it to every credential, identity, client-secret, and privilege mutation.
3. Separate password signup from login; add the password blocklist and deployed KDF benchmark.
4. Make ordinary admin APIs session-only and constrain bootstrap/emergency use.
5. Close one-time-flow side effects with an explicit D1 state machine and concurrent integration tests.
6. Add Playwright virtual-authenticator coverage and deployed Worker/D1 smoke tests.

### Gate 2: complete the identity product

1. Passkey list/rename/delete, password change/reset, recovery codes, and last-authenticator safety.
2. Verified-email lifecycle and security notifications.
3. Consent/grant storage, consent UI, account grant revocation, and refresh-family revocation.
4. Client-secret rotation and bounded overlap with audit evidence.
5. Structured event severity, correlation IDs, export/retention, and alerts.

### Gate 3: make the technical UI excellent

1. Dedicated admin routes and reusable view/form/data-table components.
2. External scripts/styles with a nonce/hash CSP and no inline handlers.
3. Inline, accessible error handling instead of modal alerts.
4. Responsive user/client/event views, search/filter, copy actions, stable URLs, and explicit loading/empty/error states.
5. Accessibility, keyboard, high-zoom, and browser-auth regression suites; then refresh the repository screenshots.

## Verification evidence

Evidence gathered during this review:

- `cargo test --workspace`: 292 unit tests plus all doc tests passed after the final changes.
- The affected-crate run included 15 storage, 16 UI, 4 server, and 207 Worker tests. A new route-registry assertion exposed a missing magic-link poll entry during development; the entry was added and the full suite then passed.
- `cargo check -p zeroth-worker --target wasm32-unknown-unknown`: passed after the final changes, with four existing dead-code warnings.
- `cargo clippy --workspace --all-targets`: passed with warnings; no lint error stopped the build.
- `npm test` in `workers/gate`: 6/6 passed.
- `cargo audit`: one remaining advisory, RUSTSEC-2023-0071 for native/dev-only `rsa 0.9.10`; informational warnings for unmaintained `paste` and `proc-macro-error2`, plus yanked `spin 0.9.8`. The actionable `anyhow` advisory was fixed.

Release should additionally require the deployed/browser tests identified above.

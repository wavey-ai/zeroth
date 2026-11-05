# zeroth-ui

Leptos UI primitives for hosted Zeroth login and account management.

The crate is intentionally generic. A deployment such as `wavey-id` supplies the
issuer URL, client context, provider state, profile, identities, sessions, and
application list. Zeroth supplies the default components and stylesheet.

The default surface covers the parts of an Auth0-style UI that are useful for
Zeroth now:

- provider login and `/identities/link` actions for Apple, Google, Spotify, and
  custom providers
- hosted `/login` provider links for browser-session SSO as well as OIDC
  `/authorize` provider links
- local profile editing for display name and picture URL
- linked identity display and guarded unlink forms
- browser session display and current-session sign out
- compact OIDC application/client inventory
- client admin editing for issuer token audience and TTL so deployments can
  configure downstream bearer-token minting without code changes
- `/admin` and `/admin/clients` provider readiness, user lifecycle, filtered
  audit event inspection, and registered-client management backed by Zeroth's
  management APIs
- `/admin/tenants` organization settings, Entra or Google Workspace connection
  drafts, application bindings, and separate audit read/export grants
- tenant SCIM endpoint and token-binding configuration, provisioned-user
  admission policy, and Google Directory polling, freshness and manual sync
- audit filters, cursor navigation, and CSV export of the displayed page

It is server-renderable today with `render_account_html` or
`render_account_document` for login/account surfaces, and
`render_clients_admin_html` or `render_clients_admin_document` for the admin
management surface. `zeroth-worker` serves these Leptos documents from `/login`,
`/authorize` provider-selection responses, `/account`, `/admin`, and
`/admin/clients`. `render_tenants_admin_document` selects tenant management in
the same shell at `/admin/tenants`.

Tenant forms accept a deployment secret **binding name**, never the provider
secret value. Configuration presence is distinct from a successful provider
sign-in. Retention days currently record policy metadata; they do not schedule
automatic deletion.

Provisioning settings are separate from tenant metadata. They load only after
the tenant is saved. SCIM can require active provisioned members; disabling that
requirement relaxes admission for unknown corporate identities but preserves
inactive-member tombstones. Google polling can be paused, while its managed
access policy stays enforced and denies online access after the directory
freshness limit. The setup guide is served at `/admin/setup#provisioning`.

The rendered document is intentionally SSR-first. CSS is inline, and provider
actions are ordinary links. A small same-origin form handler is the only
JavaScript. It handles profile saves, identity removal, sign-out, and admin API
calls.

Preview the default surface with:

```sh
cargo run -p zeroth-ui --example preview > target/zeroth-ui-preview.html
```

Preview the administration surface with non-production fixture data:

```sh
cargo run -p zeroth-ui --example admin_preview -- tenants > /tmp/zeroth-polished-admin.html
node crates/zeroth-ui/tests/admin_browser.cjs /tmp/zeroth-polished-admin.html
```

The browser check uses an installed Playwright package and local HTTP fixtures.
Set `PLAYWRIGHT_MODULE` or `CHROMIUM_EXECUTABLE` when those are outside the
default installation. Set `SCREENSHOT_DIR` to choose where desktop and mobile
screenshots are saved. It verifies UI/API contracts, CSRF headers, confirmations,
filtering, paging, and exports; it does not exercise a live identity provider.
It also checks binding-only provisioning writes, source-status isolation when
switching tenants, immutable customer IDs, and completed/failed sync feedback.

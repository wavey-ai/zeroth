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
- `/admin` and `/admin/clients` provider readiness, user lifecycle, filtered
  audit event inspection, and registered-client management backed by Zeroth's
  management APIs

It is server-renderable today with `render_account_html` or
`render_account_document` for login/account surfaces, and
`render_clients_admin_html` or `render_clients_admin_document` for the admin
management surface. `zeroth-worker` serves these Leptos documents from `/login`,
`/authorize` provider-selection responses, `/account`, `/admin`, and
`/admin/clients`.

The rendered document is intentionally SSR-first: CSS is inline, provider
actions are ordinary links, and the only JavaScript is a small same-origin form
handler for profile saves, identity unlinking, sign-out, and admin API calls.

Preview the default surface with:

```sh
cargo run -p zeroth-ui --example preview > target/zeroth-ui-preview.html
```

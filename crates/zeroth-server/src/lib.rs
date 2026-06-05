//! HTTP server boundary for Zeroth.

use zeroth_oidc::OidcIssuer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothServerConfig {
    pub public_base_url: String,
    pub cookie_name: String,
    pub cookie_domain: Option<String>,
    pub transaction_cookie_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
}

pub const ROUTES: &[Route] = &[
    Route {
        method: "GET",
        path: "/health",
    },
    Route {
        method: "GET",
        path: "/api/health",
    },
    Route {
        method: "GET",
        path: "/ready",
    },
    Route {
        method: "GET",
        path: "/status",
    },
    Route {
        method: "GET",
        path: "/api/ready",
    },
    Route {
        method: "GET",
        path: "/api/status",
    },
    Route {
        method: "GET",
        path: "/providers",
    },
    Route {
        method: "GET",
        path: "/api/providers",
    },
    Route {
        method: "GET",
        path: "/providers/status",
    },
    Route {
        method: "GET",
        path: "/api/providers/status",
    },
    Route {
        method: "GET",
        path: "/local-auth/status",
    },
    Route {
        method: "GET",
        path: "/api/local-auth/status",
    },
    Route {
        method: "GET",
        path: "/clients",
    },
    Route {
        method: "POST",
        path: "/clients",
    },
    Route {
        method: "DELETE",
        path: "/clients",
    },
    Route {
        method: "GET",
        path: "/api/clients",
    },
    Route {
        method: "POST",
        path: "/api/clients",
    },
    Route {
        method: "DELETE",
        path: "/api/clients",
    },
    Route {
        method: "GET",
        path: "/users",
    },
    Route {
        method: "PATCH",
        path: "/users",
    },
    Route {
        method: "GET",
        path: "/api/users",
    },
    Route {
        method: "PATCH",
        path: "/api/users",
    },
    Route {
        method: "GET",
        path: "/events",
    },
    Route {
        method: "GET",
        path: "/api/events",
    },
    Route {
        method: "GET",
        path: "/routes",
    },
    Route {
        method: "GET",
        path: "/api/routes",
    },
    Route {
        method: "GET",
        path: "/.well-known/openid-configuration",
    },
    Route {
        method: "GET",
        path: "/.well-known/oauth-authorization-server",
    },
    Route {
        method: "GET",
        path: "/.well-known/jwks.json",
    },
    Route {
        method: "GET",
        path: "/.well-known/apple-app-site-association",
    },
    Route {
        method: "GET",
        path: "/.well-known/assetlinks.json",
    },
    Route {
        method: "GET",
        path: "/favicon.ico",
    },
    Route {
        method: "GET",
        path: "/favicon.svg",
    },
    Route {
        method: "GET",
        path: "/apple-touch-icon.png",
    },
    Route {
        method: "GET",
        path: "/apple-touch-icon-precomposed.png",
    },
    Route {
        method: "GET",
        path: "/apple-touch-icon-{size}.png",
    },
    Route {
        method: "GET",
        path: "/apple-touch-icon-{size}-precomposed.png",
    },
    Route {
        method: "GET",
        path: "/site.webmanifest",
    },
    Route {
        method: "GET",
        path: "/manifest.json",
    },
    Route {
        method: "GET",
        path: "/browserconfig.xml",
    },
    Route {
        method: "GET",
        path: "/robots.txt",
    },
    Route {
        method: "GET",
        path: "/authorize",
    },
    Route {
        method: "GET",
        path: "/providers/{provider}/authorize",
    },
    Route {
        method: "POST",
        path: "/oauth/token",
    },
    Route {
        method: "OPTIONS",
        path: "/oauth/token",
    },
    Route {
        method: "POST",
        path: "/oauth/revoke",
    },
    Route {
        method: "OPTIONS",
        path: "/oauth/revoke",
    },
    Route {
        method: "POST",
        path: "/oauth/introspect",
    },
    Route {
        method: "OPTIONS",
        path: "/oauth/introspect",
    },
    Route {
        method: "GET",
        path: "/userinfo",
    },
    Route {
        method: "OPTIONS",
        path: "/userinfo",
    },
    Route {
        method: "GET",
        path: "/login",
    },
    Route {
        method: "GET",
        path: "/account",
    },
    Route {
        method: "GET",
        path: "/admin",
    },
    Route {
        method: "GET",
        path: "/ui",
    },
    Route {
        method: "GET",
        path: "/dashboard",
    },
    Route {
        method: "GET",
        path: "/console",
    },
    Route {
        method: "GET",
        path: "/admin/clients",
    },
    Route {
        method: "GET",
        path: "/admin/users",
    },
    Route {
        method: "GET",
        path: "/admin/events",
    },
    Route {
        method: "GET",
        path: "/admin/providers",
    },
    Route {
        method: "GET",
        path: "/admin/local-auth",
    },
    Route {
        method: "GET",
        path: "/admin/database",
    },
    Route {
        method: "GET",
        path: "/oauth2/callback",
    },
    Route {
        method: "POST",
        path: "/oauth2/callback",
    },
    Route {
        method: "GET",
        path: "/oauth/callback/{provider}",
    },
    Route {
        method: "POST",
        path: "/oauth/callback/{provider}",
    },
    Route {
        method: "GET",
        path: "/oauth2/callback/{provider}",
    },
    Route {
        method: "POST",
        path: "/oauth2/callback/{provider}",
    },
    Route {
        method: "GET",
        path: "/callback",
    },
    Route {
        method: "POST",
        path: "/callback",
    },
    Route {
        method: "GET",
        path: "/callback/{provider}",
    },
    Route {
        method: "POST",
        path: "/callback/{provider}",
    },
    Route {
        method: "GET",
        path: "/auth/callback",
    },
    Route {
        method: "POST",
        path: "/auth/callback",
    },
    Route {
        method: "GET",
        path: "/auth/callback/{provider}",
    },
    Route {
        method: "POST",
        path: "/auth/callback/{provider}",
    },
    Route {
        method: "GET",
        path: "/api/callback",
    },
    Route {
        method: "POST",
        path: "/api/callback",
    },
    Route {
        method: "GET",
        path: "/api/callback/{provider}",
    },
    Route {
        method: "POST",
        path: "/api/callback/{provider}",
    },
    Route {
        method: "GET",
        path: "/api/auth/callback",
    },
    Route {
        method: "POST",
        path: "/api/auth/callback",
    },
    Route {
        method: "GET",
        path: "/api/auth/callback/{provider}",
    },
    Route {
        method: "POST",
        path: "/api/auth/callback/{provider}",
    },
    Route {
        method: "GET",
        path: "/session",
    },
    Route {
        method: "OPTIONS",
        path: "/session",
    },
    Route {
        method: "GET",
        path: "/sessions",
    },
    Route {
        method: "DELETE",
        path: "/sessions",
    },
    Route {
        method: "OPTIONS",
        path: "/sessions",
    },
    Route {
        method: "GET",
        path: "/profile",
    },
    Route {
        method: "PATCH",
        path: "/profile",
    },
    Route {
        method: "OPTIONS",
        path: "/profile",
    },
    Route {
        method: "GET",
        path: "/identities/link",
    },
    Route {
        method: "OPTIONS",
        path: "/identities/link",
    },
    Route {
        method: "GET",
        path: "/identities",
    },
    Route {
        method: "DELETE",
        path: "/identities",
    },
    Route {
        method: "OPTIONS",
        path: "/identities",
    },
    Route {
        method: "POST",
        path: "/passkeys/register/options",
    },
    Route {
        method: "POST",
        path: "/passkeys/registration/options",
    },
    Route {
        method: "POST",
        path: "/passkeys/register/verify",
    },
    Route {
        method: "POST",
        path: "/passkeys/register/finish",
    },
    Route {
        method: "POST",
        path: "/passkeys/registration/finish",
    },
    Route {
        method: "POST",
        path: "/passkeys/authenticate/options",
    },
    Route {
        method: "POST",
        path: "/passkeys/authentication/options",
    },
    Route {
        method: "POST",
        path: "/passkeys/authenticate/verify",
    },
    Route {
        method: "POST",
        path: "/passkeys/authenticate/finish",
    },
    Route {
        method: "POST",
        path: "/passkeys/authentication/finish",
    },
    Route {
        method: "POST",
        path: "/passkeys/login/options",
    },
    Route {
        method: "POST",
        path: "/passkeys/login/verify",
    },
    Route {
        method: "POST",
        path: "/passkeys/login/finish",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/register/options",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/registration/options",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/register/verify",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/registration/verify",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/register/finish",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/registration/finish",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/authenticate/options",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/authentication/options",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/authenticate/verify",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/authentication/verify",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/authenticate/finish",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/authentication/finish",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/login/options",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/login/verify",
    },
    Route {
        method: "POST",
        path: "/api/passkeys/login/finish",
    },
    Route {
        method: "POST",
        path: "/password/register",
    },
    Route {
        method: "GET",
        path: "/password/register",
    },
    Route {
        method: "OPTIONS",
        path: "/password/register",
    },
    Route {
        method: "POST",
        path: "/api/password/register",
    },
    Route {
        method: "GET",
        path: "/api/password/register",
    },
    Route {
        method: "OPTIONS",
        path: "/api/password/register",
    },
    Route {
        method: "POST",
        path: "/auth/password/register",
    },
    Route {
        method: "GET",
        path: "/auth/password/register",
    },
    Route {
        method: "OPTIONS",
        path: "/auth/password/register",
    },
    Route {
        method: "POST",
        path: "/api/auth/password/register",
    },
    Route {
        method: "GET",
        path: "/api/auth/password/register",
    },
    Route {
        method: "OPTIONS",
        path: "/api/auth/password/register",
    },
    Route {
        method: "POST",
        path: "/local-auth/password/register",
    },
    Route {
        method: "GET",
        path: "/local-auth/password/register",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/password/register",
    },
    Route {
        method: "POST",
        path: "/password/login",
    },
    Route {
        method: "GET",
        path: "/password/login",
    },
    Route {
        method: "OPTIONS",
        path: "/password/login",
    },
    Route {
        method: "POST",
        path: "/api/password/login",
    },
    Route {
        method: "GET",
        path: "/api/password/login",
    },
    Route {
        method: "OPTIONS",
        path: "/api/password/login",
    },
    Route {
        method: "POST",
        path: "/auth/password/login",
    },
    Route {
        method: "GET",
        path: "/auth/password/login",
    },
    Route {
        method: "OPTIONS",
        path: "/auth/password/login",
    },
    Route {
        method: "POST",
        path: "/api/auth/password/login",
    },
    Route {
        method: "GET",
        path: "/api/auth/password/login",
    },
    Route {
        method: "OPTIONS",
        path: "/api/auth/password/login",
    },
    Route {
        method: "POST",
        path: "/local-auth/password/login",
    },
    Route {
        method: "GET",
        path: "/local-auth/password/login",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/password/login",
    },
    Route {
        method: "POST",
        path: "/magic-links",
    },
    Route {
        method: "GET",
        path: "/magic-links",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-links",
    },
    Route {
        method: "POST",
        path: "/magic-link",
    },
    Route {
        method: "GET",
        path: "/magic-link",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-link",
    },
    Route {
        method: "POST",
        path: "/magic-link/send",
    },
    Route {
        method: "GET",
        path: "/magic-link/send",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-link/send",
    },
    Route {
        method: "POST",
        path: "/magic_link",
    },
    Route {
        method: "GET",
        path: "/magic_link",
    },
    Route {
        method: "OPTIONS",
        path: "/magic_link",
    },
    Route {
        method: "POST",
        path: "/magic-links/request",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-links/request",
    },
    Route {
        method: "POST",
        path: "/magic-link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-link/request",
    },
    Route {
        method: "POST",
        path: "/magic_link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/magic_link/request",
    },
    Route {
        method: "POST",
        path: "/api/magic-links",
    },
    Route {
        method: "GET",
        path: "/api/magic-links",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-links",
    },
    Route {
        method: "POST",
        path: "/api/magic-link",
    },
    Route {
        method: "GET",
        path: "/api/magic-link",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-link",
    },
    Route {
        method: "POST",
        path: "/api/magic-link/send",
    },
    Route {
        method: "GET",
        path: "/api/magic-link/send",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-link/send",
    },
    Route {
        method: "POST",
        path: "/auth/magic-link/send",
    },
    Route {
        method: "GET",
        path: "/auth/magic-link/send",
    },
    Route {
        method: "OPTIONS",
        path: "/auth/magic-link/send",
    },
    Route {
        method: "POST",
        path: "/api/auth/magic-link/send",
    },
    Route {
        method: "GET",
        path: "/api/auth/magic-link/send",
    },
    Route {
        method: "OPTIONS",
        path: "/api/auth/magic-link/send",
    },
    Route {
        method: "POST",
        path: "/api/magic_link",
    },
    Route {
        method: "GET",
        path: "/api/magic_link",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic_link",
    },
    Route {
        method: "POST",
        path: "/api/magic-links/request",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-links/request",
    },
    Route {
        method: "POST",
        path: "/api/magic-link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-link/request",
    },
    Route {
        method: "POST",
        path: "/api/magic_link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic_link/request",
    },
    Route {
        method: "POST",
        path: "/auth/magic-link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/auth/magic-link/request",
    },
    Route {
        method: "POST",
        path: "/api/auth/magic-link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/api/auth/magic-link/request",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic-links",
    },
    Route {
        method: "GET",
        path: "/local-auth/magic-links",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic-links",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic-link",
    },
    Route {
        method: "GET",
        path: "/local-auth/magic-link",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic-link",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic_link",
    },
    Route {
        method: "GET",
        path: "/local-auth/magic_link",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic_link",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic-links/request",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic-links/request",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic-link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic-link/request",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic_link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic_link/request",
    },
    Route {
        method: "POST",
        path: "/api/local-auth/magic-link/request",
    },
    Route {
        method: "OPTIONS",
        path: "/api/local-auth/magic-link/request",
    },
    Route {
        method: "GET",
        path: "/magic-links/consume",
    },
    Route {
        method: "POST",
        path: "/magic-links/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-links/consume",
    },
    Route {
        method: "GET",
        path: "/magic-link/consume",
    },
    Route {
        method: "POST",
        path: "/magic-link/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/magic-link/consume",
    },
    Route {
        method: "GET",
        path: "/magic_link/consume",
    },
    Route {
        method: "POST",
        path: "/magic_link/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/magic_link/consume",
    },
    Route {
        method: "GET",
        path: "/api/magic-links/consume",
    },
    Route {
        method: "POST",
        path: "/api/magic-links/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-links/consume",
    },
    Route {
        method: "GET",
        path: "/api/magic-link/consume",
    },
    Route {
        method: "POST",
        path: "/api/magic-link/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic-link/consume",
    },
    Route {
        method: "GET",
        path: "/api/magic_link/consume",
    },
    Route {
        method: "POST",
        path: "/api/magic_link/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/api/magic_link/consume",
    },
    Route {
        method: "GET",
        path: "/local-auth/magic-links/consume",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic-links/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic-links/consume",
    },
    Route {
        method: "GET",
        path: "/local-auth/magic-link/consume",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic-link/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic-link/consume",
    },
    Route {
        method: "GET",
        path: "/local-auth/magic_link/consume",
    },
    Route {
        method: "POST",
        path: "/local-auth/magic_link/consume",
    },
    Route {
        method: "OPTIONS",
        path: "/local-auth/magic_link/consume",
    },
    Route {
        method: "GET",
        path: "/validate",
    },
    Route {
        method: "OPTIONS",
        path: "/validate",
    },
    Route {
        method: "GET",
        path: "/logout",
    },
    Route {
        method: "POST",
        path: "/logout",
    },
    Route {
        method: "OPTIONS",
        path: "/logout",
    },
    Route {
        method: "GET",
        path: "/__zeroth/db/status",
    },
    Route {
        method: "GET",
        path: "/api/__zeroth/db/status",
    },
    Route {
        method: "POST",
        path: "/__zeroth/db/ensure",
    },
];

impl ZerothServerConfig {
    pub fn issuer(&self) -> OidcIssuer {
        OidcIssuer::from_base_url(&self.public_base_url)
    }
}

impl Default for ZerothServerConfig {
    fn default() -> Self {
        Self {
            public_base_url: "http://localhost:8080".to_owned(),
            cookie_name: "zeroth_session".to_owned(),
            cookie_domain: None,
            transaction_cookie_name: "zeroth_tx".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ROUTES;

    #[test]
    fn routes_include_admin_db_status_preflight() {
        assert!(ROUTES
            .iter()
            .any(|route| route.method == "GET" && route.path == "/__zeroth/db/status"));
    }

    #[test]
    fn routes_include_favicon_assets() {
        for path in [
            "/favicon.ico",
            "/favicon.svg",
            "/apple-touch-icon.png",
            "/apple-touch-icon-precomposed.png",
            "/apple-touch-icon-{size}.png",
            "/apple-touch-icon-{size}-precomposed.png",
            "/.well-known/assetlinks.json",
            "/site.webmanifest",
            "/manifest.json",
            "/browserconfig.xml",
            "/robots.txt",
        ] {
            assert!(ROUTES
                .iter()
                .any(|route| route.method == "GET" && route.path == path));
        }
    }

    #[test]
    fn routes_include_first_party_auth_endpoints() {
        for (method, path) in [
            ("GET", "/local-auth/status"),
            ("GET", "/password/register"),
            ("POST", "/password/register"),
            ("GET", "/password/login"),
            ("POST", "/password/login"),
            ("GET", "/magic-links"),
            ("POST", "/magic-links"),
            ("GET", "/magic-links/consume"),
            ("POST", "/magic-links/consume"),
        ] {
            assert!(ROUTES
                .iter()
                .any(|route| route.method == method && route.path == path));
        }
    }

    #[test]
    fn routes_include_compatibility_aliases() {
        for (method, path) in [
            ("GET", "/api/health"),
            ("GET", "/status"),
            ("GET", "/api/ready"),
            ("GET", "/api/status"),
            ("GET", "/api/providers"),
            ("GET", "/api/providers/status"),
            ("GET", "/api/local-auth/status"),
            ("GET", "/api/routes"),
            ("GET", "/api/clients"),
            ("POST", "/api/clients"),
            ("DELETE", "/api/clients"),
            ("GET", "/api/users"),
            ("PATCH", "/api/users"),
            ("GET", "/api/events"),
            ("GET", "/api/__zeroth/db/status"),
            ("GET", "/ui"),
            ("GET", "/dashboard"),
            ("GET", "/console"),
            ("GET", "/admin/users"),
            ("GET", "/admin/events"),
            ("GET", "/admin/providers"),
            ("GET", "/admin/local-auth"),
            ("GET", "/admin/database"),
            ("GET", "/providers/{provider}/authorize"),
            ("GET", "/oauth/callback/{provider}"),
            ("POST", "/oauth/callback/{provider}"),
            ("GET", "/callback"),
            ("POST", "/callback"),
            ("GET", "/callback/{provider}"),
            ("POST", "/callback/{provider}"),
            ("GET", "/auth/callback"),
            ("POST", "/auth/callback"),
            ("GET", "/auth/callback/{provider}"),
            ("POST", "/auth/callback/{provider}"),
            ("GET", "/api/callback"),
            ("POST", "/api/callback"),
            ("GET", "/api/callback/{provider}"),
            ("POST", "/api/callback/{provider}"),
            ("GET", "/api/auth/callback"),
            ("POST", "/api/auth/callback"),
            ("GET", "/api/auth/callback/{provider}"),
            ("POST", "/api/auth/callback/{provider}"),
            ("POST", "/passkeys/registration/options"),
            ("POST", "/passkeys/registration/finish"),
            ("POST", "/passkeys/authentication/options"),
            ("POST", "/passkeys/authentication/finish"),
            ("POST", "/passkeys/login/options"),
            ("POST", "/passkeys/login/verify"),
            ("POST", "/passkeys/login/finish"),
            ("POST", "/api/passkeys/register/options"),
            ("POST", "/api/passkeys/registration/options"),
            ("POST", "/api/passkeys/registration/verify"),
            ("POST", "/api/passkeys/registration/finish"),
            ("POST", "/api/passkeys/authenticate/options"),
            ("POST", "/api/passkeys/authentication/options"),
            ("POST", "/api/passkeys/authentication/verify"),
            ("POST", "/api/passkeys/authentication/finish"),
            ("POST", "/api/passkeys/login/options"),
            ("GET", "/magic-link"),
            ("POST", "/magic-link"),
            ("GET", "/magic_link"),
            ("POST", "/magic_link"),
            ("POST", "/magic-links/request"),
            ("POST", "/magic-link/request"),
            ("POST", "/magic_link/request"),
            ("GET", "/api/password/login"),
            ("POST", "/api/password/login"),
            ("GET", "/auth/password/login"),
            ("POST", "/auth/password/login"),
            ("GET", "/api/auth/password/login"),
            ("POST", "/api/auth/password/login"),
            ("GET", "/local-auth/password/login"),
            ("POST", "/local-auth/password/login"),
            ("GET", "/api/magic-links"),
            ("POST", "/api/magic-links"),
            ("GET", "/magic-link/send"),
            ("POST", "/magic-link/send"),
            ("GET", "/api/magic-link/send"),
            ("POST", "/api/magic-link/send"),
            ("GET", "/auth/magic-link/send"),
            ("POST", "/auth/magic-link/send"),
            ("GET", "/api/auth/magic-link/send"),
            ("POST", "/api/auth/magic-link/send"),
            ("GET", "/api/magic_link"),
            ("POST", "/api/magic_link"),
            ("POST", "/api/magic-link/request"),
            ("POST", "/api/magic_link/request"),
            ("POST", "/auth/magic-link/request"),
            ("POST", "/api/auth/magic-link/request"),
            ("GET", "/local-auth/magic-links"),
            ("POST", "/local-auth/magic-links"),
            ("GET", "/local-auth/magic_link"),
            ("POST", "/local-auth/magic_link"),
            ("POST", "/local-auth/magic-link/request"),
            ("POST", "/local-auth/magic_link/request"),
            ("POST", "/api/local-auth/magic-link/request"),
            ("GET", "/magic-link/consume"),
            ("POST", "/magic-link/consume"),
            ("GET", "/magic_link/consume"),
            ("POST", "/magic_link/consume"),
            ("GET", "/api/magic-links/consume"),
            ("POST", "/api/magic-links/consume"),
            ("GET", "/api/magic_link/consume"),
            ("POST", "/api/magic_link/consume"),
            ("GET", "/local-auth/magic-links/consume"),
            ("POST", "/local-auth/magic-links/consume"),
            ("GET", "/local-auth/magic_link/consume"),
            ("POST", "/local-auth/magic_link/consume"),
        ] {
            assert!(ROUTES
                .iter()
                .any(|route| route.method == method && route.path == path));
        }
    }
}

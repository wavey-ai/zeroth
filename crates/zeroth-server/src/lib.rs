//! HTTP server boundary for Zeroth.

use zeroth_oidc::OidcIssuer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothServerConfig {
    pub public_base_url: String,
    pub cookie_name: String,
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
        path: "/ready",
    },
    Route {
        method: "GET",
        path: "/providers",
    },
    Route {
        method: "GET",
        path: "/providers/status",
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
        path: "/users",
    },
    Route {
        method: "PATCH",
        path: "/users",
    },
    Route {
        method: "GET",
        path: "/events",
    },
    Route {
        method: "GET",
        path: "/routes",
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
        path: "/authorize",
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
        path: "/admin/clients",
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
}

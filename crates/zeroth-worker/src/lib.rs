#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use k256::ecdsa::{
    RecoveryId as EvmRecoveryId, Signature as EvmSignature, VerifyingKey as EvmVerifyingKey,
};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
#[cfg(any(test, not(target_arch = "wasm32")))]
use rsa::{
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey},
    BigUint, RsaPublicKey,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{borrow::Cow, collections::BTreeMap};
use zeroth_core::{AuthTransaction, Client, ClientId, ProviderId, ScopeSet, Subject, UserId};
#[cfg(target_arch = "wasm32")]
use zeroth_core::{
    PasswordScheme, PASSWORD_CURRENT_VERSION, PASSWORD_PBKDF2_MAX_ITERATIONS,
    PASSWORD_PBKDF2_MIN_ITERATIONS,
};
use zeroth_core::{PASSWORD_PBKDF2_ITERATIONS, PASSWORD_SCHEME_PBKDF2_SHA256};
use zeroth_oidc::authorization_request_redirect_uri_registered_for_client;
#[cfg(target_arch = "wasm32")]
use zeroth_oidc::parse_authorization_request;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_oidc::validate_authorization_request_for_client;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_oidc::AuthorizationPrompt;
use zeroth_oidc::{AuthorizationRequest, AuthorizationRequestError};
use zeroth_oidc::{
    ZerothIssuedAccessTokenClaims, ZerothJwk, ZerothJwks, ZerothJwtClaims, ZerothTokenUse,
    ZerothTokenValidation,
};
use zeroth_providers::well_known;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_providers::TokenAuth;
use zeroth_providers::{
    ProviderProfile, ProviderProfileSource, ProviderTokenSet, TokenExchangeRequest,
};
use zeroth_server::ZerothServerConfig;
#[cfg(target_arch = "wasm32")]
use zeroth_ui::{render_account_document, ZerothUiState};
#[cfg(target_arch = "wasm32")]
use zeroth_ui::{render_clients_admin_document, ClientsAdminUiState};
use zeroth_ui::{
    ApplicationUi, ClientAdminUi, EventAdminUi, IdentityUi, ProfileUi, ProviderKind, ProviderUi,
    SessionUi, UserAdminUi, ZerothUiConfig, ZerothUiTheme,
};
#[cfg(target_arch = "wasm32")]
use zeroth_ui::{
    LocalAuthAdminUi, LocalAuthDeliveryAdminUi, ProviderAdminUi, ProviderFailureAdminUi,
};

#[cfg(target_arch = "wasm32")]
use zeroth_providers::{OAuthProvider, Provider, ProviderAuthorizeRequest};

#[cfg(target_arch = "wasm32")]
use zeroth_server::ROUTES;

pub const D1_BINDING: &str = "ZEROTH_DB";
const AUTH_TRANSACTION_TTL_SECONDS: i32 = 10 * 60;
const AUTH_CODE_TTL_SECONDS: i32 = 10 * 60;
const ACCESS_TOKEN_TTL_SECONDS: i32 = 60 * 60;
const ID_TOKEN_TTL_SECONDS: i32 = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS: i32 = 60 * 60 * 24 * 30;
const SESSION_TTL_SECONDS: i32 = 60 * 60 * 24 * 30;
const AUTH_TRANSACTION_CLEANUP_LIMIT: i32 = 64;
const CORS_ORIGIN_SCAN_LIMIT: i32 = 256;
const CLIENT_LIST_LIMIT: i32 = 256;
const CLIENT_MANAGEMENT_BODY_LIMIT: usize = 8 * 1024;
const CLIENT_ID_MAX_CHARS: usize = 128;
const CLIENT_NAME_MAX_CHARS: usize = 128;
const CLIENT_URI_MAX_BYTES: usize = 2048;
const CLIENT_URI_LIST_LIMIT: usize = 32;
const CLIENT_EMAIL_DOMAIN_MAX_BYTES: usize = 253;
const CLIENT_ACCOUNT_TENANT_ID_MAX_CHARS: usize = 128;
const LOGIN_METHOD_PASSKEY: &str = "passkey";
const LOGIN_METHOD_MAGIC_LINK: &str = "magic_link";
const ACCOUNT_SHARING_MODE_GLOBAL: &str = "global";
const ACCOUNT_SHARING_MODE_TENANT: &str = "tenant";
const ACCOUNT_SHARING_MODE_CLIENT: &str = "client";
const ACCOUNT_NAMESPACE_GLOBAL: &str = "global";
const USER_LIST_LIMIT: i32 = 100;
const USER_MANAGEMENT_BODY_LIMIT: usize = 1024;
const USER_ID_MAX_CHARS: usize = 128;
const AUDIT_EVENT_LIST_LIMIT: i32 = 100;
const AUDIT_EVENT_TYPE_MAX_CHARS: usize = 96;
const AUDIT_EVENT_DETAILS_MAX_BYTES: usize = 1024;
const PROVIDER_FAILURE_EVENT_LIST_LIMIT: i32 = 30;
const PROVIDER_FAILURE_CODE_MAX_CHARS: usize = 96;
const PROVIDER_FAILURE_DESCRIPTION_MAX_CHARS: usize = 240;
const SESSION_LIST_LIMIT: i32 = 100;
const IDENTITY_LIST_LIMIT: i32 = 16;
const PASSKEY_CHALLENGE_TTL_SECONDS: i32 = 5 * 60;
const PASSKEY_CHALLENGE_CLEANUP_LIMIT: i32 = 64;
const PASSKEY_CREDENTIAL_LIST_LIMIT: i32 = 64;
const PASSKEY_BODY_LIMIT: usize = 16 * 1024;
const PASSKEY_LABEL_MAX_CHARS: usize = 128;
const PASSKEY_EMAIL_MAX_BYTES: usize = 320;
const EVM_WALLET_PROVIDER_ID: &str = "wallet_evm";
const EVM_WALLET_CHALLENGE_TTL_SECONDS: i32 = 5 * 60;
const EVM_WALLET_CHALLENGE_CLEANUP_LIMIT: i32 = 64;
const EVM_WALLET_BODY_LIMIT: usize = 8 * 1024;
const EVM_WALLET_MESSAGE_MAX_BYTES: usize = 2048;
const EVM_WALLET_SIGNATURE_HEX_BYTES: usize = 65;
const LOCAL_AUTH_BODY_LIMIT: usize = 8 * 1024;
const LOCAL_AUTH_PROVIDER_ID: &str = "zeroth";
const PASSWORD_MIN_BYTES: usize = 8;
const PASSWORD_MAX_BYTES: usize = 1024;
const PASSWORD_PEPPER_ENV: &str = "PASSWORD_PEPPER";
const PASSWORD_PEPPER_ID_ENV: &str = "PASSWORD_PEPPER_ID";
const PASSWORD_PEPPER_PREVIOUS_ENV: &str = "PASSWORD_PEPPER_PREVIOUS";
const PASSWORD_PEPPER_PREVIOUS_ID_ENV: &str = "PASSWORD_PEPPER_PREVIOUS_ID";
const RATE_LIMIT_KEY_ENV: &str = "RATE_LIMIT_KEY";
const CSRF_SECRET_ENV: &str = "CSRF_SECRET";
const PASSWORD_PBKDF2_ALG: &str = PASSWORD_SCHEME_PBKDF2_SHA256;
const PASSWORD_DUMMY_SALT: &str = "f1a2c3d4e5b60718293a4b5c6d7e8f90";
const PASSWORD_DUMMY_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const MAGIC_LINK_TTL_SECONDS: i32 = 10 * 60;
const MAGIC_LINK_CLEANUP_LIMIT: i32 = 64;
const MAGIC_LINK_EMAIL_ERROR_DETAIL_MAX_CHARS: usize = 160;
const MAGIC_LINK_DELIVERY_CLOUDFLARE_EMAIL: &str = "cloudflare_email";
const MAGIC_LINK_DELIVERY_WEBHOOK: &str = "webhook";
const MAGIC_LINK_DELIVERY_RESEND: &str = "resend";
const MAGIC_LINK_DELIVERY_MAILCHANNELS: &str = "mailchannels";
const MAGIC_LINK_DELIVERY_UNSUPPORTED: &str = "unsupported";
const PROFILE_PATCH_BODY_LIMIT: usize = 4 * 1024;
const PROFILE_NAME_MAX_CHARS: usize = 128;
const PROFILE_PICTURE_MAX_BYTES: usize = 2048;
const RATE_LIMIT_CLEANUP_MODULUS: u8 = 100;
const RATE_LIMIT_CLEANUP_LIMIT: i32 = 100;
const RATE_LIMIT_RETENTION_SECONDS: i32 = 48 * 60 * 60;
const RATE_LIMIT_BLOCK_STEPS_SECONDS: [i32; 4] = [60, 5 * 60, 15 * 60, 60 * 60];
const RATE_LIMIT_SCOPE_PASSWORD_LOGIN_IP: &str = "password_login:ip";
const RATE_LIMIT_SCOPE_PASSWORD_LOGIN_EMAIL: &str = "password_login:email";
const RATE_LIMIT_SCOPE_PASSWORD_LOGIN_IP_EMAIL: &str = "password_login:ip_email";
const RATE_LIMIT_SCOPE_PASSWORD_REGISTER_IP: &str = "password_register:ip";
const RATE_LIMIT_SCOPE_PASSWORD_REGISTER_EMAIL: &str = "password_register:email";
const RATE_LIMIT_SCOPE_MAGIC_LINK_REQUEST_IP: &str = "magic_link_request:ip";
const RATE_LIMIT_SCOPE_MAGIC_LINK_REQUEST_EMAIL: &str = "magic_link_request:email";
const RATE_LIMIT_SCOPE_MAGIC_LINK_REQUEST_CLIENT: &str = "magic_link_request:client";
const RATE_LIMIT_SCOPE_MAGIC_LINK_CONSUME_IP: &str = "magic_link_consume:ip";
const RATE_LIMIT_SCOPE_MAGIC_LINK_CONSUME_TOKEN: &str = "magic_link_consume:token";
const RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_IP: &str = "passkey_options:ip";
const RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_CLIENT: &str = "passkey_options:client";
const RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_EMAIL: &str = "passkey_options:email";
const RATE_LIMIT_SCOPE_PASSKEY_VERIFY_IP: &str = "passkey_verify:ip";
const RATE_LIMIT_SCOPE_PASSKEY_VERIFY_CREDENTIAL: &str = "passkey_verify:credential";
const RATE_LIMIT_SCOPE_WALLET_CHALLENGE_IP: &str = "wallet_challenge:ip";
const RATE_LIMIT_SCOPE_WALLET_CHALLENGE_ADDRESS: &str = "wallet_challenge:address";
const RATE_LIMIT_SCOPE_WALLET_CHALLENGE_CLIENT: &str = "wallet_challenge:client";
const RATE_LIMIT_SCOPE_WALLET_VERIFY_IP: &str = "wallet_verify:ip";
const RATE_LIMIT_SCOPE_WALLET_VERIFY_ADDRESS: &str = "wallet_verify:address";
const RATE_LIMIT_SCOPE_WALLET_VERIFY_CHALLENGE: &str = "wallet_verify:challenge";
const RATE_LIMIT_SCOPE_OAUTH_TOKEN_IP: &str = "oauth_token:ip";
const RATE_LIMIT_SCOPE_OAUTH_TOKEN_CLIENT: &str = "oauth_token:client";
const RATE_LIMIT_SCOPE_OAUTH_TOKEN_GRANT: &str = "oauth_token:grant";
const CSRF_ROUTE_FAMILY_ACCOUNT: &str = "account";
const CSRF_ROUTE_FAMILY_ADMIN: &str = "admin";
const CSRF_ROUTE_FAMILY_LOGOUT: &str = "logout";
const CSRF_ROUTE_FAMILY_MAGIC_LINK_CONFIRM: &str = "magic-link-confirm";
const MAGIC_LINK_CONFIRM_TOKEN_FIELD: &str = "confirm";
const PUBLIC_LOCAL_AUTH_RESPONSE_MESSAGE: &str =
    "If this account can use this method, the next step has been initiated.";
const ADMIN_BOOTSTRAP_EMERGENCY_ENV: &str = "ADMIN_BOOTSTRAP_EMERGENCY";
const ADMIN_BOOTSTRAP_EMERGENCY_EXPIRES_AT_ENV: &str = "ADMIN_BOOTSTRAP_EMERGENCY_EXPIRES_AT";
const APPLE_CLIENT_SECRET_DEFAULT_TTL_SECONDS: i64 = 60 * 60 * 24 * 180;
const APPLE_CLIENT_SECRET_MAX_TTL_SECONDS: i64 = 60 * 60 * 24 * 180;
const APPLE_CLIENT_SECRET_CACHE_REFRESH_SECONDS: i64 = 60 * 60;
const PROVIDER_JWKS_CACHE_TTL_SECONDS: i32 = 60 * 60;
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ID_TOKEN_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
const ACCESS_TOKEN_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const DEFAULT_NATIVE_TOKEN_SCOPE: &str = "openid profile email";
const CORS_ALLOW_METHODS: &str = "GET, POST, PATCH, DELETE, OPTIONS";
const CORS_ALLOW_HEADERS: &str = "Authorization, Content-Type, X-Zeroth-Token-Purpose";
const CORS_MAX_AGE_SECONDS: &str = "600";
const ZEROTH_FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#2d333b"/><stop offset="0.58" stop-color="#1f2328"/><stop offset="1" stop-color="#0b0f19"/></linearGradient></defs><rect width="64" height="64" rx="12" fill="url(#g)"/><path d="M17 16h30L25 48h25" fill="none" stroke="#f9fafb" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;
const ZEROTH_PROFILE_MENU_JS: &str = r###"
(() => {
  const ZEROTH_COOKIE_NAME = "zeroth";
  const ZEROTH_COOKIE_MAX_AGE_SECONDS = 31536000;
  const ZEROTH_COOKIE_ICON_MAX_CHARS = 1800;
  const ZEROTH_LOCAL_ICON_PREFIX = "zeroth:userIcon:";
  const scriptOrigin = document.currentScript && document.currentScript.src
    ? new URL(document.currentScript.src, window.location.href).origin
    : "";
  const defaultIssuer = () => scriptOrigin || window.location.origin;
  const text = (value) => value == null || value === "" ? "-" : String(value);
  const esc = (value) => text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
  const first = (object, names) => {
    for (const name of names) {
      if (object && object[name] != null && object[name] !== "") return object[name];
    }
    return "";
  };
  const attr = (host, name) => host && host.getAttribute ? host.getAttribute(name) || "" : "";
  const boolAttr = (host, name, fallback = false) => {
    const value = attr(host, name);
    if (!value) return fallback;
    return !["0", "false", "no", "off"].includes(value.toLowerCase());
  };
  const boolOption = (value, fallback = false) => {
    if (value == null) return fallback;
    if (typeof value === "boolean") return value;
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) return fallback;
    return !["0", "false", "no", "off"].includes(normalized);
  };
  const compactMenuOption = (options, host) => {
    if (options.compact != null) return boolOption(options.compact);
    const variant = String(options.variant || attr(host, "variant") || attr(host, "data-variant") || "").trim().toLowerCase();
    if (variant === "compact") return true;
    if (host && typeof host.hasAttribute === "function") {
      if (host.hasAttribute("compact")) return boolAttr(host, "compact", true);
      if (host.hasAttribute("data-compact")) return boolAttr(host, "data-compact", true);
    }
    return false;
  };
  const trimSlash = (value) => String(value || "").replace(/\/+$/, "");
  const endpoint = (issuer, value, fallback) => new URL(value || fallback, trimSlash(issuer) + "/").toString();
  const clean = (value) => value == null ? "" : String(value).trim();
  const labelInitial = (label, fallback = "Z") => {
    const value = text(label || fallback).trim();
    return esc((value && value[0] ? value[0] : fallback).toUpperCase());
  };
  const initial = (user) => {
    return labelInitial(first(user, ["name", "email", "sub"]) || "Z");
  };
  const decode = (value) => {
    try { return decodeURIComponent(String(value || "").replaceAll("+", "%20")); } catch (_) { return String(value || ""); }
  };
  const cookieValue = (name) => {
    const parts = String(document.cookie || "").split(";");
    for (const part of parts) {
      const index = part.indexOf("=");
      const current = (index >= 0 ? part.slice(0, index) : part).trim();
      if (current !== name) continue;
      return decode(index >= 0 ? part.slice(index + 1) : "");
    }
    return "";
  };
  const readZerothCookie = () => {
    const raw = cookieValue(ZEROTH_COOKIE_NAME);
    if (!raw) return null;
    try {
      const value = JSON.parse(raw);
      return value && typeof value === "object" ? value : null;
    } catch (_) {
      const params = new URLSearchParams(raw);
      return Object.fromEntries(params.entries());
    }
  };
  const nowSeconds = () => Math.floor(Date.now() / 1000);
  const randomId = () => {
    if (window.crypto && typeof crypto.randomUUID === "function") return crypto.randomUUID();
    const bytes = new Uint8Array(16);
    if (window.crypto && typeof crypto.getRandomValues === "function") {
      crypto.getRandomValues(bytes);
    } else {
      for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256);
    }
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  };
  const stableNumber = (value, fallback) => {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
  };
  const imageUrl = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return "";
    if (/^data:image\/(?:png|jpe?g|gif|webp|svg\+xml);/i.test(raw)) return raw;
    try {
      const url = new URL(raw, window.location.href);
      return ["http:", "https:"].includes(url.protocol) ? url.toString() : "";
    } catch (_) {
      return "";
    }
  };
  const normalizeZerothCookie = (value = {}) => {
    const now = nowSeconds();
    const createdAt = stableNumber(value.createdAt, now);
    return {
      v: 1,
      anonId: clean(value.anonId || value.anonymousId || value.id) || randomId(),
      clientId: clean(value.clientId),
      name: clean(value.name || value.label || value.displayName),
      nameSource: ["user", "brand"].includes(clean(value.nameSource)) ? clean(value.nameSource) : "",
      icon: imageUrl(value.icon || value.iconUrl || value.picture || value.pictureUrl || ""),
      userIcon: imageUrl(value.userIcon || value.userIconUrl || value.avatarIcon || value.avatar || ""),
      userIconKey: clean(value.userIconKey || value.avatarIconKey || ""),
      createdAt,
      updatedAt: now,
    };
  };
  const writeZerothCookie = (identity) => {
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${ZEROTH_COOKIE_NAME}=${encodeURIComponent(JSON.stringify(identity))}; Path=/; Max-Age=${ZEROTH_COOKIE_MAX_AGE_SECONDS}; SameSite=Lax${secure}`;
  };
  const expireZerothCookie = () => {
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${ZEROTH_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Lax${secure}`;
  };
  const userIconStorageKey = (identity) => `${ZEROTH_LOCAL_ICON_PREFIX}${clean(identity && identity.anonId) || randomId()}`;
  const storageGet = (key) => {
    try { return key ? window.localStorage.getItem(key) || "" : ""; } catch (_) { return ""; }
  };
  const storageSet = (key, value) => {
    try { if (key) window.localStorage.setItem(key, value); return true; } catch (_) { return false; }
  };
  const storageRemove = (key) => {
    try { if (key) window.localStorage.removeItem(key); } catch (_) {}
  };
  const identityUserIcon = (identity) => {
    if (!identity) return "";
    return imageUrl(identity.userIcon || storageGet(identity.userIconKey));
  };
  const mergeZerothCookie = (patch = {}) => {
    const current = normalizeZerothCookie(readZerothCookie() || {});
    const nextPatch = { ...patch };
    if (current.nameSource === "user" && nextPatch.name && nextPatch.nameSource !== "user") {
      delete nextPatch.name;
      delete nextPatch.nameSource;
    }
    let next = normalizeZerothCookie({ ...current, ...nextPatch });
    if (next.userIcon && next.userIcon.length > ZEROTH_COOKIE_ICON_MAX_CHARS) {
      const key = userIconStorageKey(next);
      if (storageSet(key, next.userIcon)) {
        next = normalizeZerothCookie({ ...next, userIcon: "", userIconKey: key });
      }
    }
    if (current.userIconKey && current.userIconKey !== next.userIconKey) {
      storageRemove(current.userIconKey);
    }
    writeZerothCookie(next);
    window.dispatchEvent(new CustomEvent("zeroth:identity", { detail: next }));
    return next;
  };
  const clearZerothCookieIdentity = () => {
    const current = normalizeZerothCookie(readZerothCookie() || {});
    storageRemove(current.userIconKey);
    expireZerothCookie();
    window.dispatchEvent(new CustomEvent("zeroth:identity-cleared", { detail: current }));
    return current;
  };
  const zerothCookieIdentity = () => normalizeZerothCookie(readZerothCookie() || {});
  const temporaryIdentity = (identity = zerothCookieIdentity()) => {
    const name = identity.name || "";
    const icon = identityUserIcon(identity) || identity.icon || "";
    return { name: clean(name), icon: imageUrl(icon) };
  };
  const hasTemporaryIdentity = (identity) => Boolean(identity && (identity.name || identity.icon));
  const avatarMarkup = (label, picture, fallback = "Z") => {
    const src = imageUrl(picture);
    if (src) return `<img src="${esc(src)}" alt="">`;
    return labelInitial(label, fallback);
  };

  const style = `
    :host, .zeroth-profile-menu { color: #f8fafc; font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .zeroth-profile-menu { position: relative; display: inline-block; text-align: left; }
    .zeroth-profile-menu * { box-sizing: border-box; }
    .zeroth-menu-button, .zeroth-menu-link, .zeroth-menu-item { min-height: 38px; border-radius: 14px; font: inherit; font-weight: 760; text-decoration: none; cursor: pointer; }
    .zeroth-menu-button, .zeroth-menu-link { border: 1px solid rgba(255,255,255,0.16); background: linear-gradient(145deg, rgba(30,32,37,0.98) 0%, rgba(11,13,18,0.98) 62%, rgba(0,0,0,0.98) 100%); color: #fff; box-shadow: 0 14px 34px rgba(0,0,0,0.28), 0 2px 9px rgba(0,0,0,0.22), inset 0 1px 0 rgba(255,255,255,0.08); }
    .zeroth-menu-link { display: inline-flex; align-items: center; justify-content: center; gap: 9px; padding: 5px 13px 5px 6px; white-space: nowrap; }
    .zeroth-menu-button { display: inline-flex; align-items: center; gap: 9px; max-width: 260px; padding: 5px 11px 5px 6px; }
    .zeroth-menu-button-compact { gap: 6px; max-width: none; min-width: 0; padding: 5px 7px 5px 5px; }
    .zeroth-menu-link-compact { gap: 6px; min-width: 0; padding: 5px 7px 5px 5px; }
    .zeroth-menu-loading { cursor: progress; opacity: 0.86; }
    .zeroth-menu-button:hover, .zeroth-menu-link:hover { border-color: rgba(255,255,255,0.28); background: linear-gradient(145deg, rgba(40,43,49,0.98) 0%, rgba(15,17,23,0.98) 64%, rgba(0,0,0,0.98) 100%); text-decoration: none; }
    .zeroth-anon-profile { max-width: 210px; }
    .zeroth-anon-profile.zeroth-menu-button-compact { max-width: none; }
    .zeroth-mark, .zeroth-avatar { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 10px; background: linear-gradient(145deg, #3a3f47 0%, #1f2328 52%, #05070b 100%); color: #fff; font-weight: 850; line-height: 1; overflow: hidden; flex: 0 0 auto; box-shadow: inset 0 1px 0 rgba(255,255,255,0.12), 0 5px 14px rgba(0,0,0,0.24); }
    .zeroth-avatar img { width: 100%; height: 100%; object-fit: cover; }
    .zeroth-label { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .zeroth-caret { position: relative; display: inline-grid; place-items: center; width: 18px; height: 18px; border-radius: 999px; background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.78); flex: 0 0 auto; box-shadow: inset 0 1px 0 rgba(255,255,255,0.08); transition: background 140ms ease, color 140ms ease, transform 140ms ease; }
    .zeroth-caret::before { content: ""; width: 6px; height: 6px; border-right: 1.8px solid currentColor; border-bottom: 1.8px solid currentColor; transform: translateY(-1px) rotate(45deg); }
    .zeroth-menu-button:hover .zeroth-caret, .zeroth-menu-link:hover .zeroth-caret { background: rgba(255,255,255,0.13); color: #fff; }
    .zeroth-menu-button[aria-expanded="true"] .zeroth-caret { transform: rotate(180deg); }
    .zeroth-popover { position: absolute; right: 0; top: calc(100% + 10px); width: min(292px, calc(100vw - 32px)); border: 1px solid rgba(15,23,42,0.13); border-radius: 16px; background: radial-gradient(circle at 0% 0%, rgba(0,0,0,0.22) 0, rgba(0,0,0,0.08) 24%, rgba(0,0,0,0) 48%), radial-gradient(circle at 100% 100%, rgba(0,0,0,0.2) 0, rgba(0,0,0,0.06) 24%, rgba(0,0,0,0) 48%), linear-gradient(180deg, rgba(255,255,255,0.98), rgba(247,249,252,0.96)); box-shadow: 0 22px 52px rgba(0,0,0,0.28), 0 4px 14px rgba(0,0,0,0.18); overflow: hidden; z-index: 2147483647; color: #111827; }
    .zeroth-profile-menu-portal-root { position: fixed; inset: 0; z-index: 2147483647; width: 0; height: 0; pointer-events: none; }
    .zeroth-profile-menu-portal { position: fixed; top: 0; left: 0; z-index: 2147483647; width: 0; height: 0; pointer-events: none; }
    .zeroth-profile-menu-portal .zeroth-popover { position: fixed; top: auto; right: auto; overflow: auto; pointer-events: auto; }
    .zeroth-popover[hidden] { display: none; }
    .zeroth-menu-head { display: flex; align-items: center; gap: 10px; padding: 14px 14px 12px; border-bottom: 1px solid rgba(17,24,39,0.08); }
    .zeroth-menu-head-main { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1 1 auto; }
    .zeroth-menu-head-copy { min-width: 0; }
    .zeroth-menu-name { font-size: 15px; font-weight: 820; line-height: 1.18; overflow-wrap: anywhere; }
    .zeroth-menu-email { color: #4b5563; font-size: 12px; line-height: 1.3; margin-top: 3px; overflow-wrap: anywhere; }
    .zeroth-menu-list { display: grid; padding: 7px; gap: 5px; }
    .zeroth-menu-item { display: flex; width: 100%; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 10px; border: 1px solid transparent; background: rgba(255,255,255,0.74); color: #111827; font-weight: 760; }
    .zeroth-menu-item:hover { background: rgba(255,255,255,0.96); border-color: rgba(17,24,39,0.08); text-decoration: none; }
    .zeroth-menu-item-primary { background: #0b0f19; border-color: #0b0f19; color: #fff; box-shadow: 0 8px 22px rgba(0,0,0,0.18); }
    .zeroth-menu-item-primary:hover { background: #020617; color: #fff; }
    .zeroth-menu-item-danger { color: #b42318; }
    .zeroth-menu-actions { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 8px; padding: 9px 10px 10px; }
    .zeroth-menu-action { display: inline-flex; align-items: center; justify-content: center; min-width: 0; min-height: 38px; padding: 8px 9px; border: 1px solid rgba(17,24,39,0.1); border-radius: 12px; font: inherit; font-size: 12px; font-weight: 820; line-height: 1.12; text-align: center; text-decoration: none; white-space: nowrap; cursor: pointer; }
    .zeroth-menu-action:hover { text-decoration: none; }
    .zeroth-menu-action-primary { background: #0b0f19; border-color: #0b0f19; color: #fff; box-shadow: 0 8px 22px rgba(0,0,0,0.18); }
    .zeroth-menu-action-primary:hover { background: #020617; color: #fff; }
    .zeroth-menu-action-secondary { background: rgba(17,24,39,0.06); color: #111827; }
    .zeroth-menu-action-secondary:hover { background: rgba(17,24,39,0.1); border-color: rgba(17,24,39,0.16); color: #111827; }
    .zeroth-status { color: rgba(255,255,255,0.68); font-size: 12px; padding: 8px 10px; }
  `;

  async function tokenFor(options, host) {
    if (typeof options.getAccessToken === "function") return await options.getAccessToken();
    if (options.accessToken) return options.accessToken;
    if (host && typeof host.getAccessToken === "function") return await host.getAccessToken();
    return attr(host, "access-token") || attr(host, "data-access-token");
  }

  async function apiJson(url, init = {}) {
    const response = await fetch(url, init);
    let body = {};
    try { body = await response.json(); } catch (_) {}
    if (!response.ok) {
      throw new Error(body.errorDescription || body.error_description || body.error || `HTTP ${response.status}`);
    }
    return body;
  }

  async function loadIdentity(state, options, host) {
    const token = await tokenFor(options, host);
    if (token) {
      const headers = new Headers({ Accept: "application/json", Authorization: `Bearer ${token}` });
      const profile = await apiJson(endpoint(state.issuer, state.profilePath, "/profile"), {
        headers,
        credentials: "omit",
      });
      return { authenticated: true, user: profile, token };
    }
    const session = await apiJson(endpoint(state.issuer, state.sessionPath, "/session"), {
      headers: { Accept: "application/json" },
      credentials: "include",
    });
    return { authenticated: Boolean(session.authenticated), user: session.user || null, token: "" };
  }

  async function loadBranding(state) {
    if (!state.clientId) return null;
    const url = new URL(endpoint(state.issuer, state.brandingPath, "/client-branding"));
    url.searchParams.set("client_id", state.clientId);
    if (state.returnTo) url.searchParams.set("return_to", state.returnTo);
    const branding = await apiJson(url, {
      headers: { Accept: "application/json" },
      credentials: "omit",
    });
    return {
      clientId: state.clientId,
      name: text(branding.name || branding.displayName || "").trim(),
      nameSource: "brand",
      icon: imageUrl(branding.icon || branding.iconUrl || branding.picture || branding.pictureUrl || ""),
    };
  }

  function avatar(user, fallbackIcon = "") {
    const picture = user && (user.picture || user.pictureUrl);
    return avatarMarkup(first(user, ["name", "email", "sub"]) || "Z", picture || fallbackIcon);
  }

  function render(root, state) {
    const loginUrl = state.loginUrl || endpoint(state.issuer, "/login", "/login");
    const loginTarget = new URL(loginUrl);
    if (state.returnTo && !loginTarget.searchParams.has("return_to")) loginTarget.searchParams.set("return_to", state.returnTo);
    if (state.clientId && !loginTarget.searchParams.has("client_id")) loginTarget.searchParams.set("client_id", state.clientId);
    const accountUrl = state.accountUrl || `${trimSlash(state.issuer)}/account?return_to=${encodeURIComponent(state.returnTo || window.location.href)}`;
    const adminUrl = state.adminUrl || `${trimSlash(state.issuer)}/admin`;
    const compactClass = state.compact ? " zeroth-menu-button-compact" : "";
    const triggerLabel = (label) => state.compact ? "" : `<span class="zeroth-label">${esc(label)}</span>`;
    state.portalHtml = "";

    if (state.loading) {
      if (state.compact) {
        const temp = state.temporaryIdentity || {};
        const tempName = temp.name || "Account";
        root.innerHTML = `<style>${style}</style>
          <span class="zeroth-profile-menu">
            <span class="zeroth-menu-button zeroth-menu-button-compact zeroth-menu-loading" role="status" aria-label="Loading account">
              <span class="zeroth-avatar">${avatarMarkup(tempName, temp.icon)}</span>
              <span class="zeroth-caret" aria-hidden="true"></span>
            </span>
          </span>`;
        return;
      }
      root.innerHTML = `<style>${style}</style><span class="zeroth-profile-menu"><span class="zeroth-status">Loading account</span></span>`;
      return;
    }
    if (!state.authenticated || !state.user) {
      const temp = state.temporaryIdentity || {};
      const tempName = temp.name || "Account";
      if (hasTemporaryIdentity(temp)) {
        if (state.open) {
          state.portalHtml = `<div class="zeroth-popover" role="menu" data-zeroth-portal-popover>
            <div class="zeroth-menu-head">
              <div class="zeroth-menu-head-main">
                <span class="zeroth-avatar">${avatarMarkup(tempName, temp.icon)}</span>
                <div class="zeroth-menu-head-copy"><div class="zeroth-menu-name">${esc(tempName)}</div></div>
              </div>
            </div>
            <div class="zeroth-menu-actions">
              <a class="zeroth-menu-action zeroth-menu-action-primary" href="${esc(loginTarget.toString())}">Sign In</a>
              <button class="zeroth-menu-action zeroth-menu-action-secondary" type="button" data-zeroth-menu-clear>Reset Anon</button>
            </div>
          </div>`;
        }
        root.innerHTML = `<style>${style}</style>
          <div class="zeroth-profile-menu">
            <button class="zeroth-menu-button zeroth-anon-profile${compactClass}" type="button" aria-haspopup="menu" aria-expanded="${state.open ? "true" : "false"}" aria-label="${esc(`Open profile menu for ${tempName}`)}" data-zeroth-menu-toggle>
              <span class="zeroth-avatar">${avatarMarkup(tempName, temp.icon)}</span>
              ${triggerLabel(tempName)}
              <span class="zeroth-caret" aria-hidden="true"></span>
            </button>
          </div>`;
        return;
      }
      const compactLinkClass = state.compact ? " zeroth-menu-link-compact" : "";
      const compactLinkLabel = state.compact ? "" : "<span>Sign in</span>";
      const compactLinkCaret = state.compact ? `<span class="zeroth-caret" aria-hidden="true"></span>` : "";
      root.innerHTML = `<style>${style}</style><span class="zeroth-profile-menu"><a class="zeroth-menu-link${compactLinkClass}" href="${esc(loginTarget.toString())}" aria-label="Sign in"><span class="zeroth-mark" aria-hidden="true">${avatarMarkup("Z", "")}</span>${compactLinkLabel}${compactLinkCaret}</a></span>`;
      return;
    }

    const user = state.user;
    const name = first(user, ["name", "displayName", "email", "sub"]) || "Account";
    const email = first(user, ["email", "sub"]);
    const adminItem = state.showAdmin ? `<a class="zeroth-menu-item" href="${esc(adminUrl)}"><span>Admin</span><span>Open</span></a>` : "";
    if (state.open) {
      state.portalHtml = `<div class="zeroth-popover" role="menu" data-zeroth-portal-popover>
        <div class="zeroth-menu-head"><span class="zeroth-avatar">${avatar(user, identityUserIcon(state.cookieIdentity))}</span><div><div class="zeroth-menu-name">${esc(name)}</div><div class="zeroth-menu-email">${esc(email)}</div></div></div>
        <div class="zeroth-menu-list">
          <a class="zeroth-menu-item" href="${esc(accountUrl)}"><span>Account</span><span>Manage</span></a>
          ${adminItem}
          <button class="zeroth-menu-item zeroth-menu-item-danger" type="button" data-zeroth-menu-logout><span>Sign out</span><span>End session</span></button>
        </div>
      </div>`;
    }
    root.innerHTML = `<style>${style}</style>
      <div class="zeroth-profile-menu">
        <button class="zeroth-menu-button${compactClass}" type="button" aria-haspopup="menu" aria-expanded="${state.open ? "true" : "false"}" aria-label="${esc(`Open profile menu for ${name}`)}" data-zeroth-menu-toggle>
          <span class="zeroth-avatar">${avatar(user, identityUserIcon(state.cookieIdentity))}</span>
          ${triggerLabel(name)}
          <span class="zeroth-caret" aria-hidden="true"></span>
        </button>
      </div>`;
  }

  const mountedMenus = new Set();

  const refreshMountedMenus = () => {
    for (const menu of mountedMenus) {
      if (menu && typeof menu.refresh === "function") menu.refresh();
    }
  };

  function setUserIcon(icon) {
    const userIcon = imageUrl(icon);
    if (!userIcon) throw new Error("Zeroth user icon must be an http(s) or data image URL");
    const identity = mergeZerothCookie({ userIcon, userIconKey: "" });
    refreshMountedMenus();
    return identity;
  }

  function clearUserIcon() {
    const identity = mergeZerothCookie({ userIcon: "", userIconKey: "" });
    refreshMountedMenus();
    return identity;
  }

  function setAnonymousName(name) {
    const displayName = clean(name).split(/\s+/).join(" ").slice(0, 64);
    if (!displayName) throw new Error("Zeroth anonymous name must not be empty");
    const identity = mergeZerothCookie({ name: displayName, nameSource: "user" });
    refreshMountedMenus();
    return identity;
  }

  function clearAnonymousIdentity() {
    clearZerothCookieIdentity();
    refreshMountedMenus();
    return anonymousIdentity();
  }

  function anonymousIdentity() {
    return zerothCookieIdentity();
  }

  function mount(target, options = {}) {
    const host = typeof target === "string" ? document.querySelector(target) : target;
    if (!host) throw new Error("Zeroth profile menu target was not found");
    const root = host.shadowRoot || (host.attachShadow ? host.attachShadow({ mode: "open" }) : host);
    const state = {
      issuer: options.issuer || attr(host, "issuer") || attr(host, "data-issuer") || defaultIssuer(),
      clientId: options.clientId || attr(host, "client-id") || attr(host, "data-client-id"),
      returnTo: options.returnTo || attr(host, "return-to") || attr(host, "data-return-to") || window.location.href,
      accountUrl: options.accountUrl || attr(host, "account-url") || attr(host, "data-account-url"),
      adminUrl: options.adminUrl || attr(host, "admin-url") || attr(host, "data-admin-url"),
      loginUrl: options.loginUrl || attr(host, "login-url") || attr(host, "data-login-url"),
      logoutUrl: options.logoutUrl || attr(host, "logout-url") || attr(host, "data-logout-url"),
      csrfToken: options.csrfToken || attr(host, "csrf-token") || attr(host, "data-csrf-token"),
      sessionPath: options.sessionPath || attr(host, "session-path") || attr(host, "data-session-path") || "/session",
      profilePath: options.profilePath || attr(host, "profile-path") || attr(host, "data-profile-path") || "/profile",
      brandingPath: options.brandingPath || attr(host, "branding-path") || attr(host, "data-branding-path") || "/client-branding",
      showAdmin: options.showAdmin ?? boolAttr(host, "data-show-admin", boolAttr(host, "show-admin", true)),
      compact: compactMenuOption(options, host),
      cookieIdentity: null,
      temporaryIdentity: null,
      loading: true,
      authenticated: false,
      user: null,
      open: false,
      portalHtml: "",
    };
    state.cookieIdentity = mergeZerothCookie({ clientId: state.clientId });
    state.temporaryIdentity = temporaryIdentity(state.cookieIdentity);
    let portal = null;
    let portalFrame = 0;

    function syncOpenState() {
      if (state.open) host.setAttribute("data-zeroth-menu-open", "true");
      else host.removeAttribute("data-zeroth-menu-open");
    }

    function renderState() {
      syncOpenState();
      render(root, state);
      syncPopoverPortal();
    }

    function triggerButton() {
      return root.querySelector("[data-zeroth-menu-toggle]");
    }

    function removePopoverPortal() {
      if (portalFrame) {
        window.cancelAnimationFrame(portalFrame);
        portalFrame = 0;
      }
      if (portal) {
        portal.remove();
        portal = null;
      }
    }

    function positionPopoverPortal() {
      portalFrame = 0;
      if (!portal) return;
      const button = triggerButton();
      const popover = portal.querySelector("[data-zeroth-portal-popover]");
      if (!button || !popover) return;
      const rect = button.getBoundingClientRect();
      const viewportWidth = Math.max(0, document.documentElement.clientWidth || window.innerWidth || 0);
      const viewportHeight = Math.max(0, document.documentElement.clientHeight || window.innerHeight || 0);
      const margin = 16;
      const gap = 10;
      const width = Math.min(292, Math.max(180, viewportWidth - (margin * 2)));
      popover.style.position = "fixed";
      popover.style.zIndex = "2147483647";
      popover.style.width = `${width}px`;
      popover.style.maxHeight = `${Math.max(160, viewportHeight - (margin * 2))}px`;
      const height = popover.offsetHeight || 0;
      const maxLeft = Math.max(margin, viewportWidth - width - margin);
      let left = Math.min(maxLeft, Math.max(margin, rect.right - width));
      let top = rect.bottom + gap;
      if (top + height > viewportHeight - margin && rect.top - height - gap >= margin) {
        top = rect.top - height - gap;
      }
      const maxTop = Math.max(margin, viewportHeight - height - margin);
      top = Math.min(maxTop, Math.max(margin, top));
      popover.style.left = `${Math.round(left)}px`;
      popover.style.top = `${Math.round(top)}px`;
    }

    function schedulePopoverPosition() {
      if (!portal || portalFrame) return;
      portalFrame = window.requestAnimationFrame(positionPopoverPortal);
    }

    function syncPopoverPortal() {
      if (!state.open || !state.portalHtml) {
        removePopoverPortal();
        return;
      }
      if (!portal) {
        portal = document.createElement("div");
        portal.className = "zeroth-profile-menu-portal-root";
        portal.setAttribute("data-zeroth-popover-portal", "true");
        portal.style.cssText = "position:fixed;inset:0;z-index:2147483647;width:0;height:0;pointer-events:none;";
        portal.addEventListener("click", handlePortalClick);
        (document.body || document.documentElement).append(portal);
      }
      portal.innerHTML = `<style>${style}</style><div class="zeroth-profile-menu zeroth-profile-menu-portal">${state.portalHtml}</div>`;
      positionPopoverPortal();
      schedulePopoverPosition();
    }

    async function refresh() {
      state.loading = true;
      state.open = false;
      state.cookieIdentity = mergeZerothCookie({ clientId: state.clientId });
      state.temporaryIdentity = temporaryIdentity(state.cookieIdentity);
      renderState();
      const branding = await loadBranding(state).catch(() => null);
      if (hasTemporaryIdentity(branding)) {
        state.cookieIdentity = mergeZerothCookie(branding);
        state.temporaryIdentity = temporaryIdentity(state.cookieIdentity);
      }
      try {
        Object.assign(state, await loadIdentity(state, options, host), { loading: false });
      } catch (error) {
        Object.assign(state, { loading: false, authenticated: false, user: null, error });
      }
      renderState();
    }

    async function signOut() {
      if (typeof options.onLogout === "function") {
        await options.onLogout({ issuer: state.issuer, user: state.user });
        return;
      }
      const logoutUrl = endpoint(state.issuer, state.logoutUrl, "/logout");
      const headers = { Accept: "application/json" };
      if (state.csrfToken) headers["X-Zeroth-CSRF"] = state.csrfToken;
      await fetch(logoutUrl, {
        method: "POST",
        credentials: "include",
        headers,
      }).catch(() => null);
      state.authenticated = false;
      state.user = null;
      state.open = false;
      renderState();
      const signedOutUrl = options.signedOutUrl || attr(host, "signed-out-url") || attr(host, "data-signed-out-url");
      if (signedOutUrl) window.location.assign(signedOutUrl);
    }

    function handleMenuClick(event) {
      const target = event.target;
      if (!(target instanceof Element)) return false;
      if (target.closest("[data-zeroth-menu-toggle]")) {
        event.preventDefault();
        state.open = !state.open;
        renderState();
        return true;
      }
      if (target.closest("[data-zeroth-menu-logout]")) {
        event.preventDefault();
        signOut();
        return true;
      }
      if (target.closest("[data-zeroth-menu-clear]")) {
        event.preventDefault();
        state.open = false;
        clearZerothCookieIdentity();
        renderState();
        window.setTimeout(refresh, 0);
        return true;
      }
      return false;
    }

    function handlePortalClick(event) {
      if (handleMenuClick(event)) {
        event.stopPropagation();
      }
    }

    root.addEventListener("click", (event) => {
      handleMenuClick(event);
    });
    document.addEventListener("click", (event) => {
      if (!state.open) return;
      const path = typeof event.composedPath === "function" ? event.composedPath() : [];
      if (path.includes(host) || path.includes(root) || (portal && path.includes(portal))) return;
      state.open = false;
      renderState();
    });
    window.addEventListener("resize", schedulePopoverPosition, { passive: true });
    window.addEventListener("scroll", schedulePopoverPosition, { passive: true, capture: true });

    const api = {
      refresh,
      signOut,
      root,
      state,
      setUserIcon,
      clearUserIcon,
      setAnonymousName,
      clearAnonymousIdentity,
      anonymousIdentity,
    };
    mountedMenus.add(api);
    refresh();
    return api;
  }

  class ZerothProfileMenuElement extends HTMLElement {
    connectedCallback() {
      if (this.__zerothProfileMenu) return;
      this.__zerothProfileMenu = mount(this, {
        getAccessToken: () => typeof this.getAccessToken === "function" ? this.getAccessToken() : null,
      });
    }
    refresh() {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.refresh();
    }
    signOut() {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.signOut();
    }
    setUserIcon(icon) {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.setUserIcon(icon);
    }
    clearUserIcon() {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.clearUserIcon();
    }
    setAnonymousName(name) {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.setAnonymousName(name);
    }
    clearAnonymousIdentity() {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.clearAnonymousIdentity();
    }
    anonymousIdentity() {
      return this.__zerothProfileMenu && this.__zerothProfileMenu.anonymousIdentity();
    }
  }

  window.ZerothProfileMenu = { mount, setUserIcon, clearUserIcon, setAnonymousName, clearAnonymousIdentity, anonymousIdentity };
  if (window.customElements && !customElements.get("zeroth-profile-menu")) {
    customElements.define("zeroth-profile-menu", ZerothProfileMenuElement);
  }
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-zeroth-profile-menu]").forEach((node) => {
      if (!node.__zerothProfileMenu) node.__zerothProfileMenu = mount(node, {});
    });
  });
})();
"###;
const ZEROTH_PROFILE_PANEL_JS: &str = r###"
(() => {
  const defaultIssuer = () => {
    const script = document.currentScript;
    return script && script.src ? new URL(script.src, window.location.href).origin : window.location.origin;
  };
  const text = (value) => value == null || value === "" ? "-" : String(value);
  const esc = (value) => text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
  const shortId = (value) => {
    const raw = text(value);
    return raw.length > 24 ? `${raw.slice(0, 10)}...${raw.slice(-8)}` : raw;
  };
  const fmtTime = (value) => {
    const seconds = Number(value || 0);
    if (!Number.isFinite(seconds) || seconds <= 0) return "-";
    return new Date(seconds * 1000).toLocaleString();
  };
  const providerLabel = (value) => {
    const raw = text(value);
    if (raw === "wallet_evm") return "Ethereum wallet";
    if (raw === "magic_link") return "Magic link";
    return raw.replace(/[_-]+/g, " ").replace(/\b\w/g, (ch) => ch.toUpperCase());
  };
  const style = `
    :host, .zeroth-profile-panel { color: #111827; font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .zeroth-profile-panel { border: 1px solid #e5e7eb; border-radius: 8px; background: #fff; overflow: hidden; max-width: 560px; }
    .zeroth-head { display: flex; gap: 12px; align-items: center; justify-content: space-between; padding: 14px 16px; background: linear-gradient(135deg, #111827, #2d333b); color: #fff; }
    .zeroth-brand { display: flex; gap: 10px; align-items: center; min-width: 0; }
    .zeroth-mark { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 8px; background: #fff; color: #111827; font-weight: 800; }
    .zeroth-title { font-size: 15px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .zeroth-sub { color: #d1d5db; font-size: 12px; }
    .zeroth-body { padding: 14px 16px; display: grid; gap: 14px; }
    .zeroth-profile { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .zeroth-avatar { width: 42px; height: 42px; border-radius: 50%; background: #f3f4f6; color: #111827; display: grid; place-items: center; font-weight: 700; overflow: hidden; flex: 0 0 auto; }
    .zeroth-avatar img { width: 100%; height: 100%; object-fit: cover; }
    .zeroth-name { font-weight: 700; overflow-wrap: anywhere; }
    .zeroth-meta { color: #6b7280; font-size: 12px; overflow-wrap: anywhere; }
    .zeroth-grid { display: grid; gap: 8px; }
    .zeroth-section-title { color: #374151; font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    .zeroth-row { display: flex; justify-content: space-between; gap: 10px; padding: 8px 0; border-top: 1px solid #f3f4f6; }
    .zeroth-row-main { min-width: 0; }
    .zeroth-row-name { font-weight: 600; overflow-wrap: anywhere; }
    .zeroth-row-meta { color: #6b7280; font-size: 12px; overflow-wrap: anywhere; }
    .zeroth-form { display: grid; gap: 10px; }
    .zeroth-field { display: grid; gap: 4px; }
    .zeroth-field label { color: #374151; font-size: 12px; font-weight: 600; }
    .zeroth-field input { border: 1px solid #d1d5db; border-radius: 6px; padding: 8px 10px; font: inherit; min-width: 0; }
    .zeroth-actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .zeroth-action { appearance: none; border: 1px solid #d1d5db; border-radius: 6px; background: #fff; color: #111827; padding: 8px 10px; font: inherit; font-weight: 600; text-decoration: none; cursor: pointer; }
    .zeroth-primary { border-color: #111827; background: #111827; color: #fff; }
    .zeroth-status { color: #6b7280; font-size: 12px; min-height: 18px; }
    .zeroth-error { color: #991b1b; }
  `;

  async function tokenFor(options, host) {
    if (typeof options.getAccessToken === "function") return await options.getAccessToken();
    if (options.accessToken) return options.accessToken;
    if (host && typeof host.getAccessToken === "function") return await host.getAccessToken();
    return host && host.getAttribute ? host.getAttribute("access-token") : "";
  }

  async function api(issuer, path, token, init = {}) {
    const headers = new Headers(init.headers || {});
    headers.set("Accept", "application/json");
    headers.set("Authorization", `Bearer ${token}`);
    if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(new URL(path, issuer).toString(), {
      ...init,
      headers,
      credentials: "omit",
    });
    let body = {};
    try { body = await response.json(); } catch (_) {}
    if (!response.ok) {
      throw new Error(body.errorDescription || body.error_description || body.error || `HTTP ${response.status}`);
    }
    return body;
  }

  function avatar(user) {
    if (user && user.picture) return `<img src="${esc(user.picture)}" alt="">`;
    const label = text((user && (user.name || user.email || user.sub)) || "Z").trim();
    return esc(label.slice(0, 1).toUpperCase() || "Z");
  }

  function renderPanel(root, state) {
    const issuer = state.issuer.replace(/\/+$/, "");
    const manageUrl = state.manageUrl || `${issuer}/account?return_to=${encodeURIComponent(state.returnTo || window.location.href)}`;
    if (state.loading) {
      root.innerHTML = `<style>${style}</style><div class="zeroth-profile-panel"><div class="zeroth-head"><div class="zeroth-brand"><span class="zeroth-mark">Z</span><div><div class="zeroth-title">${esc(state.title)}</div><div class="zeroth-sub">Identity</div></div></div></div><div class="zeroth-body"><div class="zeroth-status">Loading profile</div></div></div>`;
      return;
    }
    if (state.error) {
      root.innerHTML = `<style>${style}</style><div class="zeroth-profile-panel"><div class="zeroth-head"><div class="zeroth-brand"><span class="zeroth-mark">Z</span><div><div class="zeroth-title">${esc(state.title)}</div><div class="zeroth-sub">Identity</div></div></div></div><div class="zeroth-body"><div class="zeroth-status zeroth-error">${esc(state.error)}</div><div class="zeroth-actions"><a class="zeroth-action zeroth-primary" href="${esc(manageUrl)}">Open account</a><button class="zeroth-action" data-zeroth-refresh type="button">Refresh</button></div></div></div>`;
      return;
    }
    const user = state.profile || {};
    const identities = Array.isArray(state.identities) ? state.identities : [];
    const sessions = Array.isArray(state.sessions) ? state.sessions : [];
    root.innerHTML = `<style>${style}</style>
      <div class="zeroth-profile-panel">
        <div class="zeroth-head">
          <div class="zeroth-brand"><span class="zeroth-mark">Z</span><div><div class="zeroth-title">${esc(state.title)}</div><div class="zeroth-sub">Identity</div></div></div>
          <a class="zeroth-action" href="${esc(manageUrl)}">Account</a>
        </div>
        <div class="zeroth-body">
          <div class="zeroth-profile"><div class="zeroth-avatar">${avatar(user)}</div><div><div class="zeroth-name">${esc(user.name || user.email || "Signed in")}</div><div class="zeroth-meta">${esc(user.email || user.sub)}</div></div></div>
          <form class="zeroth-form" data-zeroth-profile-form>
            <div class="zeroth-field"><label>Display name</label><input name="displayName" autocomplete="name" value="${esc(user.name || "")}"></div>
            <div class="zeroth-field"><label>Picture URL</label><input name="pictureUrl" autocomplete="url" value="${esc(user.picture || "")}"></div>
            <div class="zeroth-actions"><button class="zeroth-action zeroth-primary" type="submit">Save profile</button><button class="zeroth-action" data-zeroth-refresh type="button">Refresh</button></div>
            <div class="zeroth-status" data-zeroth-status>${esc(state.status || "")}</div>
          </form>
          <div class="zeroth-grid"><div class="zeroth-section-title">Sign-in methods</div>${identities.map((identity) => `<div class="zeroth-row"><div class="zeroth-row-main"><div class="zeroth-row-name">${esc(providerLabel(identity.providerId || identity.provider_id))}</div><div class="zeroth-row-meta">${esc(identity.email || identity.displayName || identity.display_name || shortId(identity.providerSubject || identity.provider_subject))}</div></div><div class="zeroth-row-meta">${identity.emailVerified || identity.email_verified ? "Verified" : ""}</div></div>`).join("") || `<div class="zeroth-meta">No linked sign-in methods returned.</div>`}</div>
          <div class="zeroth-grid"><div class="zeroth-section-title">Sessions</div>${sessions.slice(0, 4).map((session) => `<div class="zeroth-row"><div class="zeroth-row-main"><div class="zeroth-row-name">${esc(session.current ? "Current session" : "Session")}</div><div class="zeroth-row-meta">${esc(session.clientId || session.client_id || "Browser")} - expires ${esc(fmtTime(session.expiresAt || session.expires_at))}</div></div></div>`).join("") || `<div class="zeroth-meta">No active sessions returned.</div>`}</div>
        </div>
      </div>`;
  }

  function mount(target, options = {}) {
    const host = typeof target === "string" ? document.querySelector(target) : target;
    if (!host) throw new Error("Zeroth profile panel target was not found");
    const root = host.attachShadow ? host.attachShadow({ mode: "open" }) : host;
    const state = {
      issuer: options.issuer || host.getAttribute?.("issuer") || defaultIssuer(),
      returnTo: options.returnTo || host.getAttribute?.("return-to") || window.location.href,
      manageUrl: options.manageUrl || host.getAttribute?.("manage-url") || "",
      title: options.title || host.getAttribute?.("title") || "Zeroth",
      loading: true,
    };
    async function load() {
      state.loading = true;
      state.error = "";
      renderPanel(root, state);
      try {
        const token = await tokenFor(options, host);
        if (!token) throw new Error("Access token is required");
        const [profile, identities, sessions] = await Promise.all([
          api(state.issuer, "/profile", token),
          api(state.issuer, "/identities", token),
          api(state.issuer, "/sessions", token),
        ]);
        Object.assign(state, {
          loading: false,
          token,
          profile,
          identities: identities.identities || [],
          sessions: sessions.sessions || [],
        });
      } catch (error) {
        Object.assign(state, {
          loading: false,
          error: error instanceof Error ? error.message : "Profile could not be loaded",
        });
      }
      renderPanel(root, state);
    }
    root.addEventListener("click", (event) => {
      const target = event.target;
      if (target instanceof Element && target.closest("[data-zeroth-refresh]")) {
        event.preventDefault();
        load();
      }
    });
    root.addEventListener("submit", async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || !form.matches("[data-zeroth-profile-form]")) return;
      event.preventDefault();
      const status = root.querySelector("[data-zeroth-status]");
      if (status) status.textContent = "Saving";
      const data = new FormData(form);
      try {
        const updated = await api(state.issuer, "/profile", state.token, {
          method: "PATCH",
          body: JSON.stringify({
            displayName: String(data.get("displayName") || "").trim(),
            pictureUrl: String(data.get("pictureUrl") || "").trim() || null,
          }),
        });
        state.profile = updated;
        state.status = "Saved";
        renderPanel(root, state);
      } catch (error) {
        if (status) {
          status.textContent = error instanceof Error ? error.message : "Profile could not be saved";
          status.classList.add("zeroth-error");
        }
      }
    });
    load();
    return { refresh: load, root, state };
  }

  class ZerothProfilePanelElement extends HTMLElement {
    connectedCallback() {
      if (this.__zerothProfilePanel) return;
      this.__zerothProfilePanel = mount(this, {
        getAccessToken: () => typeof this.getAccessToken === "function" ? this.getAccessToken() : null,
      });
    }
    refresh() {
      return this.__zerothProfilePanel && this.__zerothProfilePanel.refresh();
    }
  }

  window.ZerothProfilePanel = { mount };
  if (window.customElements && !customElements.get("zeroth-profile-panel")) {
    customElements.define("zeroth-profile-panel", ZerothProfilePanelElement);
  }
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-zeroth-profile-panel]").forEach((node) => {
      if (!node.__zerothProfilePanel) node.__zerothProfilePanel = mount(node, {});
    });
  });
})();
"###;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderResponse {
    id: &'static str,
    kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    introspection_endpoint: String,
    end_session_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    response_modes_supported: Vec<&'static str>,
    prompt_values_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    introspection_endpoint_auth_methods_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
    authorization_response_iss_parameter_supported: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JwkKey {
    kty: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    alg: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Clone, Serialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    token_type: &'static str,
    expires_in: i32,
    scope: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct JwtHeader {
    alg: &'static str,
    kid: String,
    typ: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct AppleClientSecretHeader {
    alg: &'static str,
    kid: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct AppleClientSecretClaims {
    iss: String,
    iat: i64,
    exp: i64,
    aud: &'static str,
    sub: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i32,
    iat: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    token_use: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<String>,
}

#[derive(Clone)]
struct Es256SigningKey {
    kid: String,
    signing_key: SigningKey,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct CachedSigningMaterial {
    kid: String,
    private_key: String,
    previous_public_jwks: Option<String>,
    signing_key: Es256SigningKey,
    jwks: JwksResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppleClientSecretConfig {
    team_id: String,
    key_id: String,
    client_id: String,
    private_key_pem: String,
    ttl_seconds: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct CachedAppleClientSecret {
    config: AppleClientSecretConfig,
    token: String,
    expires_at: i64,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static SIGNING_MATERIAL_CACHE: RefCell<Option<CachedSigningMaterial>> = const { RefCell::new(None) };
    static APPLE_CLIENT_SECRET_CACHE: RefCell<Option<CachedAppleClientSecret>> = const { RefCell::new(None) };
    static PROVIDER_JWKS_CACHE: RefCell<ProviderJwksCache> = const {
        RefCell::new(ProviderJwksCache { entries: Vec::new() })
    };
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutesResponse {
    routes: Vec<RouteResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteResponse {
    method: &'static str,
    path: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationResponse {
    ok: bool,
    binding: &'static str,
    migrations_applied: Vec<&'static str>,
    migrations_skipped: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbSchemaStatusResponse {
    ok: bool,
    binding: &'static str,
    tables: Vec<DbTableStatus>,
    migrations: Vec<DbMigrationStatus>,
    compatibility_columns: Vec<DbCompatibilityColumnStatus>,
    client_count: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbTableStatus {
    name: &'static str,
    present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbMigrationStatus {
    version: i32,
    name: &'static str,
    applied: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbCompatibilityColumnStatus {
    table: &'static str,
    name: &'static str,
    present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuthErrorResponse {
    error: String,
    error_description: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssuerAccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i32,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientRow {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(default)]
    redirect_uris_json: String,
    #[serde(default)]
    allowed_origins_json: String,
    #[serde(default)]
    allowed_email_domains_json: String,
    #[serde(default)]
    issuer_token_audience: Option<String>,
    #[serde(default)]
    issuer_token_ttl_seconds: Option<i32>,
    #[serde(default)]
    account_sharing_mode: Option<String>,
    #[serde(default)]
    account_tenant_id: Option<String>,
    #[serde(default)]
    visible_login_methods_json: Option<String>,
    #[serde(default)]
    confidential: i32,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientOriginsRow {
    #[serde(default)]
    allowed_origins_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientResponse {
    id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_origins: Vec<String>,
    allowed_email_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_token_audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_token_ttl_seconds: Option<i32>,
    account_sharing_mode: String,
    account_tenant_id: String,
    account_namespace: String,
    visible_login_methods: Vec<String>,
    confidential: bool,
    disabled: bool,
    has_secret: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientsResponse {
    clients: Vec<ClientResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientBrandingResponse {
    client_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderStatusResponse {
    providers: Vec<ProviderStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalAuthStatusResponse {
    methods: Vec<LocalAuthStatus>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalAuthStatus {
    id: &'static str,
    label: &'static str,
    enabled: bool,
    credential_storage: &'static str,
    delivery: &'static str,
    notes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_status: Option<LocalAuthDeliveryStatus>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalAuthDeliveryStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    last_issue_at: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sent_at: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_failed_at: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error_detail: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MagicLinkDeliveryConfig {
    transport: &'static str,
    enabled: bool,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct LoginThemeOverride {
    name: Option<String>,
    #[serde(
        default,
        alias = "iconUrl",
        alias = "brandIcon",
        alias = "brandIconUrl"
    )]
    icon: Option<String>,
    #[serde(default, alias = "backgroundColor")]
    header_background_from: Option<String>,
    #[serde(default, alias = "backgroundToColor")]
    header_background_to: Option<String>,
    #[serde(default, alias = "textColor")]
    header_text_color: Option<String>,
}

impl LoginThemeOverride {
    fn merge_from(&mut self, other: &LoginThemeOverride) {
        if other.name.is_some() {
            self.name.clone_from(&other.name);
        }
        if other.icon.is_some() {
            self.icon.clone_from(&other.icon);
        }
        if other.header_background_from.is_some() {
            self.header_background_from
                .clone_from(&other.header_background_from);
        }
        if other.header_background_to.is_some() {
            self.header_background_to
                .clone_from(&other.header_background_to);
        }
        if other.header_text_color.is_some() {
            self.header_text_color.clone_from(&other.header_text_color);
        }
    }

    fn trimmed_name(&self) -> Option<String> {
        self.name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }

    fn trimmed_icon(&self) -> Option<String> {
        self.icon
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct LoginThemeCatalog {
    #[serde(default)]
    default: LoginThemeOverride,
    #[serde(default)]
    clients: BTreeMap<String, LoginThemeOverride>,
    #[serde(default)]
    domains: BTreeMap<String, LoginThemeOverride>,
}

impl LoginThemeCatalog {
    fn merge_from(&mut self, other: LoginThemeCatalog) {
        self.default.merge_from(&other.default);
        self.clients.extend(other.clients);
        self.domains.extend(other.domains);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MagicLinkDeliveryTransport {
    CloudflareEmail,
    Webhook,
    Resend,
    MailChannels,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessResponse {
    ready: bool,
    service: &'static str,
    issuer: String,
    issuer_check: ReadinessCheck,
    signing: ReadinessCheck,
    providers: Vec<ProviderReadiness>,
    apple_app_site_association: ReadinessCheck,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessCheck {
    configured: bool,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderReadiness {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    configured: bool,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderStatus {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    enabled: bool,
    client_id_configured: bool,
    client_secret_configured: bool,
    client_id_binding: &'static str,
    secret_binding_sets: Vec<Vec<&'static str>>,
    callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_domain: Option<String>,
    notes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    activation_requirements: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_failure: Option<ProviderFailureStatus>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderFailureStatus {
    event_type: String,
    created_at: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct ClientUpsertRequest {
    id: String,
    name: String,
    #[serde(default, alias = "redirect_uris")]
    redirect_uris: Vec<String>,
    #[serde(default, alias = "allowed_origins")]
    allowed_origins: Vec<String>,
    #[serde(default, alias = "allowed_email_domains")]
    allowed_email_domains: Vec<String>,
    #[serde(default, alias = "account_sharing_mode")]
    account_sharing_mode: Option<String>,
    #[serde(default, alias = "account_tenant_id")]
    account_tenant_id: Option<String>,
    #[serde(default, alias = "visible_login_methods")]
    visible_login_methods: Vec<String>,
    #[serde(default, alias = "issuer_token_audience")]
    issuer_token_audience: Option<String>,
    #[serde(default, alias = "issuer_token_ttl_seconds")]
    issuer_token_ttl_seconds: Option<i32>,
    #[serde(default)]
    confidential: bool,
    #[serde(default, alias = "client_secret")]
    client_secret: Option<String>,
    #[serde(default, alias = "secret_hash")]
    secret_hash: Option<String>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ValidatedClientUpsert {
    id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_origins: Vec<String>,
    allowed_email_domains: Vec<String>,
    issuer_token_audience: Option<String>,
    issuer_token_ttl_seconds: Option<i32>,
    account_sharing_mode: AccountSharingMode,
    account_tenant_id: String,
    visible_login_methods: Vec<String>,
    confidential: bool,
    secret_hash: Option<String>,
    disabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct AdminUserRow {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
    #[serde(default)]
    disabled_at: Option<i32>,
    #[serde(default)]
    email_verified: i32,
    #[serde(default)]
    admin_membership_active: i32,
    identity_count: i32,
    active_session_count: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct AdminMembershipProbeRow {
    user_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUserResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
    disabled: bool,
    admin: bool,
    identity_count: i32,
    active_session_count: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUsersResponse {
    users: Vec<AdminUserResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUserDetailResponse {
    user: AdminUserResponse,
    identities: Vec<IdentityResponse>,
    active_sessions: Vec<SessionInfoResponse>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AdminUserPatchRequest {
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    admin: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct AuditEventRow {
    id: String,
    event_type: String,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    provider_id: Option<String>,
    created_at: i32,
    #[serde(default)]
    ip_hash: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    details_json: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
struct MagicLinkDeliveryEventRow {
    event_type: String,
    created_at: i32,
    details_json: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
struct ProviderFailureEventRow {
    provider_id: String,
    event_type: String,
    created_at: i32,
    details_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventResponse {
    id: String,
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_id: Option<String>,
    created_at: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventsResponse {
    events: Vec<AuditEventResponse>,
}

#[derive(Debug, Clone, Default)]
struct AuditRequestContext {
    ip_hash: Option<String>,
    user_agent: Option<String>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
struct RateLimitPolicy {
    scope: &'static str,
    window_seconds: i32,
    max_attempts: i32,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
struct RateLimitSubject<'a> {
    policy: RateLimitPolicy,
    subject: Cow<'a, str>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Copy)]
struct RateLimitExceeded {
    retry_after_seconds: i32,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
struct RateLimitSecret([u8; 32]);

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
struct CsrfSecret([u8; 32]);

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct AuditEventFilter {
    event_type: Option<String>,
    user_id: Option<String>,
    client_id: Option<String>,
    provider_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthTransactionRow {
    provider_state: String,
    client_id: String,
    provider_id: String,
    redirect_uri: String,
    provider_redirect_uri: String,
    #[serde(default)]
    app_state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    provider_nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    scope: String,
    #[serde(default)]
    link_user_id: Option<String>,
    #[serde(default)]
    link_session_id: Option<String>,
    #[serde(default)]
    session_return_to: Option<String>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct StoredAuthTransaction {
    transaction: AuthTransaction,
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderCallback {
    state: String,
    code: Option<String>,
    provider_error: Option<ProviderCallbackError>,
    apple_user_json: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderCallbackError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ProviderTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderTokenExchangeError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SpotifyApiProfile {
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_default_vec")]
    images: Vec<SpotifyApiImage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SpotifyApiImage {
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct AppleCallbackUser {
    #[serde(default)]
    name: Option<AppleCallbackUserName>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct AppleCallbackUserName {
    #[serde(default, rename = "firstName")]
    first_name: Option<String>,
    #[serde(default, rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ResolvedProviderProfile {
    profile: ProviderProfile,
    raw_profile_json: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderProfileError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProfilePatch {
    display_name: Option<Option<String>>,
    picture_url: Option<Option<String>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProfilePatchError {
    description: String,
    status: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct IdentityReference {
    provider_id: String,
    provider_subject: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct IdentityLinkError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct ProviderJwksCache {
    entries: Vec<CachedProviderJwks>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CachedProviderJwks {
    provider_id: String,
    jwks: ProviderJwksResponse,
    expires_at: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct ProviderJwksResponse {
    keys: Vec<ProviderJwk>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct ProviderJwk {
    kty: String,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProviderJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProviderIdTokenClaims {
    iss: String,
    sub: String,
    aud: AudienceClaim,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderIdTokenValidation<'a> {
    provider_id: &'a str,
    client_id: &'a str,
    nonce: Option<&'a str>,
    now: i32,
}

#[derive(Debug, Clone)]
struct VerifiedProviderIdToken {
    claims: ProviderIdTokenClaims,
    raw_claims_json: String,
}

#[derive(Debug, Clone, Deserialize)]
struct IdentityUserRow {
    user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct IdentityCountRow {
    count: i32,
}

#[derive(Debug, Clone, Deserialize)]
struct TableColumnRow {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SchemaMigrationRow {
    version: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct IdentityRow {
    provider_id: String,
    provider_subject: String,
    #[serde(default)]
    email: Option<String>,
    email_verified: i32,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PasskeyCredentialRow {
    credential_id: String,
    user_id: String,
    #[serde(default)]
    label: Option<String>,
    public_key_x: String,
    public_key_y: String,
    sign_count: i32,
    created_at: i32,
    updated_at: i32,
    #[serde(default)]
    last_used_at: Option<i32>,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PasskeyChallengeRow {
    challenge_hash: String,
    kind: String,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    label: Option<String>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct LocalCredentialRow {
    email: String,
    user_id: String,
    password_hash: String,
    password_salt: String,
    password_alg: String,
    password_iterations: i32,
    password_scheme: String,
    password_params_json: String,
    password_version: i32,
    created_at: i32,
    updated_at: i32,
    #[serde(default)]
    last_used_at: Option<i32>,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordParamsJson {
    iterations: u32,
    prehash: PasswordPrehash,
    pepper_id: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PasswordPrehash {
    HmacSha256,
}

#[derive(Debug, Clone)]
struct PasswordPepperConfig {
    current: PasswordPepperSecret,
    previous: Option<PasswordPepperSecret>,
}

#[derive(Debug, Clone)]
struct PasswordPepperSecret {
    id: String,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PasswordVerification {
    valid: bool,
    needs_rehash: bool,
}

impl PasswordVerification {
    fn invalid() -> Self {
        Self {
            valid: false,
            needs_rehash: false,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct MagicLinkRow {
    token_hash: String,
    email: String,
    #[serde(default)]
    user_id: Option<String>,
    client_id: String,
    return_to: String,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
    #[serde(default)]
    ip_hash: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct WalletChallengeRow {
    challenge_hash: String,
    provider_id: String,
    address: String,
    chain_id: String,
    client_id: String,
    return_to: String,
    account_namespace: String,
    message: String,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
    #[serde(default)]
    ip_hash: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RateLimitStateRow {
    bucket_count: i32,
    #[serde(default)]
    blocked_until: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct RateLimitCountRow {
    count: i32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterOptionsRequest {
    #[serde(default)]
    email: Option<String>,
    #[serde(default, alias = "display_name")]
    display_name: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default, alias = "return_to")]
    return_to: Option<String>,
    #[serde(default, alias = "client_id")]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticateOptionsRequest {
    #[serde(default, alias = "return_to")]
    return_to: Option<String>,
    #[serde(default, alias = "client_id")]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasswordRegisterRequest {
    email: String,
    password: String,
    #[serde(default, alias = "display_name")]
    display_name: Option<String>,
    #[serde(default, alias = "return_to")]
    return_to: Option<String>,
    #[serde(default, alias = "client_id")]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasswordLoginRequest {
    email: String,
    password: String,
    #[serde(default, alias = "return_to")]
    return_to: Option<String>,
    #[serde(default, alias = "client_id")]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct MagicLinkRequest {
    email: String,
    #[serde(default, alias = "return_to")]
    return_to: Option<String>,
    #[serde(default, alias = "client_id")]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct MagicLinkConsumeRequest {
    token: String,
    #[serde(default)]
    confirm: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WalletChallengeRequest {
    address: String,
    #[serde(alias = "chain_id")]
    chain_id: String,
    #[serde(default, alias = "return_to")]
    return_to: Option<String>,
    #[serde(default, alias = "client_id")]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WalletVerifyRequest {
    address: String,
    #[serde(alias = "chain_id")]
    chain_id: String,
    nonce: String,
    message: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalAuthResponse {
    ok: bool,
    return_to: String,
    user: UserInfoResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicLocalAuthResponse {
    ok: bool,
    message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletChallengeResponse {
    ok: bool,
    provider: &'static str,
    address: String,
    chain_id: String,
    nonce: String,
    message: String,
}

#[derive(Debug, Clone)]
struct LocalAuthSessionIssue {
    session_id: String,
    return_to: String,
    user: UserRow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterVerifyRequest {
    id: String,
    raw_id: String,
    response: PasskeyRegisterCredentialResponse,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterCredentialResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticateVerifyRequest {
    id: String,
    raw_id: String,
    response: PasskeyAuthenticateCredentialResponse,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticateCredentialResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    #[serde(default)]
    user_handle: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: Option<bool>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyPublicKeyCredentialCreationOptions {
    challenge: String,
    rp: PasskeyRpEntity,
    user: PasskeyUserEntity,
    pub_key_cred_params: Vec<PasskeyPubKeyCredParam>,
    timeout: u32,
    authenticator_selection: PasskeyAuthenticatorSelection,
    attestation: &'static str,
    exclude_credentials: Vec<PasskeyCredentialDescriptor>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyPublicKeyCredentialRequestOptions {
    challenge: String,
    rp_id: String,
    timeout: u32,
    user_verification: &'static str,
    allow_credentials: Vec<PasskeyCredentialDescriptor>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyRpEntity {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyUserEntity {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyPubKeyCredParam {
    #[serde(rename = "type")]
    credential_type: &'static str,
    alg: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticatorSelection {
    resident_key: &'static str,
    require_resident_key: bool,
    user_verification: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyCredentialDescriptor {
    #[serde(rename = "type")]
    credential_type: &'static str,
    id: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyOptionsResponse<T> {
    public_key: T,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyVerifyResponse {
    ok: bool,
    return_to: String,
    user: UserInfoResponse,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PasskeyCredentialPublicKey {
    x: Vec<u8>,
    y: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedAuthenticatorData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    sign_count: i32,
    credential_id: Option<Vec<u8>>,
    public_key: Option<PasskeyCredentialPublicKey>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ValidatedPasskeyRegistration {
    credential_id: String,
    public_key_x: String,
    public_key_y: String,
    sign_count: i32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum CborValue {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct AuthCodeRow {
    code_hash: String,
    client_id: String,
    redirect_uri: String,
    user_id: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    scope: String,
    #[serde(default)]
    auth_time: Option<i32>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenExchangeForm {
    grant_type: String,
    client_id: String,
    client_auth: ClientAuth,
    redirect_uri: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    provider: Option<String>,
    provider_client_id: Option<String>,
    nonce: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenRevocationForm {
    client_id: String,
    client_auth: ClientAuth,
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenIntrospectionForm {
    client_id: String,
    client_auth: ClientAuth,
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ClientAuth {
    None,
    SecretPost(String),
    SecretBasic(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AccountSharingMode {
    Global,
    Tenant,
    Client,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ClientAccountScope {
    sharing_mode: AccountSharingMode,
    tenant_id: String,
    namespace: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ClientBasicAuth {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RegisteredClient {
    client: Client,
    secret_hash: Option<String>,
    account_scope: ClientAccountScope,
    visible_login_methods: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ClientManagementError {
    code: String,
    description: String,
    status: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenExchangeError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AuthorizationCodeFields<'a> {
    client_id: &'a str,
    redirect_uri: &'a str,
    code: &'a str,
    code_verifier: Option<&'a str>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct NativeProviderTokenFields<'a> {
    provider_id: &'a str,
    scope: Option<&'a str>,
    subject_token: &'a str,
    subject_token_type: &'a str,
    provider_client_id: Option<&'a str>,
    nonce: Option<&'a str>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct RefreshTokenRow {
    token_hash: String,
    client_id: String,
    user_id: String,
    #[serde(default)]
    session_id: Option<String>,
    scope: String,
    #[serde(default)]
    auth_time: Option<i32>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    rotated_at: Option<i32>,
    #[serde(default)]
    revoked_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct SessionRow {
    id: String,
    user_id: String,
    #[serde(default)]
    client_id: Option<String>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    revoked_at: Option<i32>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    ip_hash: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenIssue {
    client_id: String,
    user_id: String,
    session_id: Option<String>,
    scope: String,
    auth_time: Option<i32>,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
    roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserRow {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct UserTokenClaimsRow {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    #[serde(default)]
    disabled_at: Option<i32>,
    #[serde(default)]
    email_verified: i32,
    #[serde(default)]
    admin_membership_active: i32,
}

#[derive(Debug, Clone, Serialize)]
struct UserInfoResponse {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInfoResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    created_at: i32,
    expires_at: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserInfoResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionListItemResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    created_at: i32,
    expires_at: i32,
    current: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionsResponse {
    sessions: Vec<SessionListItemResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityResponse {
    provider_id: String,
    provider_subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentitiesResponse {
    identities: Vec<IdentityResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateResponse {
    valid: bool,
    kind: &'static str,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionInfoResponse>,
    user: UserInfoResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct TokenIntrospectionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_use: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
}

impl TokenIntrospectionResponse {
    fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            token_type: None,
            token_use: None,
            sub: None,
            aud: None,
            iss: None,
            iat: None,
            exp: None,
            sid: None,
            roles: None,
        }
    }

    fn active_access_token(claims: &JwtClaims) -> Self {
        Self {
            active: true,
            scope: claims.scope.clone(),
            client_id: Some(claims.aud.clone()),
            token_type: Some("Bearer"),
            token_use: Some("access_token"),
            sub: Some(claims.sub.clone()),
            aud: Some(claims.aud.clone()),
            iss: Some(claims.iss.clone()),
            iat: Some(claims.iat),
            exp: Some(claims.exp),
            sid: claims.sid.clone(),
            roles: (!claims.roles.is_empty()).then_some(claims.roles.clone()),
        }
    }

    fn active_refresh_token(row: &RefreshTokenRow) -> Self {
        Self {
            active: true,
            scope: Some(row.scope.clone()),
            client_id: Some(row.client_id.clone()),
            token_type: None,
            token_use: Some("refresh_token"),
            sub: Some(row.user_id.clone()),
            aud: Some(row.client_id.clone()),
            iss: None,
            iat: Some(row.created_at),
            exp: Some(row.expires_at),
            sid: row.session_id.clone(),
            roles: None,
        }
    }
}

impl ProviderJwksCache {
    fn get(&mut self, provider_id: &str, now: i32) -> Option<ProviderJwksResponse> {
        self.entries.retain(|entry| entry.expires_at > now);
        self.entries
            .iter()
            .find(|entry| entry.provider_id == provider_id)
            .map(|entry| entry.jwks.clone())
    }

    fn put(&mut self, provider_id: &str, jwks: ProviderJwksResponse, now: i32) {
        let expires_at = now.saturating_add(PROVIDER_JWKS_CACHE_TTL_SECONDS);
        self.entries
            .retain(|entry| entry.provider_id != provider_id);
        self.entries.push(CachedProviderJwks {
            provider_id: provider_id.to_owned(),
            jwks,
            expires_at,
        });
    }
}

#[derive(Debug, Clone)]
struct CurrentSession {
    session: SessionRow,
    user: UserRow,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
struct CurrentAccount {
    user: UserRow,
    client_id: Option<String>,
    session_id: Option<String>,
    scope: Option<String>,
    access_token: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AccountAuthError {
    code: &'static str,
    description: String,
    status: u16,
}

impl AccountAuthError {
    fn new(code: &'static str, description: impl Into<String>, status: u16) -> Self {
        Self {
            code,
            description: description.into(),
            status,
        }
    }

    fn invalid_token(description: impl Into<String>) -> Self {
        Self::new("invalid_token", description, 401)
    }

    fn login_required(description: impl Into<String>) -> Self {
        Self::new("login_required", description, 401)
    }

    fn invalid_request(description: impl Into<String>, status: u16) -> Self {
        Self::new("invalid_request", description, status)
    }

    fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new("invalid_scope", description, 403)
    }
}

#[cfg(target_arch = "wasm32")]
impl CurrentAccount {
    fn profile_scope(&self) -> &str {
        self.scope.as_deref().unwrap_or("email profile")
    }

    fn require_profile_scope(&self) -> Result<(), AccountAuthError> {
        if !self.access_token || scope_contains(self.scope.as_deref(), "profile") {
            return Ok(());
        }
        Err(AccountAuthError::invalid_scope(
            "access token requires profile scope",
        ))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AdminAuthorization {
    BootstrapToken,
    Session { user_id: String },
}

#[cfg(target_arch = "wasm32")]
use worker::wasm_bindgen::{JsCast as _, JsValue};
#[cfg(target_arch = "wasm32")]
use worker::wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn main(request: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();
    handle_request(request, env).await
}

#[cfg(target_arch = "wasm32")]
async fn handle_request(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let canonical_path = canonical_route_path(url.path());
    let route_path = canonical_path.as_ref();

    match (request.method(), route_path) {
        (Method::Options, path) if cors_path(path) => cors_preflight(request, env).await,
        (Method::Get, "/") => redirect_to_path(&url, "/login"),
        (Method::Get, "/health") => json(&HealthResponse {
            ok: true,
            service: "zeroth",
        }),
        (Method::Get, "/ready") => ready(request, env),
        (Method::Get, "/providers") => json(&provider_responses(&env)),
        (Method::Get, "/providers/status") => provider_status(request, env).await,
        (Method::Get, "/client-branding") => client_branding(request, env).await,
        (Method::Get, "/local-auth/status") => local_auth_status(request, env).await,
        (Method::Get | Method::Post | Method::Delete, "/clients") => clients(request, env).await,
        (Method::Get | Method::Patch, "/users") => users(request, env).await,
        (Method::Get, "/events") => events(request, env).await,
        (Method::Get, "/routes") => json(&RoutesResponse {
            routes: ROUTES
                .iter()
                .map(|route| RouteResponse {
                    method: route.method,
                    path: route.path,
                })
                .collect(),
        }),
        (Method::Get, "/.well-known/openid-configuration") => {
            json(&discovery_response(&server_config(&env, &url)))
        }
        (Method::Get, "/.well-known/oauth-authorization-server") => {
            json(&discovery_response(&server_config(&env, &url)))
        }
        (Method::Get, "/.well-known/jwks.json") => jwks(env),
        (Method::Get, "/.well-known/apple-app-site-association") => apple_app_site_association(env),
        (Method::Get, "/favicon.ico" | "/favicon.svg") => favicon(),
        (Method::Get, path) if quiet_browser_asset_path(path) => empty_cached_asset(),
        (Method::Get, "/site.webmanifest" | "/manifest.json") => web_manifest(&env),
        (Method::Get, "/browserconfig.xml") => browserconfig_xml(),
        (Method::Get, "/robots.txt") => robots_txt(),
        (Method::Get, "/login") => hosted_login(request, env).await,
        (Method::Get, "/account") => hosted_account(request, env).await,
        (Method::Get, "/profile-menu.js") => profile_menu_script(),
        (Method::Get, "/profile-panel.js") => profile_panel_script(),
        (Method::Get, "/admin") => hosted_clients_admin(request, env).await,
        (Method::Get, "/admin/clients") => hosted_clients_admin(request, env).await,
        (Method::Get, "/authorize") => authorize(request, env).await,
        (Method::Get, "/__zeroth/db/status") => d1_schema_status(request, env).await,
        (Method::Post, "/__zeroth/db/ensure") => ensure_d1_schema(request, env).await,
        (Method::Get | Method::Post, "/oauth2/callback") => provider_callback(request, env).await,
        (Method::Post, "/oauth/token") => oauth_token(request, env).await,
        (Method::Post, "/oauth/revoke") => oauth_revoke(request, env).await,
        (Method::Post, "/oauth/introspect") => oauth_introspect(request, env).await,
        (Method::Get, "/userinfo") => userinfo(request, env).await,
        (Method::Post, "/tokens") => client_issuer_access_token(request, env).await,
        (Method::Get, "/session") => session(request, env).await,
        (Method::Get | Method::Delete, "/sessions") => sessions(request, env).await,
        (Method::Get | Method::Patch, "/profile") => profile(request, env).await,
        (Method::Post, "/identities/link") => identity_link(request, env).await,
        (Method::Get | Method::Delete, "/identities") => identities(request, env).await,
        (Method::Post, "/passkeys/register/options") => {
            passkey_register_options(request, env).await
        }
        (Method::Post, "/passkeys/register/verify" | "/passkeys/register/finish") => {
            passkey_register_verify(request, env).await
        }
        (Method::Post, "/passkeys/authenticate/options") => {
            passkey_authenticate_options(request, env).await
        }
        (Method::Post, "/passkeys/authenticate/verify" | "/passkeys/authenticate/finish") => {
            passkey_authenticate_verify(request, env).await
        }
        (
            Method::Get,
            "/password/register" | "/password/login" | "/magic-links" | "/wallet/challenge"
            | "/wallet/verify",
        ) => redirect_local_auth_get_to_login(request, env),
        (Method::Post, "/password/register") => password_register(request, env).await,
        (Method::Post, "/password/login") => password_login(request, env).await,
        (Method::Post, "/wallet/challenge") => evm_wallet_challenge(request, env).await,
        (Method::Post, "/wallet/verify") => evm_wallet_verify(request, env).await,
        (Method::Post, "/magic-links") => magic_link_request(request, env).await,
        (Method::Get, "/magic-link/confirm") => magic_link_confirm(request, env).await,
        (Method::Post, "/magic-links/consume") => magic_link_consume(request, env).await,
        (Method::Get, "/validate") => validate(request, env).await,
        (Method::Get | Method::Post, "/logout") => logout(request, env).await,
        _ if known_route_path(route_path) => json_status(
            &serde_json::json!({
                "error": "method_not_allowed",
                "errorDescription": "route exists but does not allow this method"
            }),
            405,
        ),
        _ => json_status(&serde_json::json!({ "error": "not_found" }), 404),
    }
}

#[cfg(target_arch = "wasm32")]
async fn provider_callback(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let callback = match provider_callback_from_request(&mut request, &url).await {
        Ok(callback) => callback,
        Err(error) => return provider_callback_error_json(&error, 400),
    };

    let db = env.d1(D1_BINDING)?;
    let record = match get_auth_transaction(&db, &callback.state).await? {
        Some(record) => record,
        None => {
            return provider_callback_error_json(
                &ProviderCallbackError::invalid_request("unknown provider callback state"),
                400,
            )
        }
    };

    let now = unix_timestamp_seconds();
    if let Err(error) = validate_stored_auth_transaction(&record, now) {
        return provider_callback_error_json(&error, 400);
    }
    let transaction_cookie_state =
        transaction_state_from_request(&request, &config.transaction_cookie_name)?;
    if let Err(error) = provider_callback_state_matches_transaction_cookie(
        &callback.state,
        transaction_cookie_state.as_deref(),
    ) {
        return provider_callback_error_json(&error, 400);
    }
    if !consume_auth_transaction(&db, &callback.state, now).await? {
        return provider_callback_error_json(
            &ProviderCallbackError::invalid_request(
                "provider callback state has already been consumed",
            ),
            400,
        );
    }

    if let Some(provider_error) = callback.provider_error.as_ref() {
        record_audit_event(
            &db,
            &request,
            "provider.callback.error",
            None,
            Some(&record.transaction.client_id.0),
            Some(&record.transaction.provider_id.0),
            serde_json::json!({
                "code": &provider_error.code,
                "description": &provider_error.description
            }),
            now,
        )
        .await;
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            provider_error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }
    let Some(provider_code) = callback.code.as_deref() else {
        let error = ProviderCallbackError::invalid_request("missing code");
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            &error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    };

    let provider = provider_from_env(&env, &record.transaction.provider_id.0)?;
    let client_secret = provider_client_secret_from_env(&env, &record.transaction.provider_id.0)?;
    let token_request = provider
        .token_exchange_request(
            provider_code,
            &record.transaction.provider_redirect_uri,
            None,
            client_secret.as_deref(),
        )
        .map_err(|error| worker::Error::RustError(error.description))?;
    let token_set = match exchange_provider_code(token_request).await {
        Ok(token_set) => token_set,
        Err(error) => {
            record_audit_event(
                &db,
                &request,
                "provider.token_exchange.failed",
                None,
                Some(&record.transaction.client_id.0),
                Some(&record.transaction.provider_id.0),
                serde_json::json!({
                    "code": &error.code,
                    "description": &error.description
                }),
                now,
            )
            .await;
            let callback_error = provider_callback_error_from_token_exchange_error(&error);
            let response = redirect_to_provider_callback_error(
                &record.transaction,
                &config.issuer().issuer,
                &callback_error,
            )?;
            return with_set_cookie(
                response,
                &clear_transaction_cookie(&config.transaction_cookie_name),
            );
        }
    };
    let resolved_profile =
        match resolve_provider_profile(&provider, &token_set, &record.transaction, &callback).await
        {
            Ok(profile) => profile,
            Err(error) => {
                record_audit_event(
                    &db,
                    &request,
                    "provider.profile.failed",
                    None,
                    Some(&record.transaction.client_id.0),
                    Some(&record.transaction.provider_id.0),
                    serde_json::json!({
                        "code": &error.code,
                        "description": &error.description
                    }),
                    now,
                )
                .await;
                let callback_error = provider_callback_error_from_profile_error(&error);
                let response = redirect_to_provider_callback_error(
                    &record.transaction,
                    &config.issuer().issuer,
                    &callback_error,
                )?;
                return with_set_cookie(
                    response,
                    &clear_transaction_cookie(&config.transaction_cookie_name),
                );
            }
        };

    if let Some(link_user_id) = record.transaction.link_user_id.as_ref() {
        let link_result = complete_provider_identity_link(
            &db,
            link_user_id,
            record.transaction.link_session_id.as_deref(),
            &resolved_profile.profile,
            resolved_profile.raw_profile_json.as_deref(),
            now,
        )
        .await?;

        let response = match link_result {
            Ok(()) => {
                record_audit_event(
                    &db,
                    &request,
                    "identity.link",
                    Some(&link_user_id.0),
                    Some(&record.transaction.client_id.0),
                    Some(&resolved_profile.profile.provider_id.0),
                    serde_json::json!({}),
                    now,
                )
                .await;
                redirect_to_identity_link_return(&record.transaction, &resolved_profile.profile)
            }
            Err(error) => {
                record_audit_event(
                    &db,
                    &request,
                    "identity.link.failed",
                    Some(&link_user_id.0),
                    Some(&record.transaction.client_id.0),
                    Some(&resolved_profile.profile.provider_id.0),
                    serde_json::json!({
                        "code": &error.code,
                        "description": &error.description
                    }),
                    now,
                )
                .await;
                redirect_to_identity_link_error(&record.transaction, &error)
            }
        }?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }

    let Some(registered_client) =
        get_registered_client(&db, &record.transaction.client_id.0).await?
    else {
        let error = ProviderCallbackError::invalid_request("client is disabled or not found");
        record_audit_event(
            &db,
            &request,
            "client.login.denied",
            None,
            Some(&record.transaction.client_id.0),
            Some(&resolved_profile.profile.provider_id.0),
            serde_json::json!({ "reason": "client_inactive" }),
            now,
        )
        .await;
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            &error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    };
    if let Err(error) =
        validate_client_email_domain_policy(&registered_client.client, &resolved_profile.profile)
    {
        record_audit_event(
            &db,
            &request,
            "client.login.denied",
            None,
            Some(&record.transaction.client_id.0),
            Some(&resolved_profile.profile.provider_id.0),
            serde_json::json!({
                "reason": "email_domain_policy",
                "emailVerified": resolved_profile.profile.email_verified
            }),
            now,
        )
        .await;
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            &error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }

    if record.transaction.session_return_to.is_some() {
        let user_id = upsert_provider_profile(
            &db,
            &registered_client.account_scope.namespace,
            &resolved_profile.profile,
            resolved_profile.raw_profile_json.as_deref(),
            now,
        )
        .await?;
        let session_id = format!("sess_{}", random_token()?);
        let user_agent = request_header(&request, "User-Agent")?;
        let ip_hash = request_header(&request, "CF-Connecting-IP")?.map(|ip| hash_secret(&ip));
        put_session(
            &db,
            &session_id,
            &user_id,
            &record.transaction.client_id.0,
            now,
            user_agent.as_deref(),
            ip_hash.as_deref(),
        )
        .await?;
        record_audit_event(
            &db,
            &request,
            "session.login",
            Some(&user_id),
            Some(&record.transaction.client_id.0),
            Some(&resolved_profile.profile.provider_id.0),
            serde_json::json!({ "mode": "hosted" }),
            now,
        )
        .await;

        let response = redirect_to_session_login_return(&record.transaction)?;
        let response = with_set_cookie(
            response,
            &session_cookie(
                &config.cookie_name,
                &session_id,
                SESSION_TTL_SECONDS,
                config.cookie_domain.as_deref(),
            ),
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }

    let user_id = upsert_provider_profile(
        &db,
        &registered_client.account_scope.namespace,
        &resolved_profile.profile,
        resolved_profile.raw_profile_json.as_deref(),
        now,
    )
    .await?;
    let zeroth_code = random_token()?;
    let session_id = format!("sess_{}", random_token()?);
    put_authorization_code(
        &db,
        &zeroth_code,
        &record.transaction,
        &user_id,
        Some(&session_id),
        now,
        now,
    )
    .await?;
    let user_agent = request_header(&request, "User-Agent")?;
    let ip_hash = request_header(&request, "CF-Connecting-IP")?.map(|ip| hash_secret(&ip));
    put_session(
        &db,
        &session_id,
        &user_id,
        &record.transaction.client_id.0,
        now,
        user_agent.as_deref(),
        ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        &db,
        &request,
        "authorization.code.issue",
        Some(&user_id),
        Some(&record.transaction.client_id.0),
        Some(&resolved_profile.profile.provider_id.0),
        serde_json::json!({
            "scope": record.transaction.scope.as_slice().join(" ")
        }),
        now,
    )
    .await;

    let response = redirect_to_client(&record.transaction, &config.issuer().issuer, &zeroth_code)?;
    let response = with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )?;
    with_set_cookie(
        response,
        &clear_transaction_cookie(&config.transaction_cookie_name),
    )
}

#[cfg(target_arch = "wasm32")]
async fn clients(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &request_url);
    let now = unix_timestamp_seconds();
    if !matches!(request.method(), Method::Get) {
        match maybe_authorize_admin_write_request(
            &mut request,
            &env,
            &db,
            &config,
            now,
            CSRF_ROUTE_FAMILY_ADMIN,
            false,
            "client_admin_mutation",
        )
        .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return client_management_error_json(&ClientManagementError::unauthorized(
                    "admin bearer token or allowed Zeroth session is required",
                ))
            }
            Err(error) => return client_management_error_json(&error),
        };
    } else if let Err(error) = validate_admin_request(&request, &env, &db, &config, now).await {
        return client_management_error_json(&error);
    }

    match request.method() {
        Method::Get => {
            if let Some(client_id) = query_param(&request_url, "client_id") {
                let client_id = match validate_client_id(&client_id) {
                    Ok(client_id) => client_id,
                    Err(error) => return client_management_error_json(&error),
                };
                let Some(row) = get_client_row_for_admin(&db, &client_id).await? else {
                    return client_management_error_json(&ClientManagementError::not_found(
                        "client was not found",
                    ));
                };
                return match client_response_from_row(row) {
                    Ok(client) => json(&client),
                    Err(error) => {
                        client_management_error_json(&ClientManagementError::invalid_request(error))
                    }
                };
            }

            let rows = list_client_rows_for_admin(&db).await?;
            let clients = match rows
                .into_iter()
                .map(client_response_from_row)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(clients) => clients,
                Err(error) => {
                    return client_management_error_json(&ClientManagementError::invalid_request(
                        error,
                    ))
                }
            };
            json(&ClientsResponse { clients })
        }
        Method::Post => {
            let upsert = match client_upsert_from_request(&mut request).await {
                Ok(upsert) => upsert,
                Err(error) => return client_management_error_json(&error),
            };
            if upsert.confidential && upsert.secret_hash.is_none() {
                let existing = get_client_row_for_admin(&db, &upsert.id).await?;
                if existing.and_then(|row| row.secret_hash).is_none() {
                    return client_management_error_json(&ClientManagementError::invalid_request(
                        "confidential clients require clientSecret or secretHash",
                    ));
                }
            }

            upsert_client(&db, &upsert, now).await?;
            let row = get_client_row_for_admin(&db, &upsert.id)
                .await?
                .ok_or_else(|| {
                    worker::Error::RustError("client upsert did not return a row".to_owned())
                })?;
            record_audit_event(
                &db,
                &request,
                "client.upsert",
                None,
                Some(&upsert.id),
                None,
                serde_json::json!({
                    "confidential": upsert.confidential,
                    "disabled": upsert.disabled,
                    "redirectUriCount": upsert.redirect_uris.len(),
                    "allowedOriginCount": upsert.allowed_origins.len(),
                    "visibleLoginMethodCount": upsert.visible_login_methods.len(),
                    "secretUpdated": upsert.secret_hash.is_some()
                }),
                now,
            )
            .await;
            match client_response_from_row(row) {
                Ok(client) => json(&client),
                Err(error) => {
                    client_management_error_json(&ClientManagementError::invalid_request(error))
                }
            }
        }
        Method::Delete => {
            let Some(client_id) = query_param(&request_url, "client_id") else {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "missing client_id",
                ));
            };
            let client_id = match validate_client_id(&client_id) {
                Ok(client_id) => client_id,
                Err(error) => return client_management_error_json(&error),
            };
            if get_client_row_for_admin(&db, &client_id).await?.is_none() {
                return client_management_error_json(&ClientManagementError::not_found(
                    "client was not found",
                ));
            }
            disable_client(&db, &client_id, now).await?;
            record_audit_event(
                &db,
                &request,
                "client.disable",
                None,
                Some(&client_id),
                None,
                serde_json::json!({}),
                now,
            )
            .await;
            json(&serde_json::json!({ "ok": true }))
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn users(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &request_url);
    let now = unix_timestamp_seconds();
    let admin_authorization = if matches!(request.method(), Method::Patch) {
        match maybe_authorize_admin_write_request(
            &mut request,
            &env,
            &db,
            &config,
            now,
            CSRF_ROUTE_FAMILY_ADMIN,
            false,
            "user_admin_mutation",
        )
        .await
        {
            Ok(Some(admin_authorization)) => admin_authorization,
            Ok(None) => {
                return client_management_error_json(&ClientManagementError::unauthorized(
                    "admin bearer token or allowed Zeroth session is required",
                ))
            }
            Err(error) => return client_management_error_json(&error),
        }
    } else {
        match authorize_admin_request(&request, &env, &db, &config, now).await {
            Ok(admin_authorization) => admin_authorization,
            Err(error) => return client_management_error_json(&error),
        }
    };

    match request.method() {
        Method::Get => {
            if let Some(user_id) = query_param(&request_url, "user_id") {
                let user_id = match validate_admin_user_id(&user_id) {
                    Ok(user_id) => user_id,
                    Err(error) => return client_management_error_json(&error),
                };
                let Some(response) = admin_user_detail_response(&db, &user_id, now).await? else {
                    return client_management_error_json(&ClientManagementError::not_found(
                        "user was not found",
                    ));
                };
                return json(&response);
            }

            let rows = list_admin_user_rows(&db, now).await?;
            let users = rows.into_iter().map(admin_user_response_from_row).collect();
            json(&AdminUsersResponse { users })
        }
        Method::Patch => {
            let Some(user_id) = query_param(&request_url, "user_id") else {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "missing user_id",
                ));
            };
            let user_id = match validate_admin_user_id(&user_id) {
                Ok(user_id) => user_id,
                Err(error) => return client_management_error_json(&error),
            };
            if get_admin_user_row(&db, &user_id, now).await?.is_none() {
                return client_management_error_json(&ClientManagementError::not_found(
                    "user was not found",
                ));
            }
            let patch = match admin_user_patch_from_request(&mut request).await {
                Ok(patch) => patch,
                Err(error) => return client_management_error_json(&error),
            };
            if patch.disabled.is_none() && patch.admin.is_none() {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "user patch must include disabled or admin",
                ));
            }
            if matches!(
                (&admin_authorization, patch.admin),
                (AdminAuthorization::Session { user_id: current_user_id }, Some(false))
                    if current_user_id.as_str() == user_id.as_str()
            ) {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "cannot revoke the active admin session membership",
                ));
            }

            if let Some(disabled) = patch.disabled {
                set_admin_user_disabled(&db, &user_id, disabled, now).await?;
                if disabled {
                    revoke_active_sessions_for_user(&db, &user_id, now).await?;
                    revoke_active_refresh_tokens_for_user(&db, &user_id, now).await?;
                }
                record_audit_event(
                    &db,
                    &request,
                    if disabled {
                        "user.disable"
                    } else {
                        "user.enable"
                    },
                    Some(&user_id),
                    None,
                    None,
                    serde_json::json!({}),
                    now,
                )
                .await;
            }
            if let Some(admin) = patch.admin {
                if admin {
                    let granted_by = admin_authorization_granted_by(&admin_authorization);
                    upsert_admin_membership(&db, &user_id, &granted_by, now).await?;
                    record_audit_event(
                        &db,
                        &request,
                        "admin.membership.grant",
                        Some(&user_id),
                        None,
                        None,
                        serde_json::json!({ "grantedBy": granted_by, "mode": "admin_ui" }),
                        now,
                    )
                    .await;
                } else {
                    disable_admin_membership(&db, &user_id, now).await?;
                    record_audit_event(
                        &db,
                        &request,
                        "admin.membership.revoke",
                        Some(&user_id),
                        None,
                        None,
                        serde_json::json!({ "mode": "admin_ui" }),
                        now,
                    )
                    .await;
                }
            }

            let response = admin_user_detail_response(&db, &user_id, now)
                .await?
                .ok_or_else(|| worker_error("user update did not return a row".to_owned()))?;
            json(&response)
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn provider_status(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    let provider_failures = provider_failure_statuses(&db).await?;
    json(&ProviderStatusResponse {
        providers: provider_status_rows(&env, &config, true, &provider_failures),
    })
}

#[cfg(target_arch = "wasm32")]
async fn client_branding(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let origin = request_origin(&request)?;
    let Some(client_id) = query_param(&url, "client_id") else {
        return oauth_error_json("invalid_request", "missing client_id", 400);
    };
    let client_id = match validate_client_id(&client_id) {
        Ok(client_id) => client_id,
        Err(error) => {
            return oauth_error_json("invalid_request", error.description, error.status);
        }
    };

    let db = env.d1(D1_BINDING)?;
    let Some(client) = get_client(&db, &client_id).await? else {
        return oauth_error_json("invalid_request", "client is not registered", 404);
    };
    if let Err(error) = validate_cors_origin(origin.as_deref(), &client.allowed_origins) {
        return oauth_error_json("invalid_request", error, 403);
    }

    let config = server_config(&env, &url);
    let catalog = login_theme_catalog_from_env(&env);
    let target_url = query_param(&url, "return_to").or_else(|| origin.clone());
    let response = json(&client_branding_for_client(
        &product_name_from_env(&env),
        &client,
        &config.issuer().issuer,
        target_url.as_deref(),
        &catalog,
    ))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn local_auth_status(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    let magic_link_delivery = magic_link_delivery_status(&db).await?;
    json(&LocalAuthStatusResponse {
        methods: local_auth_status_rows(&env, magic_link_delivery),
    })
}

#[cfg(target_arch = "wasm32")]
async fn ready(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let response = readiness_response(&env, &server_config(&env, &url), &db).await?;
    let status = if response.ready { 200 } else { 503 };
    json_status(&response, status)
}

#[cfg(target_arch = "wasm32")]
async fn events(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    let filter = match audit_event_filter_from_url(&url) {
        Ok(filter) => filter,
        Err(error) => return client_management_error_json(&error),
    };
    let rows = list_audit_event_rows(&db, &filter).await?;
    let events = rows
        .into_iter()
        .map(audit_event_response_from_row)
        .collect();
    json(&AuditEventsResponse { events })
}

#[cfg(target_arch = "wasm32")]
async fn oauth_token(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let form = match token_exchange_form_from_request(&mut request).await {
        Ok(form) => form,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    if let Err(error) = validate_token_exchange_form(&form) {
        return token_exchange_error_json(&error, 400);
    }

    let db = env.d1(D1_BINDING)?;
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let grant_subject = format!("{}:{}", form.client_id, form.grant_type);
    let rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_OAUTH_TOKEN_IP,
                window_seconds: 5 * 60,
                max_attempts: 30,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_OAUTH_TOKEN_CLIENT,
                window_seconds: 5 * 60,
                max_attempts: 30,
            },
            form.client_id.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_OAUTH_TOKEN_GRANT,
                window_seconds: 5 * 60,
                max_attempts: 30,
            },
            grant_subject.as_str(),
        ),
    ];
    if let Some(blocked) = rate_limit_check_subjects(
        &db,
        &rate_limit_key,
        unix_timestamp_seconds(),
        &rate_limit_subjects,
    )
    .await?
    {
        return rate_limit_oauth_error_json(blocked.retry_after_seconds, origin.as_deref());
    }
    let registered_client = match get_registered_client(&db, &form.client_id).await? {
        Some(client) => client,
        None => {
            if let Some(blocked) = rate_limit_increment_subjects(
                &db,
                &rate_limit_key,
                unix_timestamp_seconds(),
                &rate_limit_subjects,
            )
            .await?
            {
                return rate_limit_oauth_error_json(blocked.retry_after_seconds, origin.as_deref());
            }
            return token_exchange_error_json(
                &TokenExchangeError::invalid_client("client is not registered"),
                401,
            );
        }
    };
    if let Err(error) =
        validate_token_client_auth(&registered_client, &form.client_id, &form.client_auth)
    {
        if let Some(blocked) = rate_limit_increment_subjects(
            &db,
            &rate_limit_key,
            unix_timestamp_seconds(),
            &rate_limit_subjects,
        )
        .await?
        {
            return rate_limit_oauth_error_json(blocked.retry_after_seconds, origin.as_deref());
        }
        return token_exchange_error_json(&error, 401);
    }
    if let Err(error) =
        validate_cors_origin(origin.as_deref(), &registered_client.client.allowed_origins)
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let now = unix_timestamp_seconds();
    let signing_key = signing_key_from_env(&env)?;
    let config = server_config(&env, &request_url);
    let response = match form.grant_type.as_str() {
        "authorization_code" => {
            authorization_code_token(&db, &config, &signing_key, &form, now).await
        }
        "refresh_token" => refresh_token_token(&db, &config, &signing_key, &form, now).await,
        TOKEN_EXCHANGE_GRANT_TYPE => {
            native_provider_token(
                &db,
                &env,
                &config,
                &signing_key,
                &registered_client,
                &form,
                now,
            )
            .await
        }
        _ => token_exchange_error_json(
            &TokenExchangeError::unsupported_grant_type(
                "grant_type must be authorization_code, refresh_token, or token exchange",
            ),
            400,
        ),
    }?;
    if response.status_code() >= 400 {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
        {
            return rate_limit_oauth_error_json(blocked.retry_after_seconds, origin.as_deref());
        }
    }
    record_audit_event(
        &db,
        &request,
        "token.issue",
        None,
        Some(&form.client_id),
        None,
        serde_json::json!({ "grantType": form.grant_type }),
        now,
    )
    .await;

    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn authorization_code_token(
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    form: &TokenExchangeForm,
    now: i32,
) -> worker::Result<Response> {
    let fields =
        authorization_code_fields(form).map_err(|error| worker_error(error.description))?;
    let auth_code = match get_authorization_code(db, fields.code).await? {
        Some(auth_code) => auth_code,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("authorization code was not found"),
                400,
            )
        }
    };

    if let Err(error) = validate_authorization_code_exchange(&auth_code, &fields, now) {
        return token_exchange_error_json(&error, 400);
    }
    if !consume_authorization_code(db, &auth_code.code_hash, now).await? {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("authorization code has already been consumed"),
            400,
        );
    }

    let user_claims = match get_user_token_claims(db, &auth_code.user_id).await? {
        Some(user_claims) => user_claims,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("authorization code user was not found"),
                400,
            )
        }
    };
    if user_claims.disabled_at.is_some() {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("authorization code user is disabled"),
            400,
        );
    }

    let refresh_token = if auth_code
        .scope
        .split_whitespace()
        .any(|scope| scope == "offline_access")
    {
        let token = random_token()?;
        put_refresh_token(&db, &token, &auth_code, now).await?;
        Some(token)
    } else {
        None
    };

    let response = token_response(
        config,
        signing_key,
        &TokenIssue::from_auth_code(&auth_code).with_user_claims(&user_claims),
        refresh_token,
        now,
    )
    .map_err(worker_error)?;
    json(&response)
}

#[cfg(target_arch = "wasm32")]
async fn refresh_token_token(
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    form: &TokenExchangeForm,
    now: i32,
) -> worker::Result<Response> {
    let refresh_token =
        refresh_token_field(form).map_err(|error| worker_error(error.description))?;
    let refresh_token_row = match get_refresh_token(db, refresh_token).await? {
        Some(refresh_token_row) => refresh_token_row,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("refresh token was not found"),
                400,
            )
        }
    };

    if let Err(error) = validate_refresh_token_exchange(&refresh_token_row, &form.client_id, now) {
        if refresh_token_replay_detected(&refresh_token_row, &form.client_id) {
            revoke_refresh_token_family(db, &refresh_token_row, now).await?;
        }
        return token_exchange_error_json(&error, 400);
    }
    let user_claims = match get_user_token_claims(db, &refresh_token_row.user_id).await? {
        Some(user_claims) => user_claims,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("refresh token user was not found"),
                400,
            )
        }
    };
    if user_claims.disabled_at.is_some() {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("refresh token user is disabled"),
            400,
        );
    }

    if !rotate_refresh_token(db, &refresh_token_row.token_hash, now).await? {
        revoke_refresh_token_family(db, &refresh_token_row, now).await?;
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("refresh token has already been rotated"),
            400,
        );
    }
    let new_refresh_token = random_token()?;
    put_rotated_refresh_token(db, &new_refresh_token, &refresh_token_row, now).await?;

    let response = token_response(
        config,
        signing_key,
        &TokenIssue::from_refresh_token(&refresh_token_row).with_user_claims(&user_claims),
        Some(new_refresh_token),
        now,
    )
    .map_err(worker_error)?;
    json(&response)
}

#[cfg(target_arch = "wasm32")]
async fn native_provider_token(
    db: &worker::d1::D1Database,
    env: &Env,
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    client: &RegisteredClient,
    form: &TokenExchangeForm,
    now: i32,
) -> worker::Result<Response> {
    let fields = match native_provider_token_fields(form) {
        Ok(fields) => fields,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    let scope = match native_token_scope(fields.scope) {
        Ok(scope) => scope,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    let provider_client_id =
        match native_provider_client_id(env, fields.provider_id, fields.provider_client_id) {
            Ok(provider_client_id) => provider_client_id,
            Err(error) => return token_exchange_error_json(&error, 400),
        };

    let resolved = match resolve_native_provider_profile(&fields, &provider_client_id, now).await {
        Ok(resolved) => resolved,
        Err((error, status)) => return provider_profile_error_json(&error, status),
    };
    if let Err(error) = validate_client_email_domain_policy(&client.client, &resolved.profile) {
        return provider_callback_error_json(&error, 403);
    }

    let user_id = upsert_provider_profile(
        db,
        &client.account_scope.namespace,
        &resolved.profile,
        resolved.raw_profile_json.as_deref(),
        now,
    )
    .await?;
    let user_claims = match get_user_token_claims(db, &user_id).await? {
        Some(user_claims) => user_claims,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("provider identity user was not found"),
                400,
            )
        }
    };
    if user_claims.disabled_at.is_some() {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("provider identity user is disabled"),
            400,
        );
    }

    let issue = TokenIssue::from_native_provider(&form.client_id, &user_id, &scope, now)
        .with_user_claims(&user_claims);
    let refresh_token = if scope_contains(Some(&scope), "offline_access") {
        let token = random_token()?;
        put_refresh_token_row(db, &hash_secret(&token), &issue, now).await?;
        Some(token)
    } else {
        None
    };
    let response =
        token_response(config, signing_key, &issue, refresh_token, now).map_err(worker_error)?;
    json(&response)
}

#[cfg(target_arch = "wasm32")]
async fn resolve_native_provider_profile(
    fields: &NativeProviderTokenFields<'_>,
    provider_client_id: &str,
    now: i32,
) -> Result<ResolvedProviderProfile, (ProviderProfileError, u16)> {
    match fields.provider_id {
        well_known::APPLE | well_known::GOOGLE => {
            resolve_native_oidc_provider_profile(fields, provider_client_id, now).await
        }
        well_known::SPOTIFY => resolve_native_spotify_profile(fields, provider_client_id).await,
        provider_id => Err((
            ProviderProfileError::invalid_response(format!(
                "unsupported native provider: {provider_id}"
            )),
            400,
        )),
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_native_oidc_provider_profile(
    fields: &NativeProviderTokenFields<'_>,
    provider_client_id: &str,
    now: i32,
) -> Result<ResolvedProviderProfile, (ProviderProfileError, u16)> {
    let jwks = cached_provider_jwks(fields.provider_id, now)
        .await
        .map_err(|error| {
            (
                ProviderProfileError::invalid_response(format!(
                    "could not load {} JWKS: {}",
                    provider_label(fields.provider_id),
                    error.description
                )),
                502,
            )
        })?;
    let verified = verify_provider_id_token_with_web_crypto(
        fields.subject_token,
        &jwks,
        ProviderIdTokenValidation {
            provider_id: fields.provider_id,
            client_id: provider_client_id,
            nonce: fields.nonce,
            now,
        },
    )
    .await
    .map_err(|error| (error, 401))?;

    Ok(native_oidc_profile_from_verified_token(
        fields.provider_id,
        verified,
    ))
}

#[cfg(target_arch = "wasm32")]
async fn resolve_native_spotify_profile(
    fields: &NativeProviderTokenFields<'_>,
    provider_client_id: &str,
) -> Result<ResolvedProviderProfile, (ProviderProfileError, u16)> {
    let provider = OAuthProvider::spotify(provider_client_id);
    let token_set = ProviderTokenSet {
        access_token: Some(fields.subject_token.to_owned()),
        id_token: None,
        refresh_token: None,
        expires_in: None,
    };

    fetch_spotify_profile(&provider, &token_set)
        .await
        .map_err(|error| (error, 401))
}

#[cfg(target_arch = "wasm32")]
async fn oauth_revoke(mut request: Request, env: Env) -> worker::Result<Response> {
    let origin = request_origin(&request)?;
    let form = match token_revocation_form_from_request(&mut request).await {
        Ok(form) => form,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    if let Err(error) = validate_token_revocation_form(&form) {
        return token_exchange_error_json(&error, 400);
    }

    let db = env.d1(D1_BINDING)?;
    let registered_client = match get_registered_client(&db, &form.client_id).await? {
        Some(client) => client,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_client("client is not registered"),
                401,
            )
        }
    };
    if let Err(error) =
        validate_token_client_auth(&registered_client, &form.client_id, &form.client_auth)
    {
        return token_exchange_error_json(&error, 401);
    }
    if let Err(error) =
        validate_cors_origin(origin.as_deref(), &registered_client.client.allowed_origins)
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    if should_attempt_refresh_token_revocation(form.token_type_hint.as_deref()) {
        if let Some(refresh_token) = get_refresh_token(&db, &form.token).await? {
            if refresh_token.client_id == form.client_id {
                revoke_refresh_token(&db, &refresh_token.token_hash, unix_timestamp_seconds())
                    .await?;
            }
        }
    }
    record_audit_event(
        &db,
        &request,
        "token.revoke",
        None,
        Some(&form.client_id),
        None,
        serde_json::json!({
            "tokenTypeHint": form.token_type_hint.as_deref().unwrap_or("")
        }),
        unix_timestamp_seconds(),
    )
    .await;

    let response = Response::empty()?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn oauth_introspect(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let form = match token_introspection_form_from_request(&mut request).await {
        Ok(form) => form,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    if let Err(error) = validate_token_introspection_form(&form) {
        return token_exchange_error_json(&error, 400);
    }

    let db = env.d1(D1_BINDING)?;
    let registered_client = match get_registered_client(&db, &form.client_id).await? {
        Some(client) => client,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_client("client is not registered"),
                401,
            )
        }
    };
    if let Err(error) =
        validate_introspection_client_auth(&registered_client, &form.client_id, &form.client_auth)
    {
        return token_exchange_error_json(&error, 401);
    }
    if let Err(error) =
        validate_cors_origin(origin.as_deref(), &registered_client.client.allowed_origins)
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let config = server_config(&env, &request_url);
    let material = signing_material_from_env(&env)?;
    let response = introspection_response_for_token(
        &db,
        &config,
        &material.jwks,
        &form,
        unix_timestamp_seconds(),
    )
    .await?;
    let response = json(&response)?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn userinfo(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let bearer_token = match bearer_token_from_request(&request) {
        Ok(token) => token,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };
    let material = signing_material_from_env(&env)?;
    let config = server_config(&env, &request_url);
    let now = unix_timestamp_seconds();
    let claims = match verify_zeroth_access_token(&bearer_token, &config, &material.jwks, now) {
        Ok(claims) => claims,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };

    let db = env.d1(D1_BINDING)?;
    let user = match get_user(&db, &claims.sub).await? {
        Some(user) => user,
        None => return oauth_error_json("invalid_token", "user was not found", 401),
    };
    if user.disabled_at.is_some() {
        return oauth_error_json("invalid_token", "user is disabled", 401);
    }
    if let Err(error) = validate_access_token_session(&db, &claims, now).await? {
        return oauth_error_json("invalid_token", error, 401);
    }
    let allowed_origins = match active_client_allowed_origins(&db, &claims.aud).await? {
        Ok(allowed_origins) => allowed_origins,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };
    if let Err(error) = validate_cors_origin(origin.as_deref(), &allowed_origins) {
        return oauth_error_json("invalid_request", error, 403);
    }

    let response = json(&userinfo_response(&user, claims.scope.as_deref()))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn client_issuer_access_token(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();

    let Some(current) = (match current_session_from_request(&request, &db, &config, now).await {
        Ok(current) => current,
        Err(_) => {
            return token_issuer_error_json(
                "token_signing_unavailable",
                "the access token could not be issued",
                503,
                origin.as_deref(),
            );
        }
    }) else {
        return token_issuer_error_json(
            "unauthenticated",
            "an active Zeroth session is required",
            401,
            origin.as_deref(),
        );
    };
    let Some(origin) = origin.as_deref() else {
        return token_issuer_error_json(
            "origin_not_allowed",
            "this origin is not permitted to request an issuer token",
            403,
            None,
        );
    };
    if validate_session_cors_origin(&db, Some(origin), &current.session)
        .await
        .is_err()
    {
        return token_issuer_error_json(
            "origin_not_allowed",
            "this origin is not permitted to request an issuer token",
            403,
            Some(origin),
        );
    }
    let Some(client_id) = current.session.client_id.as_deref() else {
        return token_issuer_error_json(
            "token_signing_unavailable",
            "issuer token minting is not configured for this session",
            503,
            Some(origin),
        );
    };
    let Some(client_row) = (match get_client_row_for_admin(&db, client_id).await {
        Ok(client_row) => client_row,
        Err(_) => {
            return token_issuer_error_json(
                "token_signing_unavailable",
                "the access token could not be issued",
                503,
                Some(origin),
            );
        }
    }) else {
        return token_issuer_error_json(
            "token_signing_unavailable",
            "issuer token minting is not configured for this client",
            503,
            Some(origin),
        );
    };
    if client_row.disabled_at.is_some() {
        return token_issuer_error_json(
            "token_signing_unavailable",
            "issuer token minting is not configured for this client",
            503,
            Some(origin),
        );
    }
    let Some(audience) = client_row
        .issuer_token_audience
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return token_issuer_error_json(
            "token_signing_unavailable",
            "issuer token minting is not configured for this client",
            503,
            Some(origin),
        );
    };
    let ttl_seconds = match issuer_token_ttl_seconds(client_row.issuer_token_ttl_seconds) {
        Ok(ttl_seconds) => ttl_seconds,
        Err(error) => {
            return token_issuer_error_json("token_signing_unavailable", error, 503, Some(origin));
        }
    };
    let material = match signing_material_from_env(&env) {
        Ok(material) => material,
        Err(_) => {
            return token_issuer_error_json(
                "token_signing_unavailable",
                "the access token could not be issued",
                503,
                Some(origin),
            )
        }
    };
    let Some(session_client_id) = current.session.client_id.as_deref() else {
        return token_issuer_error_json(
            "token_signing_unavailable",
            "issuer token minting is not configured for this session",
            503,
            Some(origin),
        );
    };
    let claims = build_issuer_access_token_claims(
        &config.issuer().issuer,
        &current.user.id,
        session_client_id,
        audience,
        i64::from(now),
        i64::from(ttl_seconds),
        match random_token() {
            Ok(token) => token,
            Err(_) => {
                return token_issuer_error_json(
                    "token_signing_unavailable",
                    "the access token could not be issued",
                    503,
                    Some(origin),
                );
            }
        },
    );
    let access_token = match sign_jwt(&material.signing_key, &claims) {
        Ok(token) => token,
        Err(_) => {
            return token_issuer_error_json(
                "token_signing_unavailable",
                "the access token could not be issued",
                503,
                Some(origin),
            );
        }
    };
    let response = json_status_no_store(
        &IssuerAccessTokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: ttl_seconds,
        },
        200,
    )?;
    with_cors_actual_headers(response, Some(origin))
}

#[cfg(target_arch = "wasm32")]
async fn session(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let current =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?;

    if let Some(current) = &current {
        if let Err(error) =
            validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
        {
            return oauth_error_json("invalid_request", error, 403);
        }
    } else {
        if let Err(error) = validate_any_client_cors_origin(&db, origin.as_deref()).await? {
            return oauth_error_json("invalid_request", error, 403);
        }
    }

    let response = json(&session_response(
        current
            .as_ref()
            .map(|current| (&current.session, &current.user)),
    ))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn sessions(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let current =
        match current_account_from_request(&request, &env, &db, &config, origin.as_deref(), now)
            .await?
        {
            Ok(current) => current,
            Err(error) => return oauth_error_json(error.code, error.description, error.status),
        };

    match request.method() {
        Method::Get => {
            if let Err(error) = current.require_profile_scope() {
                return oauth_error_json(error.code, error.description, error.status);
            }
            let sessions = list_active_sessions_for_user(&db, &current.user.id, now).await?;
            let response = json(&sessions_response(
                &sessions,
                current.session_id.as_deref().unwrap_or_default(),
            ))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        Method::Delete => {
            if current.access_token {
                return oauth_error_json(
                    "invalid_request",
                    "session revocation requires hosted account session",
                    403,
                );
            }
            let csrf_token = csrf_token_from_header(&request)?;
            if let Err(error) = validate_browser_session_mutation(
                &request,
                &env,
                &db,
                &config,
                current.client_id.as_deref(),
                current.session_id.as_deref().unwrap_or_default(),
                CSRF_ROUTE_FAMILY_ACCOUNT,
                csrf_token.as_deref(),
                now,
            )
            .await?
            {
                return oauth_error_json("invalid_request", error, 403);
            }
            let Some(session_id) =
                query_param(&request_url, "session_id").filter(|id| !id.is_empty())
            else {
                return oauth_error_json("invalid_request", "missing session_id", 400);
            };
            let now = unix_timestamp_seconds();
            revoke_user_session(&db, &session_id, &current.user.id, now).await?;
            revoke_refresh_token_family_for_session(&db, &session_id, &current.user.id, now)
                .await?;
            record_audit_event(
                &db,
                &request,
                "session.revoke",
                Some(&current.user.id),
                current.client_id.as_deref(),
                None,
                serde_json::json!({
                    "current": current.session_id.as_deref() == Some(session_id.as_str())
                }),
                now,
            )
            .await;

            let response = json(&serde_json::json!({ "ok": true }))?;
            let response = if current.session_id.as_deref() == Some(session_id.as_str()) {
                with_set_cookie(
                    response,
                    &clear_session_cookie(&config.cookie_name, config.cookie_domain.as_deref()),
                )?
            } else {
                response
            };
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn profile(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let origin = request_origin_for_config(&request, &config)?;
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let current =
        match current_account_from_request(&request, &env, &db, &config, origin.as_deref(), now)
            .await?
        {
            Ok(current) => current,
            Err(error) => return oauth_error_json(error.code, error.description, error.status),
        };

    match request.method() {
        Method::Get => {
            let response = json(&userinfo_response(
                &current.user,
                Some(current.profile_scope()),
            ))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        Method::Patch => {
            if let Err(error) = current.require_profile_scope() {
                return oauth_error_json(error.code, error.description, error.status);
            }
            let csrf_token = csrf_token_from_header(&request)?;
            if !current.access_token {
                if let Err(error) = validate_browser_session_mutation(
                    &request,
                    &env,
                    &db,
                    &config,
                    current.client_id.as_deref(),
                    current.session_id.as_deref().unwrap_or_default(),
                    CSRF_ROUTE_FAMILY_ACCOUNT,
                    csrf_token.as_deref(),
                    now,
                )
                .await?
                {
                    return oauth_error_json("invalid_request", error, 403);
                }
            }
            let patch = match profile_patch_from_request(&mut request).await {
                Ok(patch) => patch,
                Err(error) => {
                    return oauth_error_json("invalid_request", error.description, error.status)
                }
            };
            let now = unix_timestamp_seconds();
            update_user_profile_patch(&db, &current.user.id, &patch, now).await?;
            record_audit_event(
                &db,
                &request,
                "user.profile.update",
                Some(&current.user.id),
                current.client_id.as_deref(),
                None,
                serde_json::json!({
                    "displayName": patch.display_name.is_some(),
                    "pictureUrl": patch.picture_url.is_some()
                }),
                now,
            )
            .await;
            let updated_user = user_with_profile_patch(&current.user, &patch);
            let response = json(&userinfo_response(
                &updated_user,
                Some(current.profile_scope()),
            ))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn identities(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let origin = request_origin_for_config(&request, &config)?;
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let current =
        match current_account_from_request(&request, &env, &db, &config, origin.as_deref(), now)
            .await?
        {
            Ok(current) => current,
            Err(error) => return oauth_error_json(error.code, error.description, error.status),
        };

    match request.method() {
        Method::Get => {
            if let Err(error) = current.require_profile_scope() {
                return oauth_error_json(error.code, error.description, error.status);
            }
            let identities = list_identities_for_user(&db, &current.user.id).await?;
            let response = json(&identities_response(&identities))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        Method::Delete => {
            if current.access_token {
                return oauth_error_json(
                    "invalid_request",
                    "identity unlink requires hosted account session",
                    403,
                );
            }
            let csrf_token = csrf_token_from_header(&request)?;
            if let Err(error) = validate_browser_session_mutation(
                &request,
                &env,
                &db,
                &config,
                current.client_id.as_deref(),
                current.session_id.as_deref().unwrap_or_default(),
                CSRF_ROUTE_FAMILY_ACCOUNT,
                csrf_token.as_deref(),
                now,
            )
            .await?
            {
                return oauth_error_json("invalid_request", error, 403);
            }
            let identity = match identity_reference_from_url(&request_url) {
                Ok(identity) => identity,
                Err(error) => return oauth_error_json("invalid_request", error, 400),
            };
            if !identity_exists_for_user(
                &db,
                &current.user.id,
                &identity.provider_id,
                &identity.provider_subject,
            )
            .await?
            {
                return oauth_error_json("invalid_request", "identity was not found", 404);
            }
            if count_identities_for_user(&db, &current.user.id).await? <= 1 {
                return oauth_error_json("invalid_request", "cannot unlink the last identity", 400);
            }

            if !delete_user_identity(
                &db,
                &current.user.id,
                &identity.provider_id,
                &identity.provider_subject,
            )
            .await?
            {
                return oauth_error_json("invalid_request", "identity could not be unlinked", 409);
            }
            if identity.provider_id == "passkey" {
                disable_passkey_credential(
                    &db,
                    &identity.provider_subject,
                    unix_timestamp_seconds(),
                )
                .await?;
            }
            record_audit_event(
                &db,
                &request,
                "identity.unlink",
                Some(&current.user.id),
                current.client_id.as_deref(),
                Some(&identity.provider_id),
                serde_json::json!({}),
                unix_timestamp_seconds(),
            )
            .await;
            let response = json(&serde_json::json!({ "ok": true }))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn passkey_register_options(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match passkey_json_from_request::<PasskeyRegisterOptionsRequest>(&mut request).await
    {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };

    let current = current_session_from_request(&request, &db, &config, now).await?;
    if current.is_none() {
        if let Err(error) = validate_admin_request(&request, &env, &db, &config, now).await {
            return client_management_error_json(&error);
        }
    } else {
        let csrf_token = csrf_token_from_header(&request)?;
        if let Err(error) = validate_browser_session_mutation(
            &request,
            &env,
            &db,
            &config,
            current
                .as_ref()
                .and_then(|current| current.session.client_id.as_deref()),
            current
                .as_ref()
                .map(|current| current.session.id.as_str())
                .unwrap_or_default(),
            CSRF_ROUTE_FAMILY_ACCOUNT,
            csrf_token.as_deref(),
            now,
        )
        .await?
        {
            return oauth_error_json("invalid_request", error, 403);
        }
    }
    let (user_id, email, display_name) = match passkey_registration_subject(current.as_ref(), &body)
    {
        Ok(subject) => subject,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let client_id = match passkey_client_id_from_request(&env, body.client_id.as_deref()) {
        Ok(client_id) => client_id,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let client = match get_client(&db, &client_id).await? {
        Some(client) => client,
        None => {
            return oauth_error_json(
                "invalid_request",
                "passkey session client is not registered",
                400,
            )
        }
    };
    let return_to = match passkey_return_to(&url, body.return_to.as_deref(), &client, &config) {
        Ok(return_to) => return_to,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let label = match validate_passkey_label(body.label.as_deref()) {
        Ok(label) => label,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let mut rate_limit_subjects = vec![
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_CLIENT,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            client_id.as_str(),
        ),
    ];
    rate_limit_subjects.push(rate_limit_subject(
        RateLimitPolicy {
            scope: RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_EMAIL,
            window_seconds: 15 * 60,
            max_attempts: 10,
        },
        email.as_str(),
    ));
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    if let Some(blocked) =
        rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    let challenge = random_token()?;

    cleanup_expired_passkey_challenges(&db, now).await?;
    put_passkey_challenge(
        &db,
        &challenge,
        "registration",
        user_id.as_deref(),
        Some(&client_id),
        Some(&return_to),
        Some(&email),
        display_name.as_deref(),
        label.as_deref(),
        now,
    )
    .await?;

    let exclude_credentials = if let Some(user_id) = user_id.as_deref() {
        list_passkey_credentials_for_user(&db, user_id)
            .await?
            .into_iter()
            .map(|credential| PasskeyCredentialDescriptor {
                credential_type: "public-key",
                id: credential.credential_id,
            })
            .collect()
    } else {
        Vec::new()
    };
    let options = match passkey_creation_options(
        &config,
        &challenge,
        user_id.as_deref().unwrap_or(&email),
        &email,
        display_name.as_deref().unwrap_or(&email),
        exclude_credentials,
    ) {
        Ok(options) => options,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };

    json(&PasskeyOptionsResponse {
        public_key: options,
    })
}

#[cfg(target_arch = "wasm32")]
async fn passkey_register_verify(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match passkey_json_from_request::<PasskeyRegisterVerifyRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let credential_subject = hash_secret(&body.raw_id);
    let failure_rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_VERIFY_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_VERIFY_CREDENTIAL,
                window_seconds: 15 * 60,
                max_attempts: 10,
            },
            credential_subject.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    let validation = match validate_passkey_registration_response(&config, &body) {
        Ok(validation) => validation,
        Err(error) => {
            if let Some(blocked) = rate_limit_increment_subjects(
                &db,
                &rate_limit_key,
                now,
                &failure_rate_limit_subjects,
            )
            .await?
            {
                return rate_limit_error_json(blocked.retry_after_seconds);
            }
            return oauth_error_json("invalid_request", error, 400);
        }
    };
    let admin_authorization = match maybe_authorize_admin_write_request(
        &mut request,
        &env,
        &db,
        &config,
        now,
        CSRF_ROUTE_FAMILY_ADMIN,
        true,
        "first_admin_creation",
    )
    .await
    {
        Ok(admin_authorization) => admin_authorization,
        Err(error) => return client_management_error_json(&error),
    };
    let challenge_hash =
        match passkey_challenge_hash_from_client_data(&body.response.client_data_json) {
            Ok(challenge_hash) => challenge_hash,
            Err(error) => {
                if let Some(blocked) = rate_limit_increment_subjects(
                    &db,
                    &rate_limit_key,
                    now,
                    &failure_rate_limit_subjects,
                )
                .await?
                {
                    return rate_limit_error_json(blocked.retry_after_seconds);
                }
                return oauth_error_json("invalid_request", error, 400);
            }
        };
    let Some(challenge) = get_passkey_challenge_by_hash(&db, &challenge_hash).await? else {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey challenge was not found", 400);
    };
    if let Err(error) = validate_passkey_challenge(&challenge, "registration", now) {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", error, 400);
    }
    if !passkey_challenge_matches_client_data(
        &challenge.challenge_hash,
        &body.response.client_data_json,
    ) {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey challenge did not match", 400);
    }
    if admin_authorization.is_none() {
        let Some(current) = current_session_from_request(&request, &db, &config, now).await? else {
            return oauth_error_json(
                "login_required",
                "active browser session was not found",
                401,
            );
        };
        let csrf_token = csrf_token_from_header(&request)?;
        if let Err(error) = validate_browser_session_mutation(
            &request,
            &env,
            &db,
            &config,
            current.session.client_id.as_deref(),
            &current.session.id,
            CSRF_ROUTE_FAMILY_ACCOUNT,
            csrf_token.as_deref(),
            now,
        )
        .await?
        {
            return oauth_error_json("invalid_request", error, 403);
        }
    }
    if !consume_passkey_challenge(&db, &challenge.challenge_hash, now).await? {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey challenge was already used", 400);
    }

    let (user_id, email, display_name) =
        ensure_passkey_registration_user(&db, &challenge, now).await?;
    put_passkey_credential(&db, &validation, &user_id, challenge.label.as_deref(), now).await?;
    upsert_passkey_identity(
        &db,
        &user_id,
        &validation.credential_id,
        Some(&email),
        display_name.as_deref(),
        now,
    )
    .await?;
    if let Some(admin_authorization) = admin_authorization {
        let granted_by = admin_authorization_granted_by(&admin_authorization);
        upsert_admin_membership(&db, &user_id, &granted_by, now).await?;
        record_audit_event(
            &db,
            &request,
            "admin.membership.grant",
            Some(&user_id),
            challenge.client_id.as_deref(),
            Some("passkey"),
            serde_json::json!({
                "grantedBy": granted_by,
                "mode": "passkey_registration"
            }),
            now,
        )
        .await;
    }
    record_audit_event(
        &db,
        &request,
        "passkey.register",
        Some(&user_id),
        challenge.client_id.as_deref(),
        Some("passkey"),
        serde_json::json!({
            "credentialIdHash": hash_secret(&validation.credential_id),
            "label": challenge.label.as_deref().unwrap_or("")
        }),
        now,
    )
    .await;

    let Some(user) = get_user(&db, &user_id).await? else {
        return oauth_error_json("invalid_request", "passkey user was not found", 400);
    };
    json(&serde_json::json!({
        "ok": true,
        "user": userinfo_response(&user, Some("email profile"))
    }))
}

#[cfg(target_arch = "wasm32")]
async fn passkey_authenticate_options(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body =
        match passkey_json_from_request::<PasskeyAuthenticateOptionsRequest>(&mut request).await {
            Ok(body) => body,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };
    let db = env.d1(D1_BINDING)?;
    let client_id = match passkey_client_id_from_request(&env, body.client_id.as_deref()) {
        Ok(client_id) => client_id,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let client = match get_client(&db, &client_id).await? {
        Some(client) => client,
        None => {
            return oauth_error_json(
                "invalid_request",
                "passkey session client is not registered",
                400,
            )
        }
    };
    let return_to = match passkey_return_to(&url, body.return_to.as_deref(), &client, &config) {
        Ok(return_to) => return_to,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let now = unix_timestamp_seconds();
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_OPTIONS_CLIENT,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            client_id.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    if let Some(blocked) =
        rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    let challenge = random_token()?;
    cleanup_expired_passkey_challenges(&db, now).await?;
    put_passkey_challenge(
        &db,
        &challenge,
        "authentication",
        None,
        Some(&client_id),
        Some(&return_to),
        None,
        None,
        None,
        now,
    )
    .await?;
    let allow_credentials = list_active_passkey_credentials(&db)
        .await?
        .into_iter()
        .map(|credential| PasskeyCredentialDescriptor {
            credential_type: "public-key",
            id: credential.credential_id,
        })
        .collect();
    let options = match passkey_request_options(&config, &challenge, allow_credentials) {
        Ok(options) => options,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };

    json(&PasskeyOptionsResponse {
        public_key: options,
    })
}

#[cfg(target_arch = "wasm32")]
async fn passkey_authenticate_verify(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body =
        match passkey_json_from_request::<PasskeyAuthenticateVerifyRequest>(&mut request).await {
            Ok(body) => body,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let credential_subject = hash_secret(&body.raw_id);
    let failure_rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_VERIFY_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSKEY_VERIFY_CREDENTIAL,
                window_seconds: 15 * 60,
                max_attempts: 10,
            },
            credential_subject.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    let challenge_hash =
        match passkey_challenge_hash_from_client_data(&body.response.client_data_json) {
            Ok(challenge_hash) => challenge_hash,
            Err(error) => {
                if let Some(blocked) = rate_limit_increment_subjects(
                    &db,
                    &rate_limit_key,
                    now,
                    &failure_rate_limit_subjects,
                )
                .await?
                {
                    return rate_limit_error_json(blocked.retry_after_seconds);
                }
                return oauth_error_json("invalid_request", error, 400);
            }
        };
    let Some(challenge) = get_passkey_challenge_by_hash(&db, &challenge_hash).await? else {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey challenge was not found", 400);
    };
    if let Err(error) = validate_passkey_challenge(&challenge, "authentication", now) {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", error, 400);
    }
    let credential_id = match passkey_raw_id(&body.raw_id) {
        Ok(credential_id) => credential_id,
        Err(error) => {
            if let Some(blocked) = rate_limit_increment_subjects(
                &db,
                &rate_limit_key,
                now,
                &failure_rate_limit_subjects,
            )
            .await?
            {
                return rate_limit_error_json(blocked.retry_after_seconds);
            }
            return oauth_error_json("invalid_request", error, 400);
        }
    };
    let Some(credential) = get_passkey_credential(&db, &credential_id).await? else {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey credential was not found", 400);
    };
    if credential.disabled_at.is_some() {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey credential is disabled", 400);
    }
    if let Err(error) =
        validate_passkey_authentication_response(&config, &body, &credential, &challenge)
    {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", error, 400);
    }
    if !consume_passkey_challenge(&db, &challenge.challenge_hash, now).await? {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey challenge was already used", 400);
    }
    update_passkey_credential_use(
        &db,
        &credential.credential_id,
        passkey_authenticator_sign_count(&body.response.authenticator_data)?,
        now,
    )
    .await?;
    let Some(user) = get_user(&db, &credential.user_id).await? else {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey user was not found", 400);
    };
    if user.disabled_at.is_some() {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "passkey user is disabled", 400);
    }
    let client_id = challenge
        .client_id
        .as_deref()
        .ok_or_else(|| worker_error("passkey challenge did not include a client_id".to_owned()))?;
    let session_id = format!("sess_{}", random_token()?);
    let audit_context = audit_request_context(&request).unwrap_or_default();
    let success_rate_limit_subjects = [rate_limit_subject(
        RateLimitPolicy {
            scope: RATE_LIMIT_SCOPE_PASSKEY_VERIFY_CREDENTIAL,
            window_seconds: 15 * 60,
            max_attempts: 10,
        },
        credential_subject.as_str(),
    )];
    rate_limit_clear_subjects(&db, &rate_limit_key, &success_rate_limit_subjects).await?;
    put_session(
        &db,
        &session_id,
        &user.id,
        client_id,
        now,
        audit_context.user_agent.as_deref(),
        audit_context.ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        &db,
        &request,
        "session.login",
        Some(&user.id),
        Some(client_id),
        Some("passkey"),
        serde_json::json!({
            "mode": "passkey",
            "credentialIdHash": hash_secret(&credential.credential_id)
        }),
        now,
    )
    .await;

    let return_to = challenge
        .return_to
        .unwrap_or_else(|| format!("{}/admin", config.issuer().issuer));
    let response = json(&PasskeyVerifyResponse {
        ok: true,
        return_to,
        user: userinfo_response(&user, Some("email profile")),
    })?;
    with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn password_register(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match local_auth_body_from_request::<PasswordRegisterRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let email = match validate_local_auth_email(&body.email) {
        Ok(email) => email,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if let Err(error) = validate_local_auth_password(&body.password) {
        return oauth_error_json("invalid_request", error, 400);
    }
    let display_name = match body
        .display_name
        .as_deref()
        .map(validate_passkey_display_name)
        .transpose()
    {
        Ok(display_name) => display_name,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let (client, return_to) = match local_auth_client_and_return_to(
        &env,
        &url,
        &db,
        body.client_id.as_deref(),
        body.return_to.as_deref(),
        &config,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if let Err(error) = validate_local_auth_origin(&request, &db, &client, &config).await? {
        return oauth_error_json("invalid_request", error, 403);
    }
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_REGISTER_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_REGISTER_EMAIL,
                window_seconds: 15 * 60,
                max_attempts: 5,
            },
            email.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    if let Some(blocked) =
        rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }

    let current = current_session_from_request(&request, &db, &config, now).await?;
    let existing_user = get_user_by_primary_email(&db, &email).await?;
    let registration_target = match current.as_ref() {
        Some(current) => {
            if current.user.disabled_at.is_some() {
                return oauth_error_json("invalid_request", "user is disabled", 403);
            }
            if let Some(primary_email) = current.user.primary_email.as_deref() {
                if !primary_email.eq_ignore_ascii_case(&email) {
                    return oauth_error_json(
                        "invalid_request",
                        "password email must match the signed-in user",
                        403,
                    );
                }
            }
            if let Some(existing_user) = existing_user.as_ref() {
                if existing_user.id != current.user.id {
                    return oauth_error_json(
                        "invalid_request",
                        "email is already attached to another user",
                        409,
                    );
                }
            }
            Some(current.user.id.clone())
        }
        None if existing_user.is_some() => None,
        None => {
            let user_id = format!("usr_{}", random_token()?);
            insert_passkey_user(&db, &user_id, &email, display_name.as_deref(), now).await?;
            Some(user_id)
        }
    };

    if let Some(user_id) = registration_target.as_deref() {
        if let Some(user) = get_user(&db, user_id).await? {
            if user.disabled_at.is_some() {
                return oauth_error_json("invalid_request", "user is disabled", 403);
            }
        }
    }

    let peppers = password_pepper_from_env(&env).map_err(worker_error)?;
    let salt = random_token()?;
    let _password_hash =
        password_hash_current(&body.password, &salt, peppers.current.value.as_slice()).await?;
    let public_response = || {
        json_status(
            &PublicLocalAuthResponse {
                ok: true,
                message: PUBLIC_LOCAL_AUTH_RESPONSE_MESSAGE,
            },
            202,
        )
    };

    if existing_user.is_some() && current.is_none() {
        record_audit_event(
            &db,
            &request,
            "password.register.suppressed",
            existing_user.as_ref().map(|user| user.id.as_str()),
            Some(&client.id.0),
            Some(LOCAL_AUTH_PROVIDER_ID),
            serde_json::json!({
                "reason": "account_exists"
            }),
            now,
        )
        .await;
        return public_response();
    }

    if let Err(error) = validate_local_auth_client_email_policy(&client, &email) {
        if current.is_none() {
            record_audit_event(
                &db,
                &request,
                "password.register.suppressed",
                existing_user.as_ref().map(|user| user.id.as_str()),
                Some(&client.id.0),
                Some(LOCAL_AUTH_PROVIDER_ID),
                serde_json::json!({
                    "reason": error.code,
                    "description": error.description
                }),
                now,
            )
            .await;
            return public_response();
        }
        return oauth_error_json(&error.code, &error.description, 403);
    }

    let Some(user_id) = registration_target else {
        return public_response();
    };
    upsert_local_credential(
        &db,
        &email,
        &user_id,
        &_password_hash,
        &salt,
        &peppers.current.id,
        PASSWORD_PBKDF2_ITERATIONS,
        now,
    )
    .await?;
    upsert_local_auth_identity(
        &db,
        &user_id,
        &email,
        display_name.as_deref(),
        "password",
        now,
    )
    .await?;
    let response = issue_local_auth_session_response(
        &request,
        &db,
        &config,
        &client.id.0,
        &user_id,
        &return_to,
        "password.register",
        "password_register",
        now,
    )
    .await?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn password_login(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match local_auth_body_from_request::<PasswordLoginRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let email = match validate_local_auth_email(&body.email) {
        Ok(email) => email,
        Err(_) => return oauth_error_json("invalid_grant", "invalid email or password", 401),
    };
    let (client, return_to) = match local_auth_client_and_return_to(
        &env,
        &url,
        &db,
        body.client_id.as_deref(),
        body.return_to.as_deref(),
        &config,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if let Err(error) = validate_local_auth_origin(&request, &db, &client, &config).await? {
        return oauth_error_json("invalid_request", error, 403);
    }
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let ip_email = format!("{ip}:{email}");
    let failure_rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_LOGIN_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_LOGIN_EMAIL,
                window_seconds: 15 * 60,
                max_attempts: 5,
            },
            email.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_LOGIN_IP_EMAIL,
                window_seconds: 15 * 60,
                max_attempts: 5,
            },
            ip_email.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }

    let Some(credential) = get_local_credential(&db, &email).await? else {
        password_dummy_verify(&env, &body.password).await?;
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "invalid email or password", 401);
    };
    let password_verification =
        local_auth_password_matches(&env, &credential, &body.password).await?;
    if credential.disabled_at.is_some() || !password_verification.valid {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "invalid email or password", 401);
    }
    let Some(user) = get_user(&db, &credential.user_id).await? else {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "invalid email or password", 401);
    };
    if user.disabled_at.is_some() {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "invalid email or password", 401);
    }
    if password_verification.needs_rehash {
        let peppers = password_pepper_from_env(&env).map_err(worker_error)?;
        let new_salt = random_token()?;
        let new_hash =
            password_hash_current(&body.password, &new_salt, peppers.current.value.as_slice())
                .await?;
        upsert_local_credential(
            &db,
            &credential.email,
            &credential.user_id,
            &new_hash,
            &new_salt,
            &peppers.current.id,
            PASSWORD_PBKDF2_ITERATIONS,
            now,
        )
        .await?;
    }
    mark_local_credential_used(&db, &credential.email, now).await?;
    let success_rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_LOGIN_EMAIL,
                window_seconds: 15 * 60,
                max_attempts: 5,
            },
            email.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_PASSWORD_LOGIN_IP_EMAIL,
                window_seconds: 15 * 60,
                max_attempts: 5,
            },
            ip_email.as_str(),
        ),
    ];
    rate_limit_clear_subjects(&db, &rate_limit_key, &success_rate_limit_subjects).await?;
    let response = issue_local_auth_session_response(
        &request,
        &db,
        &config,
        &client.id.0,
        &user.id,
        &return_to,
        "session.login",
        "password",
        now,
    )
    .await?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn evm_wallet_challenge(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match wallet_json_from_request::<WalletChallengeRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let address = match validate_evm_wallet_address(&body.address) {
        Ok(address) => address,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let chain_id = match normalize_evm_chain_id(&body.chain_id) {
        Ok(chain_id) => chain_id,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let (client, return_to) = match local_auth_client_and_return_to(
        &env,
        &url,
        &db,
        body.client_id.as_deref(),
        body.return_to.as_deref(),
        &config,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if let Err(error) = validate_local_auth_origin(&request, &db, &client, &config).await? {
        return oauth_error_json("invalid_request", error, 403);
    }
    let Some(registered_client) = get_registered_client(&db, &client.id.0).await? else {
        return oauth_error_json("invalid_request", "wallet client is not registered", 400);
    };
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_WALLET_CHALLENGE_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_WALLET_CHALLENGE_ADDRESS,
                window_seconds: 15 * 60,
                max_attempts: 10,
            },
            address.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_WALLET_CHALLENGE_CLIENT,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            client.id.0.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    if let Some(blocked) =
        rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }

    cleanup_expired_wallet_challenges(&db, now).await?;
    let nonce = random_token()?;
    let challenge_hash = hash_secret(&nonce);
    let domain = url
        .host_str()
        .ok_or_else(|| worker_error("wallet login host is missing".to_owned()))?;
    let message = evm_wallet_signin_message(
        domain,
        &config.public_base_url,
        &product_name_from_env(&env),
        &address,
        &chain_id,
        &nonce,
        now,
    );
    let audit_context = audit_request_context(&request).unwrap_or_default();
    put_wallet_challenge(
        &db,
        &challenge_hash,
        &address,
        &chain_id,
        &client.id.0,
        &return_to,
        &registered_client.account_scope.namespace,
        &message,
        now,
        audit_context.user_agent.as_deref(),
        audit_context.ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        &db,
        &request,
        "wallet.challenge",
        None,
        Some(&client.id.0),
        Some(EVM_WALLET_PROVIDER_ID),
        serde_json::json!({
            "addressHash": hash_secret(&address),
            "chainId": &chain_id
        }),
        now,
    )
    .await;
    json(&WalletChallengeResponse {
        ok: true,
        provider: EVM_WALLET_PROVIDER_ID,
        address,
        chain_id,
        nonce,
        message,
    })
}

#[cfg(target_arch = "wasm32")]
async fn evm_wallet_verify(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match wallet_json_from_request::<WalletVerifyRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let address = match validate_evm_wallet_address(&body.address) {
        Ok(address) => address,
        Err(_) => return oauth_error_json("invalid_grant", "invalid wallet signature", 401),
    };
    let chain_id = match normalize_evm_chain_id(&body.chain_id) {
        Ok(chain_id) => chain_id,
        Err(_) => return oauth_error_json("invalid_grant", "invalid wallet signature", 401),
    };
    if !wallet_nonce_valid(&body.nonce) {
        return oauth_error_json("invalid_grant", "invalid wallet challenge", 401);
    }
    let challenge_hash = hash_secret(&body.nonce);
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let failure_rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_WALLET_VERIFY_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_WALLET_VERIFY_ADDRESS,
                window_seconds: 15 * 60,
                max_attempts: 10,
            },
            address.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_WALLET_VERIFY_CHALLENGE,
                window_seconds: 15 * 60,
                max_attempts: 10,
            },
            challenge_hash.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    let Some(challenge) = get_wallet_challenge(&db, &challenge_hash).await? else {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "invalid wallet challenge", 401);
    };
    if let Err(error) = validate_wallet_challenge(&challenge, now) {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", error, 401);
    }
    if challenge.provider_id != EVM_WALLET_PROVIDER_ID
        || challenge.address != address
        || challenge.chain_id != chain_id
        || challenge.message != body.message
    {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json(
            "invalid_grant",
            "wallet challenge did not match request",
            401,
        );
    }
    let recovered_address = match recover_evm_wallet_address(&body.message, &body.signature) {
        Ok(recovered_address) => recovered_address,
        Err(_) => {
            if let Some(blocked) = rate_limit_increment_subjects(
                &db,
                &rate_limit_key,
                now,
                &failure_rate_limit_subjects,
            )
            .await?
            {
                return rate_limit_error_json(blocked.retry_after_seconds);
            }
            return oauth_error_json("invalid_grant", "invalid wallet signature", 401);
        }
    };
    if recovered_address != address {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "invalid wallet signature", 401);
    }
    if !consume_wallet_challenge(&db, &challenge_hash, now).await? {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_grant", "wallet challenge was already used", 401);
    }

    let profile = evm_wallet_profile(&address);
    let raw_profile_json = serde_json::json!({
        "kind": "wallet",
        "provider": EVM_WALLET_PROVIDER_ID,
        "address": &address,
        "chainId": &chain_id
    })
    .to_string();
    let user_id = upsert_provider_profile(
        &db,
        &challenge.account_namespace,
        &profile,
        Some(&raw_profile_json),
        now,
    )
    .await?;
    let Some(user) = get_user(&db, &user_id).await? else {
        return oauth_error_json("invalid_request", "wallet user was not found", 400);
    };
    if user.disabled_at.is_some() {
        if let Some(blocked) =
            rate_limit_increment_subjects(&db, &rate_limit_key, now, &failure_rate_limit_subjects)
                .await?
        {
            return rate_limit_error_json(blocked.retry_after_seconds);
        }
        return oauth_error_json("invalid_request", "wallet user is disabled", 403);
    }
    let success_rate_limit_subjects = [rate_limit_subject(
        RateLimitPolicy {
            scope: RATE_LIMIT_SCOPE_WALLET_VERIFY_ADDRESS,
            window_seconds: 15 * 60,
            max_attempts: 10,
        },
        address.as_str(),
    )];
    rate_limit_clear_subjects(&db, &rate_limit_key, &success_rate_limit_subjects).await?;
    let response = issue_wallet_session_response(
        &request,
        &db,
        &config,
        &challenge.client_id,
        &user,
        &challenge.return_to,
        &address,
        &chain_id,
        now,
    )
    .await?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn magic_link_request(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let body = match local_auth_body_from_request::<MagicLinkRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let email = match validate_local_auth_email(&body.email) {
        Ok(email) => email,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let (client, return_to) = match local_auth_client_and_return_to(
        &env,
        &url,
        &db,
        body.client_id.as_deref(),
        body.return_to.as_deref(),
        &config,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if let Err(error) = validate_local_auth_origin(&request, &db, &client, &config).await? {
        return oauth_error_json("invalid_request", error, 403);
    }
    if let Err(error) = validate_local_auth_client_email_policy(&client, &email) {
        return oauth_error_json(&error.code, &error.description, 403);
    }
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_MAGIC_LINK_REQUEST_IP,
                window_seconds: 60 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_MAGIC_LINK_REQUEST_EMAIL,
                window_seconds: 60 * 60,
                max_attempts: 3,
            },
            email.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_MAGIC_LINK_REQUEST_CLIENT,
                window_seconds: 60 * 60,
                max_attempts: 20,
            },
            client.id.0.as_str(),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    if let Some(blocked) =
        rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }

    cleanup_expired_magic_links(&db, now).await?;
    let user = get_user_by_primary_email(&db, &email).await?;
    let policy_ok = validate_local_auth_client_email_policy(&client, &email).is_ok();
    let user_id = user.as_ref().map(|user| user.id.clone());
    let token = random_token()?;
    let token_hash = hash_secret(&token);
    let audit_context = audit_request_context(&request).unwrap_or_default();
    let public_response = || {
        json_status(
            &PublicLocalAuthResponse {
                ok: true,
                message: PUBLIC_LOCAL_AUTH_RESPONSE_MESSAGE,
            },
            202,
        )
    };

    if !policy_ok || user.is_none() {
        record_audit_event(
            &db,
            &request,
            "magic_link.issue.suppressed",
            user_id.as_deref(),
            Some(&client.id.0),
            Some(LOCAL_AUTH_PROVIDER_ID),
            serde_json::json!({
                "reason": if policy_ok { "account_missing_or_disabled" } else { "policy_denied" }
            }),
            now,
        )
        .await;
        return public_response();
    }

    put_magic_link(
        &db,
        &token_hash,
        &email,
        user_id.as_deref(),
        &client.id.0,
        &return_to,
        now,
        audit_context.user_agent.as_deref(),
        audit_context.ip_hash.as_deref(),
    )
    .await?;
    let link = magic_link_url(&config, &token)?;
    let sent = match send_magic_link_email(&env, &email, &link).await {
        Ok(sent) => sent,
        Err(error) => {
            let error_class = classify_magic_link_email_error(&error);
            record_audit_event(
                &db,
                &request,
                "magic_link.email.failed",
                user_id.as_deref(),
                Some(&client.id.0),
                Some(LOCAL_AUTH_PROVIDER_ID),
                magic_link_email_failed_details(error_class, &error),
                now,
            )
            .await;
            false
        }
    };
    record_audit_event(
        &db,
        &request,
        "magic_link.issue",
        user_id.as_deref(),
        Some(&client.id.0),
        Some(LOCAL_AUTH_PROVIDER_ID),
        serde_json::json!({ "sent": sent }),
        now,
    )
    .await;
    public_response()
}

#[cfg(target_arch = "wasm32")]
async fn magic_link_confirm(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let Some(token) = query_param(&url, "token").filter(|token| !token.trim().is_empty()) else {
        return oauth_error_json("invalid_request", "missing magic link token", 400);
    };
    let token_hash = hash_secret(token.trim());
    let Some(row) = get_magic_link(&db, &token_hash).await? else {
        return oauth_error_json("invalid_request", "magic link is invalid or expired", 400);
    };
    if let Err(error) = validate_magic_link(&row, now) {
        return oauth_error_json("invalid_request", error, 400);
    }
    let secret = csrf_secret_from_env(&env).map_err(worker_error)?;
    let confirm_token = csrf_token(
        &secret,
        &token_hash,
        CSRF_ROUTE_FAMILY_MAGIC_LINK_CONFIRM,
        now,
    );
    let action = format!(
        "{}/magic-links/consume",
        config.public_base_url.trim_end_matches('/')
    );
    let cancel_href = format!("{}/login", config.public_base_url.trim_end_matches('/'));
    let document = render_confirmation_document(
        "Confirm Magic Link",
        "Continue with magic link?",
        "This will sign you in and create a browser session.",
        &action,
        "Continue",
        &cancel_href,
        &[
            ("token", token.trim()),
            (MAGIC_LINK_CONFIRM_TOKEN_FIELD, &confirm_token),
        ],
    );
    let response = html(document)?;
    with_confirmation_document_headers(response)
}

#[cfg(target_arch = "wasm32")]
async fn magic_link_consume(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let rate_limit_key = rate_limit_key_from_env(&env).map_err(worker_error)?;
    let origin = request_origin_for_config(&request, &config)?;
    let Some(origin) = origin else {
        return oauth_error_json("invalid_request", "Origin header is required", 403);
    };
    if !origin_matches_public_base_url(&origin, &config.public_base_url) {
        return oauth_error_json("invalid_request", cors_disallowed_origin(&origin), 403);
    }
    let body = match local_auth_body_from_request::<MagicLinkConsumeRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let Some(token) = Some(body.token).filter(|token| !token.trim().is_empty()) else {
        return oauth_error_json("invalid_request", "missing magic link token", 400);
    };
    let token_hash = hash_secret(token.trim());
    let Some(confirm_token) = body
        .confirm
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return oauth_error_json(
            "invalid_request",
            "missing magic link confirmation token",
            403,
        );
    };
    let secret = csrf_secret_from_env(&env).map_err(worker_error)?;
    if let Err(error) = validate_csrf_token(
        &secret,
        &token_hash,
        CSRF_ROUTE_FAMILY_MAGIC_LINK_CONFIRM,
        confirm_token.trim(),
        now,
    ) {
        return oauth_error_json("invalid_request", error, 403);
    }
    let ip = rate_limit_request_ip(&request)?.unwrap_or_else(|| "missing".to_owned());
    let rate_limit_subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_MAGIC_LINK_CONSUME_IP,
                window_seconds: 15 * 60,
                max_attempts: 20,
            },
            ip.as_str(),
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_MAGIC_LINK_CONSUME_TOKEN,
                window_seconds: 15 * 60,
                max_attempts: 10,
            },
            rate_limit_token_subject(&token_hash),
        ),
    ];
    if let Some(blocked) =
        rate_limit_check_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    if let Some(blocked) =
        rate_limit_increment_subjects(&db, &rate_limit_key, now, &rate_limit_subjects).await?
    {
        return rate_limit_error_json(blocked.retry_after_seconds);
    }
    let Some(row) = get_magic_link(&db, &token_hash).await? else {
        return oauth_error_json("invalid_request", "magic link is invalid or expired", 400);
    };
    if let Err(error) = validate_magic_link(&row, now) {
        return oauth_error_json("invalid_request", error, 400);
    }
    if !consume_magic_link(&db, &token_hash, now).await? {
        return oauth_error_json("invalid_request", "magic link is invalid or expired", 400);
    }
    let Some(client) = get_client(&db, &row.client_id).await? else {
        return oauth_error_json(
            "invalid_request",
            "magic link client is not registered",
            400,
        );
    };
    if let Err(error) = validate_local_auth_client_email_policy(&client, &row.email) {
        return oauth_error_json(&error.code, &error.description, 403);
    }
    let user_id = ensure_magic_link_user(&db, &row, now).await?;
    if let Some(user) = get_user(&db, &user_id).await? {
        if user.disabled_at.is_some() {
            return oauth_error_json("invalid_request", "user is disabled", 403);
        }
    }
    upsert_local_auth_identity(&db, &user_id, &row.email, None, "magic_link", now).await?;
    let issue = issue_local_auth_session(
        &request,
        &db,
        &row.client_id,
        &user_id,
        &row.return_to,
        "session.login",
        "magic_link",
        now,
    )
    .await?;
    let response = json(&LocalAuthResponse {
        ok: true,
        return_to: issue.return_to,
        user: userinfo_response(&issue.user, Some("email profile")),
    })?;
    with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &issue.session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn identity_link(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let provider_id = match provider_id_from_url(&request_url) {
        Ok(provider_id) => provider_id,
        Err(error) => return auth_error_json(&error, 400),
    };
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let mut request = request;
    let csrf_token = csrf_token_from_request(&mut request).await?;
    let Some(current) = current_session_from_request(&request, &db, &config, now).await? else {
        return oauth_error_json(
            "login_required",
            "active browser session was not found",
            401,
        );
    };
    if let Err(error) = validate_browser_session_mutation(
        &request,
        &env,
        &db,
        &config,
        current.session.client_id.as_deref(),
        &current.session.id,
        CSRF_ROUTE_FAMILY_ACCOUNT,
        csrf_token.as_deref(),
        now,
    )
    .await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let Some(client_id) = current.session.client_id.as_deref() else {
        return oauth_error_json(
            "invalid_request",
            "active browser session is not associated with a client",
            400,
        );
    };
    let client = match get_client(&db, client_id).await? {
        Some(client) => client,
        None => {
            return oauth_error_json(
                "unauthorized_client",
                "session client is not registered",
                400,
            )
        }
    };
    let return_to = match identity_link_return_to_from_url(
        &request_url,
        &client,
        Some(&config.public_base_url),
    ) {
        Ok(return_to) => return_to,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if !provider_configured_for_login(&env, &provider_id) {
        return oauth_error_json(
            "invalid_request",
            format!("provider is not fully configured: {provider_id}"),
            400,
        );
    }

    let provider = provider_from_env(&env, &provider_id)?;
    let provider_redirect_uri = config.issuer().provider_callback_endpoint();
    let provider_state = random_token()?;
    let provider_nonce = random_token()?;
    cleanup_expired_auth_transactions(&db, now).await?;
    let transaction = auth_transaction_from_link_request(
        &client,
        &provider_id,
        provider_state,
        provider_nonce,
        provider_redirect_uri,
        return_to,
        query_param(&request_url, "state"),
        &current.user.id,
        &current.session.id,
        now,
    );
    put_auth_transaction(&db, &transaction).await?;

    let auth = provider
        .authorize_url(ProviderAuthorizeRequest {
            redirect_uri: &transaction.provider_redirect_uri,
            state: &transaction.provider_state,
            nonce: provider_authorize_nonce(&transaction),
            code_challenge: None,
            scopes: None,
        })
        .map_err(|error| worker::Error::RustError(error.description))?;

    let target = url::Url::parse(&auth.url)
        .map_err(|error| worker::Error::RustError(format!("invalid authorize URL: {error}")))?;
    let response = Response::redirect(target)?;
    with_set_cookie(
        response,
        &transaction_cookie(
            &config.transaction_cookie_name,
            &transaction.provider_state,
            AUTH_TRANSACTION_TTL_SECONDS,
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn validate(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let authorization = request_header(&request, "Authorization")?;
    let bearer_token = match bearer_token_from_authorization_header(authorization.as_deref()) {
        Ok(token) => token,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };
    let db = env.d1(D1_BINDING)?;

    if let Some(bearer_token) = bearer_token {
        let material = signing_material_from_env(&env)?;
        let config = server_config(&env, &request_url);
        let now = unix_timestamp_seconds();
        let claims = match verify_zeroth_access_token(&bearer_token, &config, &material.jwks, now) {
            Ok(claims) => claims,
            Err(error) => return oauth_error_json("invalid_token", error, 401),
        };
        let user = match get_user(&db, &claims.sub).await? {
            Some(user) => user,
            None => return oauth_error_json("invalid_token", "user was not found", 401),
        };
        if user.disabled_at.is_some() {
            return oauth_error_json("invalid_token", "user is disabled", 401);
        }
        if let Err(error) = validate_access_token_session(&db, &claims, now).await? {
            return oauth_error_json("invalid_token", error, 401);
        }
        let allowed_origins = match active_client_allowed_origins(&db, &claims.aud).await? {
            Ok(allowed_origins) => allowed_origins,
            Err(error) => return oauth_error_json("invalid_token", error, 401),
        };
        if let Err(error) = validate_cors_origin(origin.as_deref(), &allowed_origins) {
            return oauth_error_json("invalid_request", error, 403);
        }

        let response = json(&validate_access_token_response(&claims, &user))?;
        return with_cors_actual_headers(response, origin.as_deref());
    }

    let config = server_config(&env, &request_url);
    let Some(current) =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?
    else {
        return oauth_error_json(
            "invalid_token",
            "bearer token or active browser session is required",
            401,
        );
    };
    if let Err(error) =
        validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let response = json(&validate_session_response(&current.session, &current.user))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn logout(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let current = current_session_from_request(&request, &db, &config, now).await?;
    match request.method() {
        Method::Get => {
            let cancel_href = current
                .as_ref()
                .map(|_| format!("{}/account", config.public_base_url.trim_end_matches('/')))
                .unwrap_or_else(|| {
                    format!("{}/login", config.public_base_url.trim_end_matches('/'))
                });
            let action = request_url.to_string();
            let hidden_inputs = if let Some(current) = &current {
                let secret = csrf_secret_from_env(&env).map_err(worker_error)?;
                let csrf_token =
                    csrf_token(&secret, &current.session.id, CSRF_ROUTE_FAMILY_LOGOUT, now);
                vec![("_csrf", csrf_token)]
            } else {
                Vec::new()
            };
            let hidden_inputs_ref = hidden_inputs
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect::<Vec<_>>();
            let document = render_confirmation_document(
                "Confirm Logout",
                "Sign out of this session?",
                "This will revoke the current browser session.",
                &action,
                "Sign out",
                &cancel_href,
                &hidden_inputs_ref,
            );
            let response = html(document)?;
            return with_confirmation_document_headers(response);
        }
        Method::Post => {
            let origin = request_origin_for_config(&request, &config)?;
            let mut request = request;
            let csrf_token = csrf_token_from_request(&mut request).await?;
            if let Some(current) = &current {
                if let Err(error) = validate_browser_session_mutation(
                    &request,
                    &env,
                    &db,
                    &config,
                    current.session.client_id.as_deref(),
                    &current.session.id,
                    CSRF_ROUTE_FAMILY_LOGOUT,
                    csrf_token.as_deref(),
                    now,
                )
                .await?
                {
                    return oauth_error_json("invalid_request", error, 403);
                }
                revoke_session(&db, &current.session.id, now).await?;
                revoke_refresh_token_family_for_session(
                    &db,
                    &current.session.id,
                    &current.user.id,
                    now,
                )
                .await?;
                record_audit_event(
                    &db,
                    &request,
                    "session.logout",
                    Some(&current.user.id),
                    current.session.client_id.as_deref(),
                    None,
                    serde_json::json!({}),
                    now,
                )
                .await;
            } else if let Err(error) =
                validate_any_client_cors_origin(&db, origin.as_deref()).await?
            {
                return oauth_error_json("invalid_request", error, 403);
            }

            let redirect_target = match logout_redirect_target(
                &request_url,
                current.as_ref(),
                &db,
                &config,
                &env,
                now,
            )
            .await?
            {
                Ok(redirect_target) => redirect_target,
                Err(error) => return oauth_error_json("invalid_request", error, 400),
            };

            if let Some(target) = redirect_target {
                let response = Response::redirect(target)?;
                return with_set_cookie(
                    response,
                    &clear_session_cookie(&config.cookie_name, config.cookie_domain.as_deref()),
                );
            }

            let response = json(&serde_json::json!({ "ok": true }))?;
            let response = with_set_cookie(
                response,
                &clear_session_cookie(&config.cookie_name, config.cookie_domain.as_deref()),
            )?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn cors_preflight(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let origin = match request_origin(&request)? {
        Some(origin) => origin,
        None => return Response::empty().map(|response| response.with_status(400)),
    };
    let requested_method = request_header(&request, "Access-Control-Request-Method")?
        .unwrap_or_default()
        .to_ascii_uppercase();
    let canonical_path = canonical_route_path(url.path());
    if !cors_method_allowed(canonical_path.as_ref(), &requested_method) {
        return Response::empty().map(|response| response.with_status(405));
    }

    let db = env.d1(D1_BINDING)?;
    if !origin_allowed_by_any_client(&db, &origin).await? {
        return Response::empty().map(|response| response.with_status(403));
    }

    let response = Response::empty()?.with_status(204);
    with_cors_preflight_headers(response, &origin)
}

#[cfg(target_arch = "wasm32")]
fn jwks(env: Env) -> worker::Result<Response> {
    let material = signing_material_from_env(&env)?;
    json(&material.jwks)
}

#[cfg(target_arch = "wasm32")]
fn apple_app_site_association(env: Env) -> worker::Result<Response> {
    let Some(payload) = secret_string(&env, "APPLE_APP_SITE_ASSOCIATION_JSON")
        .or_else(|| env_string(&env, "APPLE_APP_SITE_ASSOCIATION_JSON"))
    else {
        return json_status(
            &OAuthErrorResponse {
                error: "not_configured".to_owned(),
                error_description: "APPLE_APP_SITE_ASSOCIATION_JSON is not configured".to_owned(),
            },
            404,
        );
    };

    let response = Response::ok(payload)?;
    response
        .headers()
        .set("Content-Type", "application/json; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=3600")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn favicon() -> worker::Result<Response> {
    let response = Response::ok(ZEROTH_FAVICON_SVG)?;
    response
        .headers()
        .set("Content-Type", "image/svg+xml; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=86400")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn profile_menu_script() -> worker::Result<Response> {
    let response = Response::ok(ZEROTH_PROFILE_MENU_JS)?;
    response
        .headers()
        .set("Content-Type", "text/javascript; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=60")?;
    with_public_cross_origin_asset_headers(response)
}

#[cfg(target_arch = "wasm32")]
fn profile_panel_script() -> worker::Result<Response> {
    let response = Response::ok(ZEROTH_PROFILE_PANEL_JS)?;
    response
        .headers()
        .set("Content-Type", "text/javascript; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=3600")?;
    with_public_cross_origin_asset_headers(response)
}

#[cfg(target_arch = "wasm32")]
fn with_public_cross_origin_asset_headers(response: Response) -> worker::Result<Response> {
    response.headers().set("Access-Control-Allow-Origin", "*")?;
    response
        .headers()
        .set("Cross-Origin-Resource-Policy", "cross-origin")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn empty_cached_asset() -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    response
        .headers()
        .set("Cache-Control", "public, max-age=86400")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn web_manifest(env: &Env) -> worker::Result<Response> {
    let name = env
        .var("PRODUCT_NAME")
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "Zeroth".to_owned());
    let payload = serde_json::json!({
        "name": name,
        "short_name": "Zeroth",
        "start_url": "/admin",
        "display": "standalone",
        "background_color": "#f8fafc",
        "theme_color": "#111827",
        "icons": [
            {
                "src": "/favicon.svg",
                "sizes": "any",
                "type": "image/svg+xml"
            }
        ]
    });
    let response = Response::ok(payload.to_string())?;
    response
        .headers()
        .set("Content-Type", "application/manifest+json; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=3600")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn browserconfig_xml() -> worker::Result<Response> {
    let response = Response::ok(
        r#"<?xml version="1.0" encoding="utf-8"?><browserconfig><msapplication><tile><TileColor>#111827</TileColor></tile></msapplication></browserconfig>"#,
    )?;
    response
        .headers()
        .set("Content-Type", "application/xml; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=86400")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn robots_txt() -> worker::Result<Response> {
    let response = Response::ok("User-agent: *\nDisallow:\n")?;
    response
        .headers()
        .set("Content-Type", "text/plain; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=3600")?;
    Ok(response)
}

fn canonical_route_path(path: &str) -> Cow<'_, str> {
    if path == "/" || !path.ends_with('/') {
        return Cow::Borrowed(path);
    }

    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        Cow::Borrowed("/")
    } else {
        Cow::Owned(trimmed.to_owned())
    }
}

fn quiet_browser_asset_path(path: &str) -> bool {
    apple_touch_icon_path(path)
        || matches!(
            path,
            "/.well-known/assetlinks.json" | "/.well-known/appspecific/com.chrome.devtools.json"
        )
}

fn apple_touch_icon_path(path: &str) -> bool {
    if matches!(
        path,
        "/apple-touch-icon.png" | "/apple-touch-icon-precomposed.png"
    ) {
        return true;
    }

    let Some(sized) = path.strip_prefix("/apple-touch-icon-") else {
        return false;
    };
    let Some(stem) = sized.strip_suffix(".png") else {
        return false;
    };
    let dimensions = stem.strip_suffix("-precomposed").unwrap_or(stem);
    let Some((width, height)) = dimensions.split_once('x') else {
        return false;
    };

    !width.is_empty()
        && !height.is_empty()
        && width.bytes().all(|byte| byte.is_ascii_digit())
        && height.bytes().all(|byte| byte.is_ascii_digit())
}

fn known_route_path(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/ready"
            | "/providers"
            | "/providers/status"
            | "/local-auth/status"
            | "/client-branding"
            | "/clients"
            | "/users"
            | "/events"
            | "/routes"
            | "/.well-known/openid-configuration"
            | "/.well-known/oauth-authorization-server"
            | "/.well-known/jwks.json"
            | "/.well-known/apple-app-site-association"
            | "/favicon.ico"
            | "/favicon.svg"
            | "/site.webmanifest"
            | "/manifest.json"
            | "/browserconfig.xml"
            | "/robots.txt"
            | "/login"
            | "/account"
            | "/profile-menu.js"
            | "/profile-panel.js"
            | "/admin"
            | "/authorize"
            | "/__zeroth/db/status"
            | "/__zeroth/db/ensure"
            | "/oauth2/callback"
            | "/oauth/token"
            | "/oauth/revoke"
            | "/oauth/introspect"
            | "/userinfo"
            | "/session"
            | "/sessions"
            | "/profile"
            | "/identities/link"
            | "/identities"
            | "/passkeys/register/options"
            | "/passkeys/register/verify"
            | "/passkeys/register/finish"
            | "/passkeys/authenticate/options"
            | "/passkeys/authenticate/verify"
            | "/passkeys/authenticate/finish"
            | "/password/register"
            | "/password/login"
            | "/wallet/challenge"
            | "/wallet/verify"
            | "/magic-links"
            | "/magic-link/confirm"
            | "/magic-links/consume"
            | "/validate"
            | "/logout"
    ) || quiet_browser_asset_path(path)
}

#[cfg(target_arch = "wasm32")]
async fn hosted_login(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    if !authorization_login_request_present(&url) {
        return hosted_session_login(request, env).await;
    }

    let authorization_request = match parse_authorization_request(&url) {
        Ok(request) => request,
        Err(error) => return auth_error_json(&error, 400),
    };

    let db = env.d1(D1_BINDING)?;
    let registered_client =
        match get_registered_client(&db, &authorization_request.client_id.0).await? {
            Some(client) => client,
            None => {
                return auth_error_json(
                    &AuthorizationRequestError::unauthorized_client("client is not registered"),
                    400,
                )
            }
        };
    let client = &registered_client.client;
    if let Err(error) = validate_authorization_request_for_client(&authorization_request, client) {
        return auth_error_json(&error, 400);
    }

    hosted_authorization_document(
        &request,
        &env,
        &url,
        &db,
        &authorization_request,
        &registered_client,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn hosted_session_login(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let provider_id = match optional_provider_id_from_url(&url) {
        Ok(provider_id) => provider_id,
        Err(error) => return auth_error_json(&error, 400),
    };
    let client_id = match session_login_client_id_from_url(&env, &url) {
        Ok(client_id) => client_id,
        Err(error) => return auth_error_json(&error, 400),
    };

    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let registered_client = match get_registered_client(&db, &client_id).await? {
        Some(client) => client,
        None => {
            return auth_error_json(
                &AuthorizationRequestError::unauthorized_client("client is not registered"),
                400,
            )
        }
    };
    let client = &registered_client.client;
    let return_to = match session_login_return_to_from_url(&url, client, &config.public_base_url) {
        Ok(return_to) => return_to,
        Err(error) => {
            return auth_error_json(&AuthorizationRequestError::invalid_request(error), 400)
        }
    };

    let Some(provider_id) = provider_id else {
        return hosted_session_login_document(
            &request,
            &env,
            &url,
            &db,
            &registered_client,
            return_to,
        )
        .await;
    };
    if !provider_configured_for_login(&env, &provider_id) {
        return auth_error_json(
            &AuthorizationRequestError::invalid_request(format!(
                "provider is not fully configured: {provider_id}"
            )),
            400,
        );
    }

    let provider = provider_from_env(&env, &provider_id)?;
    let provider_redirect_uri = config.issuer().provider_callback_endpoint();
    let provider_state = random_token()?;
    let provider_nonce = random_token()?;
    let now = unix_timestamp_seconds();
    cleanup_expired_auth_transactions(&db, now).await?;
    let transaction = auth_transaction_from_session_login_request(
        client,
        &provider_id,
        provider_state,
        provider_nonce,
        provider_redirect_uri,
        return_to,
        query_param(&url, "state"),
        now,
    );
    put_auth_transaction(&db, &transaction).await?;

    let auth = provider
        .authorize_url(ProviderAuthorizeRequest {
            redirect_uri: &transaction.provider_redirect_uri,
            state: &transaction.provider_state,
            nonce: provider_authorize_nonce(&transaction),
            code_challenge: None,
            scopes: None,
        })
        .map_err(|error| worker::Error::RustError(error.description))?;

    let target = url::Url::parse(&auth.url)
        .map_err(|error| worker::Error::RustError(format!("invalid authorize URL: {error}")))?;
    let response = Response::redirect(target)?;
    with_set_cookie(
        response,
        &transaction_cookie(
            &config.transaction_cookie_name,
            &transaction.provider_state,
            AUTH_TRANSACTION_TTL_SECONDS,
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn hosted_account(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let current = current_session_from_request(&request, &db, &config, now).await?;

    let mut client = None;
    if let Some(current) = &current {
        if let Some(client_id) = current.session.client_id.as_deref() {
            client = get_client(&db, client_id).await?;
        }
    }

    let identities = if let Some(current) = &current {
        list_identities_for_user(&db, &current.user.id).await?
    } else {
        Vec::new()
    };
    let sessions = if let Some(current) = &current {
        list_active_sessions_for_user(&db, &current.user.id, unix_timestamp_seconds()).await?
    } else {
        Vec::new()
    };

    let account_url = config.issuer().issuer + "/account";
    let mut ui_config = if let Some(client) = &client {
        ZerothUiConfig::new(
            config.issuer().issuer.clone(),
            client.id.0.clone(),
            client
                .redirect_uris
                .first()
                .cloned()
                .unwrap_or_else(|| account_url.clone()),
        )
    } else {
        ZerothUiConfig::new(config.issuer().issuer.clone(), "", account_url.clone())
    };
    ui_config.return_to = Some(query_param(&url, "return_to").unwrap_or(account_url));
    ui_config.code_challenge = None;
    ui_config.code_challenge_method = None;
    ui_config.link_identities = true;
    ui_config.csrf_token = current.as_ref().and_then(|current| {
        csrf_secret_from_env(&env)
            .ok()
            .map(|secret| csrf_token(&secret, &current.session.id, CSRF_ROUTE_FAMILY_ACCOUNT, now))
    });

    let mut state = ZerothUiState::new(ui_config).with_product_name(product_name_from_env(&env));
    state.providers = provider_ui_rows(&env, &identities, client.is_some());
    state.profile = current
        .as_ref()
        .map(|current| profile_ui_from_user(&current.user, &identities));
    state.identities = identity_ui_rows(&identities);
    state.sessions = current
        .as_ref()
        .map(|current| session_ui_rows(&sessions, &current.session.id))
        .unwrap_or_default();
    state.applications = client
        .as_ref()
        .map(|client| vec![application_ui_from_client(client)])
        .unwrap_or_default();

    let response = html(render_account_document(state))?;
    with_refreshed_session_cookie(response, current.as_ref(), &config, now)
}

#[cfg(target_arch = "wasm32")]
async fn hosted_clients_admin(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let mut state = ClientsAdminUiState::new(config.issuer().issuer)
        .with_product_name(product_name_from_env(&env));
    state.providers = provider_admin_ui_rows(&env, &config, &[]);
    state.local_auth = local_auth_admin_ui_rows(&env, None);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();

    match authorize_admin_request(&request, &env, &db, &config, now).await {
        Ok(_) => {
            let current = current_session_from_request(&request, &db, &config, now).await?;
            state = state.with_csrf_token(current.as_ref().and_then(|current| {
                csrf_secret_from_env(&env).ok().map(|secret| {
                    csrf_token(&secret, &current.session.id, CSRF_ROUTE_FAMILY_ACCOUNT, now)
                })
            }));
            let provider_failures = provider_failure_statuses(&db).await?;
            state.providers = provider_admin_ui_rows(&env, &config, &provider_failures);
            state.local_auth =
                local_auth_admin_ui_rows(&env, magic_link_delivery_status(&db).await?);
            let rows = list_client_rows_for_admin(&db).await?;
            state.clients = rows
                .into_iter()
                .map(client_admin_ui_from_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(worker_error)?;
            state.users = list_admin_user_rows(&db, now)
                .await?
                .into_iter()
                .map(user_admin_ui_from_row)
                .collect();
            state.events = list_audit_event_rows(&db, &AuditEventFilter::default())
                .await?
                .into_iter()
                .map(audit_event_admin_ui_from_row)
                .collect();
        }
        Err(error) => {
            let current = current_session_from_request(&request, &db, &config, now).await?;
            if current.is_none()
                && error.status == 401
                && provider_configured_for_login(&env, well_known::APPLE)
            {
                return redirect_to_hosted_admin_login(&config, url.path());
            }

            return client_management_error_json(&error);
        }
    }

    html(render_clients_admin_document(state))
}

#[cfg(target_arch = "wasm32")]
async fn authorize(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let authorization_request = match parse_authorization_request(&url) {
        Ok(request) => request,
        Err(error) => return auth_error_json(&error, 400),
    };

    let db = env.d1(D1_BINDING)?;
    let registered_client =
        match get_registered_client(&db, &authorization_request.client_id.0).await? {
            Some(client) => client,
            None => {
                return auth_error_json(
                    &AuthorizationRequestError::unauthorized_client("client is not registered"),
                    400,
                )
            }
        };
    let client = &registered_client.client;

    if let Err(error) = validate_authorization_request_for_client(&authorization_request, client) {
        if let Some(redirect_url) = authorization_request_error_redirect_url_for_client(
            &authorization_request,
            client,
            &config.issuer().issuer,
            &error,
        )
        .map_err(worker::Error::RustError)?
        {
            return Response::redirect(redirect_url);
        }
        return auth_error_json(&error, 400);
    }
    let provider_id = match optional_provider_id_from_url(&url) {
        Ok(provider_id) => provider_id,
        Err(error) => {
            return redirect_to_authorization_request_error(
                &authorization_request,
                &config.issuer().issuer,
                error.code,
                &error.description,
            )
        }
    };
    if authorization_request.prompt == AuthorizationPrompt::None {
        let now = unix_timestamp_seconds();
        let Some(current) = current_session_from_request(&request, &db, &config, now).await? else {
            return redirect_to_authorization_request_error(
                &authorization_request,
                &config.issuer().issuer,
                "login_required",
                "active browser session was not found",
            );
        };
        if !authorization_request_session_is_fresh(&authorization_request, &current.session, now) {
            return redirect_to_authorization_request_error(
                &authorization_request,
                &config.issuer().issuer,
                "login_required",
                "active browser session is older than max_age",
            );
        }

        let zeroth_code = random_token()?;
        put_authorization_code_for_request(
            &db,
            &zeroth_code,
            &authorization_request,
            &current.user.id,
            Some(&current.session.id),
            current.session.created_at,
            now,
        )
        .await?;
        record_audit_event(
            &db,
            &request,
            "authorization.code.issue",
            Some(&current.user.id),
            Some(&authorization_request.client_id.0),
            None,
            serde_json::json!({
                "scope": authorization_request.scope.as_slice().join(" "),
                "mode": "prompt_none"
            }),
            now,
        )
        .await;

        return redirect_to_authorization_request_client(
            &authorization_request,
            &config.issuer().issuer,
            &zeroth_code,
        );
    }
    let Some(provider_id) = provider_id else {
        return hosted_authorization_document(
            &request,
            &env,
            &url,
            &db,
            &authorization_request,
            &registered_client,
        )
        .await;
    };
    if !provider_configured_for_login(&env, &provider_id) {
        return redirect_to_authorization_request_error(
            &authorization_request,
            &config.issuer().issuer,
            "invalid_request",
            &format!("provider is not fully configured: {provider_id}"),
        );
    }

    let provider = provider_from_env(&env, &provider_id)?;
    let provider_redirect_uri = config.issuer().provider_callback_endpoint();
    let provider_state = random_token()?;
    let provider_nonce = random_token()?;
    let now = unix_timestamp_seconds();
    cleanup_expired_auth_transactions(&db, now).await?;
    let transaction = auth_transaction_from_request(
        &authorization_request,
        &provider_id,
        provider_state,
        provider_nonce,
        provider_redirect_uri,
        now,
    );
    put_auth_transaction(&db, &transaction).await?;

    let auth = provider
        .authorize_url(ProviderAuthorizeRequest {
            redirect_uri: &transaction.provider_redirect_uri,
            state: &transaction.provider_state,
            nonce: provider_authorize_nonce(&transaction),
            code_challenge: None,
            scopes: None,
        })
        .map_err(|error| worker::Error::RustError(error.description))?;

    let target = url::Url::parse(&auth.url)
        .map_err(|error| worker::Error::RustError(format!("invalid authorize URL: {error}")))?;
    let response = Response::redirect(target)?;
    with_set_cookie(
        response,
        &transaction_cookie(
            &config.transaction_cookie_name,
            &transaction.provider_state,
            AUTH_TRANSACTION_TTL_SECONDS,
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn hosted_session_login_document(
    request: &Request,
    env: &Env,
    url: &url::Url,
    db: &worker::d1::D1Database,
    registered_client: &RegisteredClient,
    return_to: String,
) -> worker::Result<Response> {
    let client = &registered_client.client;
    let config = server_config(env, url);
    let now = unix_timestamp_seconds();
    let current = current_session_from_request(request, db, &config, now).await?;
    if current.is_some() {
        let target = url::Url::parse(&return_to)
            .map_err(|error| worker_error(format!("invalid session login return_to: {error}")))?;
        let response = Response::redirect(target)?;
        return with_refreshed_session_cookie(response, current.as_ref(), &config, now);
    }
    let identities = if let Some(current) = &current {
        list_identities_for_user(db, &current.user.id).await?
    } else {
        Vec::new()
    };

    let issuer_base_url = config.issuer().issuer;
    let mut ui_config = ZerothUiConfig::new(
        issuer_base_url.clone(),
        client.id.0.clone(),
        return_to.clone(),
    );
    ui_config.return_to = Some(return_to);
    ui_config.state = query_param(url, "state");
    ui_config.nonce = None;
    ui_config.code_challenge = None;
    ui_config.code_challenge_method = None;
    ui_config.link_identities = false;
    ui_config.provider_authorize_path = "/login".to_owned();
    ui_config.csrf_token = current.as_ref().and_then(|current| {
        csrf_secret_from_env(env)
            .ok()
            .map(|secret| csrf_token(&secret, &current.session.id, CSRF_ROUTE_FAMILY_ACCOUNT, now))
    });
    apply_client_login_method_visibility(&mut ui_config, &registered_client.visible_login_methods);
    let target_url = ui_config.return_to.clone();

    let mut state = themed_login_state(
        ZerothUiState::new(ui_config),
        env,
        client,
        &issuer_base_url,
        target_url.as_deref(),
    );
    state.providers = provider_ui_rows(env, &identities, true);
    state.profile = current
        .as_ref()
        .map(|current| profile_ui_from_user(&current.user, &identities));
    state.identities = identity_ui_rows(&identities);
    state.applications = vec![application_ui_from_client(client)];

    let response = html(render_account_document(state))?;
    with_refreshed_session_cookie(response, current.as_ref(), &config, now)
}

#[cfg(target_arch = "wasm32")]
async fn hosted_authorization_document(
    request: &Request,
    env: &Env,
    url: &url::Url,
    db: &worker::d1::D1Database,
    authorization_request: &AuthorizationRequest,
    registered_client: &RegisteredClient,
) -> worker::Result<Response> {
    let client = &registered_client.client;
    let config = server_config(env, url);
    let now = unix_timestamp_seconds();
    let current = current_session_from_request(request, db, &config, now).await?;
    let current = current.filter(|current| {
        authorization_request_may_reuse_session(authorization_request, &current.session, now)
    });
    let identities = if let Some(current) = &current {
        list_identities_for_user(db, &current.user.id).await?
    } else {
        Vec::new()
    };

    let mut ui_config = ui_config_from_authorization_request(&config, authorization_request);
    ui_config.return_to = query_param(url, "return_to");
    ui_config.link_identities = false;
    ui_config.csrf_token = current.as_ref().and_then(|current| {
        csrf_secret_from_env(env)
            .ok()
            .map(|secret| csrf_token(&secret, &current.session.id, CSRF_ROUTE_FAMILY_ACCOUNT, now))
    });
    apply_client_login_method_visibility(&mut ui_config, &registered_client.visible_login_methods);
    let target_url = ui_config
        .return_to
        .clone()
        .unwrap_or_else(|| authorization_request.redirect_uri.clone());

    let mut state = themed_login_state(
        ZerothUiState::new(ui_config),
        env,
        client,
        &config.issuer().issuer,
        Some(&target_url),
    );
    state.providers = provider_ui_rows(env, &identities, true);
    state.profile = current
        .as_ref()
        .map(|current| profile_ui_from_user(&current.user, &identities));
    state.identities = identity_ui_rows(&identities);
    state.applications = vec![application_ui_from_client(client)];

    let response = html(render_account_document(state))?;
    with_refreshed_session_cookie(response, current.as_ref(), &config, now)
}

#[cfg(target_arch = "wasm32")]
fn ui_config_from_authorization_request(
    config: &ZerothServerConfig,
    request: &AuthorizationRequest,
) -> ZerothUiConfig {
    let mut ui_config = ZerothUiConfig::new(
        config.issuer().issuer,
        request.client_id.0.clone(),
        request.redirect_uri.clone(),
    );
    ui_config.scope = request.scope.as_slice().join(" ");
    ui_config.state = request.state.clone();
    ui_config.nonce = request.nonce.clone();
    ui_config.max_age = request.max_age;
    ui_config.code_challenge = request.code_challenge.clone();
    ui_config.code_challenge_method = request
        .code_challenge_method
        .as_ref()
        .map(|method| method.as_str().to_owned());
    ui_config
}

fn apply_client_login_method_visibility(ui_config: &mut ZerothUiConfig, methods: &[String]) {
    ui_config.show_passkey_login = token_list_slice_contains(methods, LOGIN_METHOD_PASSKEY, false);
    ui_config.show_magic_link_login =
        token_list_slice_contains(methods, LOGIN_METHOD_MAGIC_LINK, false);
}

#[cfg(target_arch = "wasm32")]
fn provider_ui_rows(
    env: &Env,
    identities: &[IdentityRow],
    actions_enabled: bool,
) -> Vec<ProviderUi> {
    let mut providers = vec![
        provider_ui(well_known::APPLE, "Apple", ProviderKind::Apple, identities),
        provider_ui(
            well_known::GOOGLE,
            "Google",
            ProviderKind::Google,
            identities,
        ),
        provider_ui(
            well_known::SPOTIFY,
            "Spotify",
            ProviderKind::Spotify,
            identities,
        ),
    ];
    providers.retain(|provider| !provider_disabled(env, &provider.id));
    for provider in &mut providers {
        provider.enabled = actions_enabled && provider_configured_for_login(env, &provider.id);
    }
    providers
}

#[cfg(target_arch = "wasm32")]
fn provider_responses(env: &Env) -> Vec<ProviderResponse> {
    [
        ProviderResponse {
            id: well_known::APPLE,
            kind: "oidc",
        },
        ProviderResponse {
            id: well_known::GOOGLE,
            kind: "oidc",
        },
        ProviderResponse {
            id: well_known::SPOTIFY,
            kind: "oauth2",
        },
    ]
    .into_iter()
    .filter(|provider| !provider_disabled(env, provider.id))
    .collect()
}

fn provider_ui(
    id: &str,
    label: &str,
    kind: ProviderKind,
    identities: &[IdentityRow],
) -> ProviderUi {
    ProviderUi {
        id: id.to_owned(),
        label: label.to_owned(),
        kind,
        connected: identities.iter().any(|identity| identity.provider_id == id),
        enabled: true,
    }
}

#[cfg(target_arch = "wasm32")]
fn provider_client_id_configured(env: &Env, provider_id: &str) -> bool {
    provider_client_id_binding(provider_id)
        .and_then(|binding| binding_value_from_env(env, binding))
        .is_some_and(|value| config_value_configured(Some(&value)))
}

fn provider_client_id_binding(provider_id: &str) -> Option<&'static str> {
    Some(match provider_id {
        well_known::APPLE => "APPLE_CLIENT_ID",
        well_known::GOOGLE => "GOOGLE_CLIENT_ID",
        well_known::SPOTIFY => "SPOTIFY_CLIENT_ID",
        _ => return None,
    })
}

#[cfg(target_arch = "wasm32")]
fn provider_configured_for_login(env: &Env, provider_id: &str) -> bool {
    !provider_disabled(env, provider_id)
        && provider_client_id_configured(env, provider_id)
        && provider_client_secret_configured(env, provider_id)
}

#[cfg(target_arch = "wasm32")]
fn provider_status_rows(
    env: &Env,
    config: &ZerothServerConfig,
    include_disabled: bool,
    provider_failures: &[(String, ProviderFailureStatus)],
) -> Vec<ProviderStatus> {
    [well_known::APPLE, well_known::GOOGLE, well_known::SPOTIFY]
        .into_iter()
        .filter(|provider_id| include_disabled || !provider_disabled(env, provider_id))
        .filter_map(|provider_id| provider_status_row(env, config, provider_id, provider_failures))
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn provider_disabled(env: &Env, provider_id: &str) -> bool {
    binding_value_from_env(env, "DISABLED_PROVIDERS")
        .is_some_and(|values| token_list_contains(Some(&values), provider_id, true))
}

#[cfg(target_arch = "wasm32")]
async fn readiness_response(
    env: &Env,
    config: &ZerothServerConfig,
    db: &worker::d1::D1Database,
) -> worker::Result<ReadinessResponse> {
    let issuer_check = issuer_readiness(config);
    let signing = signing_readiness(env);
    let providers = provider_readiness_rows(env, config);
    let apple_app_site_association = apple_app_site_association_readiness(env);
    let schema = db_readiness(db).await?;
    let csrf = csrf_secret_readiness(env);
    let rate_limit = rate_limit_key_readiness(env);
    let admin_bootstrap = admin_bootstrap_readiness(env);
    let local_auth = local_auth_readiness(env, db).await?;
    let ready = readiness_is_ready(
        &issuer_check,
        &signing,
        &providers,
        &schema,
        &csrf,
        &rate_limit,
        &admin_bootstrap,
        &local_auth,
    );
    let mut notes = Vec::new();
    if !ready {
        notes.push("not_ready");
    }
    notes.extend(schema.notes.iter().copied());
    notes.extend(csrf.notes.iter().copied());
    notes.extend(rate_limit.notes.iter().copied());
    notes.extend(admin_bootstrap.notes.iter().copied());
    notes.extend(local_auth.notes.iter().copied());
    if !apple_app_site_association.configured {
        notes.push("apple_app_site_association_optional");
    }

    Ok(ReadinessResponse {
        ready,
        service: "zeroth",
        issuer: config.issuer().issuer,
        issuer_check,
        signing,
        providers,
        apple_app_site_association,
        notes,
    })
}

fn readiness_is_ready(
    issuer_check: &ReadinessCheck,
    signing: &ReadinessCheck,
    providers: &[ProviderReadiness],
    schema: &ReadinessCheck,
    csrf: &ReadinessCheck,
    rate_limit: &ReadinessCheck,
    admin_bootstrap: &ReadinessCheck,
    local_auth: &ReadinessCheck,
) -> bool {
    issuer_check.configured
        && signing.configured
        && schema.configured
        && csrf.configured
        && rate_limit.configured
        && admin_bootstrap.configured
        && local_auth.configured
        && !providers.is_empty()
        && providers.iter().all(|provider| provider.configured)
}

fn issuer_readiness(config: &ZerothServerConfig) -> ReadinessCheck {
    let mut notes = Vec::new();
    let configured = match url::Url::parse(&config.public_base_url) {
        Ok(url) if url.scheme() == "https" && url.host_str().is_some() => true,
        Ok(url) if url.host_str().is_none() => {
            notes.push("missing_issuer_host");
            false
        }
        Ok(_) => {
            notes.push("issuer_not_https");
            false
        }
        Err(_) => {
            notes.push("invalid_issuer_url");
            false
        }
    };

    ReadinessCheck { configured, notes }
}

#[cfg(target_arch = "wasm32")]
fn signing_readiness(env: &Env) -> ReadinessCheck {
    let key_id_configured =
        binding_value_from_env(env, "JWT_KEY_ID").is_some_and(|value| !value.trim().is_empty());
    let private_key_configured = binding_value_from_env(env, "JWT_ES256_PRIVATE_KEY")
        .is_some_and(|value| !value.trim().is_empty());
    let mut notes = Vec::new();
    if !key_id_configured {
        notes.push("missing_jwt_key_id");
    }
    if !private_key_configured {
        notes.push("missing_jwt_es256_private_key");
    }
    let signing_material_valid =
        key_id_configured && private_key_configured && signing_material_from_env(env).is_ok();
    if key_id_configured && private_key_configured && !signing_material_valid {
        notes.push("invalid_signing_material");
    }

    ReadinessCheck {
        configured: signing_material_valid,
        notes,
    }
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_key_readiness(env: &Env) -> ReadinessCheck {
    let mut notes = Vec::new();
    let configured = match rate_limit_key_from_env(env) {
        Ok(_) => true,
        Err(_) => {
            notes.push("invalid_or_missing_rate_limit_key");
            false
        }
    };
    ReadinessCheck { configured, notes }
}

#[cfg(target_arch = "wasm32")]
fn csrf_secret_readiness(env: &Env) -> ReadinessCheck {
    let mut notes = Vec::new();
    let configured = match csrf_secret_from_env(env) {
        Ok(_) => true,
        Err(_) => {
            notes.push("invalid_or_missing_csrf_secret");
            false
        }
    };
    ReadinessCheck { configured, notes }
}

#[cfg(target_arch = "wasm32")]
fn admin_bootstrap_readiness(env: &Env) -> ReadinessCheck {
    let mut notes = Vec::new();
    if binding_value_from_env(env, "ADMIN_TOKEN").is_some() {
        notes.push("plaintext_admin_token_not_allowed");
        return ReadinessCheck {
            configured: false,
            notes,
        };
    }
    let configured = match binding_value_from_env(env, "ADMIN_TOKEN_SHA256") {
        Some(value) => match normalize_admin_token_hash(&value) {
            Ok(_) => true,
            Err(_) => {
                notes.push("invalid_admin_token_sha256");
                false
            }
        },
        None => {
            notes.push("missing_admin_token_sha256");
            false
        }
    };
    if binding_value_from_env(env, ADMIN_BOOTSTRAP_EMERGENCY_ENV).is_some() {
        match binding_value_from_env(env, ADMIN_BOOTSTRAP_EMERGENCY_EXPIRES_AT_ENV) {
            Some(value) if value.trim().parse::<i32>().is_ok() => {}
            Some(_) => notes.push("invalid_admin_bootstrap_emergency_expires_at"),
            None => notes.push("missing_admin_bootstrap_emergency_expires_at"),
        }
    }
    ReadinessCheck { configured, notes }
}

#[cfg(target_arch = "wasm32")]
async fn db_readiness(db: &worker::d1::D1Database) -> worker::Result<ReadinessCheck> {
    let tables = db_table_statuses(db).await?;
    let migrations_table_present = tables
        .iter()
        .any(|table| table.name == zeroth_storage::SCHEMA_MIGRATIONS_TABLE && table.present);
    let applied_migration_versions = if migrations_table_present {
        applied_schema_migration_versions(db).await?
    } else {
        Vec::new()
    };
    let migrations = zeroth_storage::migrations::ALL
        .iter()
        .map(|migration| DbMigrationStatus {
            version: migration.version,
            name: migration.name,
            applied: applied_migration_versions.contains(&migration.version),
        })
        .collect::<Vec<_>>();
    let compatibility_columns = db_compatibility_column_statuses(db).await?;
    let configured = db_schema_status_ok(&tables, &migrations, &compatibility_columns);
    Ok(ReadinessCheck {
        configured,
        notes: if configured {
            Vec::new()
        } else {
            vec!["database_schema_not_ready"]
        },
    })
}

#[cfg(target_arch = "wasm32")]
async fn local_auth_readiness(
    env: &Env,
    db: &worker::d1::D1Database,
) -> worker::Result<ReadinessCheck> {
    let magic_link_delivery = magic_link_delivery_status(db).await.ok();
    let methods = local_auth_status_rows(env, magic_link_delivery);
    let password_enabled = methods
        .iter()
        .any(|method| method.id == "password" && method.enabled);
    let magic_link_enabled = methods
        .iter()
        .any(|method| method.id == "magic_link" && method.enabled);
    let rate_limit_ready = rate_limit_key_from_env(env).is_ok();
    let mut notes = Vec::new();
    if (password_enabled || magic_link_enabled) && !rate_limit_ready {
        notes.push("rate_limit_key_required_for_public_local_auth");
    }
    Ok(ReadinessCheck {
        configured: (!password_enabled && !magic_link_enabled) || rate_limit_ready,
        notes,
    })
}

#[cfg(target_arch = "wasm32")]
fn provider_readiness_rows(env: &Env, config: &ZerothServerConfig) -> Vec<ProviderReadiness> {
    provider_status_rows(env, config, false, &[])
        .into_iter()
        .map(|status| ProviderReadiness {
            id: status.id,
            label: status.label,
            kind: status.kind,
            configured: status.enabled,
            notes: status.notes,
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn apple_app_site_association_readiness(env: &Env) -> ReadinessCheck {
    apple_app_site_association_readiness_from_payload(
        binding_value_from_env(env, "APPLE_APP_SITE_ASSOCIATION_JSON").as_deref(),
    )
}

fn apple_app_site_association_readiness_from_payload(value: Option<&str>) -> ReadinessCheck {
    let mut notes = Vec::new();
    let configured = match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => match serde_json::from_str::<serde_json::Value>(value) {
            Ok(serde_json::Value::Object(_)) => true,
            Ok(_) => {
                notes.push("apple_app_site_association_not_object");
                false
            }
            Err(_) => {
                notes.push("invalid_apple_app_site_association_json");
                false
            }
        },
        None => {
            notes.push("missing_apple_app_site_association_json");
            false
        }
    };

    ReadinessCheck { configured, notes }
}

fn config_value_configured(value: Option<&str>) -> bool {
    config_value_note(value, "missing", "placeholder").is_none()
}

fn config_value_note(
    value: Option<&str>,
    missing_note: &'static str,
    placeholder_note: &'static str,
) -> Option<&'static str> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Some(missing_note);
    };
    if config_value_is_placeholder(value) {
        Some(placeholder_note)
    } else {
        None
    }
}

fn config_value_is_placeholder(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("replace-with-")
        || value == "changeme"
        || value == "change-me"
        || value == "todo"
        || (value.starts_with('<') && value.ends_with('>'))
}

#[cfg(target_arch = "wasm32")]
fn provider_status_row(
    env: &Env,
    config: &ZerothServerConfig,
    provider_id: &str,
    provider_failures: &[(String, ProviderFailureStatus)],
) -> Option<ProviderStatus> {
    let (id, label, kind) = match provider_id {
        well_known::APPLE => (well_known::APPLE, "Apple", "oidc"),
        well_known::GOOGLE => (well_known::GOOGLE, "Google", "oidc"),
        well_known::SPOTIFY => (well_known::SPOTIFY, "Spotify", "oauth2"),
        _ => return None,
    };
    let client_id_binding = provider_client_id_binding(provider_id)?;
    let client_id_value = binding_value_from_env(env, client_id_binding);
    let client_id_configured = config_value_configured(client_id_value.as_deref());
    let client_secret_configured = provider_client_secret_configured(env, provider_id);
    let disabled = provider_disabled(env, provider_id);
    let mut notes = Vec::new();
    if disabled {
        notes.push("disabled_by_deployment");
        notes.extend(provider_disabled_notes(provider_id));
    }
    if let Some(note) = config_value_note(
        client_id_value.as_deref(),
        "missing_client_id",
        "placeholder_client_id",
    ) {
        notes.push(note);
    }
    if !client_secret_configured {
        notes.push("missing_client_secret");
    }

    Some(ProviderStatus {
        id,
        label,
        kind,
        enabled: provider_status_enabled(client_id_configured, client_secret_configured, disabled),
        client_id_configured,
        client_secret_configured,
        client_id_binding,
        secret_binding_sets: provider_secret_binding_sets(provider_id),
        callback_url: config.issuer().provider_callback_endpoint(),
        web_domain: provider_web_domain(provider_id, config),
        notes,
        activation_requirements: provider_activation_requirements(provider_id, disabled),
        last_failure: provider_failure_for_provider(provider_id, provider_failures),
    })
}

fn provider_disabled_notes(provider_id: &str) -> Vec<&'static str> {
    match provider_id {
        well_known::SPOTIFY => vec![
            "spotify_development_mode_owner_premium_required",
            "spotify_development_mode_users_must_be_allowlisted",
        ],
        _ => Vec::new(),
    }
}

fn provider_activation_requirements(provider_id: &str, disabled: bool) -> Vec<&'static str> {
    if !disabled {
        return Vec::new();
    }
    match provider_id {
        well_known::SPOTIFY => vec![
            "Spotify app owner account has Premium while the app is in development mode",
            "Spotify test login user is allowlisted in the Spotify app Users Management tab",
            "Spotify current-user profile endpoint /v1/me returns HTTP 200 for an authorized user",
        ],
        _ => Vec::new(),
    }
}

fn provider_failure_for_provider(
    provider_id: &str,
    provider_failures: &[(String, ProviderFailureStatus)],
) -> Option<ProviderFailureStatus> {
    provider_failures
        .iter()
        .find(|(id, _)| id == provider_id)
        .map(|(_, failure)| failure.clone())
}

fn provider_status_enabled(
    client_id_configured: bool,
    client_secret_configured: bool,
    disabled: bool,
) -> bool {
    !disabled && client_id_configured && client_secret_configured
}

fn provider_secret_binding_sets(provider_id: &str) -> Vec<Vec<&'static str>> {
    match provider_id {
        well_known::APPLE => vec![
            vec!["APPLE_CLIENT_SECRET"],
            vec!["APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY"],
            vec!["APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY_PEM"],
        ],
        well_known::GOOGLE => vec![vec!["GOOGLE_CLIENT_SECRET"]],
        well_known::SPOTIFY => vec![vec!["SPOTIFY_CLIENT_SECRET"]],
        _ => Vec::new(),
    }
}

fn provider_web_domain(provider_id: &str, config: &ZerothServerConfig) -> Option<String> {
    if provider_id != well_known::APPLE {
        return None;
    }
    url::Url::parse(&config.issuer().issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

#[cfg(target_arch = "wasm32")]
fn local_auth_status_rows(
    env: &Env,
    magic_link_delivery: Option<LocalAuthDeliveryStatus>,
) -> Vec<LocalAuthStatus> {
    let password_ready = password_policy_ready(env);
    let magic_link_delivery_config = magic_link_delivery_config_from_env(env);

    local_auth_status_rows_from_config(
        password_ready,
        magic_link_delivery_config,
        magic_link_dev_echo_enabled(env),
        magic_link_delivery,
    )
}

#[cfg(target_arch = "wasm32")]
fn magic_link_delivery_config_from_env(env: &Env) -> MagicLinkDeliveryConfig {
    let magic_link_from_note = config_value_note(
        binding_value_from_env(env, "MAGIC_LINK_FROM").as_deref(),
        "missing_magic_link_from",
        "placeholder_magic_link_from",
    );
    let webhook_url_note = magic_link_webhook_url_note(
        binding_value_from_env(env, "MAGIC_LINK_WEBHOOK_URL").as_deref(),
    );

    magic_link_delivery_config_from_values(
        binding_value_from_env(env, "MAGIC_LINK_DELIVERY").as_deref(),
        magic_link_from_note,
        env.send_email("EMAIL").is_ok(),
        webhook_url_note,
        config_value_note(
            magic_link_resend_api_key_from_env(env).as_deref(),
            "missing_resend_api_key",
            "placeholder_resend_api_key",
        ),
        config_value_note(
            magic_link_mailchannels_api_key_from_env(env).as_deref(),
            "missing_mailchannels_api_key",
            "placeholder_mailchannels_api_key",
        ),
    )
}

fn local_auth_status_rows_from_config(
    password_ready: bool,
    magic_link_delivery_config: MagicLinkDeliveryConfig,
    magic_link_dev_echo_enabled: bool,
    magic_link_delivery: Option<LocalAuthDeliveryStatus>,
) -> Vec<LocalAuthStatus> {
    let mut password_notes = Vec::new();
    if !password_ready {
        password_notes.push("invalid_password_iterations");
    }

    let mut magic_link_notes = magic_link_delivery_config.notes.clone();
    if magic_link_delivery_config.enabled {
        let delivery_proven = magic_link_delivery
            .as_ref()
            .and_then(|status| status.last_sent_at)
            .is_some();
        if !delivery_proven {
            magic_link_notes.push("delivery_not_proven");
        }
        let recent_failure = magic_link_delivery
            .as_ref()
            .and_then(|status| status.last_failed_at)
            .is_some_and(|failed_at| {
                match magic_link_delivery
                    .as_ref()
                    .and_then(|status| status.last_sent_at)
                {
                    Some(sent_at) => failed_at >= sent_at,
                    None => true,
                }
            });
        if recent_failure {
            magic_link_notes.push("delivery_failed_recently");
        }
    }
    if magic_link_dev_echo_enabled {
        magic_link_notes.push("dev_echo_enabled");
    }

    vec![
        LocalAuthStatus {
            id: "password",
            label: "Password",
            enabled: password_ready,
            credential_storage: "zeroth_local_credentials",
            delivery: "none",
            notes: password_notes,
            delivery_status: None,
        },
        LocalAuthStatus {
            id: "passkey",
            label: "Passkey",
            enabled: true,
            credential_storage: "zeroth_passkey_credentials",
            delivery: "browser_webauthn",
            notes: vec!["requires_webauthn_browser"],
            delivery_status: None,
        },
        LocalAuthStatus {
            id: "wallet_evm",
            label: "EVM wallet",
            enabled: true,
            credential_storage: "zeroth_account_identities",
            delivery: "browser_wallet",
            notes: vec!["eoa_signatures_only", "requires_injected_eip1193_wallet"],
            delivery_status: None,
        },
        LocalAuthStatus {
            id: "magic_link",
            label: "Magic link",
            enabled: magic_link_delivery_config.enabled,
            credential_storage: "zeroth_magic_links",
            delivery: magic_link_delivery_config.transport,
            notes: magic_link_notes,
            delivery_status: magic_link_delivery,
        },
    ]
}

fn magic_link_delivery_config_from_values(
    transport_value: Option<&str>,
    magic_link_from_note: Option<&'static str>,
    email_binding_configured: bool,
    webhook_url_note: Option<&'static str>,
    resend_api_key_note: Option<&'static str>,
    mailchannels_api_key_note: Option<&'static str>,
) -> MagicLinkDeliveryConfig {
    match magic_link_delivery_transport_from_value(transport_value) {
        Ok(MagicLinkDeliveryTransport::CloudflareEmail) => {
            let mut notes = Vec::new();
            if let Some(note) = magic_link_from_note {
                notes.push(note);
            }
            if !email_binding_configured {
                notes.push("missing_email_binding");
            }
            let enabled = magic_link_from_note.is_none() && email_binding_configured;
            if enabled {
                notes.push("cloudflare_email_sending_must_be_enabled");
            }
            MagicLinkDeliveryConfig {
                transport: MAGIC_LINK_DELIVERY_CLOUDFLARE_EMAIL,
                enabled,
                notes,
            }
        }
        Ok(MagicLinkDeliveryTransport::Webhook) => {
            let mut notes = Vec::new();
            if let Some(note) = magic_link_from_note {
                notes.push(note);
            }
            if let Some(note) = webhook_url_note {
                notes.push(note);
            }
            let enabled = magic_link_from_note.is_none() && webhook_url_note.is_none();
            if enabled {
                notes.push("magic_link_webhook_must_send_email");
            }
            MagicLinkDeliveryConfig {
                transport: MAGIC_LINK_DELIVERY_WEBHOOK,
                enabled,
                notes,
            }
        }
        Ok(MagicLinkDeliveryTransport::Resend) => {
            let mut notes = Vec::new();
            if let Some(note) = magic_link_from_note {
                notes.push(note);
            }
            if let Some(note) = resend_api_key_note {
                notes.push(note);
            }
            let enabled = magic_link_from_note.is_none() && resend_api_key_note.is_none();
            if enabled {
                notes.push("resend_domain_must_be_verified");
            }
            MagicLinkDeliveryConfig {
                transport: MAGIC_LINK_DELIVERY_RESEND,
                enabled,
                notes,
            }
        }
        Ok(MagicLinkDeliveryTransport::MailChannels) => {
            let mut notes = Vec::new();
            if let Some(note) = magic_link_from_note {
                notes.push(note);
            }
            if let Some(note) = mailchannels_api_key_note {
                notes.push(note);
            }
            let enabled = magic_link_from_note.is_none() && mailchannels_api_key_note.is_none();
            if enabled {
                notes.push("mailchannels_domain_lockdown_must_be_configured");
            }
            MagicLinkDeliveryConfig {
                transport: MAGIC_LINK_DELIVERY_MAILCHANNELS,
                enabled,
                notes,
            }
        }
        Err(note) => MagicLinkDeliveryConfig {
            transport: MAGIC_LINK_DELIVERY_UNSUPPORTED,
            enabled: false,
            notes: vec![note],
        },
    }
}

fn magic_link_delivery_transport_from_value(
    value: Option<&str>,
) -> Result<MagicLinkDeliveryTransport, &'static str> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(MagicLinkDeliveryTransport::CloudflareEmail);
    };
    match value.to_ascii_lowercase().as_str() {
        "cloudflare" | "cloudflare_email" => Ok(MagicLinkDeliveryTransport::CloudflareEmail),
        "webhook" => Ok(MagicLinkDeliveryTransport::Webhook),
        "resend" => Ok(MagicLinkDeliveryTransport::Resend),
        "mailchannels" | "mail_channels" => Ok(MagicLinkDeliveryTransport::MailChannels),
        _ => Err("unsupported_magic_link_delivery"),
    }
}

fn magic_link_webhook_url_note(value: Option<&str>) -> Option<&'static str> {
    config_value_note(
        value,
        "missing_magic_link_webhook_url",
        "placeholder_magic_link_webhook_url",
    )
    .or_else(|| {
        value.and_then(|value| {
            (!magic_link_webhook_url_valid(value)).then_some("invalid_magic_link_webhook_url")
        })
    })
}

fn magic_link_webhook_url_valid(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value.trim()) else {
        return false;
    };
    url.scheme() == "https" && url.host_str().is_some()
}

#[cfg(target_arch = "wasm32")]
fn provider_client_secret_configured(env: &Env, provider_id: &str) -> bool {
    match provider_id {
        well_known::APPLE => apple_client_secret_configured(env),
        well_known::GOOGLE => provider_secret_binding_configured(env, "GOOGLE_CLIENT_SECRET"),
        well_known::SPOTIFY => provider_secret_binding_configured(env, "SPOTIFY_CLIENT_SECRET"),
        _ => false,
    }
}

#[cfg(target_arch = "wasm32")]
fn apple_client_secret_configured(env: &Env) -> bool {
    provider_secret_binding_configured(env, "APPLE_CLIENT_SECRET")
        || (provider_secret_binding_configured(env, "APPLE_TEAM_ID")
            && provider_secret_binding_configured(env, "APPLE_KEY_ID")
            && provider_client_id_configured(env, well_known::APPLE)
            && (provider_secret_binding_configured(env, "APPLE_PRIVATE_KEY")
                || provider_secret_binding_configured(env, "APPLE_PRIVATE_KEY_PEM")))
}

#[cfg(target_arch = "wasm32")]
fn provider_secret_binding_configured(env: &Env, name: &str) -> bool {
    config_value_configured(binding_value_from_env(env, name).as_deref())
}

#[cfg(target_arch = "wasm32")]
fn provider_admin_ui_rows(
    env: &Env,
    config: &ZerothServerConfig,
    provider_failures: &[(String, ProviderFailureStatus)],
) -> Vec<ProviderAdminUi> {
    provider_status_rows(env, config, true, provider_failures)
        .into_iter()
        .map(|status| ProviderAdminUi {
            id: status.id.to_owned(),
            label: status.label.to_owned(),
            kind: status.kind.to_owned(),
            enabled: status.enabled,
            client_id_configured: status.client_id_configured,
            client_secret_configured: status.client_secret_configured,
            client_id_binding: status.client_id_binding.to_owned(),
            secret_binding_sets: status
                .secret_binding_sets
                .iter()
                .map(|set| set.iter().map(|name| (*name).to_owned()).collect())
                .collect(),
            callback_url: status.callback_url,
            web_domain: status.web_domain,
            notes: status.notes.iter().map(|note| (*note).to_owned()).collect(),
            activation_requirements: status
                .activation_requirements
                .iter()
                .map(|requirement| (*requirement).to_owned())
                .collect(),
            last_failure: status.last_failure.map(provider_failure_admin_ui),
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn provider_failure_admin_ui(status: ProviderFailureStatus) -> ProviderFailureAdminUi {
    ProviderFailureAdminUi {
        event_type: status.event_type,
        created_at: status.created_at.to_string(),
        code: status.code,
        description: status.description,
    }
}

#[cfg(target_arch = "wasm32")]
fn local_auth_admin_ui_rows(
    env: &Env,
    magic_link_delivery: Option<LocalAuthDeliveryStatus>,
) -> Vec<LocalAuthAdminUi> {
    local_auth_status_rows(env, magic_link_delivery)
        .into_iter()
        .map(|status| LocalAuthAdminUi {
            id: status.id.to_owned(),
            label: status.label.to_owned(),
            enabled: status.enabled,
            credential_storage: status.credential_storage.to_owned(),
            delivery: status.delivery.to_owned(),
            delivery_status: status.delivery_status.map(local_auth_delivery_admin_ui),
            notes: status.notes.iter().map(|note| (*note).to_owned()).collect(),
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn local_auth_delivery_admin_ui(status: LocalAuthDeliveryStatus) -> LocalAuthDeliveryAdminUi {
    LocalAuthDeliveryAdminUi {
        last_issue_at: status.last_issue_at.map(|value| value.to_string()),
        last_sent_at: status.last_sent_at.map(|value| value.to_string()),
        last_failed_at: status.last_failed_at.map(|value| value.to_string()),
        last_error: status.last_error,
        last_error_detail: status.last_error_detail,
    }
}

fn profile_ui_from_user(user: &UserRow, identities: &[IdentityRow]) -> ProfileUi {
    let email_verified = user.primary_email.as_ref().is_some_and(|email| {
        identities
            .iter()
            .any(|identity| identity.email.as_ref() == Some(email) && identity.email_verified != 0)
    });

    ProfileUi {
        sub: user.id.clone(),
        email: user.primary_email.clone(),
        email_verified,
        display_name: user.display_name.clone(),
        picture_url: user.picture_url.clone(),
    }
}

fn identity_ui_rows(identities: &[IdentityRow]) -> Vec<IdentityUi> {
    let unlink_disabled = identities.len() <= 1;
    identities
        .iter()
        .map(|identity| IdentityUi {
            provider_id: identity.provider_id.clone(),
            provider_subject: identity.provider_subject.clone(),
            email: identity.email.clone(),
            email_verified: identity.email_verified != 0,
            unlink_disabled,
        })
        .collect()
}

fn session_ui_rows(sessions: &[SessionRow], current_session_id: &str) -> Vec<SessionUi> {
    sessions
        .iter()
        .map(|session| SessionUi {
            id: session.id.clone(),
            client_id: session.client_id.clone(),
            current: session.id == current_session_id,
            created_at: Some(session.created_at.to_string()),
            expires_at: Some(session.expires_at.to_string()),
        })
        .collect()
}

fn application_ui_from_client(client: &Client) -> ApplicationUi {
    ApplicationUi {
        client_id: client.id.0.clone(),
        name: client.name.clone(),
        public_client: !client.confidential,
        redirect_uris: client.redirect_uris.clone(),
        allowed_origins: client.allowed_origins.clone(),
        allowed_email_domains: client.allowed_email_domains.clone(),
    }
}

fn client_admin_ui_from_row(row: ClientRow) -> Result<ClientAdminUi, String> {
    let response = client_response_from_row(row)?;
    Ok(ClientAdminUi {
        client_id: response.id,
        name: response.name,
        confidential: response.confidential,
        redirect_uris: response.redirect_uris,
        allowed_origins: response.allowed_origins,
        allowed_email_domains: response.allowed_email_domains,
        issuer_token_audience: response.issuer_token_audience,
        issuer_token_ttl_seconds: response.issuer_token_ttl_seconds,
        account_sharing_mode: response.account_sharing_mode,
        account_tenant_id: response.account_tenant_id,
        account_namespace: response.account_namespace,
        visible_login_methods: response.visible_login_methods,
        disabled: response.disabled,
        has_secret: response.has_secret,
    })
}

#[cfg(target_arch = "wasm32")]
fn product_name_from_env(env: &Env) -> String {
    env_string(env, "PRODUCT_NAME").unwrap_or_else(|| "Zeroth".to_owned())
}

fn login_theme_for_client(
    product_name: &str,
    client: &Client,
    issuer_base_url: &str,
    target_url: Option<&str>,
    catalog: &LoginThemeCatalog,
) -> (String, ZerothUiTheme) {
    let merged = merged_login_theme_for_client(client, target_url, catalog);

    let explicit_name = merged.trimmed_name();
    let mut display_name = product_name.to_owned();
    if explicit_name.is_none() && target_is_external(issuer_base_url, target_url) {
        let client_name = client.name.trim();
        if !client_name.is_empty() {
            display_name = client_name.to_owned();
        }
    }
    if let Some(name) = explicit_name {
        display_name = name;
    }

    (
        display_name,
        ZerothUiTheme {
            header_background_from: merged.header_background_from,
            header_background_to: merged.header_background_to,
            header_text_color: merged.header_text_color,
        },
    )
}

fn client_branding_for_client(
    product_name: &str,
    client: &Client,
    issuer_base_url: &str,
    target_url: Option<&str>,
    catalog: &LoginThemeCatalog,
) -> ClientBrandingResponse {
    let (name, _) =
        login_theme_for_client(product_name, client, issuer_base_url, target_url, catalog);
    let merged = merged_login_theme_for_client(client, target_url, catalog);
    ClientBrandingResponse {
        client_id: client.id.0.clone(),
        name,
        icon: merged.trimmed_icon(),
    }
}

fn merged_login_theme_for_client(
    client: &Client,
    target_url: Option<&str>,
    catalog: &LoginThemeCatalog,
) -> LoginThemeOverride {
    let mut merged = catalog.default.clone();
    if let Some(theme) = catalog.clients.get(&client.id.0) {
        merged.merge_from(theme);
    }
    if let Some(target_host) = target_url.and_then(url_host) {
        if let Some(theme) = theme_domain_match(&catalog.domains, &target_host) {
            merged.merge_from(theme);
        }
    }
    merged
}

fn target_is_external(issuer_base_url: &str, target_url: Option<&str>) -> bool {
    let Some(issuer_host) = url_host(issuer_base_url) else {
        return false;
    };
    let Some(target_host) = target_url.and_then(url_host) else {
        return false;
    };
    issuer_host != target_host
}

fn url_host(value: &str) -> Option<String> {
    url::Url::parse(value)
        .ok()?
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
}

fn theme_domain_match<'a>(
    domains: &'a BTreeMap<String, LoginThemeOverride>,
    host: &str,
) -> Option<&'a LoginThemeOverride> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    domains
        .iter()
        .filter_map(|(domain, theme)| {
            let domain = normalized_theme_domain(domain)?;
            let matches = host == domain || host.ends_with(&format!(".{domain}"));
            matches.then_some((domain.len(), theme))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, theme)| theme)
}

fn normalized_theme_domain(value: &str) -> Option<String> {
    let domain = value
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

#[cfg(target_arch = "wasm32")]
fn login_theme_catalog_from_env(env: &Env) -> LoginThemeCatalog {
    let mut catalog = LoginThemeCatalog::default();
    catalog.default.merge_from(&LoginThemeOverride {
        name: env_string(env, "LOGIN_BRAND_NAME").or_else(|| env_string(env, "LOGIN_NAME")),
        icon: env_string(env, "LOGIN_BRAND_ICON")
            .or_else(|| env_string(env, "LOGIN_ICON"))
            .or_else(|| env_string(env, "LOGIN_ICON_URL")),
        header_background_from: env_string(env, "LOGIN_HEADER_BACKGROUND_FROM")
            .or_else(|| env_string(env, "LOGIN_HEADER_GRADIENT_FROM"))
            .or_else(|| env_string(env, "LOGIN_BACKGROUND_COLOR")),
        header_background_to: env_string(env, "LOGIN_HEADER_BACKGROUND_TO")
            .or_else(|| env_string(env, "LOGIN_HEADER_GRADIENT_TO")),
        header_text_color: env_string(env, "LOGIN_HEADER_TEXT_COLOR")
            .or_else(|| env_string(env, "LOGIN_TEXT_COLOR")),
    });

    if let Some(raw) =
        env_string(env, "LOGIN_THEMES_JSON").or_else(|| env_string(env, "ZEROTH_LOGIN_THEMES_JSON"))
    {
        if let Ok(parsed) = serde_json::from_str::<LoginThemeCatalog>(&raw) {
            catalog.merge_from(parsed);
        }
    }

    catalog
}

#[cfg(target_arch = "wasm32")]
fn themed_login_state(
    state: ZerothUiState,
    env: &Env,
    client: &Client,
    issuer_base_url: &str,
    target_url: Option<&str>,
) -> ZerothUiState {
    let catalog = login_theme_catalog_from_env(env);
    let (product_name, theme) = login_theme_for_client(
        &product_name_from_env(env),
        client,
        issuer_base_url,
        target_url,
        &catalog,
    );
    state.with_product_name(product_name).with_theme(theme)
}

#[cfg(target_arch = "wasm32")]
fn html(document: String) -> worker::Result<Response> {
    let response = Response::from_html(document)?;
    response.headers().set("Cache-Control", "no-store")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn with_confirmation_document_headers(response: Response) -> worker::Result<Response> {
    response.headers().set("Cache-Control", "no-store")?;
    response.headers().set("Referrer-Policy", "no-referrer")?;
    response.headers().set("X-Frame-Options", "DENY")?;
    response.headers().set(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    )?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn render_confirmation_document(
    title: &str,
    heading: &str,
    message: &str,
    form_action: &str,
    submit_label: &str,
    cancel_href: &str,
    hidden_inputs: &[(&str, &str)],
) -> String {
    let hidden_inputs = hidden_inputs
        .iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                html_escape(name),
                html_escape(value)
            )
        })
        .collect::<String>();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>body{{font:16px/1.5 system-ui,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:2rem}}main{{max-width:32rem;margin:4rem auto;background:#fff;border:1px solid #cbd5e1;border-radius:1rem;padding:2rem;box-shadow:0 10px 30px rgba(15,23,42,.08)}}h1{{margin-top:0;font-size:1.5rem}}p{{margin:0 0 1rem}}form{{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}}button,a{{border-radius:.75rem;padding:.75rem 1rem;text-decoration:none;font:inherit}}button{{border:0;background:#0f172a;color:#fff;cursor:pointer}}a{{border:1px solid #cbd5e1;color:#0f172a;background:#fff}}</style></head><body><main><h1>{}</h1><p>{}</p><form method=\"post\" action=\"{}\">{}<button type=\"submit\">{}</button><a href=\"{}\">Cancel</a></form></main></body></html>",
        html_escape(title),
        html_escape(heading),
        html_escape(message),
        html_escape(form_action),
        hidden_inputs,
        html_escape(submit_label),
        html_escape(cancel_href),
    )
}

#[cfg(target_arch = "wasm32")]
fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_path(request_url: &url::Url, path: &str) -> worker::Result<Response> {
    let mut target = request_url.clone();
    target.set_path(path);
    target.set_query(None);
    target.set_fragment(None);
    Response::redirect(target)
}

#[cfg(target_arch = "wasm32")]
async fn provider_callback_from_request(
    request: &mut Request,
    url: &url::Url,
) -> Result<ProviderCallback, ProviderCallbackError> {
    match request.method() {
        Method::Get => provider_callback_from_values(
            query_param(url, "code"),
            query_param(url, "state"),
            query_param(url, "error"),
            query_param(url, "error_description"),
            None,
        ),
        Method::Post => {
            let form = request.form_data().await.map_err(|error| {
                ProviderCallbackError::invalid_request(format!(
                    "could not parse provider callback form: {error}"
                ))
            })?;
            provider_callback_from_values(
                form.get_field("code"),
                form.get_field("state"),
                form.get_field("error"),
                form.get_field("error_description"),
                form.get_field("user"),
            )
        }
        _ => Err(ProviderCallbackError::invalid_request(
            "unsupported callback method",
        )),
    }
}

fn provider_callback_from_values(
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    apple_user_json: Option<String>,
) -> Result<ProviderCallback, ProviderCallbackError> {
    if let Some(error) = error {
        if error.is_empty() {
            return Err(ProviderCallbackError::invalid_request("missing error"));
        }
        let state = state.ok_or_else(|| ProviderCallbackError::invalid_request("missing state"))?;
        if state.is_empty() {
            return Err(ProviderCallbackError::invalid_request("missing state"));
        }
        return Ok(ProviderCallback {
            state,
            code: None,
            provider_error: Some(ProviderCallbackError {
                code: error,
                description: error_description
                    .unwrap_or_else(|| "provider returned an authorization error".to_owned()),
            }),
            apple_user_json: None,
        });
    }

    let code = code.ok_or_else(|| ProviderCallbackError::invalid_request("missing code"))?;
    let state = state.ok_or_else(|| ProviderCallbackError::invalid_request("missing state"))?;
    if code.is_empty() {
        return Err(ProviderCallbackError::invalid_request("missing code"));
    }
    if state.is_empty() {
        return Err(ProviderCallbackError::invalid_request("missing state"));
    }

    Ok(ProviderCallback {
        state,
        code: Some(code),
        provider_error: None,
        apple_user_json: apple_user_json.filter(|value| !value.trim().is_empty()),
    })
}

#[cfg(target_arch = "wasm32")]
async fn get_client(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<Client>> {
    get_registered_client(db, client_id)
        .await
        .map(|client| client.map(|registered_client| registered_client.client))
}

#[cfg(target_arch = "wasm32")]
async fn get_registered_client(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<RegisteredClient>> {
    let args = [worker::d1::D1Type::Text(client_id)];
    let row = db
        .prepare(
            "SELECT id, name, secret_hash, redirect_uris_json, allowed_origins_json,
                    allowed_email_domains_json, issuer_token_audience,
                    issuer_token_ttl_seconds, account_sharing_mode, account_tenant_id,
                    visible_login_methods_json, confidential, disabled_at
             FROM zeroth_clients
             WHERE id = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<ClientRow>(None)
        .await?;

    row.map(registered_client_from_row)
        .transpose()
        .map(|client| client.flatten())
        .map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
async fn get_client_row_for_admin(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<ClientRow>> {
    let args = [worker::d1::D1Type::Text(client_id)];
    db.prepare(
        "SELECT id, name, secret_hash, redirect_uris_json, allowed_origins_json,
                allowed_email_domains_json, issuer_token_audience,
                issuer_token_ttl_seconds, account_sharing_mode, account_tenant_id,
                visible_login_methods_json, confidential, disabled_at
         FROM zeroth_clients
         WHERE id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<ClientRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_client_rows_for_admin(db: &worker::d1::D1Database) -> worker::Result<Vec<ClientRow>> {
    let args = [worker::d1::D1Type::Integer(CLIENT_LIST_LIMIT)];
    db.prepare(
        "SELECT id, name, secret_hash, redirect_uris_json, allowed_origins_json,
                allowed_email_domains_json, issuer_token_audience,
                issuer_token_ttl_seconds, account_sharing_mode, account_tenant_id,
                visible_login_methods_json, confidential, disabled_at
         FROM zeroth_clients
         ORDER BY id
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<ClientRow>()
}

#[cfg(target_arch = "wasm32")]
async fn upsert_client(
    db: &worker::d1::D1Database,
    client: &ValidatedClientUpsert,
    now: i32,
) -> worker::Result<()> {
    let redirect_uris_json = serde_json::to_string(&client.redirect_uris).map_err(|error| {
        worker::Error::RustError(format!("could not serialize redirect URIs: {error}"))
    })?;
    let allowed_origins_json = serde_json::to_string(&client.allowed_origins).map_err(|error| {
        worker::Error::RustError(format!("could not serialize allowed origins: {error}"))
    })?;
    let allowed_email_domains_json =
        serde_json::to_string(&client.allowed_email_domains).map_err(|error| {
            worker::Error::RustError(format!(
                "could not serialize allowed email domains: {error}"
            ))
        })?;
    let visible_login_methods_json =
        serde_json::to_string(&client.visible_login_methods).map_err(|error| {
            worker::Error::RustError(format!(
                "could not serialize visible login methods: {error}"
            ))
        })?;
    let secret_hash = d1_optional_text(client.secret_hash.as_deref());
    let issuer_token_audience = d1_optional_text(client.issuer_token_audience.as_deref());
    let issuer_token_ttl_seconds = match client.issuer_token_ttl_seconds {
        Some(value) => worker::d1::D1Type::Integer(value),
        None => worker::d1::D1Type::Null,
    };
    let disabled_at = if client.disabled {
        worker::d1::D1Type::Integer(now)
    } else {
        worker::d1::D1Type::Null
    };
    let confidential = if client.confidential { 1 } else { 0 };
    let args = [
        worker::d1::D1Type::Text(&client.id),
        worker::d1::D1Type::Text(&client.name),
        secret_hash,
        worker::d1::D1Type::Integer(confidential),
        worker::d1::D1Type::Text(&redirect_uris_json),
        worker::d1::D1Type::Text(&allowed_origins_json),
        worker::d1::D1Type::Text(&allowed_email_domains_json),
        issuer_token_audience,
        issuer_token_ttl_seconds,
        worker::d1::D1Type::Text(account_sharing_mode_label(client.account_sharing_mode)),
        worker::d1::D1Type::Text(&client.account_tenant_id),
        worker::d1::D1Type::Text(&visible_login_methods_json),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
        disabled_at,
    ];

    db.prepare(
        "INSERT INTO zeroth_clients (
             id, name, secret_hash, confidential, redirect_uris_json,
             allowed_origins_json, allowed_email_domains_json, issuer_token_audience,
             issuer_token_ttl_seconds, account_sharing_mode, account_tenant_id,
             visible_login_methods_json, created_at, updated_at, disabled_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             secret_hash = CASE
                 WHEN excluded.confidential = 0 THEN NULL
                 WHEN excluded.secret_hash IS NOT NULL THEN excluded.secret_hash
                 ELSE zeroth_clients.secret_hash
             END,
             confidential = excluded.confidential,
             redirect_uris_json = excluded.redirect_uris_json,
             allowed_origins_json = excluded.allowed_origins_json,
             allowed_email_domains_json = excluded.allowed_email_domains_json,
             issuer_token_audience = excluded.issuer_token_audience,
             issuer_token_ttl_seconds = excluded.issuer_token_ttl_seconds,
             account_sharing_mode = excluded.account_sharing_mode,
             account_tenant_id = excluded.account_tenant_id,
             visible_login_methods_json = excluded.visible_login_methods_json,
             updated_at = excluded.updated_at,
             disabled_at = excluded.disabled_at",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn disable_client(
    db: &worker::d1::D1Database,
    client_id: &str,
    disabled_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Text(client_id),
    ];
    db.prepare(
        "UPDATE zeroth_clients
         SET disabled_at = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn active_client_allowed_origins(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Result<Vec<String>, String>> {
    Ok(active_client_allowed_origins_from_client(
        get_client(db, client_id).await?,
    ))
}

#[cfg(target_arch = "wasm32")]
async fn origin_allowed_by_any_client(
    db: &worker::d1::D1Database,
    origin: &str,
) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Integer(CORS_ORIGIN_SCAN_LIMIT)];
    let rows = db
        .prepare(
            "SELECT allowed_origins_json
             FROM zeroth_clients
             WHERE disabled_at IS NULL
             ORDER BY id
             LIMIT ?",
        )
        .bind_refs(&args)?
        .all()
        .await?
        .results::<ClientOriginsRow>()?;

    origin_allowed_in_client_origin_rows(&rows, origin).map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
async fn get_auth_transaction(
    db: &worker::d1::D1Database,
    provider_state: &str,
) -> worker::Result<Option<StoredAuthTransaction>> {
    let args = [worker::d1::D1Type::Text(provider_state)];
    let row = db
        .prepare(
            "SELECT provider_state, client_id, provider_id, redirect_uri, provider_redirect_uri,
                    app_state, nonce, provider_nonce, code_challenge, code_challenge_method, scope,
                    link_user_id, link_session_id, session_return_to, created_at, expires_at,
                    consumed_at
             FROM zeroth_auth_transactions
             WHERE provider_state = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<AuthTransactionRow>(None)
        .await?;

    row.map(auth_transaction_from_row)
        .transpose()
        .map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
async fn consume_auth_transaction(
    db: &worker::d1::D1Database,
    provider_state: &str,
    consumed_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(consumed_at),
        worker::d1::D1Type::Text(provider_state),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_auth_transactions
         SET consumed_at = ?
         WHERE provider_state = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn get_identity_user_id(
    db: &worker::d1::D1Database,
    account_namespace: &str,
    profile: &ProviderProfile,
) -> worker::Result<Option<String>> {
    let args = [
        worker::d1::D1Type::Text(account_namespace),
        worker::d1::D1Type::Text(&profile.provider_id.0),
        worker::d1::D1Type::Text(&profile.subject.0),
    ];
    let row = db
        .prepare(
            "SELECT user_id
             FROM zeroth_account_identities
             WHERE account_namespace = ? AND provider_id = ? AND provider_subject = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<IdentityUserRow>(None)
        .await?;

    Ok(row.map(|row| row.user_id))
}

#[cfg(target_arch = "wasm32")]
async fn complete_provider_identity_link(
    db: &worker::d1::D1Database,
    link_user_id: &UserId,
    link_session_id: Option<&str>,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<Result<(), IdentityLinkError>> {
    let Some(link_session_id) = link_session_id else {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link transaction is missing session binding",
        )));
    };
    let Some(session) = get_session(db, link_session_id).await? else {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link session was not found",
        )));
    };
    if session.user_id != link_user_id.0 || !session_row_is_active(&session, now) {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link session is no longer active",
        )));
    }

    let Some(user) = get_user(db, &link_user_id.0).await? else {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link user was not found",
        )));
    };
    if user.disabled_at.is_some() {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link user is disabled",
        )));
    }

    let account_namespace = if let Some(client_id) = session.client_id.as_deref() {
        let Some(registered_client) = get_registered_client(db, client_id).await? else {
            return Ok(Err(IdentityLinkError::invalid_request(
                "identity link client is disabled or not found",
            )));
        };
        registered_client.account_scope.namespace
    } else {
        ACCOUNT_NAMESPACE_GLOBAL.to_owned()
    };

    if let Some(existing_user_id) = get_identity_user_id(db, &account_namespace, profile).await? {
        if existing_user_id != link_user_id.0 {
            return Ok(Err(IdentityLinkError::conflict(
                "identity is already linked to another user",
            )));
        }
    } else if count_identities_for_user(db, &link_user_id.0).await? >= IDENTITY_LIST_LIMIT {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link limit has been reached",
        )));
    }

    update_user_from_profile(db, &link_user_id.0, profile, now).await?;
    upsert_account_identity_from_profile(
        db,
        &account_namespace,
        &link_user_id.0,
        profile,
        raw_profile_json,
        now,
    )
    .await?;

    match get_identity_user_id(db, &account_namespace, profile).await? {
        Some(user_id) if user_id == link_user_id.0 => Ok(Ok(())),
        Some(_) => Ok(Err(IdentityLinkError::conflict(
            "identity is already linked to another user",
        ))),
        None => Ok(Err(IdentityLinkError::invalid_request(
            "identity could not be linked",
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
async fn list_identities_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<Vec<IdentityRow>> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(ACCOUNT_NAMESPACE_GLOBAL),
        worker::d1::D1Type::Integer(IDENTITY_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT provider_id, provider_subject, email, email_verified, display_name,
                picture_url, created_at, updated_at
         FROM (
             SELECT provider_id, provider_subject, email, email_verified, display_name,
                    picture_url, created_at, updated_at
             FROM zeroth_account_identities
             WHERE user_id = ?
             UNION ALL
             SELECT i.provider_id, i.provider_subject, i.email, i.email_verified,
                    i.display_name, i.picture_url, i.created_at, i.updated_at
             FROM zeroth_identities i
             WHERE i.user_id = ?
               AND NOT EXISTS (
                   SELECT 1
                   FROM zeroth_account_identities ai
                   WHERE ai.account_namespace = ?
                     AND ai.provider_id = i.provider_id
                     AND ai.provider_subject = i.provider_subject
                     AND ai.user_id = i.user_id
                   LIMIT 1
               )
         )
         ORDER BY provider_id, created_at
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<IdentityRow>()
}

#[cfg(target_arch = "wasm32")]
async fn identity_exists_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    provider_id: &str,
    provider_subject: &str,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(provider_id),
        worker::d1::D1Type::Text(provider_subject),
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(provider_id),
        worker::d1::D1Type::Text(provider_subject),
    ];
    let row = db
        .prepare(
            "SELECT user_id
             FROM (
                 SELECT user_id
                 FROM zeroth_account_identities
                 WHERE user_id = ? AND provider_id = ? AND provider_subject = ?
                 UNION
                 SELECT user_id
                 FROM zeroth_identities
                 WHERE user_id = ? AND provider_id = ? AND provider_subject = ?
             )
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<IdentityUserRow>(None)
        .await?;
    Ok(row.is_some())
}

#[cfg(target_arch = "wasm32")]
async fn count_identities_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<i32> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(user_id),
    ];
    let row = db
        .prepare(
            "SELECT COUNT(*) AS count
             FROM (
                 SELECT provider_id, provider_subject
                 FROM zeroth_account_identities
                 WHERE user_id = ?
                 UNION
                 SELECT provider_id, provider_subject
                 FROM zeroth_identities
                 WHERE user_id = ?
             )",
        )
        .bind_refs(&args)?
        .first::<IdentityCountRow>(None)
        .await?;
    Ok(row.map(|row| row.count).unwrap_or(0))
}

#[cfg(target_arch = "wasm32")]
async fn delete_user_identity(
    db: &worker::d1::D1Database,
    user_id: &str,
    provider_id: &str,
    provider_subject: &str,
) -> worker::Result<bool> {
    if count_identities_for_user(db, user_id).await? <= 1 {
        return Ok(false);
    }
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(provider_id),
        worker::d1::D1Type::Text(provider_subject),
    ];
    let account_result = db
        .prepare(
            "DELETE FROM zeroth_account_identities
             WHERE user_id = ? AND provider_id = ? AND provider_subject = ?",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    let legacy_result = db
        .prepare(
            "DELETE FROM zeroth_identities
             WHERE user_id = ? AND provider_id = ? AND provider_subject = ?",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    Ok(d1_result_changed_any(account_result)? || d1_result_changed_any(legacy_result)?)
}

#[cfg(target_arch = "wasm32")]
async fn get_user_by_primary_email(
    db: &worker::d1::D1Database,
    email: &str,
) -> worker::Result<Option<UserRow>> {
    let args = [worker::d1::D1Type::Text(email)];
    db.prepare(
        "SELECT id, primary_email, display_name, picture_url, disabled_at
         FROM zeroth_users
         WHERE lower(primary_email) = lower(?)
         ORDER BY updated_at DESC
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<UserRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn insert_passkey_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    email: &str,
    display_name: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let display_name = d1_optional_text(display_name);
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(email),
        display_name,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_users (
             id, primary_email, display_name, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_passkey_registration_user(
    db: &worker::d1::D1Database,
    challenge: &PasskeyChallengeRow,
    now: i32,
) -> worker::Result<(String, String, Option<String>)> {
    if let Some(user_id) = challenge.user_id.as_deref() {
        let Some(user) = get_user(db, user_id).await? else {
            return Err(worker_error(
                "passkey registration user was not found".to_owned(),
            ));
        };
        let email = user
            .primary_email
            .or_else(|| challenge.email.clone())
            .ok_or_else(|| worker_error("passkey registration user has no email".to_owned()))?;
        let display_name = challenge.display_name.clone().or(user.display_name);
        return Ok((user_id.to_owned(), email, display_name));
    }

    let email = challenge
        .email
        .as_deref()
        .ok_or_else(|| worker_error("passkey registration challenge has no email".to_owned()))?;
    if let Some(user) = get_user_by_primary_email(db, email).await? {
        return Ok((user.id, email.to_owned(), challenge.display_name.clone()));
    }

    let user_id = format!("usr_{}", random_token()?);
    insert_passkey_user(db, &user_id, email, challenge.display_name.as_deref(), now).await?;
    Ok((user_id, email.to_owned(), challenge.display_name.clone()))
}

#[cfg(target_arch = "wasm32")]
async fn upsert_passkey_identity(
    db: &worker::d1::D1Database,
    user_id: &str,
    credential_id: &str,
    email: Option<&str>,
    display_name: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let email = d1_optional_text(email);
    let display_name = d1_optional_text(display_name);
    let raw_profile_json = serde_json::json!({
        "kind": "passkey",
        "credentialIdHash": hash_secret(credential_id)
    })
    .to_string();
    let args = [
        worker::d1::D1Type::Text("passkey"),
        worker::d1::D1Type::Text(credential_id),
        worker::d1::D1Type::Text(user_id),
        email,
        worker::d1::D1Type::Integer(1),
        display_name,
        worker::d1::D1Type::Text(&raw_profile_json),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_identities (
             provider_id, provider_subject, user_id, email, email_verified,
             display_name, raw_profile_json, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(provider_id, provider_subject) DO UPDATE SET
             email = excluded.email,
             email_verified = excluded.email_verified,
             display_name = excluded.display_name,
             raw_profile_json = excluded.raw_profile_json,
             updated_at = excluded.updated_at
         WHERE zeroth_identities.user_id = excluded.user_id",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_local_credential(
    db: &worker::d1::D1Database,
    email: &str,
) -> worker::Result<Option<LocalCredentialRow>> {
    let args = [worker::d1::D1Type::Text(email)];
    db.prepare(
        "SELECT email, user_id, password_hash, password_salt, password_alg,
                password_iterations, password_scheme, password_params_json, password_version,
                created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_local_credentials
         WHERE lower(email) = lower(?)
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<LocalCredentialRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn upsert_local_credential(
    db: &worker::d1::D1Database,
    email: &str,
    user_id: &str,
    password_hash: &str,
    password_salt: &str,
    pepper_id: &str,
    password_iterations: u32,
    now: i32,
) -> worker::Result<()> {
    let password_iterations = i32::try_from(password_iterations)
        .map_err(|_| worker_error("password iteration count is too large".to_owned()))?;
    let password_scheme = PasswordScheme::Pbkdf2Sha256.as_str();
    let password_params_json = password_params_json(pepper_id);
    let args = [
        worker::d1::D1Type::Text(email),
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(password_hash),
        worker::d1::D1Type::Text(password_salt),
        worker::d1::D1Type::Text(PASSWORD_PBKDF2_ALG),
        worker::d1::D1Type::Integer(password_iterations),
        worker::d1::D1Type::Text(password_scheme),
        worker::d1::D1Type::Text(&password_params_json),
        worker::d1::D1Type::Integer(PASSWORD_CURRENT_VERSION),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_local_credentials (
             email, user_id, password_hash, password_salt, password_alg,
             password_iterations, password_scheme, password_params_json,
             password_version, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(email) DO UPDATE SET
             password_hash = excluded.password_hash,
             password_salt = excluded.password_salt,
             password_alg = excluded.password_alg,
             password_iterations = excluded.password_iterations,
             password_scheme = excluded.password_scheme,
             password_params_json = excluded.password_params_json,
             password_version = excluded.password_version,
             updated_at = excluded.updated_at,
             disabled_at = NULL
         WHERE zeroth_local_credentials.user_id = excluded.user_id",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn mark_local_credential_used(
    db: &worker::d1::D1Database,
    email: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(email),
    ];
    db.prepare(
        "UPDATE zeroth_local_credentials
         SET last_used_at = ?
         WHERE lower(email) = lower(?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn upsert_local_auth_identity(
    db: &worker::d1::D1Database,
    user_id: &str,
    email: &str,
    display_name: Option<&str>,
    mode: &str,
    now: i32,
) -> worker::Result<()> {
    let profile = local_auth_profile(email, display_name, mode == "magic_link");
    let raw_profile_json = serde_json::json!({
        "kind": "local_auth",
        "mode": mode
    })
    .to_string();
    upsert_identity_from_profile(db, user_id, &profile, Some(&raw_profile_json), now).await
}

#[cfg(target_arch = "wasm32")]
async fn put_wallet_challenge(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
    address: &str,
    chain_id: &str,
    client_id: &str,
    return_to: &str,
    account_namespace: &str,
    message: &str,
    now: i32,
    user_agent: Option<&str>,
    ip_hash: Option<&str>,
) -> worker::Result<()> {
    let user_agent = d1_optional_text(user_agent);
    let ip_hash = d1_optional_text(ip_hash);
    let args = [
        worker::d1::D1Type::Text(challenge_hash),
        worker::d1::D1Type::Text(EVM_WALLET_PROVIDER_ID),
        worker::d1::D1Type::Text(address),
        worker::d1::D1Type::Text(chain_id),
        worker::d1::D1Type::Text(client_id),
        worker::d1::D1Type::Text(return_to),
        worker::d1::D1Type::Text(account_namespace),
        worker::d1::D1Type::Text(message),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + EVM_WALLET_CHALLENGE_TTL_SECONDS),
        ip_hash,
        user_agent,
    ];
    db.prepare(
        "INSERT INTO zeroth_wallet_challenges (
             challenge_hash, provider_id, address, chain_id, client_id, return_to,
             account_namespace, message, created_at, expires_at, ip_hash, user_agent
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_wallet_challenge(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
) -> worker::Result<Option<WalletChallengeRow>> {
    let args = [worker::d1::D1Type::Text(challenge_hash)];
    db.prepare(
        "SELECT challenge_hash, provider_id, address, chain_id, client_id, return_to,
                account_namespace, message, created_at, expires_at, consumed_at,
                ip_hash, user_agent
         FROM zeroth_wallet_challenges
         WHERE challenge_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<WalletChallengeRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn consume_wallet_challenge(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
    now: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(challenge_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_wallet_challenges
             SET consumed_at = ?
             WHERE challenge_hash = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn cleanup_expired_wallet_challenges(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(EVM_WALLET_CHALLENGE_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_wallet_challenges
         WHERE challenge_hash IN (
             SELECT challenge_hash FROM zeroth_wallet_challenges
             WHERE expires_at <= ?
             ORDER BY expires_at
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_magic_link(
    db: &worker::d1::D1Database,
    token_hash: &str,
    email: &str,
    user_id: Option<&str>,
    client_id: &str,
    return_to: &str,
    now: i32,
    user_agent: Option<&str>,
    ip_hash: Option<&str>,
) -> worker::Result<()> {
    let user_id = d1_optional_text(user_id);
    let user_agent = d1_optional_text(user_agent);
    let ip_hash = d1_optional_text(ip_hash);
    let args = [
        worker::d1::D1Type::Text(token_hash),
        worker::d1::D1Type::Text(email),
        user_id,
        worker::d1::D1Type::Text(client_id),
        worker::d1::D1Type::Text(return_to),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + MAGIC_LINK_TTL_SECONDS),
        ip_hash,
        user_agent,
    ];
    db.prepare(
        "INSERT INTO zeroth_magic_links (
             token_hash, email, user_id, client_id, return_to, created_at,
             expires_at, ip_hash, user_agent
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_magic_link(
    db: &worker::d1::D1Database,
    token_hash: &str,
) -> worker::Result<Option<MagicLinkRow>> {
    let args = [worker::d1::D1Type::Text(token_hash)];
    db.prepare(
        "SELECT token_hash, email, user_id, client_id, return_to, created_at,
                expires_at, consumed_at, ip_hash, user_agent
         FROM zeroth_magic_links
         WHERE token_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<MagicLinkRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn consume_magic_link(
    db: &worker::d1::D1Database,
    token_hash: &str,
    now: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(token_hash),
        worker::d1::D1Type::Integer(now),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_magic_links
             SET consumed_at = ?
             WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn cleanup_expired_magic_links(db: &worker::d1::D1Database, now: i32) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(MAGIC_LINK_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_magic_links
         WHERE token_hash IN (
             SELECT token_hash FROM zeroth_magic_links
             WHERE expires_at <= ? OR consumed_at IS NOT NULL
             ORDER BY expires_at
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_magic_link_user(
    db: &worker::d1::D1Database,
    row: &MagicLinkRow,
    now: i32,
) -> worker::Result<String> {
    if let Some(user_id) = row.user_id.as_deref() {
        return Ok(user_id.to_owned());
    }
    if let Some(user) = get_user_by_primary_email(db, &row.email).await? {
        return Ok(user.id);
    }
    let user_id = format!("usr_{}", random_token()?);
    insert_passkey_user(db, &user_id, &row.email, None, now).await?;
    Ok(user_id)
}

#[cfg(target_arch = "wasm32")]
async fn put_passkey_challenge(
    db: &worker::d1::D1Database,
    challenge: &str,
    kind: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    return_to: Option<&str>,
    email: Option<&str>,
    display_name: Option<&str>,
    label: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let challenge_hash = hash_secret(challenge);
    let user_id = d1_optional_text(user_id);
    let client_id = d1_optional_text(client_id);
    let return_to = d1_optional_text(return_to);
    let email = d1_optional_text(email);
    let display_name = d1_optional_text(display_name);
    let label = d1_optional_text(label);
    let args = [
        worker::d1::D1Type::Text(&challenge_hash),
        worker::d1::D1Type::Text(kind),
        user_id,
        client_id,
        return_to,
        email,
        display_name,
        label,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + PASSKEY_CHALLENGE_TTL_SECONDS),
    ];
    db.prepare(
        "INSERT INTO zeroth_passkey_challenges (
             challenge_hash, kind, user_id, client_id, return_to, email,
             display_name, label, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_passkey_challenge_by_hash(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
) -> worker::Result<Option<PasskeyChallengeRow>> {
    let args = [worker::d1::D1Type::Text(challenge_hash)];
    db.prepare(
        "SELECT challenge_hash, kind, user_id, client_id, return_to, email,
                display_name, label, created_at, expires_at, consumed_at
         FROM zeroth_passkey_challenges
         WHERE challenge_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<PasskeyChallengeRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn consume_passkey_challenge(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
    consumed_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(consumed_at),
        worker::d1::D1Type::Text(challenge_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_passkey_challenges
             SET consumed_at = ?
             WHERE challenge_hash = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn cleanup_expired_passkey_challenges(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(PASSKEY_CHALLENGE_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_passkey_challenges
         WHERE challenge_hash IN (
             SELECT challenge_hash
             FROM zeroth_passkey_challenges
             WHERE expires_at <= ?
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

fn validate_passkey_challenge(
    challenge: &PasskeyChallengeRow,
    expected_kind: &str,
    now: i32,
) -> Result<(), String> {
    if challenge.kind != expected_kind {
        return Err("passkey challenge kind did not match".to_owned());
    }
    if challenge.consumed_at.is_some() {
        return Err("passkey challenge has already been consumed".to_owned());
    }
    if challenge.expires_at <= now {
        return Err("passkey challenge has expired".to_owned());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_passkey_credential(
    db: &worker::d1::D1Database,
    credential: &ValidatedPasskeyRegistration,
    user_id: &str,
    label: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let label = d1_optional_text(label);
    let args = [
        worker::d1::D1Type::Text(&credential.credential_id),
        worker::d1::D1Type::Text(user_id),
        label,
        worker::d1::D1Type::Text(&credential.public_key_x),
        worker::d1::D1Type::Text(&credential.public_key_y),
        worker::d1::D1Type::Integer(credential.sign_count),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_passkey_credentials (
             credential_id, user_id, label, public_key_x, public_key_y,
             sign_count, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_passkey_credential(
    db: &worker::d1::D1Database,
    credential_id: &str,
) -> worker::Result<Option<PasskeyCredentialRow>> {
    let args = [worker::d1::D1Type::Text(credential_id)];
    db.prepare(
        "SELECT credential_id, user_id, label, public_key_x, public_key_y,
                sign_count, created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_passkey_credentials
         WHERE credential_id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<PasskeyCredentialRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_active_passkey_credentials(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<PasskeyCredentialRow>> {
    let args = [worker::d1::D1Type::Integer(PASSKEY_CREDENTIAL_LIST_LIMIT)];
    db.prepare(
        "SELECT credential_id, user_id, label, public_key_x, public_key_y,
                sign_count, created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_passkey_credentials
         WHERE disabled_at IS NULL
         ORDER BY created_at DESC
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<PasskeyCredentialRow>()
}

#[cfg(target_arch = "wasm32")]
async fn list_passkey_credentials_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<Vec<PasskeyCredentialRow>> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Integer(PASSKEY_CREDENTIAL_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT credential_id, user_id, label, public_key_x, public_key_y,
                sign_count, created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_passkey_credentials
         WHERE user_id = ? AND disabled_at IS NULL
         ORDER BY created_at DESC
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<PasskeyCredentialRow>()
}

#[cfg(target_arch = "wasm32")]
async fn update_passkey_credential_use(
    db: &worker::d1::D1Database,
    credential_id: &str,
    sign_count: i32,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(sign_count),
        worker::d1::D1Type::Integer(sign_count),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(credential_id),
    ];
    db.prepare(
        "UPDATE zeroth_passkey_credentials
         SET sign_count = CASE WHEN ? > sign_count THEN ? ELSE sign_count END,
             last_used_at = ?,
             updated_at = ?
         WHERE credential_id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn disable_passkey_credential(
    db: &worker::d1::D1Database,
    credential_id: &str,
    disabled_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Text(credential_id),
    ];
    db.prepare(
        "UPDATE zeroth_passkey_credentials
         SET disabled_at = COALESCE(disabled_at, ?),
             updated_at = ?
         WHERE credential_id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_user(db: &worker::d1::D1Database, user_id: &str) -> worker::Result<Option<UserRow>> {
    let args = [worker::d1::D1Type::Text(user_id)];
    db.prepare(
        "SELECT id, primary_email, display_name, picture_url, disabled_at
         FROM zeroth_users
         WHERE id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<UserRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn get_user_token_claims(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<Option<UserTokenClaimsRow>> {
    let args = [worker::d1::D1Type::Text(user_id)];
    db.prepare(
        "SELECT u.id, u.primary_email, u.display_name, u.picture_url, u.disabled_at,
                EXISTS (
                    SELECT 1
                    FROM (
                        SELECT email, email_verified
                        FROM zeroth_account_identities
                        WHERE user_id = u.id
                        UNION ALL
                        SELECT email, email_verified
                        FROM zeroth_identities
                        WHERE user_id = u.id
                    ) i
                    WHERE i.email = u.primary_email
                      AND i.email_verified != 0
                    LIMIT 1
                ) AS email_verified,
                EXISTS (
                    SELECT 1
                    FROM zeroth_admin_memberships am
                    WHERE am.user_id = u.id
                      AND am.disabled_at IS NULL
                    LIMIT 1
                ) AS admin_membership_active
         FROM zeroth_users u
         WHERE u.id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<UserTokenClaimsRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn get_admin_user_row(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<Option<AdminUserRow>> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "SELECT u.id, u.primary_email, u.display_name, u.picture_url, u.created_at,
                u.updated_at, u.disabled_at,
                (SELECT COUNT(*)
                   FROM (
                       SELECT provider_id, provider_subject
                       FROM zeroth_account_identities
                       WHERE user_id = u.id
                       UNION
                       SELECT provider_id, provider_subject
                       FROM zeroth_identities
                       WHERE user_id = u.id
                   )) AS identity_count,
                (SELECT COUNT(*)
                   FROM zeroth_sessions s
                  WHERE s.user_id = u.id
                    AND s.revoked_at IS NULL
                    AND s.expires_at > ?) AS active_session_count,
                EXISTS (
                    SELECT 1
                    FROM (
                        SELECT email, email_verified
                        FROM zeroth_account_identities
                        WHERE user_id = u.id
                        UNION ALL
                        SELECT email, email_verified
                        FROM zeroth_identities
                        WHERE user_id = u.id
                    ) i
                    WHERE i.email = u.primary_email
                      AND i.email_verified != 0
                    LIMIT 1
                ) AS email_verified,
                EXISTS (
                    SELECT 1
                    FROM zeroth_admin_memberships am
                    WHERE am.user_id = u.id
                      AND am.disabled_at IS NULL
                    LIMIT 1
                ) AS admin_membership_active
           FROM zeroth_users u
          WHERE u.id = ?
          LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<AdminUserRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_admin_user_rows(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<Vec<AdminUserRow>> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(USER_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT u.id, u.primary_email, u.display_name, u.picture_url, u.created_at,
                u.updated_at, u.disabled_at,
                (SELECT COUNT(*)
                   FROM (
                       SELECT provider_id, provider_subject
                       FROM zeroth_account_identities
                       WHERE user_id = u.id
                       UNION
                       SELECT provider_id, provider_subject
                       FROM zeroth_identities
                       WHERE user_id = u.id
                   )) AS identity_count,
                (SELECT COUNT(*)
                   FROM zeroth_sessions s
                  WHERE s.user_id = u.id
                    AND s.revoked_at IS NULL
                    AND s.expires_at > ?) AS active_session_count,
                EXISTS (
                    SELECT 1
                    FROM (
                        SELECT email, email_verified
                        FROM zeroth_account_identities
                        WHERE user_id = u.id
                        UNION ALL
                        SELECT email, email_verified
                        FROM zeroth_identities
                        WHERE user_id = u.id
                    ) i
                    WHERE i.email = u.primary_email
                      AND i.email_verified != 0
                    LIMIT 1
                ) AS email_verified,
                EXISTS (
                    SELECT 1
                    FROM zeroth_admin_memberships am
                    WHERE am.user_id = u.id
                      AND am.disabled_at IS NULL
                    LIMIT 1
                ) AS admin_membership_active
           FROM zeroth_users u
          ORDER BY u.updated_at DESC, u.id
          LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<AdminUserRow>()
}

#[cfg(target_arch = "wasm32")]
async fn user_has_active_admin_membership(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Text(user_id)];
    Ok(db
        .prepare(
            "SELECT user_id
             FROM zeroth_admin_memberships
             WHERE user_id = ? AND disabled_at IS NULL
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<AdminMembershipProbeRow>(None)
        .await?
        .is_some())
}

#[cfg(target_arch = "wasm32")]
async fn upsert_admin_membership(
    db: &worker::d1::D1Database,
    user_id: &str,
    granted_by: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text("admin"),
        worker::d1::D1Type::Text(granted_by),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_admin_memberships (
             user_id, role, granted_by, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
             role = excluded.role,
             granted_by = excluded.granted_by,
             updated_at = excluded.updated_at,
             disabled_at = NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn disable_admin_membership(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_admin_memberships
         SET disabled_at = COALESCE(disabled_at, ?),
             updated_at = ?
         WHERE user_id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn admin_user_detail_response(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<Option<AdminUserDetailResponse>> {
    let Some(row) = get_admin_user_row(db, user_id, now).await? else {
        return Ok(None);
    };
    let identities = list_identities_for_user(db, user_id).await?;
    let active_sessions = list_active_sessions_for_user(db, user_id, now).await?;

    Ok(Some(AdminUserDetailResponse {
        user: admin_user_response_from_row(row),
        identities: identities_response(&identities).identities,
        active_sessions: active_sessions.iter().map(session_info_response).collect(),
    }))
}

#[cfg(target_arch = "wasm32")]
async fn set_admin_user_disabled(
    db: &worker::d1::D1Database,
    user_id: &str,
    disabled: bool,
    now: i32,
) -> worker::Result<()> {
    let disabled_at = if disabled {
        worker::d1::D1Type::Integer(now)
    } else {
        worker::d1::D1Type::Null
    };
    let args = [
        disabled_at,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_users
            SET disabled_at = ?, updated_at = ?
          WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_active_sessions_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_sessions
            SET revoked_at = ?
          WHERE user_id = ?
            AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_active_refresh_tokens_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
            SET revoked_at = ?
          WHERE user_id = ?
            AND revoked_at IS NULL
            AND rotated_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn list_audit_event_rows(
    db: &worker::d1::D1Database,
    filter: &AuditEventFilter,
) -> worker::Result<Vec<AuditEventRow>> {
    let mut conditions = Vec::new();
    let mut args = Vec::new();
    if let Some(event_type) = &filter.event_type {
        conditions.push("event_type = ?");
        args.push(worker::d1::D1Type::Text(event_type));
    }
    if let Some(user_id) = &filter.user_id {
        conditions.push("user_id = ?");
        args.push(worker::d1::D1Type::Text(user_id));
    }
    if let Some(client_id) = &filter.client_id {
        conditions.push("client_id = ?");
        args.push(worker::d1::D1Type::Text(client_id));
    }
    if let Some(provider_id) = &filter.provider_id {
        conditions.push("provider_id = ?");
        args.push(worker::d1::D1Type::Text(provider_id));
    }
    args.push(worker::d1::D1Type::Integer(AUDIT_EVENT_LIST_LIMIT));

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "SELECT id, event_type, user_id, client_id, provider_id, created_at,
                ip_hash, user_agent, details_json
           FROM zeroth_audit_events
          {where_clause}
          ORDER BY created_at DESC, id DESC
          LIMIT ?"
    );
    db.prepare(sql)
        .bind_refs(&args)?
        .all()
        .await?
        .results::<AuditEventRow>()
}

#[cfg(target_arch = "wasm32")]
async fn magic_link_delivery_status(
    db: &worker::d1::D1Database,
) -> worker::Result<Option<LocalAuthDeliveryStatus>> {
    let rows = db
        .prepare(
            "SELECT event_type, created_at, details_json
               FROM zeroth_audit_events
              WHERE event_type IN ('magic_link.issue', 'magic_link.email.failed')
              ORDER BY created_at DESC, id DESC
              LIMIT 20",
        )
        .all()
        .await?
        .results::<MagicLinkDeliveryEventRow>()?;
    Ok(magic_link_delivery_status_from_events(&rows))
}

#[cfg(target_arch = "wasm32")]
async fn provider_failure_statuses(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<(String, ProviderFailureStatus)>> {
    let args = [worker::d1::D1Type::Integer(
        PROVIDER_FAILURE_EVENT_LIST_LIMIT,
    )];
    let rows = db
        .prepare(
            "SELECT provider_id, event_type, created_at, details_json
               FROM zeroth_audit_events
              WHERE provider_id IS NOT NULL
                AND event_type IN ('provider.token_exchange.failed', 'provider.profile.failed')
              ORDER BY created_at DESC, id DESC
              LIMIT ?",
        )
        .bind_refs(&args)?
        .all()
        .await?
        .results::<ProviderFailureEventRow>()?;
    Ok(provider_failure_statuses_from_events(&rows))
}

fn provider_failure_statuses_from_events(
    rows: &[ProviderFailureEventRow],
) -> Vec<(String, ProviderFailureStatus)> {
    let mut failures = Vec::new();
    for row in rows {
        if failures.iter().any(|(id, _)| id == &row.provider_id) {
            continue;
        }
        failures.push((
            row.provider_id.clone(),
            provider_failure_status_from_event(row),
        ));
    }
    failures
}

fn provider_failure_status_from_event(row: &ProviderFailureEventRow) -> ProviderFailureStatus {
    ProviderFailureStatus {
        event_type: provider_failure_string(
            row.event_type.as_str(),
            PROVIDER_FAILURE_CODE_MAX_CHARS,
        ),
        created_at: row.created_at,
        code: provider_failure_details_string(
            &row.details_json,
            &["code", "error"],
            PROVIDER_FAILURE_CODE_MAX_CHARS,
        ),
        description: provider_failure_details_string(
            &row.details_json,
            &["description", "errorDescription", "error_description"],
            PROVIDER_FAILURE_DESCRIPTION_MAX_CHARS,
        ),
    }
}

fn provider_failure_details_string(
    details_json: &str,
    keys: &[&str],
    max_chars: usize,
) -> Option<String> {
    let details = serde_json::from_str::<serde_json::Value>(details_json).ok()?;
    keys.iter()
        .find_map(|key| details.get(*key).and_then(serde_json::Value::as_str))
        .map(|value| provider_failure_string(value, max_chars))
        .filter(|value| !value.is_empty())
}

fn provider_failure_string(value: &str, max_chars: usize) -> String {
    let value = value.trim();
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value.chars().take(max_chars - 3).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn magic_link_delivery_status_from_events(
    rows: &[MagicLinkDeliveryEventRow],
) -> Option<LocalAuthDeliveryStatus> {
    if rows.is_empty() {
        return None;
    }

    let mut status = LocalAuthDeliveryStatus::default();
    for row in rows {
        match row.event_type.as_str() {
            "magic_link.issue" => {
                status.last_issue_at.get_or_insert(row.created_at);
                if magic_link_issue_sent(&row.details_json) {
                    status.last_sent_at.get_or_insert(row.created_at);
                }
            }
            "magic_link.email.failed" => {
                status.last_failed_at.get_or_insert(row.created_at);
                if status.last_error.is_none() {
                    status.last_error = Some(magic_link_email_error_class(&row.details_json));
                }
                if status.last_error_detail.is_none() {
                    status.last_error_detail = magic_link_email_error_detail(&row.details_json);
                }
            }
            _ => {}
        }
    }

    Some(status)
}

fn magic_link_email_failed_details(error_class: &str, error: &str) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert(
        "errorClass".to_owned(),
        serde_json::Value::String(error_class.to_owned()),
    );
    if let Some(error_detail) = sanitize_magic_link_email_error_detail(error) {
        details.insert(
            "errorDetail".to_owned(),
            serde_json::Value::String(error_detail),
        );
    }
    serde_json::Value::Object(details)
}

fn magic_link_issue_sent(details_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(details_json)
        .ok()
        .and_then(|details| details.get("sent").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

fn magic_link_email_error_class(details_json: &str) -> String {
    let error = serde_json::from_str::<serde_json::Value>(details_json)
        .ok()
        .and_then(|details| {
            details
                .get("errorClass")
                .or_else(|| details.get("error"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    classify_magic_link_email_error(&error).to_owned()
}

fn magic_link_email_error_detail(details_json: &str) -> Option<String> {
    let detail = serde_json::from_str::<serde_json::Value>(details_json)
        .ok()
        .and_then(|details| {
            details
                .get("errorDetail")
                .or_else(|| details.get("errorDescription"))
                .or_else(|| details.get("error_description"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })?;
    sanitize_magic_link_email_error_detail(&detail)
}

fn sanitize_magic_link_email_error_detail(error: &str) -> Option<String> {
    let mut sanitized = error
        .trim()
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .split_whitespace()
        .map(redact_magic_link_email_error_token)
        .collect::<Vec<_>>()
        .join(" ");
    if sanitized.is_empty() {
        return None;
    }
    if sanitized.chars().count() > MAGIC_LINK_EMAIL_ERROR_DETAIL_MAX_CHARS {
        sanitized = sanitized
            .chars()
            .take(MAGIC_LINK_EMAIL_ERROR_DETAIL_MAX_CHARS.saturating_sub(3))
            .collect::<String>();
        sanitized.push_str("...");
    }
    Some(sanitized)
}

fn redact_magic_link_email_error_token(token: &str) -> Cow<'_, str> {
    let probe =
        token.trim_matches(|ch: char| ch.is_ascii_punctuation() && !matches!(ch, '_' | '-' | '.'));
    if magic_link_error_token_is_url(probe) {
        Cow::Borrowed("[url]")
    } else if magic_link_error_token_is_email(probe) {
        Cow::Borrowed("[email]")
    } else {
        Cow::Borrowed(token)
    }
}

fn magic_link_error_token_is_url(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

fn magic_link_error_token_is_email(token: &str) -> bool {
    let Some((local, domain)) = token.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.contains('/')
        && token.bytes().all(|byte| {
            byte.is_ascii()
                && !byte.is_ascii_whitespace()
                && !matches!(byte, b'<' | b'>' | b'"' | b'\'')
        })
}

fn classify_magic_link_email_error(error: &str) -> &'static str {
    let lower = error.trim().to_ascii_lowercase();
    match lower.as_str() {
        "email_unauthorized"
        | "email_sender_rejected"
        | "email_validation_error"
        | "email_internal_server_error"
        | "email_webhook_failed"
        | "email_resend_failed"
        | "email_mailchannels_failed"
        | "email_send_failed" => return matching_magic_link_email_error_class(&lower),
        _ => {}
    }
    if lower.is_empty() {
        return "email_send_failed";
    }
    if lower.contains("unauthorized") || lower.contains("forbidden") {
        return "email_unauthorized";
    }
    if lower.contains("sender") || lower.contains("from") || lower.contains("address") {
        return "email_sender_rejected";
    }
    if lower.contains("validation") || lower.contains("invalid") || lower.contains("field") {
        return "email_validation_error";
    }
    if lower.contains("internal server error") {
        return "email_internal_server_error";
    }
    if lower.contains("email_webhook_failed") {
        return "email_webhook_failed";
    }
    if lower.contains("email_resend_failed") {
        return "email_resend_failed";
    }
    if lower.contains("email_mailchannels_failed") {
        return "email_mailchannels_failed";
    }
    "email_send_failed"
}

fn matching_magic_link_email_error_class(error: &str) -> &'static str {
    match error {
        "email_unauthorized" => "email_unauthorized",
        "email_sender_rejected" => "email_sender_rejected",
        "email_validation_error" => "email_validation_error",
        "email_internal_server_error" => "email_internal_server_error",
        "email_webhook_failed" => "email_webhook_failed",
        "email_resend_failed" => "email_resend_failed",
        "email_mailchannels_failed" => "email_mailchannels_failed",
        _ => "email_send_failed",
    }
}

#[cfg(target_arch = "wasm32")]
async fn put_audit_event(
    db: &worker::d1::D1Database,
    context: &AuditRequestContext,
    event_type: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    provider_id: Option<&str>,
    details: serde_json::Value,
    now: i32,
) -> worker::Result<()> {
    let id = format!("evt_{}", random_token()?);
    let details_json = audit_details_json(details).map_err(worker_error)?;
    let user_id = d1_optional_text(user_id);
    let client_id = d1_optional_text(client_id);
    let provider_id = d1_optional_text(provider_id);
    let ip_hash = d1_optional_text(context.ip_hash.as_deref());
    let user_agent = d1_optional_text(context.user_agent.as_deref());
    let args = [
        worker::d1::D1Type::Text(&id),
        worker::d1::D1Type::Text(event_type),
        user_id,
        client_id,
        provider_id,
        worker::d1::D1Type::Integer(now),
        ip_hash,
        user_agent,
        worker::d1::D1Type::Text(&details_json),
    ];

    db.prepare(
        "INSERT INTO zeroth_audit_events (
             id, event_type, user_id, client_id, provider_id, created_at,
             ip_hash, user_agent, details_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn record_audit_event(
    db: &worker::d1::D1Database,
    request: &Request,
    event_type: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    provider_id: Option<&str>,
    details: serde_json::Value,
    now: i32,
) {
    let context = audit_request_context(request).unwrap_or_default();
    let _ = put_audit_event(
        db,
        &context,
        event_type,
        user_id,
        client_id,
        provider_id,
        details,
        now,
    )
    .await;
}

#[cfg(target_arch = "wasm32")]
async fn upsert_provider_profile(
    db: &worker::d1::D1Database,
    account_namespace: &str,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<String> {
    let user_id = match get_identity_user_id(db, account_namespace, profile).await? {
        Some(user_id) => {
            update_user_from_profile(db, &user_id, profile, now).await?;
            user_id
        }
        None => {
            let user_id = format!("usr_{}", random_token()?);
            insert_user_from_profile(db, &user_id, profile, now).await?;
            user_id
        }
    };

    upsert_account_identity_from_profile(
        db,
        account_namespace,
        &user_id,
        profile,
        raw_profile_json,
        now,
    )
    .await?;
    let identity_user_id = get_identity_user_id(db, account_namespace, profile).await?;
    validate_provider_identity_attached_to_user(identity_user_id.as_deref(), &user_id)
        .map_err(worker_error)?;
    Ok(user_id)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn validate_provider_identity_attached_to_user(
    actual_user_id: Option<&str>,
    expected_user_id: &str,
) -> Result<(), String> {
    match actual_user_id {
        Some(actual_user_id) if actual_user_id == expected_user_id => Ok(()),
        Some(_) => Err("provider identity is already linked to another user".to_owned()),
        None => Err("provider identity could not be linked to the user".to_owned()),
    }
}

#[cfg(target_arch = "wasm32")]
async fn insert_user_from_profile(
    db: &worker::d1::D1Database,
    user_id: &str,
    profile: &ProviderProfile,
    now: i32,
) -> worker::Result<()> {
    let primary_email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let args = [
        worker::d1::D1Type::Text(user_id),
        primary_email,
        display_name,
        picture_url,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];

    db.prepare(
        "INSERT INTO zeroth_users (
             id, primary_email, display_name, picture_url, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn update_user_from_profile(
    db: &worker::d1::D1Database,
    user_id: &str,
    profile: &ProviderProfile,
    now: i32,
) -> worker::Result<()> {
    let primary_email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let args = [
        primary_email,
        display_name,
        picture_url,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];

    db.prepare(
        "UPDATE zeroth_users
         SET primary_email = COALESCE(?, primary_email),
             display_name = COALESCE(display_name, ?),
             picture_url = COALESCE(picture_url, ?),
             updated_at = ?
         WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn update_user_profile_patch(
    db: &worker::d1::D1Database,
    user_id: &str,
    patch: &ProfilePatch,
    now: i32,
) -> worker::Result<()> {
    let display_name_present = i32::from(patch.display_name.is_some());
    let picture_url_present = i32::from(patch.picture_url.is_some());
    let display_name = d1_optional_text(patch.display_name.as_ref().and_then(|value| {
        value
            .as_ref()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }));
    let picture_url = d1_optional_text(patch.picture_url.as_ref().and_then(|value| {
        value
            .as_ref()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }));
    let args = [
        worker::d1::D1Type::Integer(display_name_present),
        display_name,
        worker::d1::D1Type::Integer(picture_url_present),
        picture_url,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];

    db.prepare(
        "UPDATE zeroth_users
         SET display_name = CASE WHEN ? THEN ? ELSE display_name END,
             picture_url = CASE WHEN ? THEN ? ELSE picture_url END,
             updated_at = ?
         WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn upsert_account_identity_from_profile(
    db: &worker::d1::D1Database,
    account_namespace: &str,
    user_id: &str,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let raw_profile_json = d1_optional_text(raw_profile_json);
    let email_verified = i32::from(profile.email_verified);
    let args = [
        worker::d1::D1Type::Text(account_namespace),
        worker::d1::D1Type::Text(&profile.provider_id.0),
        worker::d1::D1Type::Text(&profile.subject.0),
        worker::d1::D1Type::Text(user_id),
        email,
        worker::d1::D1Type::Integer(email_verified),
        display_name,
        picture_url,
        raw_profile_json,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];

    db.prepare(
        "INSERT INTO zeroth_account_identities (
             account_namespace, provider_id, provider_subject, user_id, email,
             email_verified, display_name, picture_url, raw_profile_json, created_at,
             updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(account_namespace, provider_id, provider_subject) DO UPDATE SET
             email = excluded.email,
             email_verified = excluded.email_verified,
             display_name = excluded.display_name,
             picture_url = excluded.picture_url,
             raw_profile_json = excluded.raw_profile_json,
             updated_at = excluded.updated_at
         WHERE zeroth_account_identities.user_id = excluded.user_id",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn upsert_identity_from_profile(
    db: &worker::d1::D1Database,
    user_id: &str,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let raw_profile_json = d1_optional_text(raw_profile_json);
    let email_verified = i32::from(profile.email_verified);
    let args = [
        worker::d1::D1Type::Text(&profile.provider_id.0),
        worker::d1::D1Type::Text(&profile.subject.0),
        worker::d1::D1Type::Text(user_id),
        email,
        worker::d1::D1Type::Integer(email_verified),
        display_name,
        picture_url,
        raw_profile_json,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];

    db.prepare(
        "INSERT INTO zeroth_identities (
             provider_id, provider_subject, user_id, email, email_verified,
             display_name, picture_url, raw_profile_json, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(provider_id, provider_subject) DO UPDATE SET
             email = excluded.email,
             email_verified = excluded.email_verified,
             display_name = excluded.display_name,
             picture_url = excluded.picture_url,
             raw_profile_json = excluded.raw_profile_json,
             updated_at = excluded.updated_at
         WHERE zeroth_identities.user_id = excluded.user_id",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_authorization_code(
    db: &worker::d1::D1Database,
    code: &str,
    transaction: &AuthTransaction,
    user_id: &str,
    session_id: Option<&str>,
    auth_time: i32,
    now: i32,
) -> worker::Result<()> {
    let code_hash = hash_secret(code);
    let scope = transaction.scope.as_slice().join(" ");
    let session_id = d1_optional_text(session_id);
    let nonce = d1_optional_text(transaction.nonce.as_deref());
    let code_challenge = d1_optional_text(transaction.code_challenge.as_deref());
    let code_challenge_method = d1_optional_text(transaction.code_challenge_method.as_deref());
    put_authorization_code_values(
        db,
        &code_hash,
        &transaction.client_id.0,
        &transaction.redirect_uri,
        user_id,
        session_id,
        auth_time,
        nonce,
        code_challenge,
        code_challenge_method,
        &scope,
        now,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn put_authorization_code_for_request(
    db: &worker::d1::D1Database,
    code: &str,
    request: &AuthorizationRequest,
    user_id: &str,
    session_id: Option<&str>,
    auth_time: i32,
    now: i32,
) -> worker::Result<()> {
    let code_hash = hash_secret(code);
    let scope = request.scope.as_slice().join(" ");
    let session_id = d1_optional_text(session_id);
    let nonce = d1_optional_text(request.nonce.as_deref());
    let code_challenge = d1_optional_text(request.code_challenge.as_deref());
    let code_challenge_method = d1_optional_text(
        request
            .code_challenge_method
            .as_ref()
            .map(|method| method.as_str()),
    );
    put_authorization_code_values(
        db,
        &code_hash,
        &request.client_id.0,
        &request.redirect_uri,
        user_id,
        session_id,
        auth_time,
        nonce,
        code_challenge,
        code_challenge_method,
        &scope,
        now,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn put_authorization_code_values(
    db: &worker::d1::D1Database,
    code_hash: &str,
    client_id: &str,
    redirect_uri: &str,
    user_id: &str,
    session_id: worker::d1::D1Type<'_>,
    auth_time: i32,
    nonce: worker::d1::D1Type<'_>,
    code_challenge: worker::d1::D1Type<'_>,
    code_challenge_method: worker::d1::D1Type<'_>,
    scope: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Text(code_hash),
        worker::d1::D1Type::Text(client_id),
        worker::d1::D1Type::Text(redirect_uri),
        worker::d1::D1Type::Text(user_id),
        session_id,
        worker::d1::D1Type::Integer(auth_time),
        nonce,
        code_challenge,
        code_challenge_method,
        worker::d1::D1Type::Text(scope),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + AUTH_CODE_TTL_SECONDS),
    ];

    db.prepare(
        "INSERT INTO zeroth_auth_codes (
             code_hash, client_id, redirect_uri, user_id, session_id, auth_time, nonce,
             code_challenge, code_challenge_method, scope, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_authorization_code(
    db: &worker::d1::D1Database,
    code: &str,
) -> worker::Result<Option<AuthCodeRow>> {
    let code_hash = hash_secret(code);
    let args = [worker::d1::D1Type::Text(&code_hash)];
    db.prepare(
        "SELECT code_hash, client_id, redirect_uri, user_id, session_id, auth_time, nonce,
                code_challenge, code_challenge_method, scope, created_at, expires_at, consumed_at
         FROM zeroth_auth_codes
         WHERE code_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<AuthCodeRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn consume_authorization_code(
    db: &worker::d1::D1Database,
    code_hash: &str,
    consumed_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(consumed_at),
        worker::d1::D1Type::Text(code_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_auth_codes
         SET consumed_at = ?
         WHERE code_hash = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn put_refresh_token(
    db: &worker::d1::D1Database,
    refresh_token: &str,
    code: &AuthCodeRow,
    now: i32,
) -> worker::Result<()> {
    let token_hash = hash_secret(refresh_token);
    put_refresh_token_row(db, &token_hash, &TokenIssue::from_auth_code(code), now).await
}

#[cfg(target_arch = "wasm32")]
async fn put_rotated_refresh_token(
    db: &worker::d1::D1Database,
    refresh_token: &str,
    row: &RefreshTokenRow,
    now: i32,
) -> worker::Result<()> {
    let token_hash = hash_secret(refresh_token);
    put_refresh_token_row(db, &token_hash, &TokenIssue::from_refresh_token(row), now).await
}

#[cfg(target_arch = "wasm32")]
async fn put_refresh_token_row(
    db: &worker::d1::D1Database,
    token_hash: &str,
    issue: &TokenIssue,
    now: i32,
) -> worker::Result<()> {
    let session_id = d1_optional_text(issue.session_id.as_deref());
    let auth_time = d1_optional_integer(issue.auth_time);
    let args = [
        worker::d1::D1Type::Text(token_hash),
        worker::d1::D1Type::Text(&issue.client_id),
        worker::d1::D1Type::Text(&issue.user_id),
        session_id,
        auth_time,
        worker::d1::D1Type::Text(&issue.scope),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + REFRESH_TOKEN_TTL_SECONDS),
    ];
    db.prepare(
        "INSERT INTO zeroth_refresh_tokens (
             token_hash, client_id, user_id, session_id, auth_time, scope, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_refresh_token(
    db: &worker::d1::D1Database,
    refresh_token: &str,
) -> worker::Result<Option<RefreshTokenRow>> {
    let token_hash = hash_secret(refresh_token);
    let args = [worker::d1::D1Type::Text(&token_hash)];
    db.prepare(
        "SELECT token_hash, client_id, user_id, session_id, auth_time, scope,
                created_at, expires_at, rotated_at, revoked_at
         FROM zeroth_refresh_tokens
         WHERE token_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<RefreshTokenRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn rotate_refresh_token(
    db: &worker::d1::D1Database,
    token_hash: &str,
    rotated_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(rotated_at),
        worker::d1::D1Type::Text(token_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_refresh_tokens
         SET rotated_at = ?
         WHERE token_hash = ? AND rotated_at IS NULL AND revoked_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn revoke_refresh_token(
    db: &worker::d1::D1Database,
    token_hash: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(token_hash),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
         SET revoked_at = ?
         WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_refresh_token_family(
    db: &worker::d1::D1Database,
    row: &RefreshTokenRow,
    revoked_at: i32,
) -> worker::Result<()> {
    if let Some(session_id) = row.session_id.as_deref() {
        let args = [
            worker::d1::D1Type::Integer(revoked_at),
            worker::d1::D1Type::Text(&row.client_id),
            worker::d1::D1Type::Text(&row.user_id),
            worker::d1::D1Type::Text(session_id),
        ];
        db.prepare(
            "UPDATE zeroth_refresh_tokens
             SET revoked_at = ?
             WHERE client_id = ? AND user_id = ? AND session_id = ? AND revoked_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
        return Ok(());
    }

    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(&row.client_id),
        worker::d1::D1Type::Text(&row.user_id),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
         SET revoked_at = ?
         WHERE client_id = ? AND user_id = ? AND session_id IS NULL AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    user_id: &str,
    client_id: &str,
    now: i32,
    user_agent: Option<&str>,
    ip_hash: Option<&str>,
) -> worker::Result<()> {
    let user_agent = d1_optional_text(user_agent);
    let ip_hash = d1_optional_text(ip_hash);
    let args = [
        worker::d1::D1Type::Text(session_id),
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(client_id),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + SESSION_TTL_SECONDS),
        user_agent,
        ip_hash,
    ];
    db.prepare(
        "INSERT INTO zeroth_sessions (
             id, user_id, client_id, created_at, expires_at, user_agent, ip_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_session(
    db: &worker::d1::D1Database,
    session_id: &str,
) -> worker::Result<Option<SessionRow>> {
    let args = [worker::d1::D1Type::Text(session_id)];
    db.prepare(
        "SELECT id, user_id, client_id, created_at, expires_at, revoked_at, user_agent, ip_hash
         FROM zeroth_sessions
         WHERE id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<SessionRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_active_sessions_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<Vec<SessionRow>> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(SESSION_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT id, user_id, client_id, created_at, expires_at, revoked_at, user_agent, ip_hash
         FROM zeroth_sessions
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
         ORDER BY created_at DESC
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<SessionRow>()
}

#[cfg(target_arch = "wasm32")]
async fn revoke_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(session_id),
    ];
    db.prepare(
        "UPDATE zeroth_sessions
         SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_user_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(session_id),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_sessions
         SET revoked_at = ?
         WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_refresh_token_family_for_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(session_id),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
         SET revoked_at = ?
         WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn current_session_from_request(
    request: &Request,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
) -> worker::Result<Option<CurrentSession>> {
    let Some(session_id) = session_id_from_request(request, &config.cookie_name)? else {
        return Ok(None);
    };
    let Some(session) = get_session(db, &session_id).await? else {
        return Ok(None);
    };
    if !session_row_is_active(&session, now) {
        return Ok(None);
    }

    let Some(user) = get_user(db, &session.user_id).await? else {
        return Ok(None);
    };
    if user.disabled_at.is_some() {
        return Ok(None);
    }

    Ok(Some(CurrentSession { session, user }))
}

#[cfg(target_arch = "wasm32")]
async fn current_account_from_request(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    origin: Option<&str>,
    now: i32,
) -> worker::Result<Result<CurrentAccount, AccountAuthError>> {
    let authorization = request_header(request, "Authorization")?;
    let bearer_token = match bearer_token_from_authorization_header(authorization.as_deref()) {
        Ok(token) => token,
        Err(error) => return Ok(Err(AccountAuthError::invalid_token(error))),
    };

    if let Some(bearer_token) = bearer_token {
        let material = signing_material_from_env(env)?;
        let claims = match verify_zeroth_access_token(&bearer_token, config, &material.jwks, now) {
            Ok(claims) => claims,
            Err(error) => return Ok(Err(AccountAuthError::invalid_token(error))),
        };
        let user = match get_user(db, &claims.sub).await? {
            Some(user) => user,
            None => return Ok(Err(AccountAuthError::invalid_token("user was not found"))),
        };
        if user.disabled_at.is_some() {
            return Ok(Err(AccountAuthError::invalid_token("user is disabled")));
        }
        if let Err(error) = validate_access_token_session(db, &claims, now).await? {
            return Ok(Err(AccountAuthError::invalid_token(error)));
        }
        let allowed_origins = match active_client_allowed_origins(db, &claims.aud).await? {
            Ok(allowed_origins) => allowed_origins,
            Err(error) => return Ok(Err(AccountAuthError::invalid_token(error))),
        };
        if let Err(error) = validate_cors_origin(origin, &allowed_origins) {
            return Ok(Err(AccountAuthError::invalid_request(error, 403)));
        }
        return Ok(Ok(CurrentAccount {
            user,
            client_id: Some(claims.aud),
            session_id: claims.sid,
            scope: claims.scope,
            access_token: true,
        }));
    }

    let Some(current) = current_session_from_request(request, db, config, now).await? else {
        return Ok(Err(AccountAuthError::login_required(
            "active browser session or bearer token was not found",
        )));
    };
    if let Err(error) = validate_session_cors_origin(db, origin, &current.session).await? {
        return Ok(Err(AccountAuthError::invalid_request(error, 403)));
    }

    Ok(Ok(CurrentAccount {
        client_id: current.session.client_id.clone(),
        session_id: Some(current.session.id.clone()),
        user: current.user,
        scope: None,
        access_token: false,
    }))
}

#[cfg(target_arch = "wasm32")]
async fn cleanup_expired_auth_transactions(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(AUTH_TRANSACTION_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_auth_transactions
         WHERE provider_state IN (
             SELECT provider_state
             FROM zeroth_auth_transactions
             WHERE expires_at <= ?
             ORDER BY expires_at
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_auth_transaction(
    db: &worker::d1::D1Database,
    transaction: &AuthTransaction,
) -> worker::Result<()> {
    let scope = transaction.scope.as_slice().join(" ");
    let created_at = system_time_to_d1_integer(transaction.created_at)?;
    let expires_at = system_time_to_d1_integer(transaction.expires_at)?;
    let app_state = d1_optional_text(transaction.app_state.as_deref());
    let nonce = d1_optional_text(transaction.nonce.as_deref());
    let provider_nonce = d1_optional_text(transaction.provider_nonce.as_deref());
    let code_challenge = d1_optional_text(transaction.code_challenge.as_deref());
    let code_challenge_method = d1_optional_text(transaction.code_challenge_method.as_deref());
    let link_user_id = d1_optional_text(
        transaction
            .link_user_id
            .as_ref()
            .map(|user_id| user_id.0.as_str()),
    );
    let link_session_id = d1_optional_text(transaction.link_session_id.as_deref());
    let session_return_to = d1_optional_text(transaction.session_return_to.as_deref());
    let args = [
        worker::d1::D1Type::Text(&transaction.provider_state),
        worker::d1::D1Type::Text(&transaction.client_id.0),
        worker::d1::D1Type::Text(&transaction.provider_id.0),
        worker::d1::D1Type::Text(&transaction.redirect_uri),
        worker::d1::D1Type::Text(&transaction.provider_redirect_uri),
        app_state,
        nonce,
        provider_nonce,
        code_challenge,
        code_challenge_method,
        worker::d1::D1Type::Text(&scope),
        link_user_id,
        link_session_id,
        session_return_to,
        worker::d1::D1Type::Integer(created_at),
        worker::d1::D1Type::Integer(expires_at),
    ];

    db.prepare(
        "INSERT INTO zeroth_auth_transactions (
             provider_state, client_id, provider_id, redirect_uri, provider_redirect_uri,
             app_state, nonce, provider_nonce, code_challenge, code_challenge_method, scope, link_user_id,
             link_session_id, session_return_to, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_d1_schema(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let mut request = request;
    match maybe_authorize_admin_write_request(
        &mut request,
        &env,
        &db,
        &config,
        now,
        CSRF_ROUTE_FAMILY_ADMIN,
        true,
        "schema_bootstrap",
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return client_management_error_json(&ClientManagementError::unauthorized(
                "admin bearer token or allowed Zeroth session is required",
            ))
        }
        Err(error) => return client_management_error_json(&error),
    }

    let mut migrations_applied = Vec::new();
    let mut migrations_skipped = Vec::new();
    ensure_schema_migrations_table(&db).await?;
    for migration in zeroth_storage::migrations::ALL {
        if schema_migration_applied(&db, migration.version).await? {
            migrations_skipped.push(migration.name);
            continue;
        }
        for statement in migration.statements() {
            db.prepare(statement.to_owned()).run().await?;
        }
        record_schema_migration(&db, migration, now).await?;
        migrations_applied.push(migration.name);
    }
    ensure_compat_columns(&db).await?;
    record_audit_event(
        &db,
        &request,
        "schema.ensure",
        None,
        None,
        None,
        serde_json::json!({
            "applied": &migrations_applied,
            "skipped": &migrations_skipped
        }),
        now,
    )
    .await;

    json(&MigrationResponse {
        ok: true,
        binding: D1_BINDING,
        migrations_applied,
        migrations_skipped,
    })
}

#[cfg(target_arch = "wasm32")]
async fn d1_schema_status(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    let tables = db_table_statuses(&db).await?;
    let migrations_table_present = tables
        .iter()
        .any(|table| table.name == zeroth_storage::SCHEMA_MIGRATIONS_TABLE && table.present);
    let applied_migration_versions = if migrations_table_present {
        applied_schema_migration_versions(&db).await?
    } else {
        Vec::new()
    };
    let migrations = zeroth_storage::migrations::ALL
        .iter()
        .map(|migration| DbMigrationStatus {
            version: migration.version,
            name: migration.name,
            applied: applied_migration_versions.contains(&migration.version),
        })
        .collect::<Vec<_>>();
    let compatibility_columns = db_compatibility_column_statuses(&db).await?;
    let clients_table_present = tables
        .iter()
        .any(|table| table.name == "zeroth_clients" && table.present);
    let client_count = if clients_table_present {
        count_registered_clients(&db).await?
    } else {
        0
    };
    let ok = db_schema_status_ok(&tables, &migrations, &compatibility_columns);

    let response = DbSchemaStatusResponse {
        ok,
        binding: D1_BINDING,
        tables,
        migrations,
        compatibility_columns,
        client_count,
    };
    let status = if response.ok { 200 } else { 503 };
    json_status(&response, status)
}

#[cfg(target_arch = "wasm32")]
async fn db_table_statuses(db: &worker::d1::D1Database) -> worker::Result<Vec<DbTableStatus>> {
    let mut tables = Vec::with_capacity(zeroth_storage::REQUIRED_TABLES.len());
    for table in zeroth_storage::REQUIRED_TABLES {
        tables.push(DbTableStatus {
            name: table,
            present: db_table_exists(db, table).await?,
        });
    }
    Ok(tables)
}

#[cfg(target_arch = "wasm32")]
async fn db_table_exists(db: &worker::d1::D1Database, table: &str) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Text(table)];
    let row = db
        .prepare(
            "SELECT name
             FROM sqlite_master
             WHERE type = 'table' AND name = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<TableColumnRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.name == table))
}

#[cfg(target_arch = "wasm32")]
async fn applied_schema_migration_versions(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<i32>> {
    let rows = db
        .prepare(
            "SELECT version
             FROM zeroth_schema_migrations
             ORDER BY version",
        )
        .all()
        .await?
        .results::<SchemaMigrationRow>()?;
    Ok(rows.into_iter().map(|row| row.version).collect())
}

#[cfg(target_arch = "wasm32")]
async fn db_compatibility_column_statuses(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<DbCompatibilityColumnStatus>> {
    let mut statuses = Vec::with_capacity(zeroth_storage::compatibility::ALL.len());
    for table in zeroth_storage::compatibility::TABLES {
        let columns = db
            .prepare(format!("PRAGMA table_info({table})"))
            .all()
            .await?
            .results::<TableColumnRow>()?;

        for compat in zeroth_storage::compatibility::ALL
            .iter()
            .copied()
            .filter(|compat| compat.table == *table)
        {
            statuses.push(DbCompatibilityColumnStatus {
                table: compat.table,
                name: compat.name,
                present: columns.iter().any(|column| column.name == compat.name),
            });
        }
    }
    Ok(statuses)
}

#[cfg(target_arch = "wasm32")]
async fn count_registered_clients(db: &worker::d1::D1Database) -> worker::Result<i32> {
    let row = db
        .prepare("SELECT COUNT(*) AS count FROM zeroth_clients")
        .first::<IdentityCountRow>(None)
        .await?;
    Ok(row.map(|row| row.count).unwrap_or(0))
}

fn db_schema_status_ok(
    tables: &[DbTableStatus],
    migrations: &[DbMigrationStatus],
    compatibility_columns: &[DbCompatibilityColumnStatus],
) -> bool {
    zeroth_storage::REQUIRED_TABLES.iter().all(|required| {
        tables
            .iter()
            .any(|table| table.name == *required && table.present)
    }) && zeroth_storage::migrations::ALL.iter().all(|required| {
        migrations.iter().any(|migration| {
            migration.version == required.version
                && migration.name == required.name
                && migration.applied
        })
    }) && zeroth_storage::compatibility::ALL.iter().all(|required| {
        compatibility_columns.iter().any(|column| {
            column.table == required.table && column.name == required.name && column.present
        })
    })
}

#[cfg(target_arch = "wasm32")]
async fn ensure_schema_migrations_table(db: &worker::d1::D1Database) -> worker::Result<()> {
    db.prepare(zeroth_storage::SCHEMA_MIGRATIONS_CREATE_SQL)
        .run()
        .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn schema_migration_applied(
    db: &worker::d1::D1Database,
    version: i32,
) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Integer(version)];
    let row = db
        .prepare(
            "SELECT version
             FROM zeroth_schema_migrations
             WHERE version = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<SchemaMigrationRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.version == version))
}

#[cfg(target_arch = "wasm32")]
async fn record_schema_migration(
    db: &worker::d1::D1Database,
    migration: &zeroth_storage::Migration,
    applied_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(migration.version),
        worker::d1::D1Type::Text(migration.name),
        worker::d1::D1Type::Integer(applied_at),
    ];
    db.prepare(
        "INSERT OR IGNORE INTO zeroth_schema_migrations (version, name, applied_at)
         VALUES (?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_compat_columns(db: &worker::d1::D1Database) -> worker::Result<()> {
    for table in zeroth_storage::compatibility::TABLES {
        let pragma = format!("PRAGMA table_info({table})");
        let columns = db
            .prepare(pragma)
            .all()
            .await?
            .results::<TableColumnRow>()?;

        for compat in zeroth_storage::compatibility::ALL
            .iter()
            .copied()
            .filter(|compat| compat.table == *table)
        {
            if columns.iter().any(|column| column.name == compat.name) {
                continue;
            }
            db.prepare(compat.alter_table_sql()).run().await?;
        }
    }

    Ok(())
}

fn auth_transaction_from_request(
    request: &AuthorizationRequest,
    provider_id: &str,
    provider_state: String,
    provider_nonce: String,
    provider_redirect_uri: String,
    created_at: i32,
) -> AuthTransaction {
    AuthTransaction {
        provider_state,
        client_id: request.client_id.clone(),
        provider_id: ProviderId(provider_id.to_owned()),
        redirect_uri: request.redirect_uri.clone(),
        provider_redirect_uri,
        app_state: request.state.clone(),
        nonce: request.nonce.clone(),
        provider_nonce: Some(provider_nonce),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: request
            .code_challenge_method
            .as_ref()
            .map(|method| method.as_str().to_owned()),
        scope: request.scope.clone(),
        link_user_id: None,
        link_session_id: None,
        session_return_to: None,
        created_at: unix_seconds_to_system_time(created_at),
        expires_at: unix_seconds_to_system_time(created_at + AUTH_TRANSACTION_TTL_SECONDS),
    }
}

fn auth_transaction_from_session_login_request(
    client: &Client,
    provider_id: &str,
    provider_state: String,
    provider_nonce: String,
    provider_redirect_uri: String,
    return_to: String,
    app_state: Option<String>,
    created_at: i32,
) -> AuthTransaction {
    AuthTransaction {
        provider_state,
        client_id: client.id.clone(),
        provider_id: ProviderId(provider_id.to_owned()),
        redirect_uri: return_to.clone(),
        provider_redirect_uri,
        app_state,
        nonce: None,
        provider_nonce: Some(provider_nonce),
        code_challenge: None,
        code_challenge_method: None,
        scope: ScopeSet::new(["openid", "email", "profile"]),
        link_user_id: None,
        link_session_id: None,
        session_return_to: Some(return_to),
        created_at: unix_seconds_to_system_time(created_at),
        expires_at: unix_seconds_to_system_time(created_at + AUTH_TRANSACTION_TTL_SECONDS),
    }
}

fn auth_transaction_from_link_request(
    client: &Client,
    provider_id: &str,
    provider_state: String,
    provider_nonce: String,
    provider_redirect_uri: String,
    return_to: String,
    app_state: Option<String>,
    user_id: &str,
    session_id: &str,
    created_at: i32,
) -> AuthTransaction {
    AuthTransaction {
        provider_state,
        client_id: client.id.clone(),
        provider_id: ProviderId(provider_id.to_owned()),
        redirect_uri: return_to,
        provider_redirect_uri,
        app_state,
        nonce: None,
        provider_nonce: Some(provider_nonce),
        code_challenge: None,
        code_challenge_method: None,
        scope: ScopeSet::new(["openid", "email", "profile"]),
        link_user_id: Some(UserId(user_id.to_owned())),
        link_session_id: Some(session_id.to_owned()),
        session_return_to: None,
        created_at: unix_seconds_to_system_time(created_at),
        expires_at: unix_seconds_to_system_time(created_at + AUTH_TRANSACTION_TTL_SECONDS),
    }
}

fn auth_transaction_from_row(row: AuthTransactionRow) -> Result<StoredAuthTransaction, String> {
    Ok(StoredAuthTransaction {
        transaction: AuthTransaction {
            provider_state: row.provider_state,
            client_id: ClientId(row.client_id),
            provider_id: ProviderId(row.provider_id),
            redirect_uri: row.redirect_uri,
            provider_redirect_uri: row.provider_redirect_uri,
            app_state: row.app_state,
            nonce: row.nonce,
            provider_nonce: row.provider_nonce,
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            scope: ScopeSet::new(row.scope.split_whitespace()),
            link_user_id: row.link_user_id.map(UserId),
            link_session_id: row.link_session_id,
            session_return_to: row.session_return_to,
            created_at: unix_seconds_to_system_time(row.created_at),
            expires_at: unix_seconds_to_system_time(row.expires_at),
        },
        consumed_at: row.consumed_at,
    })
}

fn validate_stored_auth_transaction(
    record: &StoredAuthTransaction,
    now: i32,
) -> Result<(), ProviderCallbackError> {
    if record.consumed_at.is_some() {
        return Err(ProviderCallbackError::invalid_request(
            "provider callback state has already been consumed",
        ));
    }

    let expires_at = system_time_to_unix_seconds(record.transaction.expires_at)
        .map_err(ProviderCallbackError::invalid_request)?;
    if expires_at <= now {
        return Err(ProviderCallbackError::invalid_request(
            "provider callback state has expired",
        ));
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_client(
    transaction: &AuthTransaction,
    issuer: &str,
    code: &str,
) -> worker::Result<Response> {
    let redirect_url = client_redirect_url(transaction, issuer, code)
        .map_err(|error| worker::Error::RustError(error.description))?;
    Response::redirect(redirect_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_authorization_request_client(
    request: &AuthorizationRequest,
    issuer: &str,
    code: &str,
) -> worker::Result<Response> {
    let redirect_url = authorization_request_client_redirect_url(request, issuer, code)
        .map_err(|error| worker::Error::RustError(error.description))?;
    Response::redirect(redirect_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_authorization_request_error(
    request: &AuthorizationRequest,
    issuer: &str,
    error: &str,
    error_description: &str,
) -> worker::Result<Response> {
    let redirect_url =
        authorization_request_error_redirect_url(request, issuer, error, error_description)
            .map_err(worker::Error::RustError)?;
    Response::redirect(redirect_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_session_login_return(transaction: &AuthTransaction) -> worker::Result<Response> {
    let return_url =
        session_login_return_url(transaction).map_err(|error| worker::Error::RustError(error))?;
    Response::redirect(return_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_hosted_admin_login(
    config: &ZerothServerConfig,
    return_to_path: &str,
) -> worker::Result<Response> {
    let login_url = hosted_admin_login_url(&config.issuer().issuer, return_to_path)
        .map_err(worker::Error::RustError)?;
    Response::redirect(login_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_provider_callback_error(
    transaction: &AuthTransaction,
    issuer: &str,
    error: &ProviderCallbackError,
) -> worker::Result<Response> {
    let return_url = provider_callback_error_return_url(transaction, issuer, error)
        .map_err(|error| worker::Error::RustError(error))?;
    Response::redirect(return_url)
}

fn client_redirect_url(
    transaction: &AuthTransaction,
    issuer: &str,
    code: &str,
) -> Result<url::Url, TokenExchangeError> {
    let mut redirect_url = url::Url::parse(&transaction.redirect_uri).map_err(|error| {
        TokenExchangeError::invalid_request(format!("invalid redirect_uri: {error}"))
    })?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }
    Ok(redirect_url)
}

fn authorization_request_client_redirect_url(
    request: &AuthorizationRequest,
    issuer: &str,
    code: &str,
) -> Result<url::Url, TokenExchangeError> {
    let mut redirect_url = url::Url::parse(&request.redirect_uri).map_err(|error| {
        TokenExchangeError::invalid_request(format!("invalid redirect_uri: {error}"))
    })?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = &request.state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }
    Ok(redirect_url)
}

fn authorization_request_error_redirect_url(
    request: &AuthorizationRequest,
    issuer: &str,
    error: &str,
    error_description: &str,
) -> Result<url::Url, String> {
    let mut redirect_url = url::Url::parse(&request.redirect_uri)
        .map_err(|error| format!("invalid redirect_uri: {error}"))?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", error_description);
        if let Some(state) = &request.state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }
    Ok(redirect_url)
}

fn authorization_request_error_redirect_url_for_client(
    request: &AuthorizationRequest,
    client: &Client,
    issuer: &str,
    error: &AuthorizationRequestError,
) -> Result<Option<url::Url>, String> {
    if !authorization_request_redirect_uri_registered_for_client(request, client) {
        return Ok(None);
    }
    authorization_request_error_redirect_url(request, issuer, error.code, &error.description)
        .map(Some)
}

fn session_login_return_url(transaction: &AuthTransaction) -> Result<url::Url, String> {
    let return_to = transaction
        .session_return_to
        .as_deref()
        .unwrap_or(&transaction.redirect_uri);
    let mut return_url =
        url::Url::parse(return_to).map_err(|error| format!("invalid return_to: {error}"))?;
    if let Some(state) = &transaction.app_state {
        return_url.query_pairs_mut().append_pair("state", state);
    }
    Ok(return_url)
}

fn provider_callback_error_return_url(
    transaction: &AuthTransaction,
    issuer: &str,
    error: &ProviderCallbackError,
) -> Result<url::Url, String> {
    let return_to = transaction
        .session_return_to
        .as_deref()
        .unwrap_or(&transaction.redirect_uri);
    let mut return_url =
        url::Url::parse(return_to).map_err(|error| format!("invalid return_to: {error}"))?;
    {
        let mut pairs = return_url.query_pairs_mut();
        pairs.append_pair("error", &error.code);
        pairs.append_pair("error_description", &error.description);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
        if transaction.session_return_to.is_none() {
            pairs.append_pair("iss", issuer);
        }
    }
    Ok(return_url)
}

fn hosted_admin_login_url(issuer_base_url: &str, return_to_path: &str) -> Result<url::Url, String> {
    let base = issuer_base_url.trim_end_matches('/');
    let mut login_url = url::Url::parse(&format!("{base}/login"))
        .map_err(|error| format!("invalid issuer URL: {error}"))?;
    let return_to = format!("{base}{return_to_path}");
    login_url
        .query_pairs_mut()
        .append_pair("return_to", &return_to);
    Ok(login_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_local_auth_get_to_login(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let mut login_url = url::Url::parse(&format!(
        "{}/login",
        config.public_base_url.trim_end_matches('/')
    ))
    .map_err(|error| worker_error(format!("invalid issuer URL: {error}")))?;
    {
        let mut pairs = login_url.query_pairs_mut();
        if let Some(client_id) =
            query_param(&request_url, "client_id").or_else(|| query_param(&request_url, "clientId"))
        {
            pairs.append_pair("client_id", &client_id);
        }
        if let Some(return_to) =
            query_param(&request_url, "return_to").or_else(|| query_param(&request_url, "returnTo"))
        {
            pairs.append_pair("return_to", &return_to);
        }
    }
    Response::redirect(login_url)
}

fn client_return_to_from_url(
    url: &url::Url,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<String, String> {
    let return_to = query_param(url, "return_to")
        .or_else(|| query_param(url, "redirect_uri"))
        .or_else(|| client.redirect_uris.first().cloned())
        .ok_or_else(|| "missing return_to".to_owned())?;

    validate_client_return_to(&return_to, client, issuer_base_url)?;
    Ok(return_to)
}

fn session_login_return_to_from_url(
    url: &url::Url,
    client: &Client,
    issuer_base_url: &str,
) -> Result<String, String> {
    let return_to = query_param(url, "return_to")
        .or_else(|| query_param(url, "redirect_uri"))
        .unwrap_or_else(|| format!("{}/account", issuer_base_url.trim_end_matches('/')));

    validate_client_return_to(&return_to, client, Some(issuer_base_url))?;
    Ok(return_to)
}

fn identity_link_return_to_from_url(
    url: &url::Url,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<String, String> {
    client_return_to_from_url(url, client, issuer_base_url)
}

#[cfg(target_arch = "wasm32")]
async fn logout_redirect_target(
    url: &url::Url,
    current: Option<&CurrentSession>,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    env: &Env,
    now: i32,
) -> worker::Result<Result<Option<url::Url>, String>> {
    let Some(return_to) =
        query_param(url, "post_logout_redirect_uri").or_else(|| query_param(url, "return_to"))
    else {
        return Ok(Ok(None));
    };

    let client_id = if let Some(client_id) = current.and_then(|current| {
        current
            .session
            .client_id
            .as_ref()
            .map(std::string::ToString::to_string)
    }) {
        client_id
    } else if let Some(client_id) = query_param(url, "client_id") {
        client_id
    } else if let Some(id_token_hint) = query_param(url, "id_token_hint") {
        let material = signing_material_from_env(env)?;
        match verify_zeroth_id_token_hint(&id_token_hint, config, &material.jwks, now) {
            Ok(claims) => claims.aud,
            Err(error) => return Ok(Err(error)),
        }
    } else {
        return Ok(Err(
            "client_id, active session, or valid id_token_hint is required for logout redirects"
                .to_owned(),
        ));
    };

    let Some(client) = get_client(db, &client_id).await? else {
        return Ok(Err("logout client is not registered".to_owned()));
    };
    match validated_logout_redirect_url(url, &return_to, &client, Some(&config.public_base_url)) {
        Ok(target) => Ok(Ok(Some(target))),
        Err(error) => Ok(Err(error)),
    }
}

fn validated_logout_redirect_url(
    request_url: &url::Url,
    return_to: &str,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<url::Url, String> {
    validate_client_return_to(return_to, client, issuer_base_url)?;
    let mut target = url::Url::parse(return_to)
        .map_err(|error| format!("invalid logout redirect URI: {error}"))?;
    if let Some(state) = query_param(request_url, "state") {
        target.query_pairs_mut().append_pair("state", &state);
    }
    Ok(target)
}

fn validate_client_return_to(
    return_to: &str,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<(), String> {
    if client
        .redirect_uris
        .iter()
        .any(|redirect_uri| redirect_uri == return_to)
    {
        return Ok(());
    }

    let url = url::Url::parse(return_to).map_err(|error| {
        format!("return_to must be an absolute URL or registered redirect URI: {error}")
    })?;
    if matches!(url.scheme(), "http" | "https") {
        let origin = url.origin().ascii_serialization();
        if origin_allowed(&client.allowed_origins, &origin) {
            return Ok(());
        }
        if return_to_is_hosted_url(&url, issuer_base_url) {
            return Ok(());
        }
    }

    Err("return_to must match a registered redirect URI or allowed origin".to_owned())
}

fn return_to_is_hosted_url(url: &url::Url, issuer_base_url: Option<&str>) -> bool {
    let Some(issuer_base_url) = issuer_base_url else {
        return false;
    };
    let Ok(issuer_url) = url::Url::parse(issuer_base_url) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.origin() == issuer_url.origin()
        && matches!(url.path(), "/account" | "/admin" | "/admin/clients")
}

fn identity_link_return_url(
    transaction: &AuthTransaction,
    profile: &ProviderProfile,
) -> Result<url::Url, String> {
    let mut return_url = url::Url::parse(&transaction.redirect_uri)
        .map_err(|error| format!("invalid return_to: {error}"))?;
    {
        let mut pairs = return_url.query_pairs_mut();
        pairs.append_pair("identity_linked", "true");
        pairs.append_pair("provider", &profile.provider_id.0);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
    }
    Ok(return_url)
}

fn identity_link_error_url(
    transaction: &AuthTransaction,
    error: &IdentityLinkError,
) -> Result<url::Url, String> {
    let mut return_url = url::Url::parse(&transaction.redirect_uri)
        .map_err(|error| format!("invalid return_to: {error}"))?;
    {
        let mut pairs = return_url.query_pairs_mut();
        pairs.append_pair("error", &error.code);
        pairs.append_pair("error_description", &error.description);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
    }
    Ok(return_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_identity_link_return(
    transaction: &AuthTransaction,
    profile: &ProviderProfile,
) -> worker::Result<Response> {
    let return_url = identity_link_return_url(transaction, profile).map_err(worker_error)?;
    Response::redirect(return_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_identity_link_error(
    transaction: &AuthTransaction,
    error: &IdentityLinkError,
) -> worker::Result<Response> {
    let return_url = identity_link_error_url(transaction, error).map_err(worker_error)?;
    Response::redirect(return_url)
}

#[cfg(target_arch = "wasm32")]
async fn token_exchange_form_from_request(
    request: &mut Request,
) -> Result<TokenExchangeForm, TokenExchangeError> {
    let basic_auth = client_basic_auth_from_header(
        request
            .headers()
            .get("Authorization")
            .map_err(|error| {
                TokenExchangeError::invalid_request(format!(
                    "could not read Authorization header: {error}"
                ))
            })?
            .as_deref(),
    )?;
    let form = request.form_data().await.map_err(|error| {
        TokenExchangeError::invalid_request(format!("could not parse token request form: {error}"))
    })?;
    let (client_id, client_auth) = token_client_auth(
        optional_form_field(&form, "client_id"),
        optional_form_field(&form, "client_secret"),
        basic_auth,
    )?;

    Ok(TokenExchangeForm {
        grant_type: required_form_field(&form, "grant_type")?,
        client_id,
        client_auth,
        redirect_uri: optional_form_field(&form, "redirect_uri"),
        code: optional_form_field(&form, "code"),
        code_verifier: optional_form_field(&form, "code_verifier"),
        refresh_token: optional_form_field(&form, "refresh_token"),
        scope: optional_form_field(&form, "scope"),
        subject_token: optional_form_field(&form, "subject_token")
            .or_else(|| optional_form_field(&form, "identity_token"))
            .or_else(|| optional_form_field(&form, "access_token")),
        subject_token_type: optional_form_field(&form, "subject_token_type"),
        provider: optional_form_field(&form, "provider"),
        provider_client_id: optional_form_field(&form, "provider_client_id")
            .or_else(|| optional_form_field(&form, "apple_client_id")),
        nonce: optional_form_field(&form, "nonce"),
    })
}

#[cfg(target_arch = "wasm32")]
async fn token_revocation_form_from_request(
    request: &mut Request,
) -> Result<TokenRevocationForm, TokenExchangeError> {
    let basic_auth = client_basic_auth_from_header(
        request
            .headers()
            .get("Authorization")
            .map_err(|error| {
                TokenExchangeError::invalid_request(format!(
                    "could not read Authorization header: {error}"
                ))
            })?
            .as_deref(),
    )?;
    let form = request.form_data().await.map_err(|error| {
        TokenExchangeError::invalid_request(format!(
            "could not parse revocation request form: {error}"
        ))
    })?;
    let (client_id, client_auth) = token_client_auth(
        optional_form_field(&form, "client_id"),
        optional_form_field(&form, "client_secret"),
        basic_auth,
    )?;

    Ok(TokenRevocationForm {
        client_id,
        client_auth,
        token: required_form_field(&form, "token")?,
        token_type_hint: optional_form_field(&form, "token_type_hint"),
    })
}

#[cfg(target_arch = "wasm32")]
async fn token_introspection_form_from_request(
    request: &mut Request,
) -> Result<TokenIntrospectionForm, TokenExchangeError> {
    let basic_auth = client_basic_auth_from_header(
        request
            .headers()
            .get("Authorization")
            .map_err(|error| {
                TokenExchangeError::invalid_request(format!(
                    "could not read Authorization header: {error}"
                ))
            })?
            .as_deref(),
    )?;
    let form = request.form_data().await.map_err(|error| {
        TokenExchangeError::invalid_request(format!(
            "could not parse introspection request form: {error}"
        ))
    })?;
    let (client_id, client_auth) = token_client_auth(
        optional_form_field(&form, "client_id"),
        optional_form_field(&form, "client_secret"),
        basic_auth,
    )?;

    Ok(TokenIntrospectionForm {
        client_id,
        client_auth,
        token: required_form_field(&form, "token")?,
        token_type_hint: optional_form_field(&form, "token_type_hint"),
    })
}

#[cfg(target_arch = "wasm32")]
async fn profile_patch_from_request(
    request: &mut Request,
) -> Result<ProfilePatch, ProfilePatchError> {
    let content_type = request_header(request, "Content-Type").map_err(|error| {
        ProfilePatchError::invalid_request(format!("could not read Content-Type header: {error}"))
    })?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err(ProfilePatchError::invalid_request(
            "Content-Type must be application/json",
        ));
    }

    if let Some(content_length) = request_header(request, "Content-Length").map_err(|error| {
        ProfilePatchError::invalid_request(format!("could not read Content-Length header: {error}"))
    })? {
        let length = content_length
            .trim()
            .parse::<usize>()
            .map_err(|_| ProfilePatchError::invalid_request("Content-Length must be an integer"))?;
        if length > PROFILE_PATCH_BODY_LIMIT {
            return Err(ProfilePatchError::payload_too_large(
                "profile patch JSON body is too large",
            ));
        }
    }

    let body = request.bytes().await.map_err(|error| {
        ProfilePatchError::invalid_request(format!("could not read profile patch body: {error}"))
    })?;
    if body.len() > PROFILE_PATCH_BODY_LIMIT {
        return Err(ProfilePatchError::payload_too_large(
            "profile patch JSON body is too large",
        ));
    }
    let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        ProfilePatchError::invalid_request(format!("invalid profile patch JSON: {error}"))
    })?;
    profile_patch_from_value(value)
}

#[cfg(target_arch = "wasm32")]
async fn client_upsert_from_request(
    request: &mut Request,
) -> Result<ValidatedClientUpsert, ClientManagementError> {
    let content_type = request_header(request, "Content-Type").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Type header: {error}"
        ))
    })?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err(ClientManagementError::invalid_request(
            "Content-Type must be application/json",
        ));
    }

    if let Some(content_length) = request_header(request, "Content-Length").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Length header: {error}"
        ))
    })? {
        let length = content_length.trim().parse::<usize>().map_err(|_| {
            ClientManagementError::invalid_request("Content-Length must be an integer")
        })?;
        if length > CLIENT_MANAGEMENT_BODY_LIMIT {
            return Err(ClientManagementError::payload_too_large(
                "client management JSON body is too large",
            ));
        }
    }

    let body = request.bytes().await.map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read client management body: {error}"
        ))
    })?;
    if body.len() > CLIENT_MANAGEMENT_BODY_LIMIT {
        return Err(ClientManagementError::payload_too_large(
            "client management JSON body is too large",
        ));
    }
    let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        ClientManagementError::invalid_request(format!("invalid client JSON: {error}"))
    })?;
    client_upsert_from_value(value)
}

#[cfg(target_arch = "wasm32")]
async fn admin_user_patch_from_request(
    request: &mut Request,
) -> Result<AdminUserPatchRequest, ClientManagementError> {
    let content_type = request_header(request, "Content-Type").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Type header: {error}"
        ))
    })?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err(ClientManagementError::invalid_request(
            "Content-Type must be application/json",
        ));
    }

    if let Some(content_length) = request_header(request, "Content-Length").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Length header: {error}"
        ))
    })? {
        let length = content_length.trim().parse::<usize>().map_err(|_| {
            ClientManagementError::invalid_request("Content-Length must be an integer")
        })?;
        if length > USER_MANAGEMENT_BODY_LIMIT {
            return Err(ClientManagementError::payload_too_large(
                "user management JSON body is too large",
            ));
        }
    }

    let body = request.bytes().await.map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read user management body: {error}"
        ))
    })?;
    if body.len() > USER_MANAGEMENT_BODY_LIMIT {
        return Err(ClientManagementError::payload_too_large(
            "user management JSON body is too large",
        ));
    }
    serde_json::from_slice::<AdminUserPatchRequest>(&body).map_err(|error| {
        ClientManagementError::invalid_request(format!("invalid user JSON: {error}"))
    })
}

#[cfg(target_arch = "wasm32")]
fn required_form_field(form: &FormData, name: &str) -> Result<String, TokenExchangeError> {
    form.get_field(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenExchangeError::invalid_request(format!("missing {name}")))
}

#[cfg(target_arch = "wasm32")]
fn optional_form_field(form: &FormData, name: &str) -> Option<String> {
    form.get_field(name).filter(|value| !value.is_empty())
}

fn token_client_auth(
    form_client_id: Option<String>,
    form_client_secret: Option<String>,
    basic_auth: Option<ClientBasicAuth>,
) -> Result<(String, ClientAuth), TokenExchangeError> {
    match (basic_auth, form_client_secret) {
        (Some(_), Some(_)) => Err(TokenExchangeError::invalid_request(
            "client authentication must use only one method",
        )),
        (Some(basic_auth), None) => {
            if let Some(form_client_id) = form_client_id {
                if form_client_id != basic_auth.client_id {
                    return Err(TokenExchangeError::invalid_client(
                        "client_id did not match Basic authentication",
                    ));
                }
            }

            Ok((
                basic_auth.client_id,
                ClientAuth::SecretBasic(basic_auth.client_secret),
            ))
        }
        (None, Some(client_secret)) => {
            let client_id = form_client_id
                .ok_or_else(|| TokenExchangeError::invalid_request("missing client_id"))?;
            Ok((client_id, ClientAuth::SecretPost(client_secret)))
        }
        (None, None) => {
            let client_id = form_client_id
                .ok_or_else(|| TokenExchangeError::invalid_request("missing client_id"))?;
            Ok((client_id, ClientAuth::None))
        }
    }
}

fn client_basic_auth_from_header(
    authorization: Option<&str>,
) -> Result<Option<ClientBasicAuth>, TokenExchangeError> {
    let Some(authorization) = authorization else {
        return Ok(None);
    };
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let credentials = parts.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(TokenExchangeError::invalid_client(
            "unsupported client authentication scheme",
        ));
    }
    if credentials.is_empty() {
        return Err(TokenExchangeError::invalid_client(
            "Basic client authentication is missing credentials",
        ));
    }

    let decoded = STANDARD.decode(credentials).map_err(|error| {
        TokenExchangeError::invalid_client(format!("invalid Basic client authentication: {error}"))
    })?;
    let decoded = String::from_utf8(decoded).map_err(|error| {
        TokenExchangeError::invalid_client(format!(
            "Basic client authentication is not UTF-8: {error}"
        ))
    })?;
    let (client_id, client_secret) = decoded.split_once(':').ok_or_else(|| {
        TokenExchangeError::invalid_client(
            "Basic client authentication must contain client_id and client_secret",
        )
    })?;
    let client_id = decode_client_auth_value(client_id)?;
    let client_secret = decode_client_auth_value(client_secret)?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(TokenExchangeError::invalid_client(
            "Basic client authentication must include client_id and client_secret",
        ));
    }

    Ok(Some(ClientBasicAuth {
        client_id,
        client_secret,
    }))
}

fn decode_client_auth_value(value: &str) -> Result<String, TokenExchangeError> {
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .map_err(|error| {
            TokenExchangeError::invalid_client(format!(
                "client authentication value was not percent encoded correctly: {error}"
            ))
        })
}

fn validate_token_exchange_form(form: &TokenExchangeForm) -> Result<(), TokenExchangeError> {
    match form.grant_type.as_str() {
        "authorization_code" => {
            let fields = authorization_code_fields(form)?;
            if let Some(code_verifier) = fields.code_verifier {
                if code_verifier.len() < 43 || code_verifier.len() > 128 {
                    return Err(TokenExchangeError::invalid_request(
                        "code_verifier must be 43 to 128 characters",
                    ));
                }
            }
        }
        "refresh_token" => {
            refresh_token_field(form)?;
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            native_provider_token_fields(form)?;
        }
        _ => {
            return Err(TokenExchangeError::unsupported_grant_type(
                "grant_type must be authorization_code, refresh_token, or token exchange",
            ))
        }
    }

    Ok(())
}

fn validate_token_client_auth(
    registered_client: &RegisteredClient,
    client_id: &str,
    client_auth: &ClientAuth,
) -> Result<(), TokenExchangeError> {
    if registered_client.client.id.0 != client_id {
        return Err(TokenExchangeError::invalid_client(
            "client_id does not match registered client",
        ));
    }

    if !registered_client.client.confidential {
        if matches!(client_auth, ClientAuth::None) {
            return Ok(());
        }

        return Err(TokenExchangeError::invalid_client(
            "public clients must not use client_secret authentication",
        ));
    }

    let Some(client_secret) = client_auth_secret(client_auth) else {
        return Err(TokenExchangeError::invalid_client(
            "confidential clients must authenticate with client_secret",
        ));
    };
    let Some(secret_hash) = registered_client.secret_hash.as_deref() else {
        return Err(TokenExchangeError::invalid_client(
            "confidential client is missing secret_hash",
        ));
    };
    if !client_secret_matches(secret_hash, client_secret) {
        return Err(TokenExchangeError::invalid_client(
            "client_secret did not match registered client",
        ));
    }

    Ok(())
}

fn validate_introspection_client_auth(
    registered_client: &RegisteredClient,
    client_id: &str,
    client_auth: &ClientAuth,
) -> Result<(), TokenExchangeError> {
    if !registered_client.client.confidential {
        return Err(TokenExchangeError::invalid_client(
            "token introspection requires confidential client authentication",
        ));
    }

    validate_token_client_auth(registered_client, client_id, client_auth)
}

fn validate_token_revocation_form(form: &TokenRevocationForm) -> Result<(), TokenExchangeError> {
    if form.token.is_empty() {
        return Err(TokenExchangeError::invalid_request("missing token"));
    }

    match form.token_type_hint.as_deref() {
        None | Some("refresh_token") | Some("access_token") => Ok(()),
        Some(_) => Err(TokenExchangeError::unsupported_token_type(
            "token_type_hint must be refresh_token or access_token",
        )),
    }
}

fn validate_token_introspection_form(
    form: &TokenIntrospectionForm,
) -> Result<(), TokenExchangeError> {
    if form.token.is_empty() {
        return Err(TokenExchangeError::invalid_request("missing token"));
    }

    match form.token_type_hint.as_deref() {
        None | Some("access_token") | Some("refresh_token") => Ok(()),
        Some(_) => Err(TokenExchangeError::unsupported_token_type(
            "token_type_hint must be access_token or refresh_token",
        )),
    }
}

fn should_attempt_refresh_token_revocation(token_type_hint: Option<&str>) -> bool {
    token_type_hint != Some("access_token")
}

fn client_auth_secret(auth: &ClientAuth) -> Option<&str> {
    match auth {
        ClientAuth::None => None,
        ClientAuth::SecretPost(secret) | ClientAuth::SecretBasic(secret) => Some(secret),
    }
}

fn client_secret_matches(secret_hash: &str, client_secret: &str) -> bool {
    let expected_hash = secret_hash
        .strip_prefix("sha256:")
        .unwrap_or(secret_hash)
        .trim();
    if expected_hash.len() != 64 || !expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }

    constant_time_eq(expected_hash, &hash_secret(client_secret))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff = left.len() ^ right.len();
    let len = left.len().max(right.len());
    for index in 0..len {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

fn authorization_code_fields(
    form: &TokenExchangeForm,
) -> Result<AuthorizationCodeFields<'_>, TokenExchangeError> {
    Ok(AuthorizationCodeFields {
        client_id: &form.client_id,
        redirect_uri: required_token_form_value(form.redirect_uri.as_deref(), "redirect_uri")?,
        code: required_token_form_value(form.code.as_deref(), "code")?,
        code_verifier: form.code_verifier.as_deref(),
    })
}

fn native_provider_token_fields(
    form: &TokenExchangeForm,
) -> Result<NativeProviderTokenFields<'_>, TokenExchangeError> {
    let provider_id = form.provider.as_deref().unwrap_or(well_known::APPLE);
    if !is_native_token_exchange_provider(provider_id) {
        return Err(TokenExchangeError::invalid_request(
            "token exchange provider must be apple, google, or spotify",
        ));
    }
    let subject_token_type = match (provider_id, form.subject_token_type.as_deref()) {
        (well_known::APPLE | well_known::GOOGLE, Some(ID_TOKEN_SUBJECT_TOKEN_TYPE) | None) => {
            ID_TOKEN_SUBJECT_TOKEN_TYPE
        }
        (well_known::APPLE | well_known::GOOGLE, Some(_)) => {
            return Err(TokenExchangeError::invalid_request(
                "subject_token_type must be urn:ietf:params:oauth:token-type:id_token",
            ))
        }
        (well_known::SPOTIFY, Some(ACCESS_TOKEN_SUBJECT_TOKEN_TYPE)) => {
            ACCESS_TOKEN_SUBJECT_TOKEN_TYPE
        }
        (well_known::SPOTIFY, _) => {
            return Err(TokenExchangeError::invalid_request(
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token",
            ))
        }
        _ => unreachable!("native provider was checked above"),
    };
    Ok(NativeProviderTokenFields {
        provider_id,
        scope: form.scope.as_deref(),
        subject_token: required_token_form_value(form.subject_token.as_deref(), "subject_token")?,
        subject_token_type,
        provider_client_id: form.provider_client_id.as_deref(),
        nonce: form.nonce.as_deref(),
    })
}

fn is_native_token_exchange_provider(provider_id: &str) -> bool {
    matches!(
        provider_id,
        well_known::APPLE | well_known::GOOGLE | well_known::SPOTIFY
    )
}

fn refresh_token_field(form: &TokenExchangeForm) -> Result<&str, TokenExchangeError> {
    required_token_form_value(form.refresh_token.as_deref(), "refresh_token")
}

fn required_token_form_value<'a>(
    value: Option<&'a str>,
    name: &str,
) -> Result<&'a str, TokenExchangeError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenExchangeError::invalid_request(format!("missing {name}")))
}

fn validate_refresh_token_exchange(
    row: &RefreshTokenRow,
    client_id: &str,
    now: i32,
) -> Result<(), TokenExchangeError> {
    if row.client_id != client_id {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token client_id does not match",
        ));
    }

    if row.revoked_at.is_some() {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token has been revoked",
        ));
    }

    if row.rotated_at.is_some() {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token has already been rotated",
        ));
    }

    if row.expires_at <= now {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token has expired",
        ));
    }

    Ok(())
}

fn refresh_token_replay_detected(row: &RefreshTokenRow, client_id: &str) -> bool {
    row.client_id == client_id && row.rotated_at.is_some() && row.revoked_at.is_none()
}

fn validate_authorization_code_exchange(
    code: &AuthCodeRow,
    form: &AuthorizationCodeFields<'_>,
    now: i32,
) -> Result<(), TokenExchangeError> {
    if code.consumed_at.is_some() {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code has already been consumed",
        ));
    }

    if code.expires_at <= now {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code has expired",
        ));
    }

    if code.client_id != form.client_id {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code client_id does not match",
        ));
    }

    if code.redirect_uri != form.redirect_uri {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code redirect_uri does not match",
        ));
    }

    match code.code_challenge_method.as_deref() {
        Some("S256") => {
            let Some(code_challenge) = &code.code_challenge else {
                return Err(TokenExchangeError::invalid_grant(
                    "authorization code is missing PKCE challenge",
                ));
            };
            let Some(code_verifier) = form.code_verifier else {
                return Err(TokenExchangeError::invalid_grant(
                    "code_verifier is required for this authorization code",
                ));
            };

            if pkce_s256_challenge(code_verifier) != *code_challenge {
                return Err(TokenExchangeError::invalid_grant(
                    "code_verifier did not match code_challenge",
                ));
            }
        }
        Some(_) => {
            return Err(TokenExchangeError::invalid_grant(
                "authorization code used unsupported PKCE method",
            ))
        }
        None => {
            if code.code_challenge.is_some() {
                return Err(TokenExchangeError::invalid_grant(
                    "authorization code used unsupported PKCE method",
                ));
            }
        }
    }

    Ok(())
}

fn token_response(
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    issue: &TokenIssue,
    refresh_token: Option<String>,
    now: i32,
) -> Result<TokenResponse, String> {
    let access_claims = JwtClaims {
        iss: config.issuer().issuer.clone(),
        sub: issue.user_id.clone(),
        aud: issue.client_id.clone(),
        exp: now + ACCESS_TOKEN_TTL_SECONDS,
        iat: now,
        auth_time: None,
        sid: issue.session_id.clone(),
        nonce: None,
        scope: Some(issue.scope.clone()),
        client_id: Some(issue.client_id.clone()),
        token_use: "access".to_owned(),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        roles: issue.roles.clone(),
    };
    let id_claims = JwtClaims {
        iss: config.issuer().issuer,
        sub: issue.user_id.clone(),
        aud: issue.client_id.clone(),
        exp: now + ID_TOKEN_TTL_SECONDS,
        iat: now,
        auth_time: issue.auth_time,
        sid: issue.session_id.clone(),
        nonce: issue.nonce.clone(),
        scope: None,
        client_id: None,
        token_use: "id".to_owned(),
        email: issue.email.clone(),
        email_verified: issue.email_verified,
        name: issue.name.clone(),
        picture: issue.picture.clone(),
        roles: issue.roles.clone(),
    };

    Ok(TokenResponse {
        access_token: sign_jwt(signing_key, &access_claims)?,
        id_token: sign_jwt(signing_key, &id_claims)?,
        refresh_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        scope: issue.scope.clone(),
    })
}

fn verify_zeroth_access_token(
    token: &str,
    config: &ZerothServerConfig,
    jwks: &JwksResponse,
    now: i32,
) -> Result<JwtClaims, String> {
    let claims = zeroth_oidc::verify_zeroth_token(
        token,
        &zeroth_jwks_from_response(jwks),
        &ZerothTokenValidation::issuer_token(
            config.issuer().issuer,
            ZerothTokenUse::Access,
            now as i64,
        ),
    )
    .map_err(|error| zeroth_token_error_description(error, Some("access")))?;
    jwt_claims_from_zeroth(claims)
}

fn verify_zeroth_id_token_hint(
    token: &str,
    config: &ZerothServerConfig,
    jwks: &JwksResponse,
    now: i32,
) -> Result<JwtClaims, String> {
    let claims = zeroth_oidc::verify_zeroth_token(
        token,
        &zeroth_jwks_from_response(jwks),
        &ZerothTokenValidation::issuer_token(
            config.issuer().issuer,
            ZerothTokenUse::Id,
            now as i64,
        ),
    )
    .map_err(|error| zeroth_token_error_description(error, Some("id")))?;
    jwt_claims_from_zeroth(claims)
}

fn zeroth_jwks_from_response(jwks: &JwksResponse) -> ZerothJwks {
    ZerothJwks {
        keys: jwks
            .keys
            .iter()
            .map(|key| ZerothJwk {
                kty: key.kty.clone(),
                key_use: key.key_use.clone(),
                kid: key.kid.clone(),
                alg: key.alg.clone(),
                crv: key.crv.clone(),
                x: key.x.clone(),
                y: key.y.clone(),
            })
            .collect(),
    }
}

fn jwt_claims_from_zeroth(claims: ZerothJwtClaims) -> Result<JwtClaims, String> {
    Ok(JwtClaims {
        iss: claims.iss,
        sub: claims.sub,
        aud: claims.aud,
        exp: jwt_i32_claim(claims.exp, "exp")?,
        iat: jwt_i32_claim(claims.iat, "iat")?,
        auth_time: claims
            .auth_time
            .map(|value| jwt_i32_claim(value, "auth_time"))
            .transpose()?,
        sid: claims.sid,
        nonce: claims.nonce,
        scope: claims.scope,
        client_id: claims.client_id,
        token_use: claims.token_use,
        email: claims.email,
        email_verified: claims.email_verified,
        name: claims.name,
        picture: claims.picture,
        roles: claims.roles,
    })
}

fn jwt_i32_claim(value: i64, name: &str) -> Result<i32, String> {
    i32::try_from(value).map_err(|_| format!("JWT {name} claim is outside supported range"))
}

fn zeroth_token_error_description(
    error: zeroth_oidc::ZerothTokenError,
    token_use: Option<&str>,
) -> String {
    match (token_use, error.description.as_str()) {
        (Some("access"), "JWT token_use was not access") => {
            "token is not an access token".to_owned()
        }
        (Some("id"), "JWT token_use was not id") => "id_token_hint is not an ID token".to_owned(),
        _ => error.description,
    }
}

#[cfg(target_arch = "wasm32")]
async fn introspection_response_for_token(
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    jwks: &JwksResponse,
    form: &TokenIntrospectionForm,
    now: i32,
) -> worker::Result<TokenIntrospectionResponse> {
    if form.token_type_hint.as_deref() != Some("refresh_token") {
        if let Ok(claims) = verify_zeroth_access_token(&form.token, config, jwks, now) {
            return introspection_response_for_access_token_claims(db, &claims, now).await;
        }
    }

    if form.token_type_hint.as_deref() != Some("access_token") {
        if let Some(refresh_token) = get_refresh_token(db, &form.token).await? {
            return introspection_response_for_refresh_token_row(
                db,
                &refresh_token,
                &form.client_id,
                now,
            )
            .await;
        }
    }

    Ok(TokenIntrospectionResponse::inactive())
}

#[cfg(target_arch = "wasm32")]
async fn introspection_response_for_access_token_claims(
    db: &worker::d1::D1Database,
    claims: &JwtClaims,
    now: i32,
) -> worker::Result<TokenIntrospectionResponse> {
    let Some(user) = get_user(db, &claims.sub).await? else {
        return Ok(TokenIntrospectionResponse::inactive());
    };
    if user.disabled_at.is_some() {
        return Ok(TokenIntrospectionResponse::inactive());
    }
    if validate_access_token_session(db, claims, now)
        .await?
        .is_err()
    {
        return Ok(TokenIntrospectionResponse::inactive());
    }
    if active_client_allowed_origins(db, &claims.aud)
        .await?
        .is_err()
    {
        return Ok(TokenIntrospectionResponse::inactive());
    }

    Ok(TokenIntrospectionResponse::active_access_token(claims))
}

#[cfg(target_arch = "wasm32")]
async fn introspection_response_for_refresh_token_row(
    db: &worker::d1::D1Database,
    row: &RefreshTokenRow,
    client_id: &str,
    now: i32,
) -> worker::Result<TokenIntrospectionResponse> {
    if validate_refresh_token_exchange(row, client_id, now).is_err() {
        return Ok(TokenIntrospectionResponse::inactive());
    }
    let Some(user) = get_user(db, &row.user_id).await? else {
        return Ok(TokenIntrospectionResponse::inactive());
    };
    if user.disabled_at.is_some() {
        return Ok(TokenIntrospectionResponse::inactive());
    }

    Ok(TokenIntrospectionResponse::active_refresh_token(row))
}

fn profile_patch_from_value(value: serde_json::Value) -> Result<ProfilePatch, ProfilePatchError> {
    let Some(object) = value.as_object() else {
        return Err(ProfilePatchError::invalid_request(
            "profile patch JSON must be an object",
        ));
    };

    let mut patch = ProfilePatch {
        display_name: None,
        picture_url: None,
    };

    for (key, value) in object {
        match key.as_str() {
            "name" | "displayName" => {
                if patch.display_name.is_some() {
                    return Err(ProfilePatchError::invalid_request(
                        "profile patch included duplicate name fields",
                    ));
                }
                patch.display_name = Some(profile_patch_optional_string(
                    value,
                    "name",
                    PROFILE_NAME_MAX_CHARS,
                    ProfilePatchStringKind::DisplayName,
                )?);
            }
            "picture" | "pictureUrl" => {
                if patch.picture_url.is_some() {
                    return Err(ProfilePatchError::invalid_request(
                        "profile patch included duplicate picture fields",
                    ));
                }
                patch.picture_url = Some(profile_patch_optional_string(
                    value,
                    "picture",
                    PROFILE_PICTURE_MAX_BYTES,
                    ProfilePatchStringKind::PictureUrl,
                )?);
            }
            _ => {
                return Err(ProfilePatchError::invalid_request(format!(
                    "unsupported profile patch field: {key}"
                )));
            }
        }
    }

    if patch.display_name.is_none() && patch.picture_url.is_none() {
        return Err(ProfilePatchError::invalid_request(
            "profile patch must include name or picture",
        ));
    }

    Ok(patch)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProfilePatchStringKind {
    DisplayName,
    PictureUrl,
}

fn profile_patch_optional_string(
    value: &serde_json::Value,
    field_name: &str,
    max: usize,
    kind: ProfilePatchStringKind,
) -> Result<Option<String>, ProfilePatchError> {
    if value.is_null() {
        return Ok(None);
    }
    let Some(raw) = value.as_str() else {
        return Err(ProfilePatchError::invalid_request(format!(
            "{field_name} must be a string or null"
        )));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProfilePatchError::invalid_request(format!(
            "{field_name} must not be empty"
        )));
    }

    match kind {
        ProfilePatchStringKind::DisplayName => {
            if trimmed.chars().count() > max {
                return Err(ProfilePatchError::invalid_request(format!(
                    "{field_name} must be at most {max} characters"
                )));
            }
        }
        ProfilePatchStringKind::PictureUrl => {
            if trimmed.len() > max {
                return Err(ProfilePatchError::invalid_request(format!(
                    "{field_name} must be at most {max} bytes"
                )));
            }
            let url = url::Url::parse(trimmed).map_err(|_| {
                ProfilePatchError::invalid_request(format!("{field_name} must be an absolute URL"))
            })?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ProfilePatchError::invalid_request(
                    "picture must use http or https",
                ));
            }
        }
    }

    Ok(Some(trimmed.to_owned()))
}

fn client_upsert_from_value(
    value: serde_json::Value,
) -> Result<ValidatedClientUpsert, ClientManagementError> {
    let request = serde_json::from_value::<ClientUpsertRequest>(value).map_err(|error| {
        ClientManagementError::invalid_request(format!("invalid client JSON: {error}"))
    })?;
    validate_client_upsert_request(request)
}

fn validate_client_upsert_request(
    request: ClientUpsertRequest,
) -> Result<ValidatedClientUpsert, ClientManagementError> {
    let id = validate_client_id(&request.id)?;
    let name = validate_client_name(&request.name)?;
    let redirect_uris = validate_redirect_uris(&request.redirect_uris)?;
    let allowed_origins = validate_allowed_origins(&request.allowed_origins)?;
    let allowed_email_domains = validate_allowed_email_domains(&request.allowed_email_domains)?;
    let visible_login_methods = validate_visible_login_methods(&request.visible_login_methods)?;
    let issuer_token_audience =
        validate_issuer_token_audience(request.issuer_token_audience.as_deref())?;
    let issuer_token_ttl_seconds = validate_issuer_token_ttl_seconds(
        request.issuer_token_ttl_seconds,
        issuer_token_audience.as_deref(),
    )?;
    let account_sharing_mode =
        validate_account_sharing_mode(request.account_sharing_mode.as_deref())?;
    let account_tenant_id = validate_account_tenant_id(
        request.account_tenant_id.as_deref(),
        account_sharing_mode,
        &id,
    )?;
    let secret_hash = validated_client_secret_hash(
        request.confidential,
        request.client_secret.as_deref(),
        request.secret_hash.as_deref(),
    )?;

    Ok(ValidatedClientUpsert {
        id,
        name,
        redirect_uris,
        allowed_origins,
        allowed_email_domains,
        issuer_token_audience,
        issuer_token_ttl_seconds,
        account_sharing_mode,
        account_tenant_id,
        visible_login_methods,
        confidential: request.confidential,
        secret_hash,
        disabled: request.disabled,
    })
}

fn validate_client_id(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request("missing client id"));
    }
    if value.chars().count() > CLIENT_ID_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "client id must be at most {CLIENT_ID_MAX_CHARS} characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ClientManagementError::invalid_request(
            "client id contains unsupported characters",
        ));
    }
    Ok(value.to_owned())
}

fn validate_admin_user_id(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request("missing user id"));
    }
    if value.chars().count() > USER_ID_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "user id must be at most {USER_ID_MAX_CHARS} characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ClientManagementError::invalid_request(
            "user id contains unsupported characters",
        ));
    }
    Ok(value.to_owned())
}

fn validate_audit_event_type(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request("missing event_type"));
    }
    if value.chars().count() > AUDIT_EVENT_TYPE_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "event_type must be at most {AUDIT_EVENT_TYPE_MAX_CHARS} characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ClientManagementError::invalid_request(
            "event_type contains unsupported characters",
        ));
    }
    Ok(value.to_owned())
}

fn audit_event_filter_from_url(url: &url::Url) -> Result<AuditEventFilter, ClientManagementError> {
    let event_type = query_param(url, "event_type")
        .map(|value| validate_audit_event_type(&value))
        .transpose()?;
    let user_id = query_param(url, "user_id")
        .map(|value| validate_admin_user_id(&value))
        .transpose()?;
    let client_id = query_param(url, "client_id")
        .map(|value| validate_client_id(&value))
        .transpose()?;
    let provider_id = query_param(url, "provider_id")
        .map(|value| {
            validate_identity_provider_id(&value)
                .map_err(ClientManagementError::invalid_request)?;
            Ok::<_, ClientManagementError>(value)
        })
        .transpose()?;

    Ok(AuditEventFilter {
        event_type,
        user_id,
        client_id,
        provider_id,
    })
}

fn validate_client_name(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request(
            "missing client name",
        ));
    }
    if value.chars().count() > CLIENT_NAME_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "client name must be at most {CLIENT_NAME_MAX_CHARS} characters"
        )));
    }
    Ok(value.to_owned())
}

fn validate_redirect_uris(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.is_empty() {
        return Err(ClientManagementError::invalid_request(
            "client requires at least one redirect URI",
        ));
    }
    if raw.len() > CLIENT_URI_LIST_LIMIT {
        return Err(ClientManagementError::invalid_request(format!(
            "client can register at most {CLIENT_URI_LIST_LIMIT} redirect URIs"
        )));
    }

    let mut uris = Vec::with_capacity(raw.len());
    for raw_uri in raw {
        let uri = raw_uri.trim();
        if uri.is_empty() {
            return Err(ClientManagementError::invalid_request(
                "redirect URI must not be empty",
            ));
        }
        if uri.len() > CLIENT_URI_MAX_BYTES {
            return Err(ClientManagementError::invalid_request(format!(
                "redirect URI must be at most {CLIENT_URI_MAX_BYTES} bytes"
            )));
        }
        let parsed = url::Url::parse(uri).map_err(|error| {
            ClientManagementError::invalid_request(format!("invalid redirect URI: {error}"))
        })?;
        if parsed.scheme().is_empty() {
            return Err(ClientManagementError::invalid_request(
                "redirect URI must be absolute",
            ));
        }
        if parsed.fragment().is_some() {
            return Err(ClientManagementError::invalid_request(
                "redirect URI must not include a fragment",
            ));
        }
        push_unique(&mut uris, uri.to_owned());
    }
    Ok(uris)
}

fn validate_allowed_origins(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.len() > CLIENT_URI_LIST_LIMIT {
        return Err(ClientManagementError::invalid_request(format!(
            "client can register at most {CLIENT_URI_LIST_LIMIT} allowed origins"
        )));
    }

    let mut origins = Vec::with_capacity(raw.len());
    for raw_origin in raw {
        let origin = raw_origin.trim();
        if origin.is_empty() {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must not be empty",
            ));
        }
        if origin.len() > CLIENT_URI_MAX_BYTES {
            return Err(ClientManagementError::invalid_request(format!(
                "allowed origin must be at most {CLIENT_URI_MAX_BYTES} bytes"
            )));
        }
        let parsed = url::Url::parse(origin).map_err(|error| {
            ClientManagementError::invalid_request(format!("invalid allowed origin: {error}"))
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must use http or https",
            ));
        }
        if parsed.username() != "" || parsed.password().is_some() {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must not include credentials",
            ));
        }
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must not include a path, query, or fragment",
            ));
        }
        push_unique(&mut origins, parsed.origin().ascii_serialization());
    }
    Ok(origins)
}

fn validate_allowed_email_domains(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.len() > CLIENT_URI_LIST_LIMIT {
        return Err(ClientManagementError::invalid_request(format!(
            "client can register at most {CLIENT_URI_LIST_LIMIT} allowed email domains"
        )));
    }

    let mut domains = Vec::with_capacity(raw.len());
    for raw_domain in raw {
        push_unique(&mut domains, normalize_allowed_email_domain(raw_domain)?);
    }
    Ok(domains)
}

fn validate_visible_login_methods(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.len() > 8 {
        return Err(ClientManagementError::invalid_request(
            "client can register at most 8 visible login methods",
        ));
    }

    let mut methods = Vec::with_capacity(raw.len());
    for raw_method in raw {
        let method = normalize_visible_login_method(raw_method)?;
        push_unique(&mut methods, method);
    }
    Ok(methods)
}

fn validate_issuer_token_audience(
    raw: Option<&str>,
) -> Result<Option<String>, ClientManagementError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > 256 {
        return Err(ClientManagementError::invalid_request(
            "issuerTokenAudience must be at most 256 characters",
        ));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(ClientManagementError::invalid_request(
            "issuerTokenAudience contains unsupported characters",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn validate_issuer_token_ttl_seconds(
    raw: Option<i32>,
    issuer_token_audience: Option<&str>,
) -> Result<Option<i32>, ClientManagementError> {
    let Some(ttl_seconds) = raw else {
        return Ok(None);
    };
    if issuer_token_audience.is_none() {
        return Err(ClientManagementError::invalid_request(
            "issuerTokenTtlSeconds requires issuerTokenAudience",
        ));
    }
    if !(60..=600).contains(&ttl_seconds) {
        return Err(ClientManagementError::invalid_request(
            "issuerTokenTtlSeconds must be between 60 and 600",
        ));
    }
    Ok(Some(ttl_seconds))
}

fn normalize_visible_login_method(raw: &str) -> Result<String, ClientManagementError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        LOGIN_METHOD_PASSKEY => Ok(LOGIN_METHOD_PASSKEY.to_owned()),
        LOGIN_METHOD_MAGIC_LINK | "magic-link" | "magiclink" => {
            Ok(LOGIN_METHOD_MAGIC_LINK.to_owned())
        }
        value if value.is_empty() => Err(ClientManagementError::invalid_request(
            "visible login method must not be empty",
        )),
        value => Err(ClientManagementError::invalid_request(format!(
            "unsupported visible login method: {value}"
        ))),
    }
}

fn validate_account_sharing_mode(
    raw: Option<&str>,
) -> Result<AccountSharingMode, ClientManagementError> {
    let value = raw.map(str::trim).filter(|value| !value.is_empty());
    match value.unwrap_or(ACCOUNT_SHARING_MODE_GLOBAL) {
        ACCOUNT_SHARING_MODE_GLOBAL => Ok(AccountSharingMode::Global),
        ACCOUNT_SHARING_MODE_TENANT => Ok(AccountSharingMode::Tenant),
        ACCOUNT_SHARING_MODE_CLIENT => Ok(AccountSharingMode::Client),
        _ => Err(ClientManagementError::invalid_request(
            "accountSharingMode must be global, tenant, or client",
        )),
    }
}

fn validate_account_tenant_id(
    raw: Option<&str>,
    sharing_mode: AccountSharingMode,
    client_id: &str,
) -> Result<String, ClientManagementError> {
    match sharing_mode {
        AccountSharingMode::Global => Ok(ACCOUNT_NAMESPACE_GLOBAL.to_owned()),
        AccountSharingMode::Client => Ok(client_id.to_owned()),
        AccountSharingMode::Tenant => {
            let value = raw
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ClientManagementError::invalid_request(
                        "accountTenantId is required when accountSharingMode is tenant",
                    )
                })?;
            validate_account_tenant_id_value(value).map_err(ClientManagementError::invalid_request)
        }
    }
}

fn validate_account_tenant_id_value(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("account tenant id must not be empty".to_owned());
    }
    if value.chars().count() > CLIENT_ACCOUNT_TENANT_ID_MAX_CHARS {
        return Err(format!(
            "account tenant id must be at most {CLIENT_ACCOUNT_TENANT_ID_MAX_CHARS} characters"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err("account tenant id contains unsupported characters".to_owned());
    }
    Ok(value.to_owned())
}

fn account_sharing_mode_label(mode: AccountSharingMode) -> &'static str {
    match mode {
        AccountSharingMode::Global => ACCOUNT_SHARING_MODE_GLOBAL,
        AccountSharingMode::Tenant => ACCOUNT_SHARING_MODE_TENANT,
        AccountSharingMode::Client => ACCOUNT_SHARING_MODE_CLIENT,
    }
}

fn account_namespace_for_parts(
    sharing_mode: AccountSharingMode,
    tenant_id: &str,
    client_id: &str,
) -> String {
    match sharing_mode {
        AccountSharingMode::Global => ACCOUNT_NAMESPACE_GLOBAL.to_owned(),
        AccountSharingMode::Tenant => format!("tenant:{tenant_id}"),
        AccountSharingMode::Client => format!("client:{client_id}"),
    }
}

fn client_account_scope_from_values(
    client_id: &str,
    sharing_mode: AccountSharingMode,
    tenant_id: String,
) -> ClientAccountScope {
    let namespace = account_namespace_for_parts(sharing_mode, &tenant_id, client_id);
    ClientAccountScope {
        sharing_mode,
        tenant_id,
        namespace,
    }
}

fn client_account_scope_from_row(row: &ClientRow) -> Result<ClientAccountScope, String> {
    let sharing_mode = account_sharing_mode_from_row(row)?;
    let tenant_id = match sharing_mode {
        AccountSharingMode::Global => ACCOUNT_NAMESPACE_GLOBAL.to_owned(),
        AccountSharingMode::Client => row.id.clone(),
        AccountSharingMode::Tenant => validate_account_tenant_id_value(
            row.account_tenant_id
                .as_deref()
                .unwrap_or(ACCOUNT_NAMESPACE_GLOBAL),
        )?,
    };
    Ok(client_account_scope_from_values(
        &row.id,
        sharing_mode,
        tenant_id,
    ))
}

fn account_sharing_mode_from_row(row: &ClientRow) -> Result<AccountSharingMode, String> {
    match row
        .account_sharing_mode
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(ACCOUNT_SHARING_MODE_GLOBAL)
    {
        ACCOUNT_SHARING_MODE_GLOBAL => Ok(AccountSharingMode::Global),
        ACCOUNT_SHARING_MODE_TENANT => Ok(AccountSharingMode::Tenant),
        ACCOUNT_SHARING_MODE_CLIENT => Ok(AccountSharingMode::Client),
        value => Err(format!(
            "client account_sharing_mode is unsupported: {value}"
        )),
    }
}

fn normalize_allowed_email_domain(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim().strip_prefix('@').unwrap_or_else(|| raw.trim());
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must not be empty",
        ));
    }
    if value.len() > CLIENT_EMAIL_DOMAIN_MAX_BYTES {
        return Err(ClientManagementError::invalid_request(format!(
            "allowed email domain must be at most {CLIENT_EMAIL_DOMAIN_MAX_BYTES} bytes"
        )));
    }
    if !value.is_ascii() {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must use ASCII",
        ));
    }
    if !value.contains('.') {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must include a dot",
        ));
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must not start or end with a dot",
        ));
    }
    for label in value.split('.') {
        if label.is_empty() {
            return Err(ClientManagementError::invalid_request(
                "allowed email domain must not contain empty labels",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ClientManagementError::invalid_request(
                "allowed email domain labels must not start or end with a hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ClientManagementError::invalid_request(
                "allowed email domain contains unsupported characters",
            ));
        }
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_client_email_domain_policy(
    client: &Client,
    profile: &ProviderProfile,
) -> Result<(), ProviderCallbackError> {
    if client.allowed_email_domains.is_empty() {
        return Ok(());
    }
    if !profile.email_verified {
        return Err(ProviderCallbackError::access_denied(
            "verified email is required for this client",
        ));
    }

    let email_domain = provider_profile_email_domain(profile)?;
    if client
        .allowed_email_domains
        .iter()
        .any(|allowed_domain| allowed_domain.eq_ignore_ascii_case(&email_domain))
    {
        return Ok(());
    }

    Err(ProviderCallbackError::access_denied(
        "email domain is not allowed for this client",
    ))
}

fn provider_profile_email_domain(
    profile: &ProviderProfile,
) -> Result<String, ProviderCallbackError> {
    let email = profile
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or_else(|| ProviderCallbackError::access_denied("email is required for this client"))?;
    let (_, domain) = email.rsplit_once('@').ok_or_else(|| {
        ProviderCallbackError::access_denied("email domain is required for this client")
    })?;
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(ProviderCallbackError::access_denied(
            "email domain is required for this client",
        ));
    }
    Ok(domain.to_ascii_lowercase())
}

fn native_token_scope(scope: Option<&str>) -> Result<String, TokenExchangeError> {
    let raw = scope.unwrap_or(DEFAULT_NATIVE_TOKEN_SCOPE);
    let mut scopes = Vec::new();
    for scope in raw.split_whitespace() {
        if scope.len() > 64
            || !scope.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(TokenExchangeError::invalid_request(
                "scope contains unsupported characters",
            ));
        }
        push_unique(&mut scopes, scope.to_owned());
    }
    if scopes.is_empty() {
        return Err(TokenExchangeError::invalid_request(
            "scope must not be empty",
        ));
    }
    if !scopes.iter().any(|scope| scope == "openid") {
        return Err(TokenExchangeError::invalid_request(
            "scope must include openid",
        ));
    }
    Ok(scopes.join(" "))
}

#[cfg(target_arch = "wasm32")]
fn native_provider_client_id(
    env: &Env,
    provider_id: &str,
    requested_client_id: Option<&str>,
) -> Result<String, TokenExchangeError> {
    let configured = native_provider_client_ids_from_env(env, provider_id);
    native_provider_client_id_from_list(provider_id, &configured, requested_client_id)
}

#[cfg(target_arch = "wasm32")]
fn native_provider_client_ids_from_env(env: &Env, provider_id: &str) -> Vec<String> {
    let (native_binding, fallback_binding) = match provider_id {
        well_known::APPLE => ("APPLE_NATIVE_CLIENT_IDS", "APPLE_BUNDLE_ID"),
        well_known::GOOGLE => ("GOOGLE_NATIVE_CLIENT_IDS", "GOOGLE_CLIENT_ID"),
        well_known::SPOTIFY => ("SPOTIFY_NATIVE_CLIENT_IDS", "SPOTIFY_CLIENT_ID"),
        _ => return Vec::new(),
    };
    binding_value_from_env(env, native_binding)
        .filter(|value| config_value_configured(Some(value)))
        .or_else(|| provider_client_id_from_env(env, fallback_binding))
        .map(|value| split_token_list(&value))
        .unwrap_or_default()
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn native_apple_provider_client_id_from_list(
    configured: &[String],
    requested_client_id: Option<&str>,
) -> Result<String, TokenExchangeError> {
    native_provider_client_id_from_list(well_known::APPLE, configured, requested_client_id)
}

fn native_provider_client_id_from_list(
    provider_id: &str,
    configured: &[String],
    requested_client_id: Option<&str>,
) -> Result<String, TokenExchangeError> {
    if configured.is_empty() {
        return Err(TokenExchangeError::invalid_request(format!(
            "{} is not configured",
            native_provider_client_ids_binding(provider_id)
        )));
    }
    if let Some(requested_client_id) = requested_client_id {
        if token_list_slice_contains(configured, requested_client_id, false) {
            return Ok(requested_client_id.to_owned());
        }
        return Err(TokenExchangeError::invalid_request(
            "provider_client_id is not allowed",
        ));
    }
    if configured.len() == 1 {
        return Ok(configured[0].clone());
    }
    Err(TokenExchangeError::invalid_request(format!(
        "provider_client_id is required when multiple {} native client IDs are configured",
        provider_label(provider_id)
    )))
}

fn native_provider_client_ids_binding(provider_id: &str) -> &'static str {
    match provider_id {
        well_known::APPLE => "APPLE_NATIVE_CLIENT_IDS",
        well_known::GOOGLE => "GOOGLE_NATIVE_CLIENT_IDS",
        well_known::SPOTIFY => "SPOTIFY_NATIVE_CLIENT_IDS",
        _ => "PROVIDER_NATIVE_CLIENT_IDS",
    }
}

fn provider_label(provider_id: &str) -> &'static str {
    match provider_id {
        well_known::APPLE => "Apple",
        well_known::GOOGLE => "Google",
        well_known::SPOTIFY => "Spotify",
        _ => "provider",
    }
}

fn split_token_list(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    for token in value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        push_unique(&mut values, token.to_owned());
    }
    values
}

fn token_list_slice_contains(
    values: &[String],
    needle: &str,
    ascii_case_insensitive: bool,
) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    values.iter().any(|value| {
        if ascii_case_insensitive {
            value.eq_ignore_ascii_case(needle)
        } else {
            value == needle
        }
    })
}

fn native_oidc_profile_from_verified_token(
    provider_id: &str,
    verified: VerifiedProviderIdToken,
) -> ResolvedProviderProfile {
    let claims = verified.claims;
    ResolvedProviderProfile {
        profile: ProviderProfile {
            provider_id: ProviderId(provider_id.to_owned()),
            subject: Subject(claims.sub),
            email: claims.email,
            email_verified: boolish_claim(claims.email_verified.as_ref()).unwrap_or(false),
            display_name: claims.name,
            picture_url: claims.picture,
        },
        raw_profile_json: Some(verified.raw_claims_json),
    }
}

fn validated_client_secret_hash(
    confidential: bool,
    client_secret: Option<&str>,
    secret_hash: Option<&str>,
) -> Result<Option<String>, ClientManagementError> {
    if client_secret.is_some() && secret_hash.is_some() {
        return Err(ClientManagementError::invalid_request(
            "clientSecret and secretHash are mutually exclusive",
        ));
    }

    if !confidential {
        if client_secret.is_some() || secret_hash.is_some() {
            return Err(ClientManagementError::invalid_request(
                "public clients must not include clientSecret or secretHash",
            ));
        }
        return Ok(None);
    }

    if let Some(client_secret) = client_secret {
        let client_secret = client_secret.trim();
        if client_secret.len() < 16 {
            return Err(ClientManagementError::invalid_request(
                "clientSecret must be at least 16 bytes",
            ));
        }
        if client_secret.len() > 4096 {
            return Err(ClientManagementError::invalid_request(
                "clientSecret must be at most 4096 bytes",
            ));
        }
        return Ok(Some(format!("sha256:{}", hash_secret(client_secret))));
    }

    secret_hash
        .map(|value| normalize_sha256_secret_hash(value, "secretHash"))
        .transpose()
}

fn normalize_sha256_secret_hash(
    value: &str,
    field_name: &str,
) -> Result<String, ClientManagementError> {
    let hash = value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| value.trim());
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ClientManagementError::invalid_request(format!(
            "{field_name} must be a sha256 hex digest"
        )));
    }
    Ok(format!("sha256:{}", hash.to_ascii_lowercase()))
}

fn admin_token_matches_config(presented_token: &str, configured_hash: &str) -> bool {
    let Ok(expected_hash) = normalize_admin_token_hash(configured_hash) else {
        return false;
    };
    constant_time_eq(&expected_hash, &hash_secret(presented_token.trim()))
}

fn normalize_admin_token_hash(value: &str) -> Result<String, String> {
    let hash = value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| value.trim());
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ADMIN_TOKEN_SHA256 must be a sha256 hex digest".to_owned());
    }
    Ok(hash.to_ascii_lowercase())
}

fn client_response_from_row(row: ClientRow) -> Result<ClientResponse, String> {
    let account_scope = client_account_scope_from_row(&row)?;
    let visible_login_methods = client_visible_login_methods_from_row(&row)?;
    Ok(ClientResponse {
        id: row.id,
        name: row.name,
        redirect_uris: parse_string_array_json(&row.redirect_uris_json, "redirect_uris_json")?,
        allowed_origins: parse_string_array_json(
            &row.allowed_origins_json,
            "allowed_origins_json",
        )?,
        allowed_email_domains: parse_string_array_json(
            &row.allowed_email_domains_json,
            "allowed_email_domains_json",
        )?,
        issuer_token_audience: row.issuer_token_audience,
        issuer_token_ttl_seconds: row.issuer_token_ttl_seconds,
        account_sharing_mode: account_sharing_mode_label(account_scope.sharing_mode).to_owned(),
        account_tenant_id: account_scope.tenant_id,
        account_namespace: account_scope.namespace,
        visible_login_methods,
        confidential: row.confidential != 0,
        disabled: row.disabled_at.is_some(),
        has_secret: row
            .secret_hash
            .as_deref()
            .is_some_and(|secret_hash| !secret_hash.trim().is_empty()),
    })
}

fn admin_user_response_from_row(row: AdminUserRow) -> AdminUserResponse {
    AdminUserResponse {
        id: row.id,
        email: row.primary_email,
        display_name: row.display_name,
        picture_url: row.picture_url,
        created_at: row.created_at,
        updated_at: row.updated_at,
        disabled: row.disabled_at.is_some(),
        admin: row.admin_membership_active != 0,
        identity_count: row.identity_count,
        active_session_count: row.active_session_count,
    }
}

fn audit_event_response_from_row(row: AuditEventRow) -> AuditEventResponse {
    let details = serde_json::from_str(&row.details_json)
        .unwrap_or_else(|_| serde_json::json!({ "invalidDetailsJson": true }));
    AuditEventResponse {
        id: row.id,
        event_type: row.event_type,
        user_id: row.user_id,
        client_id: row.client_id,
        provider_id: row.provider_id,
        created_at: row.created_at,
        ip_hash: row.ip_hash,
        user_agent: row.user_agent,
        details,
    }
}

fn audit_event_admin_ui_from_row(row: AuditEventRow) -> EventAdminUi {
    EventAdminUi {
        event_id: row.id,
        event_type: row.event_type,
        user_id: row.user_id,
        client_id: row.client_id,
        provider_id: row.provider_id,
        created_at: Some(row.created_at.to_string()),
        details: Some(row.details_json),
    }
}

fn audit_details_json(details: serde_json::Value) -> Result<String, String> {
    let json = serde_json::to_string(&details)
        .map_err(|error| format!("could not serialize audit details: {error}"))?;
    if json.len() <= AUDIT_EVENT_DETAILS_MAX_BYTES {
        return Ok(json);
    }

    Ok(serde_json::json!({
        "truncated": true,
        "originalBytes": json.len()
    })
    .to_string())
}

fn user_admin_ui_from_row(row: AdminUserRow) -> UserAdminUi {
    UserAdminUi {
        user_id: row.id,
        email: row.primary_email,
        display_name: row.display_name,
        disabled: row.disabled_at.is_some(),
        admin: row.admin_membership_active != 0,
        identity_count: row.identity_count,
        active_session_count: row.active_session_count,
        created_at: Some(row.created_at.to_string()),
        updated_at: Some(row.updated_at.to_string()),
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn user_with_profile_patch(user: &UserRow, patch: &ProfilePatch) -> UserRow {
    let mut user = user.clone();
    if let Some(display_name) = &patch.display_name {
        user.display_name = display_name.clone();
    }
    if let Some(picture_url) = &patch.picture_url {
        user.picture_url = picture_url.clone();
    }
    user
}

fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

fn content_type_is_form_urlencoded(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

fn userinfo_response(user: &UserRow, scope: Option<&str>) -> UserInfoResponse {
    let has_email = scope_contains(scope, "email");
    let has_profile = scope_contains(scope, "profile");
    UserInfoResponse {
        sub: user.id.clone(),
        email: has_email.then(|| user.primary_email.clone()).flatten(),
        name: has_profile.then(|| user.display_name.clone()).flatten(),
        picture: has_profile.then(|| user.picture_url.clone()).flatten(),
    }
}

fn session_response(current: Option<(&SessionRow, &UserRow)>) -> SessionResponse {
    match current {
        Some((session, user)) => SessionResponse {
            authenticated: true,
            session: Some(session_info_response(session)),
            user: Some(userinfo_response(user, Some("email profile"))),
        },
        None => SessionResponse {
            authenticated: false,
            session: None,
            user: None,
        },
    }
}

fn sessions_response(sessions: &[SessionRow], current_session_id: &str) -> SessionsResponse {
    SessionsResponse {
        sessions: sessions
            .iter()
            .map(|session| SessionListItemResponse {
                id: session.id.clone(),
                client_id: session.client_id.clone(),
                created_at: session.created_at,
                expires_at: session.expires_at,
                current: session.id == current_session_id,
            })
            .collect(),
    }
}

fn identities_response(identities: &[IdentityRow]) -> IdentitiesResponse {
    IdentitiesResponse {
        identities: identities
            .iter()
            .map(|identity| IdentityResponse {
                provider_id: identity.provider_id.clone(),
                provider_subject: identity.provider_subject.clone(),
                email: identity.email.clone(),
                email_verified: identity.email_verified != 0,
                display_name: identity.display_name.clone(),
                picture_url: identity.picture_url.clone(),
                created_at: identity.created_at,
                updated_at: identity.updated_at,
            })
            .collect(),
    }
}

#[cfg(target_arch = "wasm32")]
async fn passkey_json_from_request<T: serde::de::DeserializeOwned>(
    request: &mut Request,
) -> Result<T, String> {
    let content_type = request
        .headers()
        .get("Content-Type")
        .map_err(|error| format!("could not read Content-Type header: {error}"))?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err("Content-Type must be application/json".to_owned());
    }
    let body = request
        .bytes()
        .await
        .map_err(|error| format!("could not read passkey body: {error}"))?;
    if body.len() > PASSKEY_BODY_LIMIT {
        return Err("passkey JSON body is too large".to_owned());
    }
    serde_json::from_slice::<T>(&body).map_err(|error| format!("invalid passkey JSON: {error}"))
}

#[cfg(target_arch = "wasm32")]
async fn wallet_json_from_request<T: serde::de::DeserializeOwned>(
    request: &mut Request,
) -> Result<T, String> {
    let content_type = request
        .headers()
        .get("Content-Type")
        .map_err(|error| format!("could not read Content-Type header: {error}"))?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err("Content-Type must be application/json".to_owned());
    }
    let body = request
        .bytes()
        .await
        .map_err(|error| format!("could not read wallet body: {error}"))?;
    if body.len() > EVM_WALLET_BODY_LIMIT {
        return Err("wallet JSON body is too large".to_owned());
    }
    serde_json::from_slice::<T>(&body).map_err(|error| format!("invalid wallet JSON: {error}"))
}

#[cfg(target_arch = "wasm32")]
async fn local_auth_body_from_request<T: serde::de::DeserializeOwned>(
    request: &mut Request,
) -> Result<T, String> {
    let content_type = request_header(request, "Content-Type")
        .map_err(|error| format!("could not read Content-Type header: {error}"))?;
    let body = request
        .bytes()
        .await
        .map_err(|error| format!("could not read local auth body: {error}"))?;
    if content_type_is_json(content_type.as_deref()) {
        if body.len() > LOCAL_AUTH_BODY_LIMIT {
            return Err("local auth JSON body is too large".to_owned());
        }
        return serde_json::from_slice::<T>(&body)
            .map_err(|error| format!("invalid local auth JSON: {error}"));
    }
    if content_type_is_form_urlencoded(content_type.as_deref()) {
        if body.len() > LOCAL_AUTH_BODY_LIMIT {
            return Err("local auth form body is too large".to_owned());
        }
        return serde_urlencoded::from_bytes::<T>(&body)
            .map_err(|error| format!("invalid local auth form: {error}"));
    }
    Err("Content-Type must be application/json or application/x-www-form-urlencoded".to_owned())
}

fn validate_local_auth_email(value: &str) -> Result<String, String> {
    validate_passkey_email(value)
}

fn validate_evm_wallet_address(value: &str) -> Result<String, String> {
    let address = value.trim();
    let Some(hex) = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
    else {
        return Err("wallet address must start with 0x".to_owned());
    };
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("wallet address must be a 20 byte EVM address".to_owned());
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

fn normalize_evm_chain_id(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("wallet chain_id must not be empty".to_owned());
    }
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("wallet chain_id is not valid".to_owned());
        }
        u64::from_str_radix(hex, 16).map_err(|_| "wallet chain_id is not valid".to_owned())?
    } else {
        if value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("wallet chain_id is not valid".to_owned());
        }
        value
            .parse::<u64>()
            .map_err(|_| "wallet chain_id is not valid".to_owned())?
    };
    if parsed == 0 {
        return Err("wallet chain_id must be positive".to_owned());
    }
    Ok(parsed.to_string())
}

fn wallet_nonce_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_wallet_challenge(row: &WalletChallengeRow, now: i32) -> Result<(), String> {
    if row.consumed_at.is_some() {
        return Err("wallet challenge was already used".to_owned());
    }
    if row.expires_at <= now {
        return Err("wallet challenge expired".to_owned());
    }
    Ok(())
}

fn evm_wallet_signin_message(
    domain: &str,
    uri: &str,
    product_name: &str,
    address: &str,
    chain_id: &str,
    nonce: &str,
    issued_at: i32,
) -> String {
    let product_name = product_name.trim();
    let product_line = if product_name.is_empty() {
        "Zeroth".to_owned()
    } else {
        product_name.to_owned()
    };
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         Sign in to {product_line}.\n\n\
         URI: {uri}\n\
         Version: 1\n\
         Chain ID: {chain_id}\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}"
    )
}

fn evm_wallet_profile(address: &str) -> ProviderProfile {
    ProviderProfile {
        provider_id: ProviderId(EVM_WALLET_PROVIDER_ID.to_owned()),
        subject: Subject(address.to_owned()),
        email: None,
        email_verified: false,
        display_name: Some(short_evm_wallet_address(address)),
        picture_url: None,
    }
}

fn short_evm_wallet_address(address: &str) -> String {
    if address.len() == 42 {
        format!("{}...{}", &address[..6], &address[38..])
    } else {
        address.to_owned()
    }
}

fn recover_evm_wallet_address(message: &str, signature: &str) -> Result<String, String> {
    if message.as_bytes().len() > EVM_WALLET_MESSAGE_MAX_BYTES {
        return Err("wallet message is too large".to_owned());
    }
    let signature = evm_signature_from_hex(signature)?;
    let recovery_id = evm_recovery_id(signature[64])?;
    let ecdsa_signature = EvmSignature::try_from(&signature[..64])
        .map_err(|_| "wallet signature is not valid".to_owned())?;
    let digest = eip191_personal_message_hash(message);
    let key = EvmVerifyingKey::recover_from_prehash(&digest, &ecdsa_signature, recovery_id)
        .map_err(|_| "wallet signature did not recover".to_owned())?;
    Ok(evm_address_from_verifying_key(&key))
}

fn evm_signature_from_hex(value: &str) -> Result<[u8; EVM_WALLET_SIGNATURE_HEX_BYTES], String> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != EVM_WALLET_SIGNATURE_HEX_BYTES * 2
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("wallet signature must be a 65 byte hex value".to_owned());
    }
    let bytes = hex_to_bytes_with_context(hex, "wallet signature")?;
    let mut signature = [0u8; EVM_WALLET_SIGNATURE_HEX_BYTES];
    signature.copy_from_slice(&bytes);
    Ok(signature)
}

fn evm_recovery_id(value: u8) -> Result<EvmRecoveryId, String> {
    let normalized = match value {
        0 | 1 => value,
        27 | 28 => value - 27,
        _ => return Err("wallet signature recovery id is not supported".to_owned()),
    };
    EvmRecoveryId::try_from(normalized).map_err(|_| "wallet recovery id is not valid".to_owned())
}

fn eip191_personal_message_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.as_bytes().len());
    let digest = Keccak256::new()
        .chain_update(prefix.as_bytes())
        .chain_update(message.as_bytes())
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn evm_address_from_verifying_key(key: &EvmVerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    let digest = Keccak256::digest(&bytes[1..]);
    format!("0x{}", bytes_to_hex(&digest[12..]))
}

fn validate_local_auth_password(value: &str) -> Result<(), String> {
    let len = value.as_bytes().len();
    if len < PASSWORD_MIN_BYTES {
        return Err(format!(
            "password must be at least {PASSWORD_MIN_BYTES} bytes"
        ));
    }
    if len > PASSWORD_MAX_BYTES {
        return Err(format!(
            "password must be at most {PASSWORD_MAX_BYTES} bytes"
        ));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn local_auth_client_and_return_to(
    env: &Env,
    request_url: &url::Url,
    db: &worker::d1::D1Database,
    client_id: Option<&str>,
    return_to: Option<&str>,
    config: &ZerothServerConfig,
) -> Result<(Client, String), String> {
    let client_id =
        passkey_client_id_from_request(env, client_id).map_err(|error| error.to_string())?;
    let client = get_client(db, &client_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "local auth client is not registered".to_owned())?;
    let return_to = passkey_return_to(request_url, return_to, &client, config)
        .map_err(|error| error.to_string())?;
    Ok((client, return_to))
}

#[cfg(target_arch = "wasm32")]
async fn validate_local_auth_origin(
    request: &Request,
    _db: &worker::d1::D1Database,
    client: &Client,
    config: &ZerothServerConfig,
) -> worker::Result<Result<(), String>> {
    let origin = request_origin_for_config(request, config)?;
    Ok(validate_cors_origin(
        origin.as_deref(),
        &client.allowed_origins,
    ))
}

fn validate_local_auth_client_email_policy(
    client: &Client,
    email: &str,
) -> Result<(), ProviderCallbackError> {
    let profile = local_auth_profile(email, None, true);
    validate_client_email_domain_policy(client, &profile)
}

fn local_auth_profile(
    email: &str,
    display_name: Option<&str>,
    email_verified: bool,
) -> ProviderProfile {
    ProviderProfile {
        provider_id: ProviderId(LOCAL_AUTH_PROVIDER_ID.to_owned()),
        subject: Subject(email.to_owned()),
        email: Some(email.to_owned()),
        email_verified,
        display_name: display_name.map(str::to_owned),
        picture_url: None,
    }
}

fn local_auth_registration_user_id(
    current: Option<&CurrentSession>,
    existing_user: Option<&UserRow>,
    email: &str,
) -> Result<Option<String>, String> {
    if let Some(current) = current {
        if current.user.disabled_at.is_some() {
            return Err("current user is disabled".to_owned());
        }
        if let Some(primary_email) = current.user.primary_email.as_deref() {
            if !primary_email.eq_ignore_ascii_case(email) {
                return Err("password email must match the signed-in user".to_owned());
            }
        }
        if let Some(existing_user) = existing_user {
            if existing_user.id != current.user.id {
                return Err("email is already attached to another user".to_owned());
            }
        }
        return Ok(Some(current.user.id.clone()));
    }

    if existing_user.is_some() {
        return Err("account already exists; sign in instead".to_owned());
    }
    Ok(None)
}

fn local_auth_registration_error_code(error: &str) -> &'static str {
    if error == "account already exists; sign in instead" {
        "account_exists"
    } else {
        "invalid_request"
    }
}

#[cfg(target_arch = "wasm32")]
fn decode_password_pepper(value: &str, name: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("{name} must be base64url without padding: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name} must decode to exactly 32 bytes"));
    }
    Ok(bytes)
}

#[cfg(target_arch = "wasm32")]
fn decode_password_pepper_id(value: &str, name: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(format!("{name} contains unsupported characters"));
    }
    Ok(value.to_owned())
}

#[cfg(target_arch = "wasm32")]
fn password_pepper_from_env(env: &Env) -> Result<PasswordPepperConfig, String> {
    let current = decode_password_pepper(
        &binding_value_from_env(env, PASSWORD_PEPPER_ENV)
            .ok_or_else(|| format!("{PASSWORD_PEPPER_ENV} is not configured"))?,
        PASSWORD_PEPPER_ENV,
    )?;
    let current_id = decode_password_pepper_id(
        &binding_value_from_env(env, PASSWORD_PEPPER_ID_ENV)
            .ok_or_else(|| format!("{PASSWORD_PEPPER_ID_ENV} is not configured"))?,
        PASSWORD_PEPPER_ID_ENV,
    )?;

    let previous = match (
        binding_value_from_env(env, PASSWORD_PEPPER_PREVIOUS_ENV),
        binding_value_from_env(env, PASSWORD_PEPPER_PREVIOUS_ID_ENV),
    ) {
        (None, None) => None,
        (Some(previous), Some(previous_id)) => {
            let previous = decode_password_pepper(&previous, PASSWORD_PEPPER_PREVIOUS_ENV)?;
            let previous_id =
                decode_password_pepper_id(&previous_id, PASSWORD_PEPPER_PREVIOUS_ID_ENV)?;
            if previous == current {
                return Err(format!(
                    "{PASSWORD_PEPPER_PREVIOUS_ENV} must differ from {PASSWORD_PEPPER_ENV}"
                ));
            }
            if previous_id == current_id {
                return Err(format!(
                    "{PASSWORD_PEPPER_PREVIOUS_ID_ENV} must differ from {PASSWORD_PEPPER_ID_ENV}"
                ));
            }
            Some(PasswordPepperSecret {
                id: previous_id,
                value: previous,
            })
        }
        _ => {
            return Err(format!(
                "{PASSWORD_PEPPER_PREVIOUS_ENV} and {PASSWORD_PEPPER_PREVIOUS_ID_ENV} must both be set"
            ));
        }
    };

    Ok(PasswordPepperConfig {
        current: PasswordPepperSecret {
            id: current_id,
            value: current,
        },
        previous,
    })
}

#[cfg(target_arch = "wasm32")]
fn password_policy_ready(env: &Env) -> bool {
    password_pepper_from_env(env).is_ok()
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_key_from_env(env: &Env) -> Result<RateLimitSecret, String> {
    let value = binding_value_from_env(env, RATE_LIMIT_KEY_ENV)
        .ok_or_else(|| format!("{RATE_LIMIT_KEY_ENV} is not configured"))?;
    let decoded = URL_SAFE_NO_PAD.decode(value.trim()).map_err(|error| {
        format!("{RATE_LIMIT_KEY_ENV} must be base64url without padding: {error}")
    })?;
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("{RATE_LIMIT_KEY_ENV} must decode to exactly 32 bytes"))?;
    Ok(RateLimitSecret(bytes))
}

#[cfg(target_arch = "wasm32")]
fn csrf_secret_from_env(env: &Env) -> Result<CsrfSecret, String> {
    let value = binding_value_from_env(env, CSRF_SECRET_ENV)
        .ok_or_else(|| format!("{CSRF_SECRET_ENV} is not configured"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|error| format!("{CSRF_SECRET_ENV} must be base64url without padding: {error}"))?;
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("{CSRF_SECRET_ENV} must decode to exactly 32 bytes"))?;
    Ok(CsrfSecret(bytes))
}

#[cfg(target_arch = "wasm32")]
fn csrf_bucket(now: i32) -> i32 {
    now.div_euclid(24 * 60 * 60)
}

#[cfg(target_arch = "wasm32")]
fn csrf_mac(secret: &CsrfSecret, subject: &str, bucket: i32, route_family: &str) -> String {
    use hmac::{Hmac, Mac};

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(&secret.0).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(subject.as_bytes());
    mac.update(&[0]);
    mac.update(bucket.to_string().as_bytes());
    mac.update(&[0]);
    mac.update(route_family.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(target_arch = "wasm32")]
fn csrf_token(secret: &CsrfSecret, session_id: &str, route_family: &str, now: i32) -> String {
    let bucket = csrf_bucket(now);
    let mac = csrf_mac(secret, session_id, bucket, route_family);
    format!("v1.{bucket}.{mac}")
}

#[cfg(target_arch = "wasm32")]
fn validate_csrf_token(
    secret: &CsrfSecret,
    subject: &str,
    route_family: &str,
    token: &str,
    now: i32,
) -> Result<(), String> {
    let mut parts = token.split('.');
    let version = parts.next().unwrap_or_default();
    let bucket = parts.next().unwrap_or_default();
    let mac = parts.next().unwrap_or_default();
    if version != "v1" || mac.is_empty() || parts.next().is_some() {
        return Err("invalid CSRF token".to_owned());
    }
    let bucket = bucket
        .parse::<i32>()
        .map_err(|_| "invalid CSRF token".to_owned())?;
    let current_bucket = csrf_bucket(now);
    if bucket != current_bucket && bucket != current_bucket.saturating_sub(1) {
        return Err("CSRF token is stale".to_owned());
    }
    let expected = csrf_mac(secret, subject, bucket, route_family);
    if !constant_time_eq(&expected, mac) {
        return Err("CSRF token did not match this session".to_owned());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn csrf_token_from_header(request: &Request) -> worker::Result<Option<String>> {
    request_header(request, "X-Zeroth-CSRF")
}

#[cfg(target_arch = "wasm32")]
async fn csrf_token_from_request(request: &mut Request) -> worker::Result<Option<String>> {
    if let Some(token) = csrf_token_from_header(request)?.filter(|value| !value.trim().is_empty()) {
        return Ok(Some(token));
    }
    let form = request.form_data().await?;
    Ok(form
        .get("_csrf")
        .and_then(|value| value.as_string())
        .filter(|value| !value.trim().is_empty()))
}

#[cfg(target_arch = "wasm32")]
async fn validate_browser_session_mutation(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    client_id: Option<&str>,
    session_id: &str,
    route_family: &str,
    csrf_token: Option<&str>,
    now: i32,
) -> worker::Result<Result<(), String>> {
    let Some(origin) = request_origin_for_config(request, config)? else {
        return Ok(Err(
            "Origin header is required for browser session mutations".to_owned(),
        ));
    };
    if origin == "null" {
        return Ok(Err(
            "opaque origins are not allowed for browser session mutations".to_owned(),
        ));
    }
    let origin_allowed = if origin_matches_public_base_url(&origin, &config.public_base_url) {
        true
    } else if let Some(client_id) = client_id {
        match active_client_allowed_origins(db, client_id).await? {
            Ok(allowed_origins) => origin_allowed(&allowed_origins, &origin),
            Err(_) => false,
        }
    } else {
        false
    };
    if !origin_allowed {
        return Ok(Err(cors_disallowed_origin(&origin)));
    }
    let Some(csrf_token) = csrf_token.filter(|value| !value.trim().is_empty()) else {
        return Ok(Err("CSRF token is required".to_owned()));
    };
    let secret = csrf_secret_from_env(env).map_err(worker_error)?;
    Ok(validate_csrf_token(
        &secret,
        session_id,
        route_family,
        csrf_token.trim(),
        now,
    ))
}

#[cfg(target_arch = "wasm32")]
async fn active_admin_membership_exists(db: &worker::d1::D1Database) -> worker::Result<bool> {
    let row = db
        .prepare(
            "SELECT user_id
             FROM zeroth_admin_memberships
             WHERE disabled_at IS NULL
             LIMIT 1",
        )
        .first::<AdminMembershipProbeRow>(None)
        .await?;
    Ok(row.is_some())
}

#[cfg(target_arch = "wasm32")]
async fn admin_bootstrap_allowed(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    now: i32,
    bootstrap_reason: &str,
    allow_first_admin: bool,
) -> Result<bool, ClientManagementError> {
    let active_admin_exists = active_admin_membership_exists(db).await.map_err(|error| {
        ClientManagementError::server_error(format!(
            "could not check active admin membership: {error}"
        ))
    })?;
    if active_admin_exists && !emergency_enabled {
        return Ok(false);
    }
    let emergency_enabled = binding_value_from_env(env, ADMIN_BOOTSTRAP_EMERGENCY_ENV)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true") || value.trim() == "1");
    let emergency_expires_at =
        binding_value_from_env(env, ADMIN_BOOTSTRAP_EMERGENCY_EXPIRES_AT_ENV)
            .map(|value| value.trim().parse::<i32>())
            .transpose()
            .map_err(|_| {
                ClientManagementError::server_error(
                    "ADMIN_BOOTSTRAP_EMERGENCY_EXPIRES_AT must be an integer timestamp",
                )
            })?;
    if emergency_enabled {
        let Some(expires_at) = emergency_expires_at else {
            return Err(ClientManagementError::server_error(
                "ADMIN_BOOTSTRAP_EMERGENCY_EXPIRES_AT is required when ADMIN_BOOTSTRAP_EMERGENCY is enabled",
            ));
        };
        if expires_at < now {
            return Err(ClientManagementError::unauthorized(
                "bootstrap credential emergency access has expired",
            ));
        }
    }
    if !allow_first_admin && !emergency_enabled {
        return Ok(false);
    }
    record_audit_event(
        db,
        request,
        "admin.bootstrap.use",
        None,
        None,
        None,
        serde_json::json!({
            "reason": bootstrap_reason,
            "emergency": emergency_enabled,
            "expiresAt": emergency_expires_at,
        }),
        now,
    )
    .await;
    Ok(true)
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_request_ip(request: &Request) -> worker::Result<Option<String>> {
    Ok(request_header(request, "CF-Connecting-IP")?.map(|value| value.trim().to_owned()))
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_subject<'a>(
    policy: RateLimitPolicy,
    subject: impl Into<Cow<'a, str>>,
) -> RateLimitSubject<'a> {
    RateLimitSubject {
        policy,
        subject: subject.into(),
    }
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_subject_hash(secret: &RateLimitSecret, subject: &str) -> String {
    use hmac::{Hmac, Mac};

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(&secret.0).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(subject.as_bytes());
    bytes_to_hex(&mac.finalize().into_bytes())
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_bucket_start(now: i32, window_seconds: i32) -> i32 {
    now - now.rem_euclid(window_seconds)
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_retry_after_seconds(blocked_until: i32, now: i32) -> i32 {
    blocked_until.saturating_sub(now).max(1)
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_blocked_until(count: i32, max_attempts: i32, now: i32) -> Option<i32> {
    if count <= max_attempts {
        return None;
    }
    let step_index = usize::try_from(count - max_attempts - 1).unwrap_or(0);
    let duration = RATE_LIMIT_BLOCK_STEPS_SECONDS
        .get(step_index)
        .copied()
        .unwrap_or(*RATE_LIMIT_BLOCK_STEPS_SECONDS.last().unwrap_or(&3600));
    Some(now.saturating_add(duration))
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_worst_exceeded(
    current: Option<RateLimitExceeded>,
    next: RateLimitExceeded,
) -> Option<RateLimitExceeded> {
    match current {
        Some(existing) if existing.retry_after_seconds >= next.retry_after_seconds => {
            Some(existing)
        }
        _ => Some(next),
    }
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_token_subject(token_hash: &str) -> &str {
    let prefix_len = usize::min(token_hash.len(), 16);
    &token_hash[..prefix_len]
}

#[cfg(target_arch = "wasm32")]
async fn rate_limit_current_state(
    db: &worker::d1::D1Database,
    scope: &str,
    subject_hash: &str,
    bucket_start: i32,
    now: i32,
) -> worker::Result<RateLimitStateRow> {
    let args = [
        worker::d1::D1Type::Integer(bucket_start),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(scope),
        worker::d1::D1Type::Text(subject_hash),
        worker::d1::D1Type::Integer(bucket_start),
        worker::d1::D1Type::Integer(now),
    ];
    Ok(db
        .prepare(
            "SELECT
                 COALESCE(MAX(CASE WHEN bucket_start = ? THEN count END), 0) AS bucket_count,
                 MAX(CASE WHEN blocked_until IS NOT NULL AND blocked_until > ? THEN blocked_until END) AS blocked_until
             FROM zeroth_rate_limits
             WHERE scope = ?
               AND subject_hash = ?
               AND (bucket_start = ? OR blocked_until > ?)",
        )
        .bind_refs(&args)?
        .first::<RateLimitStateRow>(None)
        .await?
        .unwrap_or(RateLimitStateRow {
            bucket_count: 0,
            blocked_until: None,
        }))
}

#[cfg(target_arch = "wasm32")]
async fn maybe_cleanup_rate_limits(db: &worker::d1::D1Database, now: i32) -> worker::Result<()> {
    let mut roll = [0u8; 1];
    fill_random(&mut roll)?;
    if roll[0] % RATE_LIMIT_CLEANUP_MODULUS != 0 {
        return Ok(());
    }
    let cutoff = now.saturating_sub(RATE_LIMIT_RETENTION_SECONDS);
    let args = [
        worker::d1::D1Type::Integer(cutoff),
        worker::d1::D1Type::Integer(RATE_LIMIT_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_rate_limits
         WHERE rowid IN (
             SELECT rowid
             FROM zeroth_rate_limits
             WHERE updated_at < ?
             ORDER BY updated_at
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn rate_limit_check_subjects<'a>(
    db: &worker::d1::D1Database,
    secret: &RateLimitSecret,
    now: i32,
    subjects: &[RateLimitSubject<'a>],
) -> worker::Result<Option<RateLimitExceeded>> {
    let mut blocked = None;
    for subject in subjects {
        let bucket_start = rate_limit_bucket_start(now, subject.policy.window_seconds);
        let subject_hash = rate_limit_subject_hash(secret, subject.subject.as_ref());
        let state =
            rate_limit_current_state(db, subject.policy.scope, &subject_hash, bucket_start, now)
                .await?;
        if let Some(blocked_until) = state.blocked_until.filter(|value| *value > now) {
            blocked = rate_limit_worst_exceeded(
                blocked,
                RateLimitExceeded {
                    retry_after_seconds: rate_limit_retry_after_seconds(blocked_until, now),
                },
            );
        }
    }
    Ok(blocked)
}

#[cfg(target_arch = "wasm32")]
async fn rate_limit_increment_subjects<'a>(
    db: &worker::d1::D1Database,
    secret: &RateLimitSecret,
    now: i32,
    subjects: &[RateLimitSubject<'a>],
) -> worker::Result<Option<RateLimitExceeded>> {
    let mut blocked = None;
    for subject in subjects {
        let bucket_start = rate_limit_bucket_start(now, subject.policy.window_seconds);
        let subject_hash = rate_limit_subject_hash(secret, subject.subject.as_ref());
        let args = [
            worker::d1::D1Type::Text(subject.policy.scope),
            worker::d1::D1Type::Text(&subject_hash),
            worker::d1::D1Type::Integer(bucket_start),
            worker::d1::D1Type::Integer(now),
        ];
        db.prepare(
            "INSERT INTO zeroth_rate_limits (
                 scope, subject_hash, bucket_start, count, blocked_until, updated_at
             ) VALUES (?, ?, ?, 1, NULL, ?)
             ON CONFLICT(scope, subject_hash, bucket_start)
             DO UPDATE SET
                 count = count + 1,
                 updated_at = excluded.updated_at",
        )
        .bind_refs(&args)?
        .run()
        .await?;

        let state =
            rate_limit_current_state(db, subject.policy.scope, &subject_hash, bucket_start, now)
                .await?;
        let mut blocked_until = state.blocked_until;
        if let Some(next_blocked_until) =
            rate_limit_blocked_until(state.bucket_count, subject.policy.max_attempts, now)
        {
            if blocked_until.unwrap_or_default() < next_blocked_until {
                let update_args = [
                    worker::d1::D1Type::Integer(next_blocked_until),
                    worker::d1::D1Type::Integer(now),
                    worker::d1::D1Type::Text(subject.policy.scope),
                    worker::d1::D1Type::Text(&subject_hash),
                    worker::d1::D1Type::Integer(bucket_start),
                ];
                db.prepare(
                    "UPDATE zeroth_rate_limits
                     SET blocked_until = ?, updated_at = ?
                     WHERE scope = ? AND subject_hash = ? AND bucket_start = ?",
                )
                .bind_refs(&update_args)?
                .run()
                .await?;
                blocked_until = Some(next_blocked_until);
            }
        }
        if let Some(active_until) = blocked_until.filter(|value| *value > now) {
            blocked = rate_limit_worst_exceeded(
                blocked,
                RateLimitExceeded {
                    retry_after_seconds: rate_limit_retry_after_seconds(active_until, now),
                },
            );
        }
    }
    maybe_cleanup_rate_limits(db, now).await?;
    Ok(blocked)
}

#[cfg(target_arch = "wasm32")]
async fn rate_limit_clear_subjects<'a>(
    db: &worker::d1::D1Database,
    secret: &RateLimitSecret,
    subjects: &[RateLimitSubject<'a>],
) -> worker::Result<()> {
    for subject in subjects {
        let subject_hash = rate_limit_subject_hash(secret, subject.subject.as_ref());
        let args = [
            worker::d1::D1Type::Text(subject.policy.scope),
            worker::d1::D1Type::Text(&subject_hash),
        ];
        db.prepare("DELETE FROM zeroth_rate_limits WHERE scope = ? AND subject_hash = ?")
            .bind_refs(&args)?
            .run()
            .await?;
    }
    Ok(())
}

fn password_params_json(pepper_id: &str) -> String {
    serde_json::json!({
        "iterations": PASSWORD_PBKDF2_ITERATIONS,
        "prehash": "hmac-sha256",
        "pepper_id": pepper_id,
    })
    .to_string()
}

#[cfg(target_arch = "wasm32")]
async fn local_auth_password_matches(
    env: &Env,
    credential: &LocalCredentialRow,
    password: &str,
) -> worker::Result<PasswordVerification> {
    let peppers = password_pepper_from_env(env).map_err(worker_error)?;
    match local_auth_password_record(credential) {
        PasswordRecordKind::Invalid => {
            password_dummy_verify_with_config(&peppers, password).await?;
            Ok(PasswordVerification::invalid())
        }
        PasswordRecordKind::Legacy(record) => {
            let actual = password_hash_legacy(password, &record.salt, record.iterations).await?;
            let valid = constant_time_eq(&record.hash, &actual);
            Ok(PasswordVerification {
                valid,
                needs_rehash: valid,
            })
        }
        PasswordRecordKind::Current(record) => {
            let Some(pepper) = configured_pepper_for_id(&peppers, &record.pepper_id) else {
                password_dummy_verify_with_config(&peppers, password).await?;
                return Ok(PasswordVerification::invalid());
            };
            let actual =
                password_hash_with_policy(password, &record.salt, pepper, record.iterations)
                    .await?;
            if constant_time_eq(&record.hash, &actual) {
                return Ok(PasswordVerification {
                    valid: true,
                    needs_rehash: record.needs_rehash(&peppers.current.id),
                });
            }

            Ok(PasswordVerification::invalid())
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn password_hash_current(
    password: &str,
    salt: &str,
    pepper: &[u8],
) -> worker::Result<String> {
    password_hash_with_policy(password, salt, pepper, PASSWORD_PBKDF2_ITERATIONS).await
}

#[cfg(target_arch = "wasm32")]
async fn password_hash_legacy(
    password: &str,
    salt: &str,
    iterations: u32,
) -> worker::Result<String> {
    password_hash_without_pepper(password.as_bytes(), salt.as_bytes(), iterations).await
}

#[cfg(target_arch = "wasm32")]
async fn password_dummy_verify_with_config(
    peppers: &PasswordPepperConfig,
    password: &str,
) -> worker::Result<()> {
    let actual = password_hash_current(
        password,
        PASSWORD_DUMMY_SALT,
        peppers.current.value.as_slice(),
    )
    .await?;
    let _ = constant_time_eq(PASSWORD_DUMMY_HASH, &actual);
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn configured_pepper_for_id<'a>(
    peppers: &'a PasswordPepperConfig,
    pepper_id: &str,
) -> Option<&'a [u8]> {
    if pepper_id == peppers.current.id {
        return Some(peppers.current.value.as_slice());
    }
    peppers
        .previous
        .as_ref()
        .filter(|previous| previous.id == pepper_id)
        .map(|previous| previous.value.as_slice())
}

#[cfg(target_arch = "wasm32")]
async fn password_hash_with_policy(
    password: &str,
    salt: &str,
    pepper: &[u8],
    iterations: u32,
) -> worker::Result<String> {
    let prehash = password_prehash(pepper, password.as_bytes());
    let digest = pbkdf2_sha256_webcrypto(&prehash, salt.as_bytes(), iterations, 32).await?;
    Ok(bytes_to_hex(&digest))
}

#[cfg(target_arch = "wasm32")]
async fn password_hash_without_pepper(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> worker::Result<String> {
    let digest = pbkdf2_sha256_webcrypto(password, salt, iterations, 32).await?;
    Ok(bytes_to_hex(&digest))
}

#[cfg(target_arch = "wasm32")]
fn local_auth_password_record(credential: &LocalCredentialRow) -> PasswordRecordKind {
    if credential.password_hash.len() != 64
        || !credential
            .password_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || credential.password_salt.len() != 64
        || !credential
            .password_salt
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return PasswordRecordKind::Invalid;
    }
    if credential.password_version < 1 {
        return PasswordRecordKind::Invalid;
    }
    if credential.password_scheme != PasswordScheme::Pbkdf2Sha256.as_str() {
        return PasswordRecordKind::Invalid;
    }

    match credential.password_version {
        version if version < PASSWORD_CURRENT_VERSION => {
            let Ok(iterations) = u32::try_from(credential.password_iterations) else {
                return PasswordRecordKind::Invalid;
            };
            if !(PASSWORD_PBKDF2_MIN_ITERATIONS..=PASSWORD_PBKDF2_MAX_ITERATIONS)
                .contains(&iterations)
            {
                return PasswordRecordKind::Invalid;
            }
            if credential.password_alg != PASSWORD_PBKDF2_ALG {
                return PasswordRecordKind::Invalid;
            }
            PasswordRecordKind::Legacy(LegacyPasswordRecord {
                hash: credential.password_hash.clone(),
                salt: credential.password_salt.clone(),
                iterations,
            })
        }
        PASSWORD_CURRENT_VERSION => {
            let params: PasswordParamsJson =
                match serde_json::from_str(&credential.password_params_json) {
                    Ok(params) => params,
                    Err(_) => return PasswordRecordKind::Invalid,
                };
            if params.pepper_id.trim().is_empty() {
                return PasswordRecordKind::Invalid;
            }
            if decode_password_pepper_id(&params.pepper_id, "password_params_json.pepper_id")
                .is_err()
            {
                return PasswordRecordKind::Invalid;
            }
            if params.prehash != PasswordPrehash::HmacSha256 {
                return PasswordRecordKind::Invalid;
            }
            if params.iterations < PASSWORD_PBKDF2_MIN_ITERATIONS
                || params.iterations > PASSWORD_PBKDF2_MAX_ITERATIONS
            {
                return PasswordRecordKind::Invalid;
            }
            if credential.password_alg != PASSWORD_PBKDF2_ALG {
                return PasswordRecordKind::Invalid;
            }
            if credential.password_iterations != i32::try_from(params.iterations).unwrap_or(-1) {
                return PasswordRecordKind::Invalid;
            }
            PasswordRecordKind::Current(CurrentPasswordRecord {
                hash: credential.password_hash.clone(),
                salt: credential.password_salt.clone(),
                iterations: params.iterations,
                pepper_id: params.pepper_id,
            })
        }
        _ => PasswordRecordKind::Invalid,
    }
}

enum PasswordRecordKind {
    Invalid,
    Legacy(LegacyPasswordRecord),
    Current(CurrentPasswordRecord),
}

struct LegacyPasswordRecord {
    hash: String,
    salt: String,
    iterations: u32,
}

struct CurrentPasswordRecord {
    hash: String,
    salt: String,
    iterations: u32,
    pepper_id: String,
}

impl CurrentPasswordRecord {
    fn needs_rehash(&self, current_pepper_id: &str) -> bool {
        self.iterations != PASSWORD_PBKDF2_ITERATIONS || self.pepper_id != current_pepper_id
    }
}

fn password_prehash(pepper: &[u8], password: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(pepper).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(password);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(target_arch = "wasm32")]
async fn pbkdf2_sha256_webcrypto(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> worker::Result<Vec<u8>> {
    let subtle = password_worker_global_subtle().map_err(worker_error)?;
    let password_bytes = worker::js_sys::Uint8Array::from(password);
    let key_usages = single_js_string_array("deriveBits");
    let key_value = JsFuture::from(
        subtle
            .import_key_with_str(
                "raw",
                password_bytes.unchecked_ref(),
                "PBKDF2",
                false,
                &key_usages,
            )
            .map_err(password_js_worker_error)?,
    )
    .await
    .map_err(password_js_worker_error)?;
    let key = key_value
        .dyn_into::<worker::web_sys::CryptoKey>()
        .map_err(password_js_worker_error)?;

    let params = worker::js_sys::Object::new();
    password_set_js_string_property(&params, "name", "PBKDF2").map_err(worker_error)?;
    let salt = worker::js_sys::Uint8Array::from(salt);
    password_set_js_value_property(&params, "salt", salt.as_ref()).map_err(worker_error)?;
    password_set_js_value_property(&params, "iterations", &JsValue::from_f64(iterations as f64))
        .map_err(worker_error)?;
    password_set_js_string_property(&params, "hash", "SHA-256").map_err(worker_error)?;
    let bit_len = u32::try_from(output_len)
        .ok()
        .and_then(|len| len.checked_mul(8))
        .ok_or_else(|| worker_error("password hash output length is too large".to_owned()))?;
    let bits = JsFuture::from(
        subtle
            .derive_bits_with_object(&params, &key, bit_len)
            .map_err(password_js_worker_error)?,
    )
    .await
    .map_err(password_js_worker_error)?;
    let array = worker::js_sys::Uint8Array::new(&bits);
    Ok(array.to_vec())
}

#[cfg(target_arch = "wasm32")]
fn password_worker_global_subtle() -> Result<worker::web_sys::SubtleCrypto, String> {
    let global: worker::web_sys::WorkerGlobalScope = worker::js_sys::global().unchecked_into();
    let crypto = global
        .crypto()
        .map_err(|error| password_js_error_string("could not access Worker crypto", error))?;
    Ok(crypto.subtle())
}

#[cfg(target_arch = "wasm32")]
fn password_set_js_string_property(
    target: &worker::js_sys::Object,
    name: &str,
    value: &str,
) -> Result<(), String> {
    password_set_js_value_property(target, name, &JsValue::from_str(value))
}

#[cfg(target_arch = "wasm32")]
fn password_set_js_value_property(
    target: &worker::js_sys::Object,
    name: &str,
    value: &JsValue,
) -> Result<(), String> {
    let ok =
        worker::js_sys::Reflect::set(target, &JsValue::from_str(name), value).map_err(|error| {
            password_js_error_string("could not set password hash parameter", error)
        })?;
    if ok {
        Ok(())
    } else {
        Err(format!("could not set password hash parameter: {name}"))
    }
}

#[cfg(target_arch = "wasm32")]
fn password_js_worker_error(error: JsValue) -> worker::Error {
    worker_error(password_js_error_string("JavaScript error", error))
}

#[cfg(target_arch = "wasm32")]
fn password_js_error_string(context: &str, error: JsValue) -> String {
    let detail = error
        .dyn_ref::<worker::js_sys::Error>()
        .map(|error| error.message().into())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "unknown error".to_owned());
    format!("{context}: {detail}")
}

fn html_escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(target_arch = "wasm32")]
async fn issue_local_auth_session(
    request: &Request,
    db: &worker::d1::D1Database,
    client_id: &str,
    user_id: &str,
    return_to: &str,
    event_type: &str,
    mode: &str,
    now: i32,
) -> worker::Result<LocalAuthSessionIssue> {
    let session_id = format!("sess_{}", random_token()?);
    let audit_context = audit_request_context(request).unwrap_or_default();
    put_session(
        db,
        &session_id,
        user_id,
        client_id,
        now,
        audit_context.user_agent.as_deref(),
        audit_context.ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        db,
        request,
        event_type,
        Some(user_id),
        Some(client_id),
        Some(LOCAL_AUTH_PROVIDER_ID),
        serde_json::json!({ "mode": mode }),
        now,
    )
    .await;
    let user = get_user(db, user_id)
        .await?
        .ok_or_else(|| worker_error("local auth user was not found".to_owned()))?;
    Ok(LocalAuthSessionIssue {
        session_id,
        return_to: return_to.to_owned(),
        user,
    })
}

#[cfg(target_arch = "wasm32")]
async fn issue_local_auth_session_response(
    request: &Request,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    client_id: &str,
    user_id: &str,
    return_to: &str,
    event_type: &str,
    mode: &str,
    now: i32,
) -> worker::Result<Response> {
    let issue = issue_local_auth_session(
        request, db, client_id, user_id, return_to, event_type, mode, now,
    )
    .await?;
    let response = json(&LocalAuthResponse {
        ok: true,
        return_to: issue.return_to,
        user: userinfo_response(&issue.user, Some("email profile")),
    })?;
    with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &issue.session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn issue_wallet_session_response(
    request: &Request,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    client_id: &str,
    user: &UserRow,
    return_to: &str,
    address: &str,
    chain_id: &str,
    now: i32,
) -> worker::Result<Response> {
    let session_id = format!("sess_{}", random_token()?);
    let audit_context = audit_request_context(request).unwrap_or_default();
    put_session(
        db,
        &session_id,
        &user.id,
        client_id,
        now,
        audit_context.user_agent.as_deref(),
        audit_context.ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        db,
        request,
        "session.login",
        Some(&user.id),
        Some(client_id),
        Some(EVM_WALLET_PROVIDER_ID),
        serde_json::json!({
            "mode": "wallet_evm",
            "addressHash": hash_secret(address),
            "chainId": chain_id
        }),
        now,
    )
    .await;
    let response = json(&LocalAuthResponse {
        ok: true,
        return_to: return_to.to_owned(),
        user: userinfo_response(user, Some("email profile")),
    })?;
    with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
fn magic_link_url(config: &ZerothServerConfig, token: &str) -> worker::Result<String> {
    let mut url = url::Url::parse(&format!(
        "{}/magic-link/confirm",
        config.public_base_url.trim_end_matches('/')
    ))
    .map_err(|error| worker_error(format!("invalid magic link base URL: {error}")))?;
    url.query_pairs_mut().append_pair("token", token);
    Ok(url.to_string())
}

#[cfg(target_arch = "wasm32")]
async fn send_magic_link_email(env: &Env, email: &str, link: &str) -> Result<bool, String> {
    let transport = match magic_link_delivery_transport_from_value(
        binding_value_from_env(env, "MAGIC_LINK_DELIVERY").as_deref(),
    ) {
        Ok(transport) => transport,
        Err(_) => return Ok(false),
    };
    let Some(from) = magic_link_from_env(env) else {
        return Ok(false);
    };
    let content = magic_link_email_content(env, &from, link);
    match transport {
        MagicLinkDeliveryTransport::CloudflareEmail => {
            send_magic_link_cloudflare_email(env, email, &content).await
        }
        MagicLinkDeliveryTransport::Webhook => {
            send_magic_link_webhook_email(env, email, link, &content).await
        }
        MagicLinkDeliveryTransport::Resend => {
            send_magic_link_resend_email(env, email, &content).await
        }
        MagicLinkDeliveryTransport::MailChannels => {
            send_magic_link_mailchannels_email(env, email, &content).await
        }
    }
}

#[cfg(target_arch = "wasm32")]
struct MagicLinkEmailContent {
    from: String,
    product_name: String,
    subject: String,
    text: String,
    html: String,
}

#[cfg(target_arch = "wasm32")]
fn magic_link_from_env(env: &Env) -> Option<String> {
    binding_value_from_env(env, "MAGIC_LINK_FROM")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(target_arch = "wasm32")]
fn magic_link_email_content(env: &Env, from: &str, link: &str) -> MagicLinkEmailContent {
    let product_name = env_string(env, "PRODUCT_NAME").unwrap_or_else(|| "Zeroth".to_owned());
    let subject = format!("Sign in to {product_name}");
    let text = format!("Sign in to {product_name}:\n\n{link}\n\nThis link expires in 10 minutes.");
    let html = format!(
        r#"<p>Sign in to {}:</p><p><a href="{}">{}</a></p><p>This link expires in 10 minutes.</p>"#,
        html_escape_text(&product_name),
        html_escape_text(link),
        html_escape_text(link)
    );
    MagicLinkEmailContent {
        from: from.to_owned(),
        product_name,
        subject,
        text,
        html,
    }
}

#[cfg(target_arch = "wasm32")]
async fn send_magic_link_cloudflare_email(
    env: &Env,
    email: &str,
    content: &MagicLinkEmailContent,
) -> Result<bool, String> {
    let Ok(sender) = env.send_email("EMAIL") else {
        return Ok(false);
    };
    let from_address = worker::email::EmailAddress::new(&content.product_name, &content.from);
    let builder = worker::email::SendEmailBuilder::builder_with_email_address_and_str(
        &from_address,
        email,
        &content.subject,
    )
    .text(&content.text)
    .html(&content.html)
    .build();
    sender
        .send_with_builder(&builder)
        .await
        .map(|_| true)
        .map_err(|error| String::from(error.message()))
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MagicLinkWebhookPayload<'a> {
    kind: &'static str,
    to: &'a str,
    from: &'a str,
    from_name: &'a str,
    subject: &'a str,
    text: &'a str,
    html: &'a str,
    link: &'a str,
    product_name: &'a str,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct ResendEmailPayload<'a> {
    from: String,
    to: [&'a str; 1],
    subject: &'a str,
    text: &'a str,
    html: &'a str,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct MailChannelsEmailAddress<'a> {
    email: &'a str,
    name: &'a str,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct MailChannelsPersonalization<'a> {
    to: [MailChannelsEmailAddress<'a>; 1],
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct MailChannelsEmailContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    value: &'a str,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct MailChannelsEmailPayload<'a> {
    personalizations: [MailChannelsPersonalization<'a>; 1],
    from: MailChannelsEmailAddress<'a>,
    subject: &'a str,
    content: [MailChannelsEmailContent<'a>; 2],
}

#[cfg(target_arch = "wasm32")]
async fn send_magic_link_webhook_email(
    env: &Env,
    email: &str,
    link: &str,
    content: &MagicLinkEmailContent,
) -> Result<bool, String> {
    let Some(endpoint) = magic_link_webhook_url_from_env(env) else {
        return Ok(false);
    };
    let payload = MagicLinkWebhookPayload {
        kind: "magic_link",
        to: email,
        from: &content.from,
        from_name: &content.product_name,
        subject: &content.subject,
        text: &content.text,
        html: &content.html,
        link,
        product_name: &content.product_name,
    };
    let body = serde_json::to_string(&payload)
        .map_err(|error| format!("email_webhook_failed JSON serialization: {error}"))?;
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| format!("email_webhook_failed header: {error}"))?;
    headers
        .set("Accept", "application/json")
        .map_err(|error| format!("email_webhook_failed header: {error}"))?;
    if let Some(bearer) = magic_link_webhook_bearer_from_env(env) {
        headers
            .set("Authorization", &format!("Bearer {bearer}"))
            .map_err(|error| format!("email_webhook_failed header: {error}"))?;
    }

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let outbound = Request::new_with_init(&endpoint, &init)
        .map_err(|error| format!("email_webhook_failed request: {error}"))?;
    let response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(|error| format!("email_webhook_failed fetch: {error}"))?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(format!("email_webhook_failed HTTP {status}"));
    }
    Ok(true)
}

#[cfg(target_arch = "wasm32")]
async fn send_magic_link_resend_email(
    env: &Env,
    email: &str,
    content: &MagicLinkEmailContent,
) -> Result<bool, String> {
    let Some(api_key) = magic_link_resend_api_key_from_env(env) else {
        return Ok(false);
    };
    let payload = ResendEmailPayload {
        from: friendly_sender_address(&content.product_name, &content.from),
        to: [email],
        subject: &content.subject,
        text: &content.text,
        html: &content.html,
    };
    let body = serde_json::to_string(&payload)
        .map_err(|error| format!("email_resend_failed JSON serialization: {error}"))?;
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| format!("email_resend_failed header: {error}"))?;
    headers
        .set("Accept", "application/json")
        .map_err(|error| format!("email_resend_failed header: {error}"))?;
    headers
        .set("Authorization", &format!("Bearer {api_key}"))
        .map_err(|error| format!("email_resend_failed header: {error}"))?;

    post_magic_link_email_json(
        "https://api.resend.com/emails",
        Method::Post,
        headers,
        body,
        "email_resend_failed",
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn send_magic_link_mailchannels_email(
    env: &Env,
    email: &str,
    content: &MagicLinkEmailContent,
) -> Result<bool, String> {
    let Some(api_key) = magic_link_mailchannels_api_key_from_env(env) else {
        return Ok(false);
    };
    let payload = MailChannelsEmailPayload {
        personalizations: [MailChannelsPersonalization {
            to: [MailChannelsEmailAddress { email, name: "" }],
        }],
        from: MailChannelsEmailAddress {
            email: &content.from,
            name: &content.product_name,
        },
        subject: &content.subject,
        content: [
            MailChannelsEmailContent {
                content_type: "text/plain",
                value: &content.text,
            },
            MailChannelsEmailContent {
                content_type: "text/html",
                value: &content.html,
            },
        ],
    };
    let body = serde_json::to_string(&payload)
        .map_err(|error| format!("email_mailchannels_failed JSON serialization: {error}"))?;
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| format!("email_mailchannels_failed header: {error}"))?;
    headers
        .set("Accept", "application/json")
        .map_err(|error| format!("email_mailchannels_failed header: {error}"))?;
    headers
        .set("X-Api-Key", &api_key)
        .map_err(|error| format!("email_mailchannels_failed header: {error}"))?;

    post_magic_link_email_json(
        "https://api.mailchannels.net/tx/v1/send",
        Method::Post,
        headers,
        body,
        "email_mailchannels_failed",
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn post_magic_link_email_json(
    endpoint: &str,
    method: Method,
    headers: Headers,
    body: String,
    error_class: &str,
) -> Result<bool, String> {
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let outbound = Request::new_with_init(endpoint, &init)
        .map_err(|error| format!("{error_class} request: {error}"))?;
    let response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(|error| format!("{error_class} fetch: {error}"))?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(format!("{error_class} HTTP {status}"));
    }
    Ok(true)
}

#[cfg(target_arch = "wasm32")]
fn magic_link_webhook_url_from_env(env: &Env) -> Option<String> {
    binding_value_from_env(env, "MAGIC_LINK_WEBHOOK_URL")
        .map(|value| value.trim().to_owned())
        .filter(|value| magic_link_webhook_url_valid(value))
}

#[cfg(target_arch = "wasm32")]
fn magic_link_webhook_bearer_from_env(env: &Env) -> Option<String> {
    ["MAGIC_LINK_WEBHOOK_BEARER", "MAGIC_LINK_WEBHOOK_TOKEN"]
        .into_iter()
        .find_map(|name| {
            binding_value_from_env(env, name)
                .map(|value| value.trim().to_owned())
                .filter(|value| config_value_configured(Some(value)))
        })
}

#[cfg(target_arch = "wasm32")]
fn magic_link_resend_api_key_from_env(env: &Env) -> Option<String> {
    ["MAGIC_LINK_RESEND_API_KEY", "RESEND_API_KEY"]
        .into_iter()
        .find_map(|name| {
            binding_value_from_env(env, name)
                .map(|value| value.trim().to_owned())
                .filter(|value| config_value_configured(Some(value)))
        })
}

#[cfg(target_arch = "wasm32")]
fn magic_link_mailchannels_api_key_from_env(env: &Env) -> Option<String> {
    ["MAGIC_LINK_MAILCHANNELS_API_KEY", "MAILCHANNELS_API_KEY"]
        .into_iter()
        .find_map(|name| {
            binding_value_from_env(env, name)
                .map(|value| value.trim().to_owned())
                .filter(|value| config_value_configured(Some(value)))
        })
}

#[cfg(target_arch = "wasm32")]
fn friendly_sender_address(name: &str, email: &str) -> String {
    let name = name.trim();
    if name.is_empty()
        || name
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '<' | '>' | '"'))
    {
        email.to_owned()
    } else {
        format!("{name} <{email}>")
    }
}

#[cfg(target_arch = "wasm32")]
fn magic_link_dev_echo_enabled(env: &Env) -> bool {
    binding_value_from_env(env, "MAGIC_LINK_DEV_ECHO")
        .as_deref()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn validate_magic_link(row: &MagicLinkRow, now: i32) -> Result<(), String> {
    if row.consumed_at.is_some() || row.expires_at <= now {
        return Err("magic link is invalid or expired".to_owned());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn passkey_registration_subject(
    current: Option<&CurrentSession>,
    body: &PasskeyRegisterOptionsRequest,
) -> Result<(Option<String>, String, Option<String>), String> {
    if let Some(current) = current {
        let email = current
            .user
            .primary_email
            .as_deref()
            .or(body.email.as_deref())
            .ok_or_else(|| "current user has no email; provide email".to_owned())
            .and_then(validate_passkey_email)?;
        let display_name = body
            .display_name
            .as_deref()
            .or(current.user.display_name.as_deref())
            .map(validate_passkey_display_name)
            .transpose()?;
        return Ok((Some(current.user.id.clone()), email, display_name));
    }

    let email = body
        .email
        .as_deref()
        .ok_or_else(|| "email is required to register the first passkey".to_owned())
        .and_then(validate_passkey_email)?;
    let display_name = body
        .display_name
        .as_deref()
        .map(validate_passkey_display_name)
        .transpose()?;
    Ok((None, email, display_name))
}

#[cfg(target_arch = "wasm32")]
fn passkey_client_id_from_request(env: &Env, client_id: Option<&str>) -> worker::Result<String> {
    client_id
        .map(str::trim)
        .filter(|client_id| !client_id.is_empty())
        .map(str::to_owned)
        .or_else(|| env_string(env, "DEFAULT_LOGIN_CLIENT_ID"))
        .filter(|client_id| !client_id.is_empty())
        .ok_or_else(|| {
            worker_error(
                "missing client_id and DEFAULT_LOGIN_CLIENT_ID is not configured".to_owned(),
            )
        })
}

#[cfg(target_arch = "wasm32")]
fn passkey_return_to(
    request_url: &url::Url,
    return_to: Option<&str>,
    client: &Client,
    config: &ZerothServerConfig,
) -> worker::Result<String> {
    let value = return_to
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}/account", config.issuer().issuer));
    let value = if value.starts_with('/') {
        let mut target = request_url.clone();
        target.set_path(&value);
        target.set_query(None);
        target.set_fragment(None);
        target.to_string()
    } else {
        value
    };
    validate_client_return_to(&value, client, Some(&config.public_base_url))
        .map_err(|error| worker_error(format!("invalid passkey return_to: {error}")))?;
    Ok(value)
}

fn validate_passkey_email(value: &str) -> Result<String, String> {
    let email = value.trim().to_ascii_lowercase();
    if email.is_empty() {
        return Err("email must not be empty".to_owned());
    }
    if email.len() > PASSKEY_EMAIL_MAX_BYTES {
        return Err("email is too long".to_owned());
    }
    if email.bytes().any(|byte| byte.is_ascii_whitespace()) || !email.contains('@') {
        return Err("email is not valid".to_owned());
    }
    Ok(email)
}

fn validate_passkey_display_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("displayName must not be empty".to_owned());
    }
    if value.chars().count() > PROFILE_NAME_MAX_CHARS {
        return Err(format!(
            "displayName must be at most {PROFILE_NAME_MAX_CHARS} characters"
        ));
    }
    Ok(value.to_owned())
}

fn validate_passkey_label(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > PASSKEY_LABEL_MAX_CHARS {
        return Err(format!(
            "label must be at most {PASSKEY_LABEL_MAX_CHARS} characters"
        ));
    }
    Ok(Some(value.to_owned()))
}

fn passkey_creation_options(
    config: &ZerothServerConfig,
    challenge: &str,
    user_id: &str,
    email: &str,
    display_name: &str,
    exclude_credentials: Vec<PasskeyCredentialDescriptor>,
) -> Result<PasskeyPublicKeyCredentialCreationOptions, String> {
    Ok(PasskeyPublicKeyCredentialCreationOptions {
        challenge: passkey_challenge_for_browser(challenge),
        rp: PasskeyRpEntity {
            id: passkey_rp_id(config)?,
            name: passkey_rp_name(config),
        },
        user: PasskeyUserEntity {
            id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
            name: email.to_owned(),
            display_name: display_name.to_owned(),
        },
        pub_key_cred_params: vec![PasskeyPubKeyCredParam {
            credential_type: "public-key",
            alg: -7,
        }],
        timeout: 300_000,
        authenticator_selection: PasskeyAuthenticatorSelection {
            resident_key: "required",
            require_resident_key: true,
            user_verification: "required",
        },
        attestation: "none",
        exclude_credentials,
    })
}

fn passkey_request_options(
    config: &ZerothServerConfig,
    challenge: &str,
    allow_credentials: Vec<PasskeyCredentialDescriptor>,
) -> Result<PasskeyPublicKeyCredentialRequestOptions, String> {
    Ok(PasskeyPublicKeyCredentialRequestOptions {
        challenge: passkey_challenge_for_browser(challenge),
        rp_id: passkey_rp_id(config)?,
        timeout: 300_000,
        user_verification: "required",
        allow_credentials,
    })
}

fn passkey_challenge_for_browser(challenge: &str) -> String {
    URL_SAFE_NO_PAD.encode(challenge.as_bytes())
}

fn passkey_challenge_from_browser(value: &str) -> Result<String, String> {
    let bytes = decode_base64url(value)?;
    String::from_utf8(bytes).map_err(|error| format!("challenge was not UTF-8: {error}"))
}

fn passkey_challenge_hash_from_client_data(client_data_json: &str) -> Result<String, String> {
    let client_data = decode_passkey_client_data(client_data_json)?;
    let challenge = passkey_challenge_from_browser(&client_data.challenge)?;
    Ok(hash_secret(&challenge))
}

fn passkey_challenge_matches_client_data(challenge_hash: &str, client_data_json: &str) -> bool {
    passkey_challenge_hash_from_client_data(client_data_json)
        .is_ok_and(|actual| actual == challenge_hash)
}

fn passkey_rp_id(config: &ZerothServerConfig) -> Result<String, String> {
    let url = url::Url::parse(&config.public_base_url)
        .map_err(|error| format!("PUBLIC_BASE_URL is invalid: {error}"))?;
    url.host_str()
        .map(str::to_owned)
        .ok_or_else(|| "PUBLIC_BASE_URL must include a host".to_owned())
}

fn passkey_rp_name(config: &ZerothServerConfig) -> String {
    url::Url::parse(&config.public_base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "Zeroth".to_owned())
}

fn passkey_expected_origin(config: &ZerothServerConfig) -> Result<String, String> {
    let url = url::Url::parse(&config.public_base_url)
        .map_err(|error| format!("PUBLIC_BASE_URL is invalid: {error}"))?;
    Ok(url.origin().ascii_serialization())
}

fn validate_passkey_client_data(
    config: &ZerothServerConfig,
    client_data_json: &str,
    expected_type: &str,
) -> Result<WebAuthnClientData, String> {
    let client_data = decode_passkey_client_data(client_data_json)?;
    if client_data.ceremony_type != expected_type {
        return Err(format!("passkey client data type must be {expected_type}"));
    }
    let expected_origin = passkey_expected_origin(config)?;
    if client_data.origin != expected_origin {
        return Err("passkey origin did not match Zeroth issuer".to_owned());
    }
    if client_data.cross_origin.unwrap_or(false) {
        return Err("cross-origin passkey ceremonies are not accepted".to_owned());
    }
    Ok(client_data)
}

fn decode_passkey_client_data(client_data_json: &str) -> Result<WebAuthnClientData, String> {
    let bytes = decode_base64url(client_data_json)?;
    serde_json::from_slice::<WebAuthnClientData>(&bytes)
        .map_err(|error| format!("invalid passkey clientDataJSON: {error}"))
}

fn validate_passkey_registration_response(
    config: &ZerothServerConfig,
    body: &PasskeyRegisterVerifyRequest,
) -> Result<ValidatedPasskeyRegistration, String> {
    let raw_id = passkey_raw_id(&body.raw_id)?;
    if passkey_raw_id(&body.id)? != raw_id {
        return Err("passkey id and rawId did not match".to_owned());
    }
    validate_passkey_client_data(config, &body.response.client_data_json, "webauthn.create")?;
    let attestation_object = decode_base64url(&body.response.attestation_object)?;
    let auth_data = parse_passkey_attestation_object(&attestation_object)?;
    validate_passkey_authenticator_data(config, &auth_data, true)?;
    let credential_id = auth_data
        .credential_id
        .ok_or_else(|| "passkey registration did not include credential data".to_owned())
        .map(|credential_id| URL_SAFE_NO_PAD.encode(credential_id))?;
    if credential_id != raw_id {
        return Err("passkey authenticator credential id did not match rawId".to_owned());
    }
    let public_key = auth_data
        .public_key
        .ok_or_else(|| "passkey registration did not include a public key".to_owned())?;
    Ok(ValidatedPasskeyRegistration {
        credential_id,
        public_key_x: URL_SAFE_NO_PAD.encode(public_key.x),
        public_key_y: URL_SAFE_NO_PAD.encode(public_key.y),
        sign_count: auth_data.sign_count,
    })
}

fn validate_passkey_authentication_response(
    config: &ZerothServerConfig,
    body: &PasskeyAuthenticateVerifyRequest,
    credential: &PasskeyCredentialRow,
    challenge: &PasskeyChallengeRow,
) -> Result<(), String> {
    let raw_id = passkey_raw_id(&body.raw_id)?;
    if passkey_raw_id(&body.id)? != raw_id || raw_id != credential.credential_id {
        return Err("passkey credential id did not match".to_owned());
    }
    let client_data =
        validate_passkey_client_data(config, &body.response.client_data_json, "webauthn.get")?;
    let challenge_value = passkey_challenge_from_browser(&client_data.challenge)?;
    if hash_secret(&challenge_value) != challenge.challenge_hash {
        return Err("passkey challenge did not match".to_owned());
    }
    let authenticator_data_bytes = decode_base64url(&body.response.authenticator_data)?;
    let auth_data = parse_passkey_authenticator_data(&authenticator_data_bytes)?;
    validate_passkey_authenticator_data(config, &auth_data, false)?;
    validate_passkey_sign_count(credential.sign_count, auth_data.sign_count)?;
    let client_data_bytes = decode_base64url(&body.response.client_data_json)?;
    let mut signed_data = authenticator_data_bytes;
    signed_data.extend_from_slice(&Sha256::digest(&client_data_bytes));
    let signature = decode_base64url(&body.response.signature)?;
    verify_passkey_es256_signature(credential, &signed_data, &signature)
}

fn validate_passkey_authenticator_data(
    config: &ZerothServerConfig,
    auth_data: &ParsedAuthenticatorData,
    require_attested_credential: bool,
) -> Result<(), String> {
    let rp_id = passkey_rp_id(config)?;
    let expected_hash = Sha256::digest(rp_id.as_bytes()).to_vec();
    if auth_data.rp_id_hash != expected_hash {
        return Err("passkey relying-party id hash did not match".to_owned());
    }
    if auth_data.flags & 0x01 == 0 {
        return Err("passkey user-present flag was not set".to_owned());
    }
    if auth_data.flags & 0x04 == 0 {
        return Err("passkey user-verified flag was not set".to_owned());
    }
    if require_attested_credential && auth_data.flags & 0x40 == 0 {
        return Err("passkey attested-credential flag was not set".to_owned());
    }
    Ok(())
}

fn validate_passkey_sign_count(stored: i32, incoming: i32) -> Result<(), String> {
    if stored > 0 && incoming > 0 && incoming <= stored {
        return Err("passkey sign counter did not increase".to_owned());
    }
    Ok(())
}

fn verify_passkey_es256_signature(
    credential: &PasskeyCredentialRow,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let x = decode_base64url(&credential.public_key_x)?;
    let y = decode_base64url(&credential.public_key_y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("stored passkey public key is not P-256".to_owned());
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|error| format!("invalid passkey public key: {error}"))?;
    let signature = Signature::from_der(signature)
        .map_err(|error| format!("invalid passkey signature: {error}"))?;
    verifying_key
        .verify(signed_data, &signature)
        .map_err(|_| "passkey signature did not verify".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn passkey_authenticator_sign_count(authenticator_data: &str) -> worker::Result<i32> {
    let authenticator_data = decode_base64url(authenticator_data).map_err(worker_error)?;
    parse_passkey_authenticator_data(&authenticator_data)
        .map(|data| data.sign_count)
        .map_err(worker_error)
}

fn passkey_raw_id(value: &str) -> Result<String, String> {
    decode_base64url(value).map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|error| format!("invalid base64url value: {error}"))
}

fn parse_passkey_attestation_object(bytes: &[u8]) -> Result<ParsedAuthenticatorData, String> {
    let value = CborReader::new(bytes).read_single()?;
    let CborValue::Map(entries) = value else {
        return Err("passkey attestationObject must be a CBOR map".to_owned());
    };
    let auth_data = cbor_map_text_bytes(&entries, "authData")
        .ok_or_else(|| "passkey attestationObject is missing authData".to_owned())?;
    parse_passkey_authenticator_data(auth_data)
}

fn parse_passkey_authenticator_data(bytes: &[u8]) -> Result<ParsedAuthenticatorData, String> {
    if bytes.len() < 37 {
        return Err("passkey authenticatorData is too short".to_owned());
    }
    let rp_id_hash = bytes[0..32].to_vec();
    let flags = bytes[32];
    let sign_count = i32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    let mut credential_id = None;
    let mut public_key = None;

    if flags & 0x40 != 0 {
        if bytes.len() < 55 {
            return Err("passkey attested credential data is too short".to_owned());
        }
        let credential_id_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
        let credential_start = 55;
        let credential_end = credential_start + credential_id_len;
        if bytes.len() <= credential_end {
            return Err("passkey credential public key is missing".to_owned());
        }
        credential_id = Some(bytes[credential_start..credential_end].to_vec());
        public_key = Some(parse_passkey_cose_public_key(&bytes[credential_end..])?);
    }

    Ok(ParsedAuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        public_key,
    })
}

fn parse_passkey_cose_public_key(bytes: &[u8]) -> Result<PasskeyCredentialPublicKey, String> {
    let value = CborReader::new(bytes).read_single()?;
    let CborValue::Map(entries) = value else {
        return Err("passkey public key must be a COSE_Key map".to_owned());
    };
    if cbor_map_int_i64(&entries, 1) != Some(2) {
        return Err("passkey public key must be EC2".to_owned());
    }
    if cbor_map_int_i64(&entries, 3) != Some(-7) {
        return Err("passkey public key must use ES256".to_owned());
    }
    if cbor_map_int_i64(&entries, -1) != Some(1) {
        return Err("passkey public key must use P-256".to_owned());
    }
    let x = cbor_map_int_bytes(&entries, -2)
        .ok_or_else(|| "passkey public key is missing x coordinate".to_owned())?
        .to_vec();
    let y = cbor_map_int_bytes(&entries, -3)
        .ok_or_else(|| "passkey public key is missing y coordinate".to_owned())?
        .to_vec();
    if x.len() != 32 || y.len() != 32 {
        return Err("passkey public key coordinates must be 32 bytes".to_owned());
    }
    Ok(PasskeyCredentialPublicKey { x, y })
}

fn cbor_map_text_bytes<'a>(entries: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a [u8]> {
    entries
        .iter()
        .find_map(|(entry_key, value)| match (entry_key, value) {
            (CborValue::Text(entry_key), CborValue::Bytes(value)) if entry_key == key => {
                Some(value.as_slice())
            }
            _ => None,
        })
}

fn cbor_map_int_i64(entries: &[(CborValue, CborValue)], key: i64) -> Option<i64> {
    entries.iter().find_map(|(entry_key, value)| {
        if cbor_int(entry_key)? != key {
            return None;
        }
        cbor_int(value)
    })
}

fn cbor_map_int_bytes<'a>(entries: &'a [(CborValue, CborValue)], key: i64) -> Option<&'a [u8]> {
    entries.iter().find_map(|(entry_key, value)| {
        if cbor_int(entry_key)? != key {
            return None;
        }
        match value {
            CborValue::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    })
}

fn cbor_int(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Unsigned(value) => i64::try_from(*value).ok(),
        CborValue::Negative(value) => Some(*value),
        _ => None,
    }
}

struct CborReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_single(mut self) -> Result<CborValue, String> {
        let value = self.read_value()?;
        if self.offset != self.bytes.len() {
            return Err("CBOR value had trailing bytes".to_owned());
        }
        Ok(value)
    }

    fn read_value(&mut self) -> Result<CborValue, String> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(CborValue::Unsigned(self.read_len(additional)?)),
            1 => {
                let value = self.read_len(additional)?;
                let value = i64::try_from(value)
                    .map_err(|_| "CBOR negative integer is too large".to_owned())?;
                Ok(CborValue::Negative(-1 - value))
            }
            2 => {
                let len = self.read_len_usize(additional)?;
                Ok(CborValue::Bytes(self.read_exact(len)?.to_vec()))
            }
            3 => {
                let len = self.read_len_usize(additional)?;
                let bytes = self.read_exact(len)?;
                let text = std::str::from_utf8(bytes)
                    .map_err(|error| format!("CBOR text was not UTF-8: {error}"))?;
                Ok(CborValue::Text(text.to_owned()))
            }
            4 => {
                let len = self.read_len_usize(additional)?;
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    values.push(self.read_value()?);
                }
                Ok(CborValue::Array(values))
            }
            5 => {
                let len = self.read_len_usize(additional)?;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.read_value()?;
                    let value = self.read_value()?;
                    entries.push((key, value));
                }
                Ok(CborValue::Map(entries))
            }
            7 => match additional {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err("unsupported CBOR simple value".to_owned()),
            },
            _ => Err("unsupported CBOR major type".to_owned()),
        }
    }

    fn read_len_usize(&mut self, additional: u8) -> Result<usize, String> {
        let len = self.read_len(additional)?;
        usize::try_from(len).map_err(|_| "CBOR length is too large".to_owned())
    }

    fn read_len(&mut self, additional: u8) -> Result<u64, String> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.read_u8()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.read_array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.read_array()?))),
            27 => Ok(u64::from_be_bytes(self.read_array()?)),
            _ => Err("indefinite or reserved CBOR length is not supported".to_owned()),
        }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let Some(byte) = self.bytes.get(self.offset).copied() else {
            return Err("unexpected end of CBOR data".to_owned());
        };
        self.offset += 1;
        Ok(byte)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.read_exact(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "CBOR length overflow".to_owned())?;
        if end > self.bytes.len() {
            return Err("unexpected end of CBOR data".to_owned());
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
}

fn validate_access_token_response(claims: &JwtClaims, user: &UserRow) -> ValidateResponse {
    ValidateResponse {
        valid: true,
        kind: "access_token",
        sub: claims.sub.clone(),
        client_id: Some(claims.aud.clone()),
        scope: claims.scope.clone(),
        expires_at: Some(claims.exp),
        session_id: claims.sid.clone(),
        session: None,
        user: userinfo_response(user, claims.scope.as_deref()),
    }
}

fn validate_session_response(session: &SessionRow, user: &UserRow) -> ValidateResponse {
    ValidateResponse {
        valid: true,
        kind: "session",
        sub: user.id.clone(),
        client_id: session.client_id.clone(),
        scope: None,
        expires_at: Some(session.expires_at),
        session_id: Some(session.id.clone()),
        session: Some(session_info_response(session)),
        user: userinfo_response(user, Some("email profile")),
    }
}

#[cfg(target_arch = "wasm32")]
async fn validate_access_token_session(
    db: &worker::d1::D1Database,
    claims: &JwtClaims,
    now: i32,
) -> worker::Result<Result<(), String>> {
    let Some(session_id) = claims.sid.as_deref() else {
        return Ok(Ok(()));
    };
    let session = get_session(db, session_id).await?;
    Ok(validate_access_token_session_claims(
        claims,
        session.as_ref(),
        now,
    ))
}

fn validate_access_token_session_claims(
    claims: &JwtClaims,
    session: Option<&SessionRow>,
    now: i32,
) -> Result<(), String> {
    let Some(session_id) = claims.sid.as_deref() else {
        return Ok(());
    };
    let Some(session) = session else {
        return Err("access token session was not found".to_owned());
    };
    if session.id != session_id {
        return Err("access token session id did not match session row".to_owned());
    }
    if session.user_id != claims.sub {
        return Err("access token session user did not match subject".to_owned());
    }
    if session.client_id.as_deref() != Some(&claims.aud) {
        return Err("access token session client did not match audience".to_owned());
    }
    if !session_row_is_active(session, now) {
        return Err("access token session is no longer active".to_owned());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn validate_session_cors_origin(
    db: &worker::d1::D1Database,
    origin: Option<&str>,
    session: &SessionRow,
) -> worker::Result<Result<(), String>> {
    let Some(client_id) = session.client_id.as_deref() else {
        return validate_any_client_cors_origin(db, origin).await;
    };
    match active_client_allowed_origins(db, client_id).await? {
        Ok(allowed_origins) => Ok(validate_cors_origin(origin, &allowed_origins)),
        Err(error) => Ok(Err(error)),
    }
}

#[cfg(target_arch = "wasm32")]
async fn validate_any_client_cors_origin(
    db: &worker::d1::D1Database,
    origin: Option<&str>,
) -> worker::Result<Result<(), String>> {
    let Some(origin) = origin else {
        return Ok(Ok(()));
    };
    if origin_allowed_by_any_client(db, origin).await? {
        Ok(Ok(()))
    } else {
        Ok(Err(cors_disallowed_origin(origin)))
    }
}

fn validate_cors_origin(origin: Option<&str>, allowed_origins: &[String]) -> Result<(), String> {
    let Some(origin) = origin else {
        return Ok(());
    };
    if origin_allowed(allowed_origins, origin) {
        Ok(())
    } else {
        Err(cors_disallowed_origin(origin))
    }
}

fn cors_disallowed_origin(origin: &str) -> String {
    format!("Origin is not allowed for this client: {origin}")
}

fn origin_allowed(allowed_origins: &[String], origin: &str) -> bool {
    allowed_origins
        .iter()
        .any(|allowed_origin| allowed_origin == origin)
}

fn origin_allowed_in_client_origin_rows(
    rows: &[ClientOriginsRow],
    origin: &str,
) -> Result<bool, String> {
    for row in rows {
        if !row.allowed_origins_json.contains(origin) {
            continue;
        }
        let allowed_origins =
            parse_string_array_json(&row.allowed_origins_json, "allowed_origins_json")?;
        if origin_allowed(&allowed_origins, origin) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn active_client_allowed_origins_from_client(
    client: Option<Client>,
) -> Result<Vec<String>, String> {
    client
        .map(|client| client.allowed_origins)
        .ok_or_else(|| "client is not registered or is disabled".to_owned())
}

fn cors_path(path: &str) -> bool {
    matches!(
        path,
        "/oauth/token"
            | "/oauth/revoke"
            | "/oauth/introspect"
            | "/tokens"
            | "/client-branding"
            | "/userinfo"
            | "/session"
            | "/sessions"
            | "/profile"
            | "/identities/link"
            | "/identities"
            | "/passkeys/register/options"
            | "/passkeys/register/verify"
            | "/passkeys/register/finish"
            | "/passkeys/authenticate/options"
            | "/passkeys/authenticate/verify"
            | "/passkeys/authenticate/finish"
            | "/password/register"
            | "/password/login"
            | "/wallet/challenge"
            | "/wallet/verify"
            | "/magic-links"
            | "/magic-link/confirm"
            | "/magic-links/consume"
            | "/validate"
            | "/logout"
    )
}

fn cors_method_allowed(path: &str, method: &str) -> bool {
    match path {
        "/oauth/token" | "/oauth/revoke" | "/oauth/introspect" | "/tokens" => method == "POST",
        "/client-branding" | "/userinfo" | "/session" | "/validate" => method == "GET",
        "/profile" => method == "GET" || method == "PATCH",
        "/identities/link" => method == "POST",
        "/identities" => method == "GET" || method == "DELETE",
        "/passkeys/register/options"
        | "/passkeys/register/verify"
        | "/passkeys/register/finish"
        | "/passkeys/authenticate/options"
        | "/passkeys/authenticate/verify"
        | "/passkeys/authenticate/finish" => method == "POST",
        "/password/register" => method == "POST",
        "/password/login" => method == "POST",
        "/wallet/challenge" | "/wallet/verify" => method == "POST",
        "/magic-links" => method == "POST",
        "/magic-link/confirm" => method == "GET",
        "/magic-links/consume" => method == "POST",
        "/sessions" => method == "GET" || method == "DELETE",
        "/logout" => method == "GET" || method == "POST",
        _ => false,
    }
}

fn session_info_response(session: &SessionRow) -> SessionInfoResponse {
    SessionInfoResponse {
        id: session.id.clone(),
        client_id: session.client_id.clone(),
        created_at: session.created_at,
        expires_at: session.expires_at,
    }
}

fn session_row_is_active(session: &SessionRow, now: i32) -> bool {
    session.revoked_at.is_none() && session.expires_at > now
}

fn authorization_request_may_reuse_session(
    request: &AuthorizationRequest,
    session: &SessionRow,
    now: i32,
) -> bool {
    request.prompt.allows_session_reuse()
        && authorization_request_session_is_fresh(request, session, now)
}

fn authorization_request_session_is_fresh(
    request: &AuthorizationRequest,
    session: &SessionRow,
    now: i32,
) -> bool {
    request
        .max_age
        .map(|max_age| now.saturating_sub(session.created_at) <= max_age)
        .unwrap_or(true)
}

fn session_cookie(name: &str, value: &str, max_age_seconds: i32, domain: Option<&str>) -> String {
    let domain = cookie_domain_attribute(domain);
    format!(
        "{name}={value}; Path=/; Max-Age={max_age_seconds};{domain} HttpOnly; Secure; SameSite=None"
    )
}

fn clear_session_cookie(name: &str, domain: Option<&str>) -> String {
    let domain = cookie_domain_attribute(domain);
    format!("{name}=; Path=/; Max-Age=0;{domain} HttpOnly; Secure; SameSite=None")
}

fn transaction_cookie(name: &str, value: &str, max_age_seconds: i32) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age_seconds}; HttpOnly; Secure; SameSite=None")
}

fn clear_transaction_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None")
}

fn cookie_domain_attribute(domain: Option<&str>) -> String {
    let Some(domain) = domain.and_then(valid_cookie_domain) else {
        return String::new();
    };
    format!(" Domain={domain};")
}

fn valid_cookie_domain(domain: &str) -> Option<&str> {
    let domain = domain.trim();
    if domain.is_empty() {
        return None;
    }
    if domain
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        Some(domain)
    } else {
        None
    }
}

fn cookie_value(cookie_header: Option<&str>, name: &str) -> Option<String> {
    cookie_header?.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name && !value.is_empty()).then(|| value.to_owned())
    })
}

fn provider_callback_state_matches_transaction_cookie(
    callback_state: &str,
    cookie_state: Option<&str>,
) -> Result<(), ProviderCallbackError> {
    if cookie_state == Some(callback_state) {
        return Ok(());
    }
    Err(ProviderCallbackError::invalid_request(
        "provider callback state did not match browser transaction",
    ))
}

fn scope_contains(scope: Option<&str>, expected: &str) -> bool {
    scope
        .map(|scope| {
            scope
                .split_whitespace()
                .any(|candidate| candidate == expected)
        })
        .unwrap_or(false)
}

impl TokenIssue {
    fn from_auth_code(code: &AuthCodeRow) -> Self {
        Self {
            client_id: code.client_id.clone(),
            user_id: code.user_id.clone(),
            session_id: code.session_id.clone(),
            scope: code.scope.clone(),
            auth_time: Some(code.auth_time.unwrap_or(code.created_at)),
            nonce: code.nonce.clone(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: Vec::new(),
        }
    }

    fn from_native_provider(client_id: &str, user_id: &str, scope: &str, auth_time: i32) -> Self {
        Self {
            client_id: client_id.to_owned(),
            user_id: user_id.to_owned(),
            session_id: None,
            scope: scope.to_owned(),
            auth_time: Some(auth_time),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: Vec::new(),
        }
    }

    fn from_refresh_token(row: &RefreshTokenRow) -> Self {
        Self {
            client_id: row.client_id.clone(),
            user_id: row.user_id.clone(),
            session_id: row.session_id.clone(),
            scope: row.scope.clone(),
            auth_time: row.auth_time,
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: Vec::new(),
        }
    }

    fn with_user_claims(mut self, user: &UserTokenClaimsRow) -> Self {
        self.roles = user_token_roles(user);
        if scope_contains(Some(&self.scope), "email") {
            self.email = user.primary_email.clone();
            self.email_verified = user
                .primary_email
                .as_ref()
                .map(|_| user.email_verified != 0);
        }
        if scope_contains(Some(&self.scope), "profile") {
            self.name = user.display_name.clone();
            self.picture = user.picture_url.clone();
        }
        self
    }
}

fn user_token_roles(user: &UserTokenClaimsRow) -> Vec<String> {
    let mut roles = vec!["user".to_owned()];
    if user.admin_membership_active != 0 {
        roles.push("admin".to_owned());
    }
    roles
}

fn sign_jwt<T: Serialize>(signing_key: &Es256SigningKey, claims: &T) -> Result<String, String> {
    let header = JwtHeader {
        alg: "ES256",
        kid: signing_key.kid.clone(),
        typ: "JWT",
    };
    let signing_input = format!(
        "{}.{}",
        jwt_json_segment(&header)?,
        jwt_json_segment(claims)?
    );
    let signature: Signature = signing_key.signing_key.sign(signing_input.as_bytes());

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn apple_client_secret_from_config(
    config: &AppleClientSecretConfig,
    issued_at: i64,
) -> Result<(String, i64), String> {
    let signing_key = SigningKey::from_pkcs8_pem(&config.private_key_pem)
        .map_err(|error| format!("invalid Apple private key PEM: {error}"))?;
    let expires_at = issued_at + config.ttl_seconds;
    let token = apple_client_secret_from_signing_key(&signing_key, config, issued_at, expires_at)?;
    Ok((token, expires_at))
}

fn apple_client_secret_from_signing_key(
    signing_key: &SigningKey,
    config: &AppleClientSecretConfig,
    issued_at: i64,
    expires_at: i64,
) -> Result<String, String> {
    let header = AppleClientSecretHeader {
        alg: "ES256",
        kid: config.key_id.clone(),
    };
    let claims = AppleClientSecretClaims {
        iss: config.team_id.clone(),
        iat: issued_at,
        exp: expires_at,
        aud: "https://appleid.apple.com",
        sub: config.client_id.clone(),
    };
    let signing_input = format!(
        "{}.{}",
        jwt_json_segment(&header)?,
        jwt_json_segment(&claims)?
    );
    let signature: Signature = signing_key.sign(signing_input.as_bytes());

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn jwt_json_segment<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|json| URL_SAFE_NO_PAD.encode(json))
        .map_err(|error| format!("could not serialize JWT segment: {error}"))
}

fn jwks_response(
    signing_key: &Es256SigningKey,
    previous_public_jwks_json: Option<&str>,
) -> Result<JwksResponse, String> {
    let active_key = es256_public_jwk(signing_key)?;
    let mut seen_kids = vec![active_key.kid.clone()];
    let mut keys = vec![active_key];

    if let Some(previous_public_jwks_json) = previous_public_jwks_json {
        for key in parse_previous_public_jwks(previous_public_jwks_json)? {
            if seen_kids.iter().any(|kid| kid == &key.kid) {
                continue;
            }
            seen_kids.push(key.kid.clone());
            keys.push(key);
        }
    }

    Ok(JwksResponse { keys })
}

fn es256_public_jwk(signing_key: &Es256SigningKey) -> Result<JwkKey, String> {
    let verifying_key = signing_key.signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| "ES256 public key is missing x coordinate".to_owned())?;
    let y = point
        .y()
        .ok_or_else(|| "ES256 public key is missing y coordinate".to_owned())?;

    Ok(JwkKey {
        kty: "EC".to_owned(),
        key_use: "sig".to_owned(),
        kid: signing_key.kid.clone(),
        alg: "ES256".to_owned(),
        crv: "P-256".to_owned(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
    })
}

fn parse_previous_public_jwks(value: &str) -> Result<Vec<JwkKey>, String> {
    let jwks = serde_json::from_str::<JwksResponse>(value)
        .map_err(|error| format!("invalid JWT_PREVIOUS_PUBLIC_JWKS_JSON JWKS JSON: {error}"))?;
    for key in &jwks.keys {
        validate_previous_public_jwk(key)?;
    }
    Ok(jwks.keys)
}

fn validate_previous_public_jwk(key: &JwkKey) -> Result<(), String> {
    validate_es256_public_jwk(key, "JWT_PREVIOUS_PUBLIC_JWKS_JSON")
}

fn validate_es256_public_jwk(key: &JwkKey, source: &str) -> Result<(), String> {
    if key.kty != "EC" {
        return Err(format!("{source} only supports EC keys"));
    }
    if key.key_use != "sig" {
        return Err(format!("{source} keys must have use=sig"));
    }
    if key.alg != "ES256" {
        return Err(format!("{source} keys must have alg=ES256"));
    }
    if key.crv != "P-256" {
        return Err(format!("{source} keys must have crv=P-256"));
    }
    if key.kid.trim().is_empty() {
        return Err(format!("{source} keys must include kid"));
    }
    decode_public_jwk_coordinate(&key.x, "x", source)?;
    decode_public_jwk_coordinate(&key.y, "y", source)?;
    Ok(())
}

fn decode_public_jwk_coordinate(
    value: &str,
    field_name: &str,
    source: &str,
) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|error| format!("{source} key {field_name} must be base64url: {error}"))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!("{source} key {field_name} must decode to 32 bytes"))
            }
        })
}

#[cfg(target_arch = "wasm32")]
fn signing_key_from_env(env: &Env) -> worker::Result<Es256SigningKey> {
    Ok(signing_material_from_env(env)?.signing_key)
}

#[cfg(target_arch = "wasm32")]
fn signing_material_from_env(env: &Env) -> worker::Result<CachedSigningMaterial> {
    let kid =
        binding_value_from_env(env, "JWT_KEY_ID").unwrap_or_else(|| "zeroth-es256-1".to_owned());
    let private_key = binding_value_from_env(env, "JWT_ES256_PRIVATE_KEY")
        .ok_or_else(|| worker::Error::RustError("missing JWT_ES256_PRIVATE_KEY".to_owned()))?;
    let previous_public_jwks = binding_value_from_env(env, "JWT_PREVIOUS_PUBLIC_JWKS_JSON")
        .filter(|value| !value.trim().is_empty());

    SIGNING_MATERIAL_CACHE.with(|cache| {
        if let Some(material) = cache.borrow().as_ref() {
            if material.kid == kid
                && material.private_key == private_key
                && material.previous_public_jwks == previous_public_jwks
            {
                return Ok(material.clone());
            }
        }

        let signing_key =
            es256_signing_key_from_config(kid.clone(), &private_key).map_err(worker_error)?;
        let jwks =
            jwks_response(&signing_key, previous_public_jwks.as_deref()).map_err(worker_error)?;
        let material = CachedSigningMaterial {
            kid,
            private_key,
            previous_public_jwks,
            signing_key,
            jwks,
        };
        *cache.borrow_mut() = Some(material.clone());
        Ok(material)
    })
}

fn es256_signing_key_from_config(
    kid: impl Into<String>,
    private_key: &str,
) -> Result<Es256SigningKey, String> {
    let scalar = es256_private_scalar_from_config(private_key)?;
    let signing_key = SigningKey::from_slice(&scalar)
        .map_err(|error| format!("invalid ES256 private key: {error}"))?;
    Ok(Es256SigningKey {
        kid: kid.into(),
        signing_key,
    })
}

fn es256_private_scalar_from_config(private_key: &str) -> Result<Vec<u8>, String> {
    let trimmed = private_key.trim();
    if trimmed.starts_with('{') {
        let value = serde_json::from_str::<serde_json::Value>(trimmed)
            .map_err(|error| format!("invalid ES256 JWK JSON: {error}"))?;
        let d = value
            .get("d")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "ES256 JWK private key is missing d".to_owned())?;
        return decode_base64(d, "ES256 JWK d");
    }

    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex_to_bytes(trimmed);
    }

    decode_base64(trimmed, "ES256 private key")
}

fn decode_base64(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .map_err(|error| format!("{field_name} must be base64url, base64, or hex: {error}"))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!("{field_name} must decode to 32 bytes"))
            }
        })
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    hex_to_bytes_with_context(value, "ES256 private key")
}

fn hex_to_bytes_with_context(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err(format!("invalid hex {field_name}: odd length"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|error| format!("invalid hex {field_name}: {error}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn discovery_response(config: &ZerothServerConfig) -> DiscoveryResponse {
    let issuer = config.issuer();
    let revocation_endpoint = format!("{}/oauth/revoke", issuer.issuer);
    let introspection_endpoint = format!("{}/oauth/introspect", issuer.issuer);
    let end_session_endpoint = format!("{}/logout", issuer.issuer);
    DiscoveryResponse {
        issuer: issuer.issuer,
        authorization_endpoint: issuer.authorization_endpoint,
        token_endpoint: issuer.token_endpoint,
        revocation_endpoint,
        introspection_endpoint,
        end_session_endpoint,
        userinfo_endpoint: issuer.userinfo_endpoint,
        jwks_uri: issuer.jwks_uri,
        response_types_supported: vec!["code"],
        response_modes_supported: vec!["query"],
        prompt_values_supported: vec!["none", "login", "consent", "select_account"],
        grant_types_supported: vec![
            "authorization_code",
            "refresh_token",
            TOKEN_EXCHANGE_GRANT_TYPE,
        ],
        scopes_supported: vec!["openid", "profile", "email", "offline_access"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec![
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        revocation_endpoint_auth_methods_supported: vec![
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        introspection_endpoint_auth_methods_supported: vec![
            "client_secret_post",
            "client_secret_basic",
        ],
        id_token_signing_alg_values_supported: vec!["ES256"],
        subject_types_supported: vec!["public"],
        claims_supported: vec![
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "sid",
            "nonce",
            "email",
            "email_verified",
            "name",
            "picture",
            "roles",
        ],
        authorization_response_iss_parameter_supported: true,
    }
}

fn registered_client_from_row(row: ClientRow) -> Result<Option<RegisteredClient>, String> {
    let secret_hash = row.secret_hash.clone();
    let account_scope = client_account_scope_from_row(&row)?;
    let visible_login_methods = client_visible_login_methods_from_row(&row)?;
    Ok(client_from_row(row)?.map(|client| RegisteredClient {
        client,
        secret_hash,
        account_scope,
        visible_login_methods,
    }))
}

fn client_from_row(row: ClientRow) -> Result<Option<Client>, String> {
    if row.disabled_at.is_some() {
        return Ok(None);
    }

    Ok(Some(Client {
        id: ClientId(row.id),
        name: row.name,
        redirect_uris: parse_string_array_json(&row.redirect_uris_json, "redirect_uris_json")?,
        allowed_origins: parse_string_array_json(
            &row.allowed_origins_json,
            "allowed_origins_json",
        )?,
        allowed_email_domains: parse_string_array_json(
            &row.allowed_email_domains_json,
            "allowed_email_domains_json",
        )?,
        confidential: row.confidential != 0,
    }))
}

fn parse_string_array_json(value: &str, field_name: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(value)
        .map_err(|error| format!("client {field_name} must be a JSON string array: {error}"))
}

fn client_visible_login_methods_from_row(row: &ClientRow) -> Result<Vec<String>, String> {
    let value = row
        .visible_login_methods_json
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("[]");
    parse_string_array_json(value, "visible_login_methods_json")
        .and_then(|methods| validate_stored_visible_login_methods(&methods))
}

fn validate_stored_visible_login_methods(methods: &[String]) -> Result<Vec<String>, String> {
    let mut visible = Vec::with_capacity(methods.len());
    for method in methods {
        match method.trim() {
            LOGIN_METHOD_PASSKEY => push_unique(&mut visible, LOGIN_METHOD_PASSKEY.to_owned()),
            LOGIN_METHOD_MAGIC_LINK => {
                push_unique(&mut visible, LOGIN_METHOD_MAGIC_LINK.to_owned())
            }
            value => {
                return Err(format!(
                    "client visible_login_methods_json includes unsupported method: {value}"
                ))
            }
        }
    }
    Ok(visible)
}

#[cfg(target_arch = "wasm32")]
fn server_config(env: &Env, request_url: &url::Url) -> ZerothServerConfig {
    ZerothServerConfig {
        public_base_url: env_string(env, "PUBLIC_BASE_URL")
            .unwrap_or_else(|| request_url.origin().ascii_serialization()),
        cookie_name: env_string(env, "SESSION_COOKIE_NAME")
            .unwrap_or_else(|| ZerothServerConfig::default().cookie_name),
        cookie_domain: env_string(env, "SESSION_COOKIE_DOMAIN")
            .and_then(|value| valid_cookie_domain(&value).map(str::to_owned)),
        transaction_cookie_name: env_string(env, "TX_COOKIE_NAME")
            .unwrap_or_else(|| ZerothServerConfig::default().transaction_cookie_name),
    }
}

fn provider_id_from_url(url: &url::Url) -> Result<String, AuthorizationRequestError> {
    optional_provider_id_from_url(url)?
        .ok_or_else(|| AuthorizationRequestError::invalid_request("missing provider"))
}

fn optional_provider_id_from_url(
    url: &url::Url,
) -> Result<Option<String>, AuthorizationRequestError> {
    let Some(provider_id) = query_param(url, "provider") else {
        return Ok(None);
    };
    if !is_supported_provider_id(&provider_id) {
        return Err(AuthorizationRequestError::invalid_request(format!(
            "unsupported provider: {provider_id}"
        )));
    }
    Ok(Some(provider_id))
}

fn is_supported_provider_id(provider_id: &str) -> bool {
    matches!(
        provider_id,
        well_known::APPLE | well_known::GOOGLE | well_known::SPOTIFY
    )
}

fn provider_authorize_nonce(transaction: &AuthTransaction) -> Option<&str> {
    if !provider_uses_oidc_nonce(&transaction.provider_id.0) {
        return None;
    }
    transaction
        .provider_nonce
        .as_deref()
        .or(transaction.nonce.as_deref())
}

fn provider_uses_oidc_nonce(provider_id: &str) -> bool {
    matches!(provider_id, well_known::APPLE | well_known::GOOGLE)
}

fn authorization_login_request_present(url: &url::Url) -> bool {
    query_param(url, "response_type").is_some()
}

#[cfg(target_arch = "wasm32")]
fn session_login_client_id_from_url(
    env: &Env,
    url: &url::Url,
) -> Result<String, AuthorizationRequestError> {
    query_param(url, "client_id")
        .filter(|client_id| !client_id.is_empty())
        .or_else(|| env_string(env, "DEFAULT_LOGIN_CLIENT_ID"))
        .filter(|client_id| !client_id.is_empty())
        .ok_or_else(|| {
            AuthorizationRequestError::invalid_request(
                "missing client_id and DEFAULT_LOGIN_CLIENT_ID is not configured",
            )
        })
}

#[cfg(target_arch = "wasm32")]
fn provider_from_env(env: &Env, provider_id: &str) -> worker::Result<OAuthProvider> {
    match provider_id {
        well_known::APPLE => provider_client_id_from_env(env, "APPLE_CLIENT_ID")
            .map(OAuthProvider::apple)
            .ok_or_else(|| missing_provider_config("APPLE_CLIENT_ID")),
        well_known::GOOGLE => provider_client_id_from_env(env, "GOOGLE_CLIENT_ID")
            .map(OAuthProvider::google)
            .ok_or_else(|| missing_provider_config("GOOGLE_CLIENT_ID")),
        well_known::SPOTIFY => provider_client_id_from_env(env, "SPOTIFY_CLIENT_ID")
            .map(OAuthProvider::spotify)
            .ok_or_else(|| missing_provider_config("SPOTIFY_CLIENT_ID")),
        _ => Err(worker::Error::RustError(format!(
            "unknown provider: {provider_id}"
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
fn provider_client_secret_from_env(env: &Env, provider_id: &str) -> worker::Result<Option<String>> {
    if provider_id == well_known::APPLE {
        return apple_client_secret_from_env(env);
    }

    let binding = match provider_id {
        well_known::GOOGLE => "GOOGLE_CLIENT_SECRET",
        well_known::SPOTIFY => "SPOTIFY_CLIENT_SECRET",
        _ => {
            return Err(worker::Error::RustError(format!(
                "unknown provider: {provider_id}"
            )))
        }
    };

    secret_string(env, binding)
        .or_else(|| env_string(env, binding))
        .map(Some)
        .ok_or_else(|| missing_provider_config(binding))
}

#[cfg(target_arch = "wasm32")]
fn apple_client_secret_from_env(env: &Env) -> worker::Result<Option<String>> {
    if let Some(client_secret) =
        secret_string(env, "APPLE_CLIENT_SECRET").or_else(|| env_string(env, "APPLE_CLIENT_SECRET"))
    {
        return Ok(Some(client_secret));
    }

    let config = match apple_client_secret_config_from_env(env)? {
        Some(config) => config,
        None => {
            return Err(missing_provider_config(
                "APPLE_CLIENT_SECRET or APPLE_TEAM_ID/APPLE_KEY_ID/APPLE_PRIVATE_KEY",
            ))
        }
    };
    let now = i64::from(unix_timestamp_seconds());

    APPLE_CLIENT_SECRET_CACHE.with(|cache| {
        if let Some(cached) = cache.borrow().as_ref() {
            if cached.config == config
                && cached.expires_at - APPLE_CLIENT_SECRET_CACHE_REFRESH_SECONDS > now
            {
                return Ok(Some(cached.token.clone()));
            }
        }

        let (token, expires_at) =
            apple_client_secret_from_config(&config, now).map_err(worker_error)?;
        *cache.borrow_mut() = Some(CachedAppleClientSecret {
            config,
            token: token.clone(),
            expires_at,
        });
        Ok(Some(token))
    })
}

#[cfg(target_arch = "wasm32")]
fn apple_client_secret_config_from_env(
    env: &Env,
) -> worker::Result<Option<AppleClientSecretConfig>> {
    let Some(team_id) =
        secret_string(env, "APPLE_TEAM_ID").or_else(|| env_string(env, "APPLE_TEAM_ID"))
    else {
        return Ok(None);
    };
    let Some(key_id) =
        secret_string(env, "APPLE_KEY_ID").or_else(|| env_string(env, "APPLE_KEY_ID"))
    else {
        return Ok(None);
    };
    let Some(client_id) = provider_client_id_from_env(env, "APPLE_CLIENT_ID") else {
        return Ok(None);
    };
    let Some(private_key) = secret_string(env, "APPLE_PRIVATE_KEY")
        .or_else(|| secret_string(env, "APPLE_PRIVATE_KEY_PEM"))
        .or_else(|| env_string(env, "APPLE_PRIVATE_KEY"))
        .or_else(|| env_string(env, "APPLE_PRIVATE_KEY_PEM"))
    else {
        return Ok(None);
    };
    let ttl_seconds = apple_client_secret_ttl_seconds(
        env_string(env, "APPLE_CLIENT_SECRET_TTL_SECONDS").as_deref(),
    )
    .map_err(worker_error)?;

    Ok(Some(AppleClientSecretConfig {
        team_id,
        key_id,
        client_id,
        private_key_pem: normalize_private_key_pem_secret(&private_key),
        ttl_seconds,
    }))
}

fn apple_client_secret_ttl_seconds(value: Option<&str>) -> Result<i64, String> {
    let Some(value) = value else {
        return Ok(APPLE_CLIENT_SECRET_DEFAULT_TTL_SECONDS);
    };
    let ttl = value
        .trim()
        .parse::<i64>()
        .map_err(|error| format!("APPLE_CLIENT_SECRET_TTL_SECONDS must be an integer: {error}"))?;
    if !(60..=APPLE_CLIENT_SECRET_MAX_TTL_SECONDS).contains(&ttl) {
        return Err(format!(
            "APPLE_CLIENT_SECRET_TTL_SECONDS must be between 60 and {APPLE_CLIENT_SECRET_MAX_TTL_SECONDS}"
        ));
    }
    Ok(ttl)
}

fn normalize_private_key_pem_secret(value: &str) -> String {
    value.trim().replace("\\n", "\n")
}

#[cfg(target_arch = "wasm32")]
fn provider_client_id_from_env(env: &Env, name: &str) -> Option<String> {
    binding_value_from_env(env, name).filter(|value| config_value_configured(Some(value)))
}

#[cfg(target_arch = "wasm32")]
fn missing_provider_config(name: &str) -> worker::Error {
    worker::Error::RustError(format!("missing provider configuration: {name}"))
}

#[cfg(target_arch = "wasm32")]
fn binding_value_from_env(env: &Env, name: &str) -> Option<String> {
    secret_string(env, name).or_else(|| env_string(env, name))
}

#[cfg(target_arch = "wasm32")]
fn env_string(env: &Env, name: &str) -> Option<String> {
    env.var(name).map(|value| value.to_string()).ok()
}

#[cfg(target_arch = "wasm32")]
fn secret_string(env: &Env, name: &str) -> Option<String> {
    env.secret(name).map(|value| value.to_string()).ok()
}

#[cfg(target_arch = "wasm32")]
fn request_origin(request: &Request) -> worker::Result<Option<String>> {
    request_header(request, "Origin")
}

#[cfg(target_arch = "wasm32")]
fn request_origin_for_config(
    request: &Request,
    config: &ZerothServerConfig,
) -> worker::Result<Option<String>> {
    let origin = request_origin(request)?;
    Ok(origin.filter(|origin| !origin_matches_public_base_url(origin, &config.public_base_url)))
}

#[cfg(target_arch = "wasm32")]
fn audit_request_context(request: &Request) -> worker::Result<AuditRequestContext> {
    Ok(AuditRequestContext {
        ip_hash: request_header(request, "CF-Connecting-IP")?.map(|ip| hash_secret(&ip)),
        user_agent: request_header(request, "User-Agent")?,
    })
}

fn origin_matches_public_base_url(origin: &str, public_base_url: &str) -> bool {
    let Ok(base_url) = url::Url::parse(public_base_url) else {
        return false;
    };
    base_url.origin().ascii_serialization() == origin
}

#[cfg(target_arch = "wasm32")]
fn session_id_from_request(request: &Request, cookie_name: &str) -> worker::Result<Option<String>> {
    let cookie = request_header(request, "Cookie")?;
    Ok(cookie_value(cookie.as_deref(), cookie_name))
}

#[cfg(target_arch = "wasm32")]
fn transaction_state_from_request(
    request: &Request,
    cookie_name: &str,
) -> worker::Result<Option<String>> {
    let cookie = request_header(request, "Cookie")?;
    Ok(cookie_value(cookie.as_deref(), cookie_name))
}

#[cfg(target_arch = "wasm32")]
fn request_header(request: &Request, name: &str) -> worker::Result<Option<String>> {
    request
        .headers()
        .get(name)
        .map_err(|error| worker::Error::RustError(format!("could not read {name} header: {error}")))
}

#[cfg(target_arch = "wasm32")]
fn with_set_cookie(response: Response, cookie: &str) -> worker::Result<Response> {
    let headers = response.headers().clone();
    headers.append("Set-Cookie", cookie)?;
    Ok(response.with_headers(headers))
}

#[cfg(target_arch = "wasm32")]
fn with_refreshed_session_cookie(
    response: Response,
    current: Option<&CurrentSession>,
    config: &ZerothServerConfig,
    now: i32,
) -> worker::Result<Response> {
    let Some(current) = current else {
        return Ok(response);
    };
    let max_age_seconds = current.session.expires_at.saturating_sub(now);
    if max_age_seconds <= 0 {
        return Ok(response);
    }
    with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &current.session.id,
            max_age_seconds,
            config.cookie_domain.as_deref(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
fn with_cors_actual_headers(response: Response, origin: Option<&str>) -> worker::Result<Response> {
    if let Some(origin) = origin {
        set_cors_origin_headers(&response, origin)?;
    }
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn with_cors_preflight_headers(response: Response, origin: &str) -> worker::Result<Response> {
    set_cors_origin_headers(&response, origin)?;
    response
        .headers()
        .set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)?;
    response
        .headers()
        .set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)?;
    response
        .headers()
        .set("Access-Control-Max-Age", CORS_MAX_AGE_SECONDS)?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn set_cors_origin_headers(response: &Response, origin: &str) -> worker::Result<()> {
    response
        .headers()
        .set("Access-Control-Allow-Origin", origin)?;
    response
        .headers()
        .set("Access-Control-Allow-Credentials", "true")?;
    response
        .headers()
        .set("Cross-Origin-Resource-Policy", "cross-origin")?;
    response.headers().set("Vary", "Origin")?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn bearer_token_from_request(request: &Request) -> Result<String, String> {
    let authorization = request
        .headers()
        .get("Authorization")
        .map_err(|error| format!("could not read Authorization header: {error}"))?
        .ok_or_else(|| "missing bearer token".to_owned())?;
    bearer_token_from_authorization_header(Some(&authorization))?
        .ok_or_else(|| "missing bearer token".to_owned())
}

#[cfg(target_arch = "wasm32")]
async fn validate_admin_request(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
) -> Result<(), ClientManagementError> {
    authorize_admin_request(request, env, db, config, now)
        .await
        .map(|_| ())
}

#[cfg(target_arch = "wasm32")]
async fn authorize_admin_request(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
) -> Result<AdminAuthorization, ClientManagementError> {
    if validate_admin_bearer_request(request, env).is_ok() {
        return Ok(AdminAuthorization::BootstrapToken);
    }

    let Some(current) = current_session_from_request(request, db, config, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!(
                "could not validate admin session: {error}"
            ))
        })?
    else {
        return Err(ClientManagementError::unauthorized(
            "admin bearer token or allowed Zeroth session is required",
        ));
    };
    let Some(admin_user) = get_admin_user_row(db, &current.user.id, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!("could not load admin user: {error}"))
        })?
    else {
        return Err(ClientManagementError::unauthorized(
            "admin session user was not found",
        ));
    };

    if admin_user_allowed(env, &admin_user)
        || user_has_active_admin_membership(db, &admin_user.id)
            .await
            .map_err(|error| {
                ClientManagementError::server_error(format!(
                    "could not load admin membership: {error}"
                ))
            })?
    {
        Ok(AdminAuthorization::Session {
            user_id: current.user.id,
        })
    } else {
        Err(ClientManagementError::unauthorized(
            "admin session user is not allowlisted",
        ))
    }
}

#[cfg(target_arch = "wasm32")]
async fn authorize_admin_write_request(
    request: &mut Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
    route_family: &'static str,
    allow_bootstrap: bool,
    bootstrap_reason: &'static str,
) -> Result<AdminAuthorization, ClientManagementError> {
    if validate_admin_bearer_request(request, env).is_ok() {
        if !allow_bootstrap {
            return Err(ClientManagementError::unauthorized(
                "admin bootstrap token is not allowed for this route",
            ));
        }
        if !admin_bootstrap_allowed(request, env, db, now, bootstrap_reason, allow_bootstrap)
            .await?
        {
            return Err(ClientManagementError::unauthorized(
                "admin bootstrap token is not allowed",
            ));
        }
        return Ok(AdminAuthorization::BootstrapToken);
    }

    let Some(current) = current_session_from_request(request, db, config, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!(
                "could not validate admin session: {error}"
            ))
        })?
    else {
        return Err(ClientManagementError::unauthorized(
            "admin bearer token or allowed Zeroth session is required",
        ));
    };
    let csrf_token = csrf_token_from_request(request).await.map_err(|error| {
        ClientManagementError::server_error(format!("could not read CSRF token: {error}"))
    })?;
    let Some(admin_user) = get_admin_user_row(db, &current.user.id, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!("could not load admin user: {error}"))
        })?
    else {
        return Err(ClientManagementError::unauthorized(
            "admin session user was not found",
        ));
    };

    if !(admin_user_allowed(env, &admin_user)
        || user_has_active_admin_membership(db, &admin_user.id)
            .await
            .map_err(|error| {
                ClientManagementError::server_error(format!(
                    "could not load admin membership: {error}"
                ))
            })?)
    {
        return Err(ClientManagementError::unauthorized(
            "admin session user is not allowlisted",
        ));
    }

    if let Err(error) = validate_browser_session_mutation(
        request,
        env,
        db,
        config,
        current.session.client_id.as_deref(),
        &current.session.id,
        route_family,
        csrf_token.as_deref(),
        now,
    )
    .await?
    {
        return Err(ClientManagementError::unauthorized(error));
    }

    Ok(AdminAuthorization::Session {
        user_id: current.user.id,
    })
}

#[cfg(target_arch = "wasm32")]
async fn maybe_authorize_admin_write_request(
    request: &mut Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
    route_family: &'static str,
    allow_bootstrap: bool,
    bootstrap_reason: &'static str,
) -> Result<Option<AdminAuthorization>, ClientManagementError> {
    if validate_admin_bearer_request(request, env).is_ok() {
        if !allow_bootstrap {
            return Err(ClientManagementError::unauthorized(
                "admin bootstrap token is not allowed for this route",
            ));
        }
        if !admin_bootstrap_allowed(request, env, db, now, bootstrap_reason, allow_bootstrap)
            .await?
        {
            return Err(ClientManagementError::unauthorized(
                "admin bootstrap token is not allowed",
            ));
        }
        return Ok(Some(AdminAuthorization::BootstrapToken));
    }

    let Some(current) = current_session_from_request(request, db, config, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!(
                "could not validate admin session: {error}"
            ))
        })?
    else {
        return Ok(None);
    };
    let Some(admin_user) = get_admin_user_row(db, &current.user.id, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!("could not load admin user: {error}"))
        })?
    else {
        return Ok(None);
    };

    if !(admin_user_allowed(env, &admin_user)
        || user_has_active_admin_membership(db, &admin_user.id)
            .await
            .map_err(|error| {
                ClientManagementError::server_error(format!(
                    "could not load admin membership: {error}"
                ))
            })?)
    {
        return Ok(None);
    }

    let csrf_token = csrf_token_from_request(request).await.map_err(|error| {
        ClientManagementError::server_error(format!("could not read CSRF token: {error}"))
    })?;
    if let Err(error) = validate_browser_session_mutation(
        request,
        env,
        db,
        config,
        current.session.client_id.as_deref(),
        &current.session.id,
        route_family,
        csrf_token.as_deref(),
        now,
    )
    .await?
    {
        return Err(ClientManagementError::unauthorized(error));
    }

    Ok(Some(AdminAuthorization::Session {
        user_id: current.user.id,
    }))
}

#[cfg(target_arch = "wasm32")]
fn validate_admin_bearer_request(
    request: &Request,
    env: &Env,
) -> Result<(), ClientManagementError> {
    let token = bearer_token_from_request(request).map_err(ClientManagementError::unauthorized)?;
    let configured_hash = admin_token_hash_from_env(env)?;
    if admin_token_matches_config(&token, &configured_hash) {
        Ok(())
    } else {
        Err(ClientManagementError::unauthorized(
            "admin token did not match",
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn admin_user_allowed(env: &Env, user: &AdminUserRow) -> bool {
    let verified_email = if user.email_verified != 0 {
        user.primary_email.as_deref()
    } else {
        None
    };
    admin_identity_allowed(
        &user.id,
        verified_email,
        binding_value_from_env(env, "ADMIN_USER_IDS").as_deref(),
        binding_value_from_env(env, "ADMIN_EMAILS").as_deref(),
    )
}

fn admin_identity_allowed(
    user_id: &str,
    verified_email: Option<&str>,
    allowed_user_ids: Option<&str>,
    allowed_emails: Option<&str>,
) -> bool {
    token_list_contains(allowed_user_ids, user_id, false)
        || verified_email.is_some_and(|email| token_list_contains(allowed_emails, email, true))
}

fn admin_authorization_granted_by(authorization: &AdminAuthorization) -> String {
    match authorization {
        AdminAuthorization::BootstrapToken => "bootstrap_token".to_owned(),
        AdminAuthorization::Session { user_id } => format!("user:{user_id}"),
    }
}

fn token_list_contains(values: Option<&str>, needle: &str, ascii_case_insensitive: bool) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    values
        .unwrap_or_default()
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|value| !value.trim().is_empty())
        .any(|value| {
            let value = value.trim();
            if ascii_case_insensitive {
                value.eq_ignore_ascii_case(needle)
            } else {
                value == needle
            }
        })
}

#[cfg(target_arch = "wasm32")]
fn admin_token_hash_from_env(env: &Env) -> Result<String, ClientManagementError> {
    if binding_value_from_env(env, "ADMIN_TOKEN").is_some() {
        return Err(ClientManagementError::server_error(
            "ADMIN_TOKEN is not allowed; configure ADMIN_TOKEN_SHA256 instead",
        ));
    }
    let Some(hash) =
        secret_string(env, "ADMIN_TOKEN_SHA256").or_else(|| env_string(env, "ADMIN_TOKEN_SHA256"))
    else {
        return Err(ClientManagementError::server_error(
            "ADMIN_TOKEN_SHA256 is not configured",
        ));
    };
    normalize_admin_token_hash(&hash).map_err(ClientManagementError::server_error)
}

fn bearer_token_from_authorization_header(
    authorization: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(authorization) = authorization else {
        return Ok(None);
    };
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err("missing bearer token".to_owned());
    }
    Ok(Some(token.to_owned()))
}

#[cfg(target_arch = "wasm32")]
fn auth_error_json(error: &AuthorizationRequestError, status: u16) -> worker::Result<Response> {
    oauth_error_json(error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn provider_callback_error_json(
    error: &ProviderCallbackError,
    status: u16,
) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn provider_profile_error_json(
    error: &ProviderProfileError,
    status: u16,
) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn token_exchange_error_json(error: &TokenExchangeError, status: u16) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn client_management_error_json(error: &ClientManagementError) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, error.status)
}

#[cfg(target_arch = "wasm32")]
fn token_issuer_error_json(
    error: &str,
    message: impl Into<String>,
    status: u16,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let response = json_status_no_store(
        &serde_json::json!({
            "error": error,
            "message": message.into(),
        }),
        status,
    )?;
    with_cors_actual_headers(response, origin)
}

#[cfg(target_arch = "wasm32")]
fn issuer_token_ttl_seconds(value: Option<i32>) -> Result<i32, String> {
    let ttl_seconds = value.unwrap_or(300);
    if !(60..=600).contains(&ttl_seconds) {
        return Err("issuer token ttl_seconds must be between 60 and 600".to_owned());
    }
    Ok(ttl_seconds)
}

fn build_issuer_access_token_claims(
    issuer: &str,
    subject: &str,
    client_id: &str,
    audience: &str,
    issued_at: i64,
    ttl_seconds: i64,
    jti: String,
) -> ZerothIssuedAccessTokenClaims {
    ZerothIssuedAccessTokenClaims {
        iss: issuer.to_owned(),
        sub: subject.to_owned(),
        aud: audience.to_owned(),
        iat: issued_at,
        exp: issued_at + ttl_seconds,
        jti,
        client_id: client_id.to_owned(),
    }
}

#[cfg(target_arch = "wasm32")]
fn oauth_error_json(
    error: impl Into<String>,
    error_description: impl Into<String>,
    status: u16,
) -> worker::Result<Response> {
    json_status(
        &OAuthErrorResponse {
            error: error.into(),
            error_description: error_description.into(),
        },
        status,
    )
}

#[cfg(target_arch = "wasm32")]
fn with_retry_after_header(
    response: Response,
    retry_after_seconds: i32,
) -> worker::Result<Response> {
    response
        .headers()
        .set("Retry-After", &retry_after_seconds.max(1).to_string())?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_error_json(retry_after_seconds: i32) -> worker::Result<Response> {
    let response = json_status_no_store(
        &OAuthErrorResponse {
            error: "temporarily_unavailable".to_owned(),
            error_description: "too many requests".to_owned(),
        },
        429,
    )?;
    with_retry_after_header(response, retry_after_seconds)
}

#[cfg(target_arch = "wasm32")]
fn rate_limit_oauth_error_json(
    retry_after_seconds: i32,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let response = rate_limit_error_json(retry_after_seconds)?;
    with_cors_actual_headers(response, origin)
}

fn query_param(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn identity_reference_from_url(url: &url::Url) -> Result<IdentityReference, String> {
    let provider_id =
        query_param(url, "provider_id").ok_or_else(|| "missing provider_id".to_owned())?;
    let provider_subject = query_param(url, "provider_subject")
        .ok_or_else(|| "missing provider_subject".to_owned())?;

    validate_identity_provider_id(&provider_id)?;
    validate_identity_provider_subject(&provider_subject)?;

    Ok(IdentityReference {
        provider_id,
        provider_subject,
    })
}

fn validate_identity_provider_id(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("missing provider_id".to_owned());
    }
    if value.len() > 64 {
        return Err("provider_id is too long".to_owned());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("provider_id contains unsupported characters".to_owned());
    }
    Ok(())
}

fn validate_identity_provider_subject(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("missing provider_subject".to_owned());
    }
    if value.len() > 512 {
        return Err("provider_subject is too long".to_owned());
    }
    Ok(())
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    bytes_to_hex(&digest)
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn provider_token_request_body(request: &TokenExchangeRequest) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in &request.params {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

fn provider_token_response_to_set(
    response: ProviderTokenResponse,
) -> Result<ProviderTokenSet, ProviderTokenExchangeError> {
    if let Some(error) = response.error {
        return Err(ProviderTokenExchangeError {
            code: error,
            description: response
                .error_description
                .unwrap_or_else(|| "provider token exchange failed".to_owned()),
        });
    }

    if response.access_token.is_none() && response.id_token.is_none() {
        return Err(ProviderTokenExchangeError::invalid_response(
            "provider token response did not include an access_token or id_token",
        ));
    }

    Ok(ProviderTokenSet {
        access_token: response.access_token,
        id_token: response.id_token,
        refresh_token: response.refresh_token,
        expires_in: response.expires_in,
    })
}

#[cfg(target_arch = "wasm32")]
async fn resolve_provider_profile(
    provider: &OAuthProvider,
    token_set: &ProviderTokenSet,
    transaction: &AuthTransaction,
    callback: &ProviderCallback,
) -> Result<ResolvedProviderProfile, ProviderProfileError> {
    match provider.id().0.as_str() {
        well_known::SPOTIFY => fetch_spotify_profile(provider, token_set).await,
        well_known::APPLE | well_known::GOOGLE => {
            resolve_oidc_provider_profile(provider, token_set, transaction, callback).await
        }
        provider_id => Err(ProviderProfileError::invalid_response(format!(
            "unsupported provider profile source: {provider_id}"
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_oidc_provider_profile(
    provider: &OAuthProvider,
    token_set: &ProviderTokenSet,
    transaction: &AuthTransaction,
    callback: &ProviderCallback,
) -> Result<ResolvedProviderProfile, ProviderProfileError> {
    let id_token = token_set
        .id_token
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("missing provider id_token"))?;
    let now = unix_timestamp_seconds();
    let jwks = cached_provider_jwks(&provider.id().0, now).await?;
    let verified = verify_provider_id_token_with_web_crypto(
        id_token,
        &jwks,
        ProviderIdTokenValidation {
            provider_id: &provider.id().0,
            client_id: &provider.config().client_id,
            nonce: provider_authorize_nonce(transaction),
            now,
        },
    )
    .await?;
    let claims = verified.claims;
    let apple_user = if provider.id().0 == well_known::APPLE {
        callback
            .apple_user_json
            .as_deref()
            .map(apple_callback_user_from_json)
            .transpose()?
    } else {
        None
    };
    let display_name = claims.name.or_else(|| {
        apple_user
            .as_ref()
            .and_then(apple_callback_user_display_name)
    });
    let raw_profile_json = merge_oidc_raw_profile_json(
        &verified.raw_claims_json,
        apple_user
            .as_ref()
            .and_then(|_| callback.apple_user_json.as_deref()),
    );
    let source = ProviderProfileSource::OidcClaims {
        sub: claims.sub,
        email: claims.email,
        email_verified: boolish_claim(claims.email_verified.as_ref()).unwrap_or(false),
        name: display_name,
        picture: claims.picture,
    };
    let profile = provider
        .normalize_profile(source)
        .map_err(|error| ProviderProfileError {
            code: error.code,
            description: error.description,
        })?;

    Ok(ResolvedProviderProfile {
        profile,
        raw_profile_json,
    })
}

fn apple_callback_user_from_json(value: &str) -> Result<AppleCallbackUser, ProviderProfileError> {
    serde_json::from_str(value).map_err(|error| {
        ProviderProfileError::invalid_response(format!("invalid Apple callback user JSON: {error}"))
    })
}

fn apple_callback_user_display_name(user: &AppleCallbackUser) -> Option<String> {
    let name = user.name.as_ref()?;
    let first = name.first_name.as_deref().map(str::trim).unwrap_or("");
    let last = name.last_name.as_deref().map(str::trim).unwrap_or("");
    let display_name = match (first.is_empty(), last.is_empty()) {
        (false, false) => format!("{first} {last}"),
        (false, true) => first.to_owned(),
        (true, false) => last.to_owned(),
        (true, true) => String::new(),
    };
    (!display_name.is_empty()).then_some(display_name)
}

fn merge_oidc_raw_profile_json(claims_json: &str, apple_user_json: Option<&str>) -> Option<String> {
    let Some(apple_user_json) = apple_user_json else {
        return Some(claims_json.to_owned());
    };
    let claims = serde_json::from_str::<serde_json::Value>(claims_json).ok()?;
    let apple_user = serde_json::from_str::<serde_json::Value>(apple_user_json).ok()?;
    serde_json::to_string(&serde_json::json!({
        "id_token_claims": claims,
        "apple_user": apple_user,
    }))
    .ok()
}

#[cfg(target_arch = "wasm32")]
async fn cached_provider_jwks(
    provider_id: &str,
    now: i32,
) -> Result<ProviderJwksResponse, ProviderProfileError> {
    if let Some(jwks) = PROVIDER_JWKS_CACHE.with(|cache| cache.borrow_mut().get(provider_id, now)) {
        return Ok(jwks);
    }

    let jwks = fetch_provider_jwks(provider_id).await?;
    PROVIDER_JWKS_CACHE.with(|cache| cache.borrow_mut().put(provider_id, jwks.clone(), now));
    Ok(jwks)
}

#[cfg(target_arch = "wasm32")]
async fn fetch_provider_jwks(
    provider_id: &str,
) -> Result<ProviderJwksResponse, ProviderProfileError> {
    let endpoint = provider_jwks_endpoint(provider_id)?;
    let headers = Headers::new();
    headers
        .set("Accept", "application/json")
        .map_err(ProviderProfileError::worker)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let outbound = Request::new_with_init(endpoint, &init).map_err(ProviderProfileError::worker)?;
    let mut response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(ProviderProfileError::worker)?;
    let status = response.status_code();
    let jwks = response
        .json::<ProviderJwksResponse>()
        .await
        .map_err(ProviderProfileError::worker)?;
    if !(200..300).contains(&status) {
        return Err(ProviderProfileError::invalid_response(format!(
            "provider JWKS endpoint returned HTTP {status}"
        )));
    }

    Ok(jwks)
}

fn provider_jwks_endpoint(provider_id: &str) -> Result<&'static str, ProviderProfileError> {
    match provider_id {
        well_known::APPLE => Ok("https://appleid.apple.com/auth/keys"),
        well_known::GOOGLE => Ok("https://www.googleapis.com/oauth2/v3/certs"),
        _ => Err(ProviderProfileError::invalid_response(format!(
            "provider does not expose OIDC JWKS: {provider_id}"
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
async fn verify_provider_id_token_with_web_crypto(
    id_token: &str,
    jwks: &ProviderJwksResponse,
    validation: ProviderIdTokenValidation<'_>,
) -> Result<VerifiedProviderIdToken, ProviderProfileError> {
    let segments = jwt_segments(id_token)?;
    let header = decode_jwt_segment::<ProviderJwtHeader>(segments[0])?;
    if header.alg != "RS256" {
        return Err(ProviderProfileError::invalid_response(format!(
            "unsupported provider id_token alg: {}",
            header.alg
        )));
    }

    let jwk = provider_jwk_for_header(jwks, &header)?;
    verify_rs256_signature_with_web_crypto(
        jwk,
        &format!("{}.{}", segments[0], segments[1]),
        segments[2],
    )
    .await?;

    verified_provider_id_token_from_segments(&segments, validation)
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn verify_provider_id_token(
    id_token: &str,
    jwks: &ProviderJwksResponse,
    validation: ProviderIdTokenValidation<'_>,
) -> Result<VerifiedProviderIdToken, ProviderProfileError> {
    let segments = jwt_segments(id_token)?;
    let header = decode_jwt_segment::<ProviderJwtHeader>(segments[0])?;
    if header.alg != "RS256" {
        return Err(ProviderProfileError::invalid_response(format!(
            "unsupported provider id_token alg: {}",
            header.alg
        )));
    }

    let key = provider_rsa_key_for_header(jwks, &header)?;
    verify_rs256_signature(
        &key,
        &format!("{}.{}", segments[0], segments[1]),
        segments[2],
    )?;

    verified_provider_id_token_from_segments(&segments, validation)
}

fn verified_provider_id_token_from_segments(
    segments: &[&str],
    validation: ProviderIdTokenValidation<'_>,
) -> Result<VerifiedProviderIdToken, ProviderProfileError> {
    let raw_claims_json =
        String::from_utf8(decode_jwt_segment_bytes(segments[1])?).map_err(|error| {
            ProviderProfileError::invalid_response(format!(
                "id_token claims are not UTF-8: {error}"
            ))
        })?;
    let claims =
        serde_json::from_str::<ProviderIdTokenClaims>(&raw_claims_json).map_err(|error| {
            ProviderProfileError::invalid_response(format!("invalid id_token claims: {error}"))
        })?;
    validate_provider_id_token_claims(&claims, validation)?;

    Ok(VerifiedProviderIdToken {
        claims,
        raw_claims_json,
    })
}

fn jwt_segments(jwt: &str) -> Result<Vec<&str>, ProviderProfileError> {
    let segments = jwt.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(ProviderProfileError::invalid_response(
            "id_token must have three non-empty JWT segments",
        ));
    }
    Ok(segments)
}

fn decode_jwt_segment<T: serde::de::DeserializeOwned>(
    segment: &str,
) -> Result<T, ProviderProfileError> {
    let bytes = decode_jwt_segment_bytes(segment)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ProviderProfileError::invalid_response(format!("invalid JWT JSON: {error}"))
    })
}

fn decode_jwt_segment_bytes(segment: &str) -> Result<Vec<u8>, ProviderProfileError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .map_err(|error| {
            ProviderProfileError::invalid_response(format!(
                "invalid JWT base64url segment: {error}"
            ))
        })
}

fn provider_jwk_for_header<'a>(
    jwks: &'a ProviderJwksResponse,
    header: &ProviderJwtHeader,
) -> Result<&'a ProviderJwk, ProviderProfileError> {
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("id_token header is missing kid"))?;
    jwks.keys
        .iter()
        .find(|key| {
            key.kid.as_deref() == Some(kid)
                && key.kty == "RSA"
                && key.key_use.as_deref().unwrap_or("sig") == "sig"
                && key.alg.as_deref().unwrap_or("RS256") == "RS256"
        })
        .ok_or_else(|| {
            ProviderProfileError::invalid_response("matching provider JWKS key was not found")
        })
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn provider_rsa_key_for_header(
    jwks: &ProviderJwksResponse,
    header: &ProviderJwtHeader,
) -> Result<RsaPublicKey, ProviderProfileError> {
    let jwk = provider_jwk_for_header(jwks, header)?;
    let n = decode_jwk_rsa_part(jwk.n.as_deref(), "n")?;
    let e = decode_jwk_rsa_part(jwk.e.as_deref(), "e")?;

    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).map_err(|error| {
        ProviderProfileError::invalid_response(format!("invalid provider RSA JWK: {error}"))
    })
}

#[cfg(target_arch = "wasm32")]
async fn verify_rs256_signature_with_web_crypto(
    jwk: &ProviderJwk,
    signing_input: &str,
    signature_segment: &str,
) -> Result<(), ProviderProfileError> {
    let signature = decode_jwt_segment_bytes(signature_segment)?;
    let subtle = worker_global_crypto_subtle()?;
    let algorithm = rsa_pkcs1_sha256_algorithm()?;
    let key_data = provider_jwk_key_data(jwk)?;
    let key_usages = single_js_string_array("verify");

    let key_value = JsFuture::from(
        subtle
            .import_key_with_object("jwk", &key_data, &algorithm, false, &key_usages)
            .map_err(|error| js_profile_error("could not import provider RSA JWK", error))?,
    )
    .await
    .map_err(|error| js_profile_error("provider RSA JWK import failed", error))?;
    let key = key_value
        .dyn_into::<worker::web_sys::CryptoKey>()
        .map_err(|error| js_profile_error("provider RSA JWK did not produce a CryptoKey", error))?;

    let verified = JsFuture::from(
        subtle
            .verify_with_object_and_u8_array_and_u8_array(
                &algorithm,
                &key,
                &signature,
                signing_input.as_bytes(),
            )
            .map_err(|error| js_profile_error("could not verify provider id_token", error))?,
    )
    .await
    .map_err(|error| js_profile_error("provider id_token verification failed", error))?;

    if verified.as_bool() == Some(true) {
        Ok(())
    } else {
        Err(ProviderProfileError::invalid_response(
            "provider id_token signature did not verify",
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn worker_global_crypto_subtle() -> Result<worker::web_sys::SubtleCrypto, ProviderProfileError> {
    let global: worker::web_sys::WorkerGlobalScope = worker::js_sys::global().unchecked_into();
    let crypto = global
        .crypto()
        .map_err(|error| js_profile_error("could not access Worker crypto", error))?;
    Ok(crypto.subtle())
}

#[cfg(target_arch = "wasm32")]
fn rsa_pkcs1_sha256_algorithm() -> Result<worker::js_sys::Object, ProviderProfileError> {
    let algorithm = worker::js_sys::Object::new();
    set_js_string_property(&algorithm, "name", "RSASSA-PKCS1-v1_5")?;
    set_js_string_property(&algorithm, "hash", "SHA-256")?;
    Ok(algorithm)
}

#[cfg(target_arch = "wasm32")]
fn provider_jwk_key_data(
    jwk: &ProviderJwk,
) -> Result<worker::js_sys::Object, ProviderProfileError> {
    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("provider RSA JWK is missing n"))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("provider RSA JWK is missing e"))?;

    let key_data = worker::js_sys::Object::new();
    set_js_string_property(&key_data, "kty", "RSA")?;
    set_js_string_property(&key_data, "n", n)?;
    set_js_string_property(&key_data, "e", e)?;
    set_js_string_property(&key_data, "alg", "RS256")?;
    set_js_string_property(&key_data, "use", "sig")?;
    set_js_value_property(&key_data, "ext", &JsValue::from_bool(true))?;
    set_js_value_property(&key_data, "key_ops", &single_js_string_array("verify"))?;
    Ok(key_data)
}

#[cfg(target_arch = "wasm32")]
fn single_js_string_array(value: &str) -> JsValue {
    let array = worker::js_sys::Array::new();
    array.push(&JsValue::from_str(value));
    array.into()
}

#[cfg(target_arch = "wasm32")]
fn set_js_string_property(
    target: &worker::js_sys::Object,
    name: &str,
    value: &str,
) -> Result<(), ProviderProfileError> {
    set_js_value_property(target, name, &JsValue::from_str(value))
}

#[cfg(target_arch = "wasm32")]
fn set_js_value_property(
    target: &worker::js_sys::Object,
    name: &str,
    value: &JsValue,
) -> Result<(), ProviderProfileError> {
    let ok = worker::js_sys::Reflect::set(target, &JsValue::from_str(name), value)
        .map_err(|error| js_profile_error("could not set WebCrypto parameter", error))?;
    if ok {
        Ok(())
    } else {
        Err(ProviderProfileError::invalid_response(format!(
            "could not set WebCrypto parameter: {name}"
        )))
    }
}

#[cfg(target_arch = "wasm32")]
fn js_profile_error(context: &str, error: JsValue) -> ProviderProfileError {
    let detail = error
        .dyn_ref::<worker::js_sys::Error>()
        .map(|error| error.message().into())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "JavaScript error".to_owned());
    ProviderProfileError::invalid_response(format!("{context}: {detail}"))
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn decode_jwk_rsa_part(value: Option<&str>, name: &str) -> Result<Vec<u8>, ProviderProfileError> {
    let value = value.ok_or_else(|| {
        ProviderProfileError::invalid_response(format!("provider RSA JWK is missing {name}"))
    })?;
    decode_jwt_segment_bytes(value)
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn verify_rs256_signature(
    key: &RsaPublicKey,
    signing_input: &str,
    signature_segment: &str,
) -> Result<(), ProviderProfileError> {
    let signature_bytes = decode_jwt_segment_bytes(signature_segment)?;
    let signature =
        RsaPkcs1v15Signature::try_from(signature_bytes.as_slice()).map_err(|error| {
            ProviderProfileError::invalid_response(format!("invalid RS256 signature: {error}"))
        })?;
    let verifying_key = RsaPkcs1v15VerifyingKey::<Sha256>::new(key.clone());
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            ProviderProfileError::invalid_response("provider id_token signature did not verify")
        })
}

fn validate_provider_id_token_claims(
    claims: &ProviderIdTokenClaims,
    validation: ProviderIdTokenValidation<'_>,
) -> Result<(), ProviderProfileError> {
    if !provider_issuer_matches(validation.provider_id, &claims.iss) {
        return Err(ProviderProfileError::invalid_response(format!(
            "id_token issuer did not match provider: {}",
            claims.iss
        )));
    }

    if !claims.aud.contains(validation.client_id) {
        return Err(ProviderProfileError::invalid_response(
            "id_token audience did not include provider client_id",
        ));
    }

    if claims.exp <= i64::from(validation.now) {
        return Err(ProviderProfileError::invalid_response(
            "id_token has expired",
        ));
    }

    if let Some(expected_nonce) = validation.nonce {
        if claims.nonce.as_deref() != Some(expected_nonce) {
            return Err(ProviderProfileError::invalid_response(
                "id_token nonce did not match authorization request",
            ));
        }
    }

    if claims.sub.is_empty() {
        return Err(ProviderProfileError::invalid_response(
            "id_token subject is empty",
        ));
    }

    Ok(())
}

fn provider_issuer_matches(provider_id: &str, issuer: &str) -> bool {
    match provider_id {
        well_known::APPLE => issuer == "https://appleid.apple.com",
        well_known::GOOGLE => {
            issuer == "https://accounts.google.com" || issuer == "accounts.google.com"
        }
        _ => false,
    }
}

impl AudienceClaim {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(value) => value == audience,
            Self::Many(values) => values.iter().any(|value| value == audience),
        }
    }
}

fn boolish_claim(value: Option<&serde_json::Value>) -> Option<bool> {
    match value {
        Some(serde_json::Value::Bool(value)) => Some(*value),
        Some(serde_json::Value::String(value)) if value == "true" => Some(true),
        Some(serde_json::Value::String(value)) if value == "false" => Some(false),
        Some(serde_json::Value::Number(value)) => value.as_i64().map(|value| value != 0),
        _ => None,
    }
}

fn deserialize_default_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

#[cfg(target_arch = "wasm32")]
async fn fetch_spotify_profile(
    provider: &OAuthProvider,
    token_set: &ProviderTokenSet,
) -> Result<ResolvedProviderProfile, ProviderProfileError> {
    let endpoint = provider
        .config()
        .profile_endpoint
        .as_deref()
        .ok_or_else(|| {
            ProviderProfileError::invalid_response("missing Spotify profile endpoint")
        })?;
    let access_token = token_set
        .access_token
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("missing Spotify access token"))?;

    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {access_token}"))
        .map_err(ProviderProfileError::worker)?;
    headers
        .set("Accept", "application/json")
        .map_err(ProviderProfileError::worker)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let outbound = Request::new_with_init(endpoint, &init).map_err(ProviderProfileError::worker)?;
    let mut response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(ProviderProfileError::worker)?;
    let status = response.status_code();
    let raw_profile_json = response
        .text()
        .await
        .map_err(ProviderProfileError::worker)?;
    if !(200..300).contains(&status) {
        return Err(ProviderProfileError::invalid_response(format!(
            "Spotify profile endpoint returned HTTP {status}: {}",
            response_body_excerpt(&raw_profile_json)
        )));
    }

    let spotify_profile =
        serde_json::from_str::<SpotifyApiProfile>(&raw_profile_json).map_err(|error| {
            ProviderProfileError::invalid_response(format!("invalid Spotify profile JSON: {error}"))
        })?;
    let source = spotify_profile_source(spotify_profile)?;
    let profile = provider
        .normalize_profile(source)
        .map_err(|error| ProviderProfileError {
            code: error.code,
            description: error.description,
        })?;

    Ok(ResolvedProviderProfile {
        profile,
        raw_profile_json: Some(raw_profile_json),
    })
}

fn spotify_profile_source(
    profile: SpotifyApiProfile,
) -> Result<ProviderProfileSource, ProviderProfileError> {
    let subject = spotify_profile_subject(&profile)?;

    Ok(ProviderProfileSource::SpotifyProfile {
        id: subject,
        email: profile.email,
        display_name: profile.display_name,
        image_url: spotify_profile_image_url(&profile.images),
    })
}

fn spotify_profile_subject(profile: &SpotifyApiProfile) -> Result<String, ProviderProfileError> {
    profile
        .account_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| (!profile.id.is_empty()).then_some(profile.id.as_str()))
        .map(str::to_owned)
        .ok_or_else(|| {
            ProviderProfileError::invalid_response(
                "Spotify profile did not include an account_id or id",
            )
        })
}

fn spotify_profile_image_url(images: &[SpotifyApiImage]) -> Option<String> {
    images.iter().find_map(|image| image.url.clone())
}

fn response_body_excerpt(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "empty response body".to_owned();
    }
    let excerpt = trimmed.chars().take(512).collect::<String>();
    if trimmed.chars().count() > 512 {
        format!("{excerpt}...")
    } else {
        excerpt
    }
}

#[cfg(target_arch = "wasm32")]
async fn exchange_provider_code(
    request: TokenExchangeRequest,
) -> Result<ProviderTokenSet, ProviderTokenExchangeError> {
    if matches!(request.token_auth, TokenAuth::None) {
        return Err(ProviderTokenExchangeError::invalid_request(
            "unsupported provider token auth mode",
        ));
    }

    let body = provider_token_request_body(&request);
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(ProviderTokenExchangeError::worker)?;
    headers
        .set("Accept", "application/json")
        .map_err(ProviderTokenExchangeError::worker)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));

    let outbound = Request::new_with_init(&request.endpoint, &init)
        .map_err(ProviderTokenExchangeError::worker)?;
    let mut response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(ProviderTokenExchangeError::worker)?;
    let status = response.status_code();
    let token_response = response
        .json::<ProviderTokenResponse>()
        .await
        .map_err(ProviderTokenExchangeError::worker)?;

    let token_set = provider_token_response_to_set(token_response)?;
    if !(200..300).contains(&status) {
        return Err(ProviderTokenExchangeError::invalid_response(format!(
            "provider token endpoint returned HTTP {status}"
        )));
    }
    Ok(token_set)
}

#[cfg(target_arch = "wasm32")]
fn d1_optional_text(value: Option<&str>) -> worker::d1::D1Type<'_> {
    match value {
        Some(value) => worker::d1::D1Type::Text(value),
        None => worker::d1::D1Type::Null,
    }
}

#[cfg(target_arch = "wasm32")]
fn d1_optional_integer(value: Option<i32>) -> worker::d1::D1Type<'static> {
    match value {
        Some(value) => worker::d1::D1Type::Integer(value),
        None => worker::d1::D1Type::Null,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn d1_changes_exactly_one(changes: Option<usize>) -> bool {
    changes == Some(1)
}

#[cfg(target_arch = "wasm32")]
fn d1_result_changed_one(result: worker::d1::D1Result) -> worker::Result<bool> {
    let meta = result
        .meta()?
        .ok_or_else(|| worker_error("D1 result metadata was not populated".to_owned()))?;
    Ok(d1_changes_exactly_one(meta.changes))
}

#[cfg(target_arch = "wasm32")]
fn d1_result_changed_any(result: worker::d1::D1Result) -> worker::Result<bool> {
    let meta = result
        .meta()?
        .ok_or_else(|| worker_error("D1 result metadata was not populated".to_owned()))?;
    Ok(meta.changes.is_some_and(|changes| changes > 0))
}

#[cfg(target_arch = "wasm32")]
fn unix_timestamp_seconds() -> i32 {
    (worker::js_sys::Date::now() / 1000.0) as i32
}

fn unix_seconds_to_system_time(seconds: i32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds as u64)
}

fn system_time_to_unix_seconds(time: SystemTime) -> Result<i32, String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "time is before unix epoch".to_owned())?
        .as_secs();
    i32::try_from(seconds).map_err(|_| "time exceeds D1 integer range".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn system_time_to_d1_integer(time: SystemTime) -> worker::Result<i32> {
    system_time_to_unix_seconds(time).map_err(worker_error)
}

impl ProviderCallbackError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn access_denied(description: impl Into<String>) -> Self {
        Self {
            code: "access_denied".to_owned(),
            description: description.into(),
        }
    }
}

fn provider_callback_error_from_token_exchange_error(
    error: &ProviderTokenExchangeError,
) -> ProviderCallbackError {
    ProviderCallbackError {
        code: "temporarily_unavailable".to_owned(),
        description: format!(
            "provider token exchange failed ({}): {}",
            error.code, error.description
        ),
    }
}

fn provider_callback_error_from_profile_error(
    error: &ProviderProfileError,
) -> ProviderCallbackError {
    ProviderCallbackError {
        code: "temporarily_unavailable".to_owned(),
        description: format!(
            "provider profile lookup failed ({}): {}",
            error.code, error.description
        ),
    }
}

impl ProviderTokenExchangeError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn invalid_response(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_response".to_owned(),
            description: description.into(),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn worker(error: worker::Error) -> Self {
        Self {
            code: "provider_exchange_failed".to_owned(),
            description: error.to_string(),
        }
    }
}

impl ProviderProfileError {
    fn invalid_response(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_response".to_owned(),
            description: description.into(),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn worker(error: worker::Error) -> Self {
        Self {
            code: "provider_profile_failed".to_owned(),
            description: error.to_string(),
        }
    }
}

impl IdentityLinkError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn conflict(description: impl Into<String>) -> Self {
        Self {
            code: "identity_link_conflict".to_owned(),
            description: description.into(),
        }
    }
}

impl ProfilePatchError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: 400,
        }
    }

    fn payload_too_large(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: 413,
        }
    }
}

impl ClientManagementError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
            status: 400,
        }
    }

    fn unauthorized(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_token".to_owned(),
            description: description.into(),
            status: 401,
        }
    }

    fn not_found(description: impl Into<String>) -> Self {
        Self {
            code: "not_found".to_owned(),
            description: description.into(),
            status: 404,
        }
    }

    fn payload_too_large(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
            status: 413,
        }
    }

    fn server_error(description: impl Into<String>) -> Self {
        Self {
            code: "server_error".to_owned(),
            description: description.into(),
            status: 503,
        }
    }
}

impl TokenExchangeError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn invalid_client(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_client".to_owned(),
            description: description.into(),
        }
    }

    fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_grant".to_owned(),
            description: description.into(),
        }
    }

    fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self {
            code: "unsupported_grant_type".to_owned(),
            description: description.into(),
        }
    }

    fn unsupported_token_type(description: impl Into<String>) -> Self {
        Self {
            code: "unsupported_token_type".to_owned(),
            description: description.into(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn worker_error(error: String) -> worker::Error {
    worker::Error::RustError(error)
}

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
#[worker::wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues, catch)]
    fn get_random_values(buf: &mut [u8]) -> Result<(), worker::wasm_bindgen::JsValue>;
}

#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
#[worker::wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues, catch)]
    fn get_random_values(
        buf: &worker::js_sys::Uint8Array,
    ) -> Result<(), worker::wasm_bindgen::JsValue>;
}

#[cfg(target_arch = "wasm32")]
const MAX_RANDOM_BYTES: usize = 65_536;

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
fn fill_random(bytes: &mut [u8]) -> worker::Result<()> {
    for chunk in bytes.chunks_mut(MAX_RANDOM_BYTES) {
        get_random_values(chunk)
            .map_err(|_| worker::Error::RustError("WebCrypto getRandomValues failed".to_owned()))?;
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
fn fill_random(bytes: &mut [u8]) -> worker::Result<()> {
    let buffer_len = usize::min(bytes.len(), MAX_RANDOM_BYTES);
    let buffer_len = u32::try_from(buffer_len)
        .map_err(|_| worker::Error::RustError("random buffer is too large".to_owned()))?;
    let buffer = worker::js_sys::Uint8Array::new_with_length(buffer_len);

    for chunk in bytes.chunks_mut(buffer_len as usize) {
        let chunk_len = u32::try_from(chunk.len())
            .map_err(|_| worker::Error::RustError("random chunk is too large".to_owned()))?;
        let sub_buffer = if chunk_len == buffer_len {
            buffer.clone()
        } else {
            buffer.subarray(0, chunk_len)
        };

        get_random_values(&sub_buffer)
            .map_err(|_| worker::Error::RustError("WebCrypto getRandomValues failed".to_owned()))?;
        sub_buffer.copy_to(chunk);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn random_token() -> worker::Result<String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;

    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

#[cfg(target_arch = "wasm32")]
fn json<T: Serialize>(value: &T) -> worker::Result<Response> {
    Response::from_json(value)
}

#[cfg(target_arch = "wasm32")]
fn json_status<T: Serialize>(value: &T, status: u16) -> worker::Result<Response> {
    Response::from_json(value).map(|response| response.with_status(status))
}

#[cfg(target_arch = "wasm32")]
fn json_status_no_store<T: Serialize>(value: &T, status: u16) -> worker::Result<Response> {
    let response = json_status(value, status)?;
    response.headers().set("Cache-Control", "no-store")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::{
        pkcs1v15::SigningKey as RsaPkcs1v15SigningKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use zeroth_oidc::PkceChallengeMethod;

    #[test]
    fn discovery_uses_base_url() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };

        let discovery = discovery_response(&config);
        assert_eq!(discovery.issuer, "https://id.example.com");
        assert_eq!(
            discovery.authorization_endpoint,
            "https://id.example.com/authorize"
        );
        assert_eq!(
            discovery.revocation_endpoint,
            "https://id.example.com/oauth/revoke"
        );
        assert_eq!(
            discovery.introspection_endpoint,
            "https://id.example.com/oauth/introspect"
        );
        assert_eq!(
            discovery.end_session_endpoint,
            "https://id.example.com/logout"
        );
        assert!(discovery
            .grant_types_supported
            .contains(&"authorization_code"));
        assert!(discovery
            .revocation_endpoint_auth_methods_supported
            .contains(&"client_secret_basic"));
        assert!(discovery
            .introspection_endpoint_auth_methods_supported
            .contains(&"client_secret_basic"));
        assert!(!discovery
            .introspection_endpoint_auth_methods_supported
            .contains(&"none"));
        assert!(discovery.response_modes_supported.contains(&"query"));
        assert!(discovery.prompt_values_supported.contains(&"none"));
        assert!(discovery.prompt_values_supported.contains(&"login"));
        assert!(discovery
            .id_token_signing_alg_values_supported
            .contains(&"ES256"));
        assert!(discovery.claims_supported.contains(&"email"));
        assert!(discovery.claims_supported.contains(&"email_verified"));
        assert!(discovery.claims_supported.contains(&"name"));
        assert!(discovery.claims_supported.contains(&"picture"));
        assert!(discovery.claims_supported.contains(&"sid"));
        assert!(discovery.authorization_response_iss_parameter_supported);
    }

    #[test]
    fn readiness_requires_all_mandatory_checks_and_all_providers() {
        let ready_check = || ReadinessCheck {
            configured: true,
            notes: Vec::new(),
        };

        let issuer = ready_check();
        let signing = ready_check();
        let schema = ready_check();
        let csrf = ready_check();
        let rate_limit = ready_check();
        let admin_bootstrap = ready_check();
        let local_auth = ready_check();

        let providers = vec![
            ProviderReadiness {
                id: "apple",
                label: "Apple",
                kind: "oidc",
                configured: true,
                notes: Vec::new(),
            },
            ProviderReadiness {
                id: "google",
                label: "Google",
                kind: "oidc",
                configured: true,
                notes: Vec::new(),
            },
            ProviderReadiness {
                id: "spotify",
                label: "Spotify",
                kind: "oauth2",
                configured: true,
                notes: Vec::new(),
            },
        ];

        assert!(readiness_is_ready(
            &issuer,
            &signing,
            &providers,
            &schema,
            &csrf,
            &rate_limit,
            &admin_bootstrap,
            &local_auth,
        ));

        let mut missing_provider = providers.clone();
        missing_provider[2].configured = false;

        assert!(!readiness_is_ready(
            &issuer,
            &signing,
            &missing_provider,
            &schema,
            &csrf,
            &rate_limit,
            &admin_bootstrap,
            &local_auth,
        ));

        let missing_signing = ReadinessCheck {
            configured: false,
            notes: vec!["missing_jwt_es256_private_key"],
        };

        assert!(!readiness_is_ready(
            &issuer,
            &missing_signing,
            &providers,
            &schema,
            &csrf,
            &rate_limit,
            &admin_bootstrap,
            &local_auth,
        ));
    }

    #[test]
    fn provider_status_enabled_requires_not_disabled() {
        assert!(provider_status_enabled(true, true, false));
        assert!(!provider_status_enabled(true, true, true));
        assert!(!provider_status_enabled(true, false, false));
        assert!(!provider_status_enabled(false, true, false));
    }

    #[test]
    fn spotify_disabled_status_includes_activation_requirements() {
        assert_eq!(
            provider_disabled_notes(well_known::SPOTIFY),
            vec![
                "spotify_development_mode_owner_premium_required",
                "spotify_development_mode_users_must_be_allowlisted",
            ]
        );
        assert_eq!(
            provider_activation_requirements(well_known::SPOTIFY, true),
            vec![
                "Spotify app owner account has Premium while the app is in development mode",
                "Spotify test login user is allowlisted in the Spotify app Users Management tab",
                "Spotify current-user profile endpoint /v1/me returns HTTP 200 for an authorized user",
            ]
        );
        assert!(provider_activation_requirements(well_known::SPOTIFY, false).is_empty());
        assert!(provider_activation_requirements(well_known::GOOGLE, true).is_empty());
    }

    #[test]
    fn provider_failure_status_summarizes_latest_safe_details_per_provider() {
        let long_description = "Spotify profile endpoint returned HTTP 403: ".to_owned()
            + &"premium subscription required ".repeat(20);
        let rows = vec![
            ProviderFailureEventRow {
                provider_id: well_known::SPOTIFY.to_owned(),
                event_type: "provider.profile.failed".to_owned(),
                created_at: 1_780_000_400,
                details_json: serde_json::json!({
                    "code": "invalid_response",
                    "description": long_description,
                    "accessToken": "must-not-appear"
                })
                .to_string(),
            },
            ProviderFailureEventRow {
                provider_id: well_known::SPOTIFY.to_owned(),
                event_type: "provider.token_exchange.failed".to_owned(),
                created_at: 1_780_000_300,
                details_json: serde_json::json!({
                    "code": "invalid_grant",
                    "description": "older failure"
                })
                .to_string(),
            },
            ProviderFailureEventRow {
                provider_id: well_known::GOOGLE.to_owned(),
                event_type: "provider.token_exchange.failed".to_owned(),
                created_at: 1_780_000_200,
                details_json: serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "bad client secret"
                })
                .to_string(),
            },
        ];

        let failures = provider_failure_statuses_from_events(&rows);

        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].0, well_known::SPOTIFY);
        assert_eq!(failures[0].1.event_type, "provider.profile.failed");
        assert_eq!(failures[0].1.created_at, 1_780_000_400);
        assert_eq!(failures[0].1.code.as_deref(), Some("invalid_response"));
        let description = failures[0].1.description.as_deref().unwrap();
        assert!(description.starts_with("Spotify profile endpoint returned HTTP 403"));
        assert!(description.len() <= PROVIDER_FAILURE_DESCRIPTION_MAX_CHARS);
        assert!(!description.contains("must-not-appear"));
        assert_eq!(failures[1].0, well_known::GOOGLE);
        assert_eq!(failures[1].1.code.as_deref(), Some("invalid_client"));
        assert_eq!(
            failures[1].1.description.as_deref(),
            Some("bad client secret")
        );
    }

    #[test]
    fn apple_touch_icon_path_matches_common_browser_probes() {
        for path in [
            "/apple-touch-icon.png",
            "/apple-touch-icon-precomposed.png",
            "/apple-touch-icon-120x120.png",
            "/apple-touch-icon-180x180-precomposed.png",
        ] {
            assert!(apple_touch_icon_path(path), "{path}");
        }

        for path in [
            "/apple-touch-icon.svg",
            "/apple-touch-icon-180.png",
            "/apple-touch-icon-180x.png",
            "/apple-touch-icon-bigx180.png",
            "/assets/apple-touch-icon-180x180.png",
        ] {
            assert!(!apple_touch_icon_path(path), "{path}");
        }
    }

    #[test]
    fn quiet_browser_asset_path_matches_common_browser_probes() {
        for path in [
            "/apple-touch-icon.png",
            "/apple-touch-icon-120x120.png",
            "/.well-known/appspecific/com.chrome.devtools.json",
        ] {
            assert!(quiet_browser_asset_path(path), "{path}");
        }

        for path in [
            "/.well-known/openid-configuration",
            "/favicon.ico",
            "/assets/com.chrome.devtools.json",
        ] {
            assert!(!quiet_browser_asset_path(path), "{path}");
        }
    }

    #[test]
    fn favicon_uses_subtle_black_mark() {
        assert!(ZEROTH_FAVICON_SVG.contains(r##"stop-color="#2d333b""##));
        assert!(ZEROTH_FAVICON_SVG.contains(r##"stop-color="#0b0f19""##));
        assert!(ZEROTH_FAVICON_SVG.contains(r##"stroke="#f9fafb""##));
        assert!(!ZEROTH_FAVICON_SVG.contains(r##"stroke="#ff6a00""##));
    }

    #[test]
    fn canonical_route_path_trims_trailing_slashes_without_touching_root() {
        assert_eq!(canonical_route_path("/").as_ref(), "/");
        assert_eq!(canonical_route_path("/admin").as_ref(), "/admin");
        assert_eq!(canonical_route_path("/admin/").as_ref(), "/admin");
        assert_eq!(
            canonical_route_path("/magic-links//").as_ref(),
            "/magic-links"
        );
        assert_eq!(
            canonical_route_path("/.well-known/openid-configuration/").as_ref(),
            "/.well-known/openid-configuration"
        );
    }

    #[test]
    fn issuer_readiness_requires_https_url_with_host() {
        let ready = issuer_readiness(&ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        });
        assert!(ready.configured);
        assert!(ready.notes.is_empty());

        let http = issuer_readiness(&ZerothServerConfig {
            public_base_url: "http://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        });
        assert!(!http.configured);
        assert_eq!(http.notes, vec!["issuer_not_https"]);

        let invalid = issuer_readiness(&ZerothServerConfig {
            public_base_url: "not a url".to_owned(),
            ..ZerothServerConfig::default()
        });
        assert!(!invalid.configured);
        assert_eq!(invalid.notes, vec!["invalid_issuer_url"]);
    }

    #[test]
    fn apple_app_site_association_readiness_requires_object_json() {
        let ready = apple_app_site_association_readiness_from_payload(Some(
            r#"{"webcredentials":{"apps":["TEAM.ai.wavey.app"]}}"#,
        ));
        assert!(ready.configured);
        assert!(ready.notes.is_empty());

        let missing = apple_app_site_association_readiness_from_payload(None);
        assert!(!missing.configured);
        assert_eq!(
            missing.notes,
            vec!["missing_apple_app_site_association_json"]
        );

        let array = apple_app_site_association_readiness_from_payload(Some("[]"));
        assert!(!array.configured);
        assert_eq!(array.notes, vec!["apple_app_site_association_not_object"]);
    }

    #[test]
    fn local_auth_status_reports_magic_link_delivery_dependencies() {
        let methods = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(None, None, true, None, None, None),
            false,
            None,
        );
        let password = methods
            .iter()
            .find(|method| method.id == "password")
            .unwrap();
        assert!(password.enabled);
        assert_eq!(password.credential_storage, "zeroth_local_credentials");
        assert!(password.notes.is_empty());

        let magic_link = methods
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();
        assert!(magic_link.enabled);
        assert_eq!(magic_link.delivery, "cloudflare_email");
        assert!(magic_link
            .notes
            .contains(&"cloudflare_email_sending_must_be_enabled"));
        assert!(magic_link.notes.contains(&"delivery_not_proven"));

        let missing = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(
                None,
                Some("missing_magic_link_from"),
                false,
                None,
                None,
                None,
            ),
            false,
            None,
        );
        let missing_magic_link = missing
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();
        assert!(!missing_magic_link.enabled);
        assert!(missing_magic_link
            .notes
            .contains(&"missing_magic_link_from"));
        assert!(missing_magic_link.notes.contains(&"missing_email_binding"));
    }

    #[test]
    fn local_auth_status_reports_magic_link_webhook_delivery_dependencies() {
        let methods = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(
                Some("webhook"),
                None,
                false,
                magic_link_webhook_url_note(Some("https://mail.example.com/zeroth")),
                None,
                None,
            ),
            false,
            None,
        );
        let magic_link = methods
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();
        assert!(magic_link.enabled);
        assert_eq!(magic_link.delivery, "webhook");
        assert!(magic_link
            .notes
            .contains(&"magic_link_webhook_must_send_email"));
        assert!(magic_link.notes.contains(&"delivery_not_proven"));
        assert!(!magic_link.notes.contains(&"missing_email_binding"));

        let missing_url = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(
                Some("webhook"),
                None,
                true,
                magic_link_webhook_url_note(None),
                None,
                None,
            ),
            false,
            None,
        );
        let missing_magic_link = missing_url
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();
        assert!(!missing_magic_link.enabled);
        assert!(missing_magic_link
            .notes
            .contains(&"missing_magic_link_webhook_url"));

        let invalid_url = magic_link_delivery_config_from_values(
            Some("webhook"),
            None,
            true,
            magic_link_webhook_url_note(Some("http://mail.example.com/zeroth")),
            None,
            None,
        );
        assert!(!invalid_url.enabled);
        assert!(invalid_url
            .notes
            .contains(&"invalid_magic_link_webhook_url"));

        let unsupported =
            magic_link_delivery_config_from_values(Some("postmark"), None, true, None, None, None);
        assert!(!unsupported.enabled);
        assert_eq!(unsupported.transport, "unsupported");
        assert!(unsupported
            .notes
            .contains(&"unsupported_magic_link_delivery"));
    }

    #[test]
    fn local_auth_status_reports_direct_email_provider_dependencies() {
        let resend = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(Some("resend"), None, false, None, None, None),
            false,
            None,
        );
        let magic_link = resend
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();
        assert!(magic_link.enabled);
        assert_eq!(magic_link.delivery, "resend");
        assert!(magic_link.notes.contains(&"resend_domain_must_be_verified"));
        assert!(magic_link.notes.contains(&"delivery_not_proven"));
        assert!(!magic_link.notes.contains(&"missing_email_binding"));

        let missing_resend = magic_link_delivery_config_from_values(
            Some("resend"),
            None,
            false,
            None,
            Some("missing_resend_api_key"),
            None,
        );
        assert!(!missing_resend.enabled);
        assert_eq!(missing_resend.transport, "resend");
        assert!(missing_resend.notes.contains(&"missing_resend_api_key"));

        let mailchannels = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(
                Some("mailchannels"),
                None,
                false,
                None,
                None,
                None,
            ),
            false,
            None,
        );
        let magic_link = mailchannels
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();
        assert!(magic_link.enabled);
        assert_eq!(magic_link.delivery, "mailchannels");
        assert!(magic_link
            .notes
            .contains(&"mailchannels_domain_lockdown_must_be_configured"));
        assert!(magic_link.notes.contains(&"delivery_not_proven"));

        let missing_mailchannels = magic_link_delivery_config_from_values(
            Some("mail_channels"),
            None,
            false,
            None,
            None,
            Some("missing_mailchannels_api_key"),
        );
        assert!(!missing_mailchannels.enabled);
        assert_eq!(missing_mailchannels.transport, "mailchannels");
        assert!(missing_mailchannels
            .notes
            .contains(&"missing_mailchannels_api_key"));
    }

    #[test]
    fn local_auth_status_uses_magic_link_delivery_evidence() {
        let delivery = LocalAuthDeliveryStatus {
            last_issue_at: Some(20),
            last_sent_at: Some(18),
            last_failed_at: Some(20),
            last_error: Some("email_internal_server_error".to_owned()),
            last_error_detail: Some("email.sending.error.internal_server [code: 10002]".to_owned()),
        };
        let methods = local_auth_status_rows_from_config(
            true,
            magic_link_delivery_config_from_values(None, None, true, None, None, None),
            false,
            Some(delivery),
        );
        let magic_link = methods
            .iter()
            .find(|method| method.id == "magic_link")
            .unwrap();

        assert!(!magic_link.notes.contains(&"delivery_not_proven"));
        assert!(magic_link.notes.contains(&"delivery_failed_recently"));
        assert_eq!(
            magic_link.delivery_status.as_ref().unwrap().last_error,
            Some("email_internal_server_error".to_owned())
        );
        assert_eq!(
            magic_link
                .delivery_status
                .as_ref()
                .unwrap()
                .last_error_detail,
            Some("email.sending.error.internal_server [code: 10002]".to_owned())
        );
    }

    #[test]
    fn magic_link_delivery_status_summarizes_recent_audit_events() {
        let rows = vec![
            MagicLinkDeliveryEventRow {
                event_type: "magic_link.email.failed".to_owned(),
                created_at: 30,
                details_json: r#"{"errorClass":"email_internal_server_error","errorDetail":"email.sending.error.internal_server [code: 10002]"}"#.to_owned(),
            },
            MagicLinkDeliveryEventRow {
                event_type: "magic_link.issue".to_owned(),
                created_at: 30,
                details_json: r#"{"sent":false}"#.to_owned(),
            },
            MagicLinkDeliveryEventRow {
                event_type: "magic_link.issue".to_owned(),
                created_at: 20,
                details_json: r#"{"sent":true}"#.to_owned(),
            },
        ];

        let status = magic_link_delivery_status_from_events(&rows).unwrap();

        assert_eq!(status.last_issue_at, Some(30));
        assert_eq!(status.last_sent_at, Some(20));
        assert_eq!(status.last_failed_at, Some(30));
        assert_eq!(
            status.last_error,
            Some("email_internal_server_error".to_owned())
        );
        assert_eq!(
            status.last_error_detail,
            Some("email.sending.error.internal_server [code: 10002]".to_owned())
        );
    }

    #[test]
    fn magic_link_email_error_classification_is_safe() {
        assert_eq!(
            classify_magic_link_email_error("Unauthorized"),
            "email_unauthorized"
        );
        assert_eq!(
            classify_magic_link_email_error("invalid from address"),
            "email_sender_rejected"
        );
        assert_eq!(
            classify_magic_link_email_error("internal server error"),
            "email_internal_server_error"
        );
        assert_eq!(
            classify_magic_link_email_error("email_webhook_failed HTTP 500"),
            "email_webhook_failed"
        );
        assert_eq!(
            classify_magic_link_email_error("email_resend_failed HTTP 422"),
            "email_resend_failed"
        );
        assert_eq!(
            classify_magic_link_email_error("email_mailchannels_failed HTTP 403"),
            "email_mailchannels_failed"
        );
        assert_eq!(classify_magic_link_email_error(""), "email_send_failed");
    }

    #[test]
    fn magic_link_email_error_detail_is_bounded_and_single_line() {
        assert_eq!(
            sanitize_magic_link_email_error_detail("  first\nsecond\tthird  "),
            Some("first second third".to_owned())
        );
        assert_eq!(
            sanitize_magic_link_email_error_detail(
                "failed for jamie@wavey.ai at https://id.wavey.ai/magic-links/consume?token=secret"
            ),
            Some("failed for [email] at [url]".to_owned())
        );
        assert_eq!(sanitize_magic_link_email_error_detail(" \n\t "), None);

        let long = "x".repeat(MAGIC_LINK_EMAIL_ERROR_DETAIL_MAX_CHARS + 10);
        let sanitized = sanitize_magic_link_email_error_detail(&long).unwrap();
        assert_eq!(
            sanitized.chars().count(),
            MAGIC_LINK_EMAIL_ERROR_DETAIL_MAX_CHARS
        );
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn passkey_challenge_round_trips_through_browser_encoding() {
        let challenge = "0123456789abcdef";
        let encoded = passkey_challenge_for_browser(challenge);

        assert_eq!(passkey_challenge_from_browser(&encoded).unwrap(), challenge);
        assert!(passkey_challenge_matches_client_data(
            &hash_secret(challenge),
            &test_passkey_client_data("webauthn.get", challenge, "https://id.example.com")
        ));
    }

    #[test]
    fn passkey_registration_response_extracts_es256_credential() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let credential_id = b"credential-1";
        let x = [3u8; 32];
        let y = [7u8; 32];
        let auth_data = test_passkey_authenticator_data(
            "id.example.com",
            0x45,
            9,
            credential_id,
            &test_passkey_cose_key(&x, &y),
        );
        let body = PasskeyRegisterVerifyRequest {
            id: URL_SAFE_NO_PAD.encode(credential_id),
            raw_id: URL_SAFE_NO_PAD.encode(credential_id),
            response: PasskeyRegisterCredentialResponse {
                client_data_json: test_passkey_client_data(
                    "webauthn.create",
                    "challenge-1",
                    "https://id.example.com",
                ),
                attestation_object: URL_SAFE_NO_PAD
                    .encode(test_passkey_attestation_object(&auth_data)),
                transports: Vec::new(),
            },
        };

        let validated = validate_passkey_registration_response(&config, &body).unwrap();

        assert_eq!(
            validated.credential_id,
            URL_SAFE_NO_PAD.encode(credential_id)
        );
        assert_eq!(validated.public_key_x, URL_SAFE_NO_PAD.encode(x));
        assert_eq!(validated.public_key_y, URL_SAFE_NO_PAD.encode(y));
        assert_eq!(validated.sign_count, 9);
    }

    #[test]
    fn passkey_es256_signature_verifies_signed_authenticator_payload() {
        let signing_key = SigningKey::from_slice(&[11u8; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        let credential = PasskeyCredentialRow {
            credential_id: "cred_1".to_owned(),
            user_id: "usr_1".to_owned(),
            label: None,
            public_key_x: URL_SAFE_NO_PAD.encode(x),
            public_key_y: URL_SAFE_NO_PAD.encode(y),
            sign_count: 0,
            created_at: 1,
            updated_at: 1,
            last_used_at: None,
            disabled_at: None,
        };
        let signed_data = b"authenticator-data-and-client-data-hash";
        let signature: Signature = signing_key.sign(signed_data);
        let der = signature.to_der();

        verify_passkey_es256_signature(&credential, signed_data, der.as_bytes()).unwrap();

        let error =
            verify_passkey_es256_signature(&credential, b"tampered", der.as_bytes()).unwrap_err();
        assert_eq!(error, "passkey signature did not verify");
    }

    #[test]
    fn login_theme_uses_client_name_for_external_target_without_override() {
        let client = Client {
            id: ClientId("app-web".to_owned()),
            name: "App Web".to_owned(),
            redirect_uris: vec!["https://app.example.com/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: Vec::new(),
            confidential: false,
        };

        let (name, theme) = login_theme_for_client(
            "Wavey ID",
            &client,
            "https://id.example.com",
            Some("https://app.example.com/home"),
            &LoginThemeCatalog::default(),
        );

        assert_eq!(name, "App Web");
        assert_eq!(theme, ZerothUiTheme::default());
    }

    #[test]
    fn login_theme_domain_override_wins_over_client_override() {
        let client = Client {
            id: ClientId("app-web".to_owned()),
            name: "App Web".to_owned(),
            redirect_uris: vec!["https://app.example.com/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: Vec::new(),
            confidential: false,
        };
        let mut catalog = LoginThemeCatalog::default();
        catalog.clients.insert(
            "app-web".to_owned(),
            LoginThemeOverride {
                name: Some("Client Name".to_owned()),
                icon: None,
                header_background_from: Some("#111111".to_owned()),
                header_background_to: Some("#222222".to_owned()),
                header_text_color: None,
            },
        );
        catalog.domains.insert(
            "example.com".to_owned(),
            LoginThemeOverride {
                name: Some("Domain Name".to_owned()),
                icon: None,
                header_background_from: Some("#ffffff".to_owned()),
                header_background_to: Some("#f6f8fa".to_owned()),
                header_text_color: Some("#101820".to_owned()),
            },
        );

        let (name, theme) = login_theme_for_client(
            "Wavey ID",
            &client,
            "https://id.example.com",
            Some("https://sub.example.com/home"),
            &catalog,
        );

        assert_eq!(name, "Domain Name");
        assert_eq!(theme.header_background_from.as_deref(), Some("#ffffff"));
        assert_eq!(theme.header_background_to.as_deref(), Some("#f6f8fa"));
        assert_eq!(theme.header_text_color.as_deref(), Some("#101820"));
    }

    #[test]
    fn client_branding_uses_domain_name_and_icon() {
        let client = Client {
            id: ClientId("app-web".to_owned()),
            name: "App Web".to_owned(),
            redirect_uris: vec!["https://app.example.com/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: Vec::new(),
            confidential: false,
        };
        let mut catalog = LoginThemeCatalog::default();
        catalog.clients.insert(
            "app-web".to_owned(),
            LoginThemeOverride {
                name: Some("Client Name".to_owned()),
                icon: Some("/client-icon.png".to_owned()),
                ..LoginThemeOverride::default()
            },
        );
        catalog.domains.insert(
            "example.com".to_owned(),
            LoginThemeOverride {
                name: Some("Domain Name".to_owned()),
                icon: Some("/domain-icon.png".to_owned()),
                ..LoginThemeOverride::default()
            },
        );

        let branding = client_branding_for_client(
            "Wavey ID",
            &client,
            "https://id.example.com",
            Some("https://sub.example.com/home"),
            &catalog,
        );

        assert_eq!(branding.client_id, "app-web");
        assert_eq!(branding.name, "Domain Name");
        assert_eq!(branding.icon.as_deref(), Some("/domain-icon.png"));
    }

    #[test]
    fn login_theme_prefers_most_specific_domain() {
        let client = Client {
            id: ClientId("app-web".to_owned()),
            name: "App Web".to_owned(),
            redirect_uris: vec!["https://app.example.com/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: Vec::new(),
            confidential: false,
        };
        let mut catalog = LoginThemeCatalog::default();
        catalog.domains.insert(
            "example.com".to_owned(),
            LoginThemeOverride {
                name: Some("Example".to_owned()),
                ..LoginThemeOverride::default()
            },
        );
        catalog.domains.insert(
            "app.example.com".to_owned(),
            LoginThemeOverride {
                name: Some("App Example".to_owned()),
                ..LoginThemeOverride::default()
            },
        );

        let (name, _) = login_theme_for_client(
            "Wavey ID",
            &client,
            "https://id.example.com",
            Some("https://app.example.com/home"),
            &catalog,
        );

        assert_eq!(name, "App Example");
    }

    #[test]
    fn config_value_configured_rejects_empty_and_scaffold_placeholders() {
        assert!(config_value_configured(Some(
            "real-google-client-id.apps.googleusercontent.com"
        )));
        assert!(config_value_configured(Some("ai.wavey.signin")));

        for value in [
            None,
            Some(""),
            Some("   "),
            Some("replace-with-google-oauth-client-id"),
            Some("replace-with-sign-in-with-apple-service-id"),
            Some("<Sign in with Apple service id>"),
            Some("changeme"),
            Some("change-me"),
            Some("todo"),
        ] {
            assert!(
                !config_value_configured(value),
                "value should not be configured: {value:?}"
            );
        }
    }

    #[test]
    fn config_value_note_distinguishes_missing_and_placeholder_values() {
        assert_eq!(
            config_value_note(None, "missing_client_id", "placeholder_client_id"),
            Some("missing_client_id")
        );
        assert_eq!(
            config_value_note(
                Some("replace-with-google-oauth-client-id"),
                "missing_client_id",
                "placeholder_client_id"
            ),
            Some("placeholder_client_id")
        );
        assert_eq!(
            config_value_note(
                Some("real-google-client-id.apps.googleusercontent.com"),
                "missing_client_id",
                "placeholder_client_id"
            ),
            None
        );
    }

    #[test]
    fn discovery_serializes_oidc_snake_case_fields() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };

        let value = serde_json::to_value(discovery_response(&config)).unwrap();

        assert!(value.get("authorization_endpoint").is_some());
        assert!(value.get("revocation_endpoint").is_some());
        assert!(value.get("introspection_endpoint").is_some());
        assert!(value.get("end_session_endpoint").is_some());
        assert!(value
            .get("revocation_endpoint_auth_methods_supported")
            .is_some());
        assert!(value
            .get("introspection_endpoint_auth_methods_supported")
            .is_some());
        assert!(value.get("response_modes_supported").is_some());
        assert!(value.get("prompt_values_supported").is_some());
        assert!(value.get("id_token_signing_alg_values_supported").is_some());
        assert!(value.get("claims_supported").is_some());
        assert!(value
            .get("authorization_response_iss_parameter_supported")
            .is_some());
        assert!(value.get("authorizationEndpoint").is_none());
    }

    #[test]
    fn migration_response_reports_applied_and_skipped_migrations() {
        let value = serde_json::to_value(MigrationResponse {
            ok: true,
            binding: D1_BINDING,
            migrations_applied: vec!["init"],
            migrations_skipped: vec!["future"],
        })
        .unwrap();

        assert_eq!(value["ok"], true);
        assert_eq!(value["binding"], D1_BINDING);
        assert_eq!(value["migrationsApplied"][0], "init");
        assert_eq!(value["migrationsSkipped"][0], "future");
        assert!(value.get("migrations_applied").is_none());
    }

    #[test]
    fn db_schema_status_response_serializes_camel_case() {
        let value = serde_json::to_value(DbSchemaStatusResponse {
            ok: true,
            binding: D1_BINDING,
            tables: vec![DbTableStatus {
                name: "zeroth_clients",
                present: true,
            }],
            migrations: vec![DbMigrationStatus {
                version: 1,
                name: "init",
                applied: true,
            }],
            compatibility_columns: vec![DbCompatibilityColumnStatus {
                table: "zeroth_auth_codes",
                name: "auth_time",
                present: true,
            }],
            client_count: 5,
        })
        .unwrap();

        assert_eq!(value["ok"], true);
        assert_eq!(value["binding"], D1_BINDING);
        assert_eq!(value["tables"][0]["name"], "zeroth_clients");
        assert_eq!(value["tables"][0]["present"], true);
        assert_eq!(value["migrations"][0]["applied"], true);
        assert_eq!(
            value["compatibilityColumns"][0]["table"],
            "zeroth_auth_codes"
        );
        assert_eq!(value["clientCount"], 5);
        assert!(value.get("compatibility_columns").is_none());
        assert!(value.get("client_count").is_none());
    }

    #[test]
    fn db_schema_status_ok_requires_every_schema_piece() {
        let tables = zeroth_storage::REQUIRED_TABLES
            .iter()
            .map(|table| DbTableStatus {
                name: table,
                present: true,
            })
            .collect::<Vec<_>>();
        let migrations = zeroth_storage::migrations::ALL
            .iter()
            .map(|migration| DbMigrationStatus {
                version: migration.version,
                name: migration.name,
                applied: true,
            })
            .collect::<Vec<_>>();
        let compatibility_columns = zeroth_storage::compatibility::ALL
            .iter()
            .map(|column| DbCompatibilityColumnStatus {
                table: column.table,
                name: column.name,
                present: true,
            })
            .collect::<Vec<_>>();

        assert!(db_schema_status_ok(
            &tables,
            &migrations,
            &compatibility_columns
        ));

        let mut missing_table = tables.clone();
        missing_table[0].present = false;
        assert!(!db_schema_status_ok(
            &missing_table,
            &migrations,
            &compatibility_columns
        ));
        let partial_tables = tables[1..].to_vec();
        assert!(!db_schema_status_ok(
            &partial_tables,
            &migrations,
            &compatibility_columns
        ));

        let mut pending_migration = migrations.clone();
        pending_migration[0].applied = false;
        assert!(!db_schema_status_ok(
            &tables,
            &pending_migration,
            &compatibility_columns
        ));
        assert!(!db_schema_status_ok(&tables, &[], &compatibility_columns));

        let mut missing_column = compatibility_columns.clone();
        missing_column[0].present = false;
        assert!(!db_schema_status_ok(&tables, &migrations, &missing_column));
        let partial_columns = compatibility_columns[1..].to_vec();
        assert!(!db_schema_status_ok(&tables, &migrations, &partial_columns));
    }

    #[test]
    fn client_row_parses_registered_redirects() {
        let client = client_from_row(ClientRow {
            id: "ios".to_owned(),
            name: "Wavey iOS".to_owned(),
            secret_hash: None,
            redirect_uris_json: r#"["wavey://auth/callback"]"#.to_owned(),
            allowed_origins_json: "[]".to_owned(),
            allowed_email_domains_json: "[]".to_owned(),
            issuer_token_audience: None,
            issuer_token_ttl_seconds: None,
            account_sharing_mode: None,
            account_tenant_id: None,
            visible_login_methods_json: None,
            confidential: 0,
            disabled_at: None,
        })
        .unwrap()
        .unwrap();

        assert_eq!(client.id, ClientId("ios".to_owned()));
        assert_eq!(client.redirect_uris, vec!["wavey://auth/callback"]);
        assert!(!client.confidential);
    }

    #[test]
    fn disabled_client_rows_are_hidden() {
        let client = client_from_row(ClientRow {
            id: "web".to_owned(),
            name: "Wavey Web".to_owned(),
            secret_hash: Some(format!("sha256:{}", hash_secret("web-secret"))),
            redirect_uris_json: r#"["https://app.example.com/callback"]"#.to_owned(),
            allowed_origins_json: "[]".to_owned(),
            allowed_email_domains_json: "[]".to_owned(),
            issuer_token_audience: None,
            issuer_token_ttl_seconds: None,
            account_sharing_mode: None,
            account_tenant_id: None,
            visible_login_methods_json: None,
            confidential: 1,
            disabled_at: Some(1_780_000_000),
        })
        .unwrap();

        assert_eq!(client, None);
    }

    #[test]
    fn active_client_allowed_origins_requires_active_client() {
        let client = registered_confidential_client("web-secret").client;

        let allowed_origins = active_client_allowed_origins_from_client(Some(client)).unwrap();

        assert_eq!(allowed_origins, vec!["https://app.example.com"]);
        assert_eq!(
            active_client_allowed_origins_from_client(None).unwrap_err(),
            "client is not registered or is disabled"
        );
    }

    #[test]
    fn client_upsert_accepts_native_and_web_redirects() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "ai.wavey.ios",
            "name": "Wavey iOS",
            "redirectUris": [
                "wavey://auth/callback",
                "https://app.example.com/auth/callback",
                "wavey://auth/callback"
            ],
            "allowedOrigins": ["https://app.example.com/"],
            "confidential": false
        }))
        .unwrap();

        assert_eq!(upsert.id, "ai.wavey.ios");
        assert_eq!(
            upsert.redirect_uris,
            vec![
                "wavey://auth/callback".to_owned(),
                "https://app.example.com/auth/callback".to_owned()
            ]
        );
        assert_eq!(
            upsert.allowed_origins,
            vec!["https://app.example.com".to_owned()]
        );
        assert_eq!(upsert.allowed_email_domains, Vec::<String>::new());
        assert_eq!(upsert.account_sharing_mode, AccountSharingMode::Global);
        assert_eq!(upsert.account_tenant_id, ACCOUNT_NAMESPACE_GLOBAL);
        assert!(upsert.visible_login_methods.is_empty());
        assert!(!upsert.confidential);
        assert_eq!(upsert.secret_hash, None);
    }

    #[test]
    fn client_upsert_accepts_visible_login_methods() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "bitneedle",
            "name": "Bitneedle",
            "redirectUris": ["https://bitneedle.example.com/callback"],
            "visibleLoginMethods": ["passkey", "magic-link", "magic_link"],
            "confidential": false
        }))
        .unwrap();

        assert_eq!(
            upsert.visible_login_methods,
            vec![
                LOGIN_METHOD_PASSKEY.to_owned(),
                LOGIN_METHOD_MAGIC_LINK.to_owned()
            ]
        );

        let error = client_upsert_from_value(serde_json::json!({
            "id": "web",
            "name": "Web",
            "redirectUris": ["https://app.example.com/callback"],
            "visibleLoginMethods": ["sms"],
            "confidential": false
        }))
        .unwrap_err();
        assert_eq!(error.description, "unsupported visible login method: sms");
    }

    #[test]
    fn client_login_method_visibility_controls_ui_flags() {
        let mut config = ZerothUiConfig::new(
            "https://id.example.com",
            "web",
            "https://app.example.com/callback",
        );

        apply_client_login_method_visibility(&mut config, &[]);
        assert!(!config.show_passkey_login);
        assert!(!config.show_magic_link_login);

        apply_client_login_method_visibility(
            &mut config,
            &[
                LOGIN_METHOD_PASSKEY.to_owned(),
                LOGIN_METHOD_MAGIC_LINK.to_owned(),
            ],
        );
        assert!(config.show_passkey_login);
        assert!(config.show_magic_link_login);
    }

    #[test]
    fn client_upsert_accepts_issuer_token_config() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "yl-web",
            "name": "YL Web",
            "redirectUris": ["https://yl.vin/callback"],
            "issuerTokenAudience": "yl-record-issuer",
            "issuerTokenTtlSeconds": 300,
            "confidential": false
        }))
        .unwrap();

        assert_eq!(
            upsert.issuer_token_audience,
            Some("yl-record-issuer".to_owned())
        );
        assert_eq!(upsert.issuer_token_ttl_seconds, Some(300));
    }

    #[test]
    fn client_upsert_rejects_invalid_issuer_token_ttl_seconds() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "yl-web",
            "name": "YL Web",
            "redirectUris": ["https://yl.vin/callback"],
            "issuerTokenAudience": "yl-record-issuer",
            "issuerTokenTtlSeconds": 30,
            "confidential": false
        }))
        .unwrap_err();

        assert_eq!(
            error.description,
            "issuerTokenTtlSeconds must be between 60 and 600"
        );
    }

    #[test]
    fn client_upsert_accepts_account_sharing_modes() {
        let tenant = client_upsert_from_value(serde_json::json!({
            "id": "wavey-admin",
            "name": "Wavey Admin",
            "redirectUris": ["https://id.example.com/admin"],
            "accountSharingMode": "tenant",
            "accountTenantId": "wavey",
            "confidential": false
        }))
        .unwrap();
        assert_eq!(tenant.account_sharing_mode, AccountSharingMode::Tenant);
        assert_eq!(tenant.account_tenant_id, "wavey");

        let client = client_upsert_from_value(serde_json::json!({
            "id": "bitneedle",
            "name": "Bitneedle",
            "redirectUris": ["https://bitneedle.example.com/callback"],
            "account_sharing_mode": "client",
            "confidential": false
        }))
        .unwrap();
        assert_eq!(client.account_sharing_mode, AccountSharingMode::Client);
        assert_eq!(client.account_tenant_id, "bitneedle");
    }

    #[test]
    fn client_upsert_rejects_invalid_account_sharing_config() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "web",
            "name": "Web",
            "redirectUris": ["https://app.example.com/callback"],
            "accountSharingMode": "org",
            "confidential": false
        }))
        .unwrap_err();
        assert_eq!(
            error.description,
            "accountSharingMode must be global, tenant, or client"
        );

        let error = client_upsert_from_value(serde_json::json!({
            "id": "web",
            "name": "Web",
            "redirectUris": ["https://app.example.com/callback"],
            "accountSharingMode": "tenant",
            "confidential": false
        }))
        .unwrap_err();
        assert_eq!(
            error.description,
            "accountTenantId is required when accountSharingMode is tenant"
        );
    }

    #[test]
    fn account_namespace_is_derived_from_client_mode() {
        assert_eq!(
            account_namespace_for_parts(AccountSharingMode::Global, "wavey", "bitneedle"),
            "global"
        );
        assert_eq!(
            account_namespace_for_parts(AccountSharingMode::Tenant, "wavey", "bitneedle"),
            "tenant:wavey"
        );
        assert_eq!(
            account_namespace_for_parts(AccountSharingMode::Client, "wavey", "bitneedle"),
            "client:bitneedle"
        );
    }

    #[test]
    fn client_upsert_accepts_normalized_allowed_email_domains() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "wavey-admin",
            "name": "Wavey Admin",
            "redirectUris": ["https://id.example.com/admin"],
            "allowedEmailDomains": [" @Wavey.ai ", "wavey.ai", "example.com"],
            "confidential": false
        }))
        .unwrap();

        assert_eq!(
            upsert.allowed_email_domains,
            vec!["wavey.ai".to_owned(), "example.com".to_owned()]
        );
    }

    #[test]
    fn confidential_client_upsert_hashes_client_secret() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "wavey-web",
            "name": "Wavey Web",
            "redirectUris": ["https://app.example.com/auth/callback"],
            "allowedOrigins": ["https://app.example.com"],
            "confidential": true,
            "clientSecret": "super-secret-client-value"
        }))
        .unwrap();

        assert_eq!(
            upsert.secret_hash,
            Some(format!(
                "sha256:{}",
                hash_secret("super-secret-client-value")
            ))
        );
    }

    #[test]
    fn confidential_client_upsert_accepts_normalized_secret_hash() {
        let hash = hash_secret("super-secret-client-value").to_uppercase();
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "wavey-web",
            "name": "Wavey Web",
            "redirect_uris": ["https://app.example.com/auth/callback"],
            "allowed_origins": ["https://app.example.com"],
            "confidential": true,
            "secret_hash": format!("sha256:{hash}")
        }))
        .unwrap();

        assert_eq!(
            upsert.secret_hash,
            Some(format!("sha256:{}", hash.to_ascii_lowercase()))
        );
    }

    #[test]
    fn public_client_upsert_rejects_secret_material() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "ios",
            "name": "Wavey iOS",
            "redirectUris": ["wavey://auth/callback"],
            "confidential": false,
            "clientSecret": "super-secret-client-value"
        }))
        .unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "public clients must not include clientSecret or secretHash"
        );
    }

    #[test]
    fn client_upsert_rejects_origin_paths() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "web",
            "name": "Wavey Web",
            "redirectUris": ["https://app.example.com/auth/callback"],
            "allowedOrigins": ["https://app.example.com/path"],
            "confidential": false
        }))
        .unwrap_err();

        assert_eq!(
            error.description,
            "allowed origin must not include a path, query, or fragment"
        );
    }

    #[test]
    fn client_upsert_rejects_invalid_allowed_email_domains() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "wavey-admin",
            "name": "Wavey Admin",
            "redirectUris": ["https://id.example.com/admin"],
            "allowedEmailDomains": ["wavey"],
            "confidential": false
        }))
        .unwrap_err();

        assert_eq!(error.description, "allowed email domain must include a dot");
    }

    #[test]
    fn client_email_domain_policy_requires_verified_allowed_domain() {
        let client = Client {
            id: ClientId("admin".to_owned()),
            name: "Admin".to_owned(),
            redirect_uris: vec!["https://id.example.com/admin".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec!["wavey.ai".to_owned()],
            confidential: false,
        };
        let mut profile = ProviderProfile {
            provider_id: ProviderId(well_known::GOOGLE.to_owned()),
            subject: zeroth_core::Subject("google-sub".to_owned()),
            email: Some("Admin@Wavey.ai".to_owned()),
            email_verified: true,
            display_name: None,
            picture_url: None,
        };

        validate_client_email_domain_policy(&client, &profile).unwrap();

        profile.email_verified = false;
        let error = validate_client_email_domain_policy(&client, &profile).unwrap_err();
        assert_eq!(error.code, "access_denied");
        assert_eq!(
            error.description,
            "verified email is required for this client"
        );

        profile.email_verified = true;
        profile.email = Some("admin@example.com".to_owned());
        let error = validate_client_email_domain_policy(&client, &profile).unwrap_err();
        assert_eq!(
            error.description,
            "email domain is not allowed for this client"
        );
    }

    #[test]
    fn provider_identity_attachment_validation_rejects_missing_or_conflicting_identity() {
        validate_provider_identity_attached_to_user(Some("usr_123"), "usr_123").unwrap();

        let error = validate_provider_identity_attached_to_user(None, "usr_123").unwrap_err();
        assert_eq!(error, "provider identity could not be linked to the user");

        let error =
            validate_provider_identity_attached_to_user(Some("usr_other"), "usr_123").unwrap_err();
        assert_eq!(error, "provider identity is already linked to another user");
    }

    #[test]
    fn client_response_marks_disabled_and_secret_state() {
        let response = client_response_from_row(ClientRow {
            id: "web".to_owned(),
            name: "Wavey Web".to_owned(),
            secret_hash: Some(format!("sha256:{}", hash_secret("web-secret"))),
            redirect_uris_json: r#"["https://app.example.com/callback"]"#.to_owned(),
            allowed_origins_json: r#"["https://app.example.com"]"#.to_owned(),
            allowed_email_domains_json: r#"["example.com"]"#.to_owned(),
            issuer_token_audience: Some("yl-record-issuer".to_owned()),
            issuer_token_ttl_seconds: Some(300),
            account_sharing_mode: Some(ACCOUNT_SHARING_MODE_GLOBAL.to_owned()),
            account_tenant_id: Some(ACCOUNT_NAMESPACE_GLOBAL.to_owned()),
            visible_login_methods_json: Some(r#"["passkey","magic_link"]"#.to_owned()),
            confidential: 1,
            disabled_at: Some(1_780_000_000),
        })
        .unwrap();

        assert_eq!(response.id, "web");
        assert_eq!(
            response.redirect_uris,
            vec!["https://app.example.com/callback".to_owned()]
        );
        assert_eq!(
            response.allowed_origins,
            vec!["https://app.example.com".to_owned()]
        );
        assert_eq!(
            response.issuer_token_audience,
            Some("yl-record-issuer".to_owned())
        );
        assert_eq!(response.issuer_token_ttl_seconds, Some(300));
        assert!(response.confidential);
        assert!(response.disabled);
        assert!(response.has_secret);
        assert_eq!(response.account_sharing_mode, ACCOUNT_SHARING_MODE_GLOBAL);
        assert_eq!(response.account_namespace, ACCOUNT_NAMESPACE_GLOBAL);
        assert_eq!(
            response.visible_login_methods,
            vec![
                LOGIN_METHOD_PASSKEY.to_owned(),
                LOGIN_METHOD_MAGIC_LINK.to_owned()
            ]
        );
    }

    #[test]
    fn admin_user_response_marks_disabled_and_counts() {
        let response = admin_user_response_from_row(AdminUserRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: None,
            created_at: 1_780_000_000,
            updated_at: 1_780_000_100,
            disabled_at: Some(1_780_000_200),
            email_verified: 1,
            admin_membership_active: 1,
            identity_count: 2,
            active_session_count: 3,
        });

        assert_eq!(response.id, "usr_123");
        assert_eq!(response.email.as_deref(), Some("user@example.com"));
        assert!(response.disabled);
        assert!(response.admin);
        assert_eq!(response.identity_count, 2);
        assert_eq!(response.active_session_count, 3);
    }

    #[test]
    fn admin_user_id_validation_rejects_unsupported_input() {
        assert_eq!(validate_admin_user_id(" usr_123 ").unwrap(), "usr_123");
        let error = validate_admin_user_id("usr/123").unwrap_err();
        assert_eq!(error.description, "user id contains unsupported characters");
    }

    #[test]
    fn admin_identity_allowlist_accepts_user_ids_and_verified_emails() {
        assert!(admin_identity_allowed(
            "usr_admin",
            None,
            Some("usr_other, usr_admin"),
            None,
        ));
        assert!(admin_identity_allowed(
            "usr_123",
            Some("Admin@Wavey.ai"),
            None,
            Some("ops@example.com admin@wavey.ai"),
        ));
        assert!(!admin_identity_allowed(
            "usr_123",
            Some("user@example.com"),
            Some("usr_other"),
            Some("admin@wavey.ai"),
        ));
        assert!(!admin_identity_allowed(
            "usr_123",
            None,
            None,
            Some("admin@wavey.ai"),
        ));
    }

    #[test]
    fn admin_authorization_granted_by_records_source() {
        assert_eq!(
            admin_authorization_granted_by(&AdminAuthorization::BootstrapToken),
            "bootstrap_token"
        );
        assert_eq!(
            admin_authorization_granted_by(&AdminAuthorization::Session {
                user_id: "usr_admin".to_owned()
            }),
            "user:usr_admin"
        );
    }

    #[test]
    fn audit_event_response_parses_details_json() {
        let response = audit_event_response_from_row(AuditEventRow {
            id: "evt_123".to_owned(),
            event_type: "session.login".to_owned(),
            user_id: Some("usr_123".to_owned()),
            client_id: Some("web".to_owned()),
            provider_id: Some("google".to_owned()),
            created_at: 1_780_000_000,
            ip_hash: Some("ip-hash".to_owned()),
            user_agent: Some("agent".to_owned()),
            details_json: r#"{"mode":"hosted"}"#.to_owned(),
        });

        assert_eq!(response.event_type, "session.login");
        assert_eq!(response.details["mode"], "hosted");
        assert_eq!(response.user_id.as_deref(), Some("usr_123"));
    }

    #[test]
    fn audit_details_json_truncates_large_payloads() {
        let details = serde_json::json!({ "value": "x".repeat(AUDIT_EVENT_DETAILS_MAX_BYTES) });
        let json = audit_details_json(details).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["truncated"], true);
        assert!(value["originalBytes"].as_u64().unwrap() > AUDIT_EVENT_DETAILS_MAX_BYTES as u64);
    }

    #[test]
    fn audit_event_filter_validates_query_values() {
        let url = url::Url::parse(
            "https://id.example.com/events?event_type=session.login&user_id=usr_123&client_id=web&provider_id=google",
        )
        .unwrap();
        let filter = audit_event_filter_from_url(&url).unwrap();

        assert_eq!(filter.event_type.as_deref(), Some("session.login"));
        assert_eq!(filter.user_id.as_deref(), Some("usr_123"));
        assert_eq!(filter.client_id.as_deref(), Some("web"));
        assert_eq!(filter.provider_id.as_deref(), Some("google"));

        let url =
            url::Url::parse("https://id.example.com/events?event_type=session/login").unwrap();
        let error = audit_event_filter_from_url(&url).unwrap_err();
        assert_eq!(
            error.description,
            "event_type contains unsupported characters"
        );
    }

    #[test]
    fn client_admin_ui_from_row_includes_disabled_secret_state() {
        let client = client_admin_ui_from_row(ClientRow {
            id: "web".to_owned(),
            name: "Wavey Web".to_owned(),
            secret_hash: Some(format!("sha256:{}", hash_secret("web-secret"))),
            redirect_uris_json: r#"["https://app.example.com/callback"]"#.to_owned(),
            allowed_origins_json: r#"["https://app.example.com"]"#.to_owned(),
            allowed_email_domains_json: r#"["example.com"]"#.to_owned(),
            issuer_token_audience: Some("yl-record-issuer".to_owned()),
            issuer_token_ttl_seconds: Some(300),
            account_sharing_mode: None,
            account_tenant_id: None,
            visible_login_methods_json: Some(r#"["passkey"]"#.to_owned()),
            confidential: 1,
            disabled_at: Some(1_780_000_000),
        })
        .unwrap();

        assert_eq!(client.client_id, "web");
        assert!(client.confidential);
        assert!(client.disabled);
        assert!(client.has_secret);
        assert_eq!(client.visible_login_methods, vec!["passkey".to_owned()]);
        assert_eq!(
            client.issuer_token_audience,
            Some("yl-record-issuer".to_owned())
        );
        assert_eq!(client.issuer_token_ttl_seconds, Some(300));
    }

    #[test]
    fn admin_token_matches_sha256_config() {
        let hash = hash_secret("admin-token");

        assert!(admin_token_matches_config(
            "admin-token",
            &format!("sha256:{hash}")
        ));
        assert!(admin_token_matches_config("admin-token", &hash));
        assert!(!admin_token_matches_config("wrong-token", &hash));
    }

    #[test]
    fn provider_query_can_be_absent_for_hosted_picker() {
        let url = url::Url::parse("https://id.example.com/authorize").unwrap();
        assert_eq!(optional_provider_id_from_url(&url).unwrap(), None);
        let error = provider_id_from_url(&url).unwrap_err();
        assert_eq!(error.description, "missing provider");

        let url = url::Url::parse("https://id.example.com/authorize?provider=github").unwrap();
        let error = optional_provider_id_from_url(&url).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn transaction_preserves_downstream_state_and_redirect() {
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: Some("downstream-pkce".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        };

        let transaction = auth_transaction_from_request(
            &request,
            well_known::APPLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            1_780_000_000,
        );

        assert_eq!(transaction.provider_state, "provider-state");
        assert_eq!(transaction.nonce, Some("nonce-1".to_owned()));
        assert_eq!(
            transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(transaction.app_state, Some("app-state".to_owned()));
        assert_eq!(transaction.redirect_uri, "wavey://auth/callback");
        assert_eq!(
            transaction.provider_redirect_uri,
            "https://id.example.com/oauth2/callback"
        );
        assert_eq!(transaction.code_challenge_method, Some("S256".to_owned()));
        assert_eq!(transaction.link_user_id, None);
        assert_eq!(transaction.link_session_id, None);
        assert_eq!(transaction.session_return_to, None);
    }

    #[test]
    fn link_transaction_records_user_session_and_return() {
        let client = Client {
            id: ClientId("web".to_owned()),
            name: "Wavey Web".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let transaction = auth_transaction_from_link_request(
            &client,
            well_known::SPOTIFY,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/settings".to_owned(),
            Some("app-state".to_owned()),
            "usr_123",
            "sess_123",
            1_780_000_000,
        );

        assert_eq!(transaction.client_id, ClientId("web".to_owned()));
        assert_eq!(
            transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(transaction.redirect_uri, "https://app.example.com/settings");
        assert_eq!(transaction.app_state, Some("app-state".to_owned()));
        assert_eq!(transaction.link_user_id, Some(UserId("usr_123".to_owned())));
        assert_eq!(transaction.link_session_id, Some("sess_123".to_owned()));
        assert_eq!(transaction.session_return_to, None);
        assert!(transaction.scope.contains("openid"));
    }

    #[test]
    fn session_login_transaction_records_return() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard".to_owned(),
            Some("app-state".to_owned()),
            1_780_000_000,
        );

        assert_eq!(transaction.client_id, ClientId("browser".to_owned()));
        assert_eq!(
            transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(
            transaction.redirect_uri,
            "https://app.example.com/dashboard"
        );
        assert_eq!(
            transaction.session_return_to,
            Some("https://app.example.com/dashboard".to_owned())
        );
        assert_eq!(transaction.link_user_id, None);
        assert_eq!(transaction.link_session_id, None);
        assert!(transaction.scope.contains("profile"));
    }

    #[test]
    fn provider_authorize_nonce_prefers_provider_nonce_for_oidc() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let google_transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard".to_owned(),
            None,
            1_780_000_000,
        );
        let spotify_transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::SPOTIFY,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard".to_owned(),
            None,
            1_780_000_000,
        );

        assert_eq!(
            provider_authorize_nonce(&google_transaction),
            Some("provider-nonce")
        );
        assert_eq!(provider_authorize_nonce(&spotify_transaction), None);
    }

    #[test]
    fn identity_link_return_to_is_client_bounded() {
        let client = Client {
            id: ClientId("web".to_owned()),
            name: "Wavey Web".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fapp.example.com%2Fsettings",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, None).unwrap(),
            "https://app.example.com/settings"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=wavey%3A%2F%2Fauth%2Fcallback",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, None).unwrap(),
            "wavey://auth/callback"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fevil.example%2Fsettings",
        )
        .unwrap();
        let error = identity_link_return_to_from_url(&url, &client, None).unwrap_err();
        assert_eq!(
            error,
            "return_to must match a registered redirect URI or allowed origin"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Faccount",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
                .unwrap(),
            "https://id.example.com/account"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Fadmin",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
                .unwrap(),
            "https://id.example.com/admin"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Fadmin%2Fclients",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
                .unwrap(),
            "https://id.example.com/admin/clients"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Fadmin%2Fevil",
        )
        .unwrap();
        let error = identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
            .unwrap_err();
        assert_eq!(
            error,
            "return_to must match a registered redirect URI or allowed origin"
        );
    }

    #[test]
    fn logout_redirect_url_is_client_bounded_and_preserves_state() {
        let client = Client {
            id: ClientId("web".to_owned()),
            name: "Wavey Web".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let url = url::Url::parse(
            "https://id.example.com/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fsigned-out&state=done",
        )
        .unwrap();
        assert_eq!(
            validated_logout_redirect_url(
                &url,
                "https://app.example.com/signed-out",
                &client,
                None
            )
            .unwrap()
            .as_str(),
            "https://app.example.com/signed-out?state=done"
        );

        let url = url::Url::parse(
            "https://id.example.com/logout?post_logout_redirect_uri=wavey%3A%2F%2Fauth%2Fcallback&state=done",
        )
        .unwrap();
        assert_eq!(
            validated_logout_redirect_url(&url, "wavey://auth/callback", &client, None)
                .unwrap()
                .as_str(),
            "wavey://auth/callback?state=done"
        );

        let error =
            validated_logout_redirect_url(&url, "https://evil.example/signed-out", &client, None)
                .unwrap_err();
        assert_eq!(
            error,
            "return_to must match a registered redirect URI or allowed origin"
        );
    }

    #[test]
    fn identity_link_return_url_preserves_state_and_provider() {
        let transaction = auth_transaction_from_link_request(
            &Client {
                id: ClientId("web".to_owned()),
                name: "Wavey Web".to_owned(),
                redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
                allowed_origins: vec!["https://app.example.com".to_owned()],
                allowed_email_domains: vec![],
                confidential: false,
            },
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/settings?tab=login".to_owned(),
            Some("app-state".to_owned()),
            "usr_123",
            "sess_123",
            1_780_000_000,
        );
        let profile = ProviderProfile {
            provider_id: ProviderId(well_known::GOOGLE.to_owned()),
            subject: zeroth_core::Subject("google-sub".to_owned()),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            display_name: None,
            picture_url: None,
        };

        let return_url = identity_link_return_url(&transaction, &profile).unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            return_url.as_str().split('?').next().unwrap(),
            "https://app.example.com/settings"
        );
        assert!(query_pairs.contains(&("tab".to_owned(), "login".to_owned())));
        assert!(query_pairs.contains(&("identity_linked".to_owned(), "true".to_owned())));
        assert!(query_pairs.contains(&("provider".to_owned(), "google".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
    }

    #[test]
    fn session_login_return_url_preserves_return_and_optional_state() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard?existing=1".to_owned(),
            Some("app-state".to_owned()),
            1_780_000_000,
        );

        let return_url = session_login_return_url(&transaction).unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            return_url.as_str().split('?').next().unwrap(),
            "https://app.example.com/dashboard"
        );
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
    }

    #[test]
    fn provider_callback_error_return_url_uses_oidc_redirect() {
        let transaction = AuthTransaction {
            provider_state: "provider-state".to_owned(),
            client_id: ClientId("ios".to_owned()),
            provider_id: ProviderId(well_known::APPLE.to_owned()),
            redirect_uri: "wavey://auth/callback?existing=1".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: Some("app-state".to_owned()),
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: unix_seconds_to_system_time(1_780_000_000),
            expires_at: unix_seconds_to_system_time(1_780_000_600),
        };
        let error = ProviderCallbackError {
            code: "access_denied".to_owned(),
            description: "User cancelled".to_owned(),
        };

        let return_url =
            provider_callback_error_return_url(&transaction, "https://id.example.com", &error)
                .unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(return_url.scheme(), "wavey");
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("error".to_owned(), "access_denied".to_owned())));
        assert!(
            query_pairs.contains(&("error_description".to_owned(), "User cancelled".to_owned()))
        );
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(query_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));
        assert!(!query_pairs.iter().any(|(key, _)| key == "code"));
    }

    #[test]
    fn provider_callback_error_return_url_uses_session_return_to() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard?existing=1".to_owned(),
            Some("app-state".to_owned()),
            1_780_000_000,
        );
        let error = ProviderCallbackError {
            code: "access_denied".to_owned(),
            description: "User cancelled".to_owned(),
        };

        let return_url =
            provider_callback_error_return_url(&transaction, "https://id.example.com", &error)
                .unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            return_url.as_str().split('?').next().unwrap(),
            "https://app.example.com/dashboard"
        );
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("error".to_owned(), "access_denied".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(!query_pairs.iter().any(|(key, _)| key == "iss"));
    }

    #[test]
    fn provider_upstream_failures_map_to_oauth_callback_errors() {
        let token_error = provider_callback_error_from_token_exchange_error(
            &ProviderTokenExchangeError::invalid_response("provider token endpoint returned 502"),
        );
        assert_eq!(token_error.code, "temporarily_unavailable");
        assert!(token_error
            .description
            .contains("provider token exchange failed"));
        assert!(token_error
            .description
            .contains("provider token endpoint returned 502"));

        let profile_error =
            provider_callback_error_from_profile_error(&ProviderProfileError::invalid_response(
                "Spotify profile endpoint returned HTTP 403: premium required",
            ));
        assert_eq!(profile_error.code, "temporarily_unavailable");
        assert!(profile_error
            .description
            .contains("provider profile lookup failed"));
        assert!(profile_error
            .description
            .contains("Spotify profile endpoint returned HTTP 403"));
    }

    #[test]
    fn client_redirect_url_includes_auth_code_and_app_state() {
        let transaction = AuthTransaction {
            provider_state: "provider-state".to_owned(),
            client_id: ClientId("ios".to_owned()),
            provider_id: ProviderId(well_known::SPOTIFY.to_owned()),
            redirect_uri: "wavey://auth/callback?existing=1".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: Some("app-state".to_owned()),
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: unix_seconds_to_system_time(1_780_000_000),
            expires_at: unix_seconds_to_system_time(1_780_000_600),
        };

        let redirect_url =
            client_redirect_url(&transaction, "https://id.example.com", "zeroth-code").unwrap();
        let query_pairs = redirect_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(redirect_url.scheme(), "wavey");
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("code".to_owned(), "zeroth-code".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(query_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));
    }

    #[test]
    fn prompt_none_redirect_urls_include_code_or_login_required() {
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback?existing=1".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            prompt: AuthorizationPrompt::None,
            max_age: None,
            code_challenge: Some("downstream-pkce".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        };

        let success_url =
            authorization_request_client_redirect_url(&request, "https://id.example.com", "code-1")
                .unwrap();
        let success_pairs = success_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(success_url.scheme(), "wavey");
        assert!(success_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(success_pairs.contains(&("code".to_owned(), "code-1".to_owned())));
        assert!(success_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(success_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));

        let error_url = authorization_request_error_redirect_url(
            &request,
            "https://id.example.com",
            "login_required",
            "active browser session was not found",
        )
        .unwrap();
        let error_pairs = error_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(error_url.scheme(), "wavey");
        assert!(error_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(error_pairs.contains(&("error".to_owned(), "login_required".to_owned())));
        assert!(error_pairs.contains(&(
            "error_description".to_owned(),
            "active browser session was not found".to_owned()
        )));
        assert!(error_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(error_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));
        assert!(!error_pairs.iter().any(|(key, _)| key == "code"));
    }

    #[test]
    fn hosted_admin_login_url_targets_hosted_login_chooser() {
        let url = hosted_admin_login_url("https://id.example.com", "/admin").unwrap();
        let query_pairs = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            url.as_str(),
            "https://id.example.com/login?return_to=https%3A%2F%2Fid.example.com%2Fadmin"
        );
        assert!(!query_pairs.iter().any(|(key, _)| key == "provider"));
        assert!(query_pairs.contains(&(
            "return_to".to_owned(),
            "https://id.example.com/admin".to_owned()
        )));

        let clients_url =
            hosted_admin_login_url("https://id.example.com/", "/admin/clients").unwrap();
        assert_eq!(
            clients_url.as_str(),
            "https://id.example.com/login?return_to=https%3A%2F%2Fid.example.com%2Fadmin%2Fclients"
        );
    }

    #[test]
    fn session_login_return_to_defaults_to_hosted_account() {
        let client = Client {
            id: ClientId("wavey-browser".to_owned()),
            name: "Wavey Browser SSO".to_owned(),
            redirect_uris: vec!["https://wavey.ai/auth/callback".to_owned()],
            allowed_origins: vec!["https://wavey.ai".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let url = url::Url::parse("https://id.example.com/login").unwrap();

        assert_eq!(
            session_login_return_to_from_url(&url, &client, "https://id.example.com").unwrap(),
            "https://id.example.com/account"
        );
    }

    #[test]
    fn session_login_return_to_keeps_explicit_product_target() {
        let client = Client {
            id: ClientId("wavey-browser".to_owned()),
            name: "Wavey Browser SSO".to_owned(),
            redirect_uris: vec!["https://wavey.ai/auth/callback".to_owned()],
            allowed_origins: vec!["https://wavey.ai".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let url = url::Url::parse(
            "https://id.example.com/login?return_to=https%3A%2F%2Fwavey.ai%2Fsettings",
        )
        .unwrap();

        assert_eq!(
            session_login_return_to_from_url(&url, &client, "https://id.example.com").unwrap(),
            "https://wavey.ai/settings"
        );

        let url = url::Url::parse(
            "https://id.example.com/login?redirect_uri=https%3A%2F%2Fwavey.ai%2Fauth%2Fcallback",
        )
        .unwrap();
        assert_eq!(
            session_login_return_to_from_url(&url, &client, "https://id.example.com").unwrap(),
            "https://wavey.ai/auth/callback"
        );
    }

    #[test]
    fn authorization_request_errors_redirect_only_for_registered_redirect_uri() {
        let client = Client {
            id: ClientId("ios".to_owned()),
            name: "Wavey iOS".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: None,
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let error = validate_authorization_request_for_client(&request, &client).unwrap_err();

        let redirect_url = authorization_request_error_redirect_url_for_client(
            &request,
            &client,
            "https://id.example.com",
            &error,
        )
        .unwrap()
        .unwrap();
        let query_pairs = redirect_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(redirect_url.scheme(), "wavey");
        assert!(query_pairs.contains(&("error".to_owned(), "invalid_request".to_owned())));
        assert!(query_pairs.contains(&(
            "error_description".to_owned(),
            "public clients must use PKCE".to_owned()
        )));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(query_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));

        let unregistered_redirect_request = AuthorizationRequest {
            redirect_uri: "wavey://evil/callback".to_owned(),
            ..request
        };
        let error =
            validate_authorization_request_for_client(&unregistered_redirect_request, &client)
                .unwrap_err();

        assert!(authorization_request_error_redirect_url_for_client(
            &unregistered_redirect_request,
            &client,
            "https://id.example.com",
            &error,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn hash_secret_returns_sha256_hex() {
        assert_eq!(
            hash_secret("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pkce_s256_challenge_matches_rfc7636_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        assert_eq!(
            pkce_s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn token_exchange_form_rejects_wrong_grant_type() {
        let mut form = valid_token_exchange_form();
        form.grant_type = "client_credentials".to_owned();

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "unsupported_grant_type");
    }

    #[test]
    fn token_exchange_form_rejects_short_code_verifier() {
        let mut form = valid_token_exchange_form();
        form.code_verifier = Some("short".to_owned());

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "code_verifier must be 43 to 128 characters"
        );
    }

    #[test]
    fn token_exchange_form_accepts_refresh_token_grant() {
        let form = TokenExchangeForm {
            grant_type: "refresh_token".to_owned(),
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            redirect_uri: None,
            code: None,
            code_verifier: None,
            refresh_token: Some("refresh-token".to_owned()),
            scope: None,
            subject_token: None,
            subject_token_type: None,
            provider: None,
            provider_client_id: None,
            nonce: None,
        };

        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn token_exchange_form_accepts_native_apple_id_token_grant() {
        let form = valid_native_apple_token_exchange_form();

        let fields = native_provider_token_fields(&form).unwrap();

        assert_eq!(fields.provider_id, well_known::APPLE);
        assert_eq!(fields.subject_token, "apple.id.token");
        assert_eq!(fields.provider_client_id, Some("ai.wavey.id"));
        assert_eq!(fields.subject_token_type, ID_TOKEN_SUBJECT_TOKEN_TYPE);
        assert_eq!(
            native_token_scope(fields.scope).unwrap(),
            DEFAULT_NATIVE_TOKEN_SCOPE
        );
        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn token_exchange_form_accepts_native_google_id_token_grant() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some(well_known::GOOGLE.to_owned());
        form.subject_token = Some("google.id.token".to_owned());
        form.provider_client_id = Some("google-ios-client".to_owned());

        let fields = native_provider_token_fields(&form).unwrap();

        assert_eq!(fields.provider_id, well_known::GOOGLE);
        assert_eq!(fields.subject_token, "google.id.token");
        assert_eq!(fields.provider_client_id, Some("google-ios-client"));
        assert_eq!(fields.subject_token_type, ID_TOKEN_SUBJECT_TOKEN_TYPE);
        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn token_exchange_form_accepts_native_spotify_access_token_grant() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some(well_known::SPOTIFY.to_owned());
        form.subject_token = Some("spotify.access.token".to_owned());
        form.subject_token_type = Some(ACCESS_TOKEN_SUBJECT_TOKEN_TYPE.to_owned());
        form.provider_client_id = Some("spotify-ios-client".to_owned());

        let fields = native_provider_token_fields(&form).unwrap();

        assert_eq!(fields.provider_id, well_known::SPOTIFY);
        assert_eq!(fields.subject_token, "spotify.access.token");
        assert_eq!(fields.provider_client_id, Some("spotify-ios-client"));
        assert_eq!(fields.subject_token_type, ACCESS_TOKEN_SUBJECT_TOKEN_TYPE);
        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn native_provider_token_grant_rejects_unsupported_provider() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some("github".to_owned());

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "token exchange provider must be apple, google, or spotify"
        );
    }

    #[test]
    fn native_spotify_token_grant_requires_access_token_type() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some(well_known::SPOTIFY.to_owned());

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "subject_token_type must be urn:ietf:params:oauth:token-type:access_token"
        );
    }

    #[test]
    fn native_apple_client_id_selects_single_configured_audience() {
        let configured = vec!["ai.wavey.id".to_owned()];

        assert_eq!(
            native_apple_provider_client_id_from_list(&configured, None).unwrap(),
            "ai.wavey.id"
        );
        assert_eq!(
            native_apple_provider_client_id_from_list(&configured, Some("ai.wavey.id")).unwrap(),
            "ai.wavey.id"
        );
    }

    #[test]
    fn native_apple_client_id_requires_allowed_requested_audience() {
        let configured = vec!["ai.wavey.id".to_owned(), "ai.bitneedle.app".to_owned()];

        let missing = native_apple_provider_client_id_from_list(&configured, None).unwrap_err();
        assert_eq!(
            missing.description,
            "provider_client_id is required when multiple Apple native client IDs are configured"
        );

        let denied =
            native_apple_provider_client_id_from_list(&configured, Some("evil.app")).unwrap_err();
        assert_eq!(denied.description, "provider_client_id is not allowed");
    }

    #[test]
    fn native_google_client_id_selects_allowed_audience() {
        let configured = vec!["google-ios-client".to_owned()];

        assert_eq!(
            native_provider_client_id_from_list(well_known::GOOGLE, &configured, None).unwrap(),
            "google-ios-client"
        );
        assert_eq!(
            native_provider_client_id_from_list(
                well_known::GOOGLE,
                &configured,
                Some("google-ios-client")
            )
            .unwrap(),
            "google-ios-client"
        );
    }

    #[test]
    fn native_spotify_client_id_requires_configured_audience() {
        let error =
            native_provider_client_id_from_list(well_known::SPOTIFY, &[], None).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "SPOTIFY_NATIVE_CLIENT_IDS is not configured"
        );
    }

    #[test]
    fn native_token_scope_defaults_to_openid_profile_email() {
        assert_eq!(
            native_token_scope(None).unwrap(),
            DEFAULT_NATIVE_TOKEN_SCOPE.to_owned()
        );

        let error = native_token_scope(Some("email profile")).unwrap_err();
        assert_eq!(error.description, "scope must include openid");
    }

    #[test]
    fn token_client_auth_accepts_client_secret_post() {
        let (client_id, auth) =
            token_client_auth(Some("web".to_owned()), Some("web-secret".to_owned()), None).unwrap();

        assert_eq!(client_id, "web");
        assert_eq!(auth, ClientAuth::SecretPost("web-secret".to_owned()));
    }

    #[test]
    fn token_client_auth_accepts_basic_auth() {
        let credentials = STANDARD.encode("web:web-secret");
        let basic = client_basic_auth_from_header(Some(&format!("Basic {credentials}")))
            .unwrap()
            .unwrap();
        let (client_id, auth) =
            token_client_auth(Some("web".to_owned()), None, Some(basic)).unwrap();

        assert_eq!(client_id, "web");
        assert_eq!(auth, ClientAuth::SecretBasic("web-secret".to_owned()));
    }

    #[test]
    fn token_client_auth_rejects_mixed_auth_methods() {
        let basic = ClientBasicAuth {
            client_id: "web".to_owned(),
            client_secret: "basic-secret".to_owned(),
        };

        let error = token_client_auth(
            Some("web".to_owned()),
            Some("post-secret".to_owned()),
            Some(basic),
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "client authentication must use only one method"
        );
    }

    #[test]
    fn confidential_client_auth_accepts_matching_secret_hash() {
        let client = registered_confidential_client("web-secret");
        let mut form = valid_token_exchange_form();
        form.client_id = "web".to_owned();
        form.client_auth = ClientAuth::SecretPost("web-secret".to_owned());

        validate_token_client_auth(&client, &form.client_id, &form.client_auth).unwrap();
    }

    #[test]
    fn confidential_client_auth_rejects_missing_secret() {
        let client = registered_confidential_client("web-secret");
        let mut form = valid_token_exchange_form();
        form.client_id = "web".to_owned();
        form.client_auth = ClientAuth::None;

        let error =
            validate_token_client_auth(&client, &form.client_id, &form.client_auth).unwrap_err();

        assert_eq!(error.code, "invalid_client");
        assert_eq!(
            error.description,
            "confidential clients must authenticate with client_secret"
        );
    }

    #[test]
    fn public_client_auth_rejects_client_secret() {
        let client = registered_public_client();
        let mut form = valid_token_exchange_form();
        form.client_auth = ClientAuth::SecretPost("ios-secret".to_owned());

        let error =
            validate_token_client_auth(&client, &form.client_id, &form.client_auth).unwrap_err();

        assert_eq!(error.code, "invalid_client");
        assert_eq!(
            error.description,
            "public clients must not use client_secret authentication"
        );
    }

    #[test]
    fn authorization_code_exchange_accepts_matching_pkce() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = valid_auth_code_row(pkce_s256_challenge(verifier));
        let mut form = valid_token_exchange_form();
        form.code_verifier = Some(verifier.to_owned());
        let fields = authorization_code_fields(&form).unwrap();

        validate_authorization_code_exchange(&code, &fields, 1_780_000_100).unwrap();
    }

    #[test]
    fn authorization_code_exchange_accepts_confidential_code_without_pkce() {
        let mut code = valid_auth_code_row(String::new());
        code.client_id = "web".to_owned();
        code.redirect_uri = "https://app.example.com/auth/callback".to_owned();
        code.code_challenge = None;
        code.code_challenge_method = None;
        let form = TokenExchangeForm {
            grant_type: "authorization_code".to_owned(),
            client_id: "web".to_owned(),
            client_auth: ClientAuth::SecretBasic("web-secret".to_owned()),
            redirect_uri: Some("https://app.example.com/auth/callback".to_owned()),
            code: Some("zeroth-code".to_owned()),
            code_verifier: None,
            refresh_token: None,
            scope: None,
            subject_token: None,
            subject_token_type: None,
            provider: None,
            provider_client_id: None,
            nonce: None,
        };
        let fields = authorization_code_fields(&form).unwrap();

        validate_authorization_code_exchange(&code, &fields, 1_780_000_100).unwrap();
    }

    #[test]
    fn authorization_code_exchange_rejects_bad_pkce() {
        let code = valid_auth_code_row(pkce_s256_challenge(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ));
        let mut form = valid_token_exchange_form();
        form.code_verifier = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned());
        let fields = authorization_code_fields(&form).unwrap();

        let error =
            validate_authorization_code_exchange(&code, &fields, 1_780_000_100).unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(
            error.description,
            "code_verifier did not match code_challenge"
        );
    }

    #[test]
    fn refresh_token_exchange_rejects_rotated_token() {
        let mut row = valid_refresh_token_row();
        row.rotated_at = Some(1_780_000_100);

        let error = validate_refresh_token_exchange(&row, "ios", 1_780_000_200).unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(error.description, "refresh token has already been rotated");
        assert!(refresh_token_replay_detected(&row, "ios"));
    }

    #[test]
    fn refresh_token_exchange_rejects_wrong_client() {
        let row = valid_refresh_token_row();

        let error = validate_refresh_token_exchange(&row, "web", 1_780_000_200).unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(error.description, "refresh token client_id does not match");
        assert!(!refresh_token_replay_detected(&row, "web"));
    }

    #[test]
    fn refresh_token_replay_detection_ignores_revoked_or_unrotated_tokens() {
        let mut row = valid_refresh_token_row();
        assert!(!refresh_token_replay_detected(&row, "ios"));

        row.rotated_at = Some(1_780_000_100);
        row.revoked_at = Some(1_780_000_150);
        assert!(!refresh_token_replay_detected(&row, "ios"));
    }

    #[test]
    fn d1_change_detection_requires_exactly_one_change() {
        assert!(d1_changes_exactly_one(Some(1)));
        assert!(!d1_changes_exactly_one(Some(0)));
        assert!(!d1_changes_exactly_one(Some(2)));
        assert!(!d1_changes_exactly_one(None));
    }

    #[test]
    fn token_issue_preserves_session_id_for_refresh_token_family() {
        let code = valid_auth_code_row("challenge".to_owned());
        let issue = TokenIssue::from_auth_code(&code);
        assert_eq!(issue.session_id, Some("sess_123".to_owned()));

        let row = valid_refresh_token_row();
        let issue = TokenIssue::from_refresh_token(&row);
        assert_eq!(issue.session_id, Some("sess_123".to_owned()));

        let mut legacy_row = row;
        legacy_row.session_id = None;
        let issue = TokenIssue::from_refresh_token(&legacy_row);
        assert_eq!(issue.session_id, None);
    }

    #[test]
    fn token_issue_preserves_original_auth_time_for_silent_sso() {
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.created_at = 1_780_000_500;
        code.auth_time = Some(1_780_000_000);

        let issue = TokenIssue::from_auth_code(&code);

        assert_eq!(issue.auth_time, Some(1_780_000_000));

        let mut legacy_code = code;
        legacy_code.auth_time = None;
        let issue = TokenIssue::from_auth_code(&legacy_code);
        assert_eq!(issue.auth_time, Some(1_780_000_500));
    }

    #[test]
    fn token_issue_preserves_refresh_token_auth_time() {
        let mut row = valid_refresh_token_row();
        row.created_at = 1_780_000_600;
        row.auth_time = Some(1_780_000_000);

        let issue = TokenIssue::from_refresh_token(&row);

        assert_eq!(issue.auth_time, Some(1_780_000_000));
    }

    #[test]
    fn token_revocation_form_accepts_refresh_token_hint() {
        let form = TokenRevocationForm {
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            token: "refresh-token".to_owned(),
            token_type_hint: Some("refresh_token".to_owned()),
        };

        validate_token_revocation_form(&form).unwrap();
        assert!(should_attempt_refresh_token_revocation(
            form.token_type_hint.as_deref()
        ));
    }

    #[test]
    fn token_revocation_form_accepts_access_token_noop_hint() {
        let form = TokenRevocationForm {
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            token: "access-token".to_owned(),
            token_type_hint: Some("access_token".to_owned()),
        };

        validate_token_revocation_form(&form).unwrap();
        assert!(!should_attempt_refresh_token_revocation(
            form.token_type_hint.as_deref()
        ));
    }

    #[test]
    fn token_revocation_form_rejects_unknown_hint() {
        let form = TokenRevocationForm {
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            token: "refresh-token".to_owned(),
            token_type_hint: Some("id_token".to_owned()),
        };

        let error = validate_token_revocation_form(&form).unwrap_err();

        assert_eq!(error.code, "unsupported_token_type");
        assert_eq!(
            error.description,
            "token_type_hint must be refresh_token or access_token"
        );
    }

    #[test]
    fn token_introspection_form_accepts_access_and_refresh_hints() {
        let access_form = TokenIntrospectionForm {
            client_id: "web".to_owned(),
            client_auth: ClientAuth::SecretPost("web-secret".to_owned()),
            token: "access-token".to_owned(),
            token_type_hint: Some("access_token".to_owned()),
        };
        let refresh_form = TokenIntrospectionForm {
            token_type_hint: Some("refresh_token".to_owned()),
            ..access_form.clone()
        };

        validate_token_introspection_form(&access_form).unwrap();
        validate_token_introspection_form(&refresh_form).unwrap();
    }

    #[test]
    fn token_introspection_form_rejects_unknown_hint() {
        let form = TokenIntrospectionForm {
            client_id: "web".to_owned(),
            client_auth: ClientAuth::SecretPost("web-secret".to_owned()),
            token: "access-token".to_owned(),
            token_type_hint: Some("id_token".to_owned()),
        };

        let error = validate_token_introspection_form(&form).unwrap_err();

        assert_eq!(error.code, "unsupported_token_type");
        assert_eq!(
            error.description,
            "token_type_hint must be access_token or refresh_token"
        );
    }

    #[test]
    fn token_introspection_requires_confidential_client() {
        let client = registered_public_client();

        let error =
            validate_introspection_client_auth(&client, "ios", &ClientAuth::None).unwrap_err();

        assert_eq!(error.code, "invalid_client");
        assert_eq!(
            error.description,
            "token introspection requires confidential client authentication"
        );
    }

    #[test]
    fn token_introspection_response_serializes_inactive_minimally() {
        let value = serde_json::to_value(TokenIntrospectionResponse::inactive()).unwrap();

        assert_eq!(value["active"], false);
        assert_eq!(value.as_object().unwrap().len(), 1);
    }

    #[test]
    fn token_introspection_response_serializes_active_access_token() {
        let claims = JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "web".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: Some("sess_123".to_owned()),
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("web".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned(), "admin".to_owned()],
        };

        let value =
            serde_json::to_value(TokenIntrospectionResponse::active_access_token(&claims)).unwrap();

        assert_eq!(value["active"], true);
        assert_eq!(value["scope"], "openid email");
        assert_eq!(value["client_id"], "web");
        assert_eq!(value["token_type"], "Bearer");
        assert_eq!(value["token_use"], "access_token");
        assert_eq!(value["sub"], "usr_123");
        assert_eq!(value["aud"], "web");
        assert_eq!(value["iss"], "https://id.example.com");
        assert_eq!(value["iat"], 1_780_000_000);
        assert_eq!(value["exp"], 1_780_003_600);
        assert_eq!(value["sid"], "sess_123");
        assert_eq!(value["roles"][0], "user");
        assert_eq!(value["roles"][1], "admin");
        assert!(value.get("clientId").is_none());
    }

    #[test]
    fn token_introspection_response_serializes_active_refresh_token() {
        let row = valid_refresh_token_row();

        let value =
            serde_json::to_value(TokenIntrospectionResponse::active_refresh_token(&row)).unwrap();

        assert_eq!(value["active"], true);
        assert_eq!(value["scope"], "openid profile email offline_access");
        assert_eq!(value["client_id"], "ios");
        assert_eq!(value["token_use"], "refresh_token");
        assert_eq!(value["sub"], "usr_123");
        assert_eq!(value["aud"], "ios");
        assert_eq!(value["iat"], 1_780_000_000);
        assert_eq!(value["exp"], 1_780_086_400);
        assert_eq!(value["sid"], "sess_123");
        assert!(value.get("token_type").is_none());
        assert!(value.get("iss").is_none());
    }

    #[test]
    fn jwks_response_publishes_es256_public_key() {
        let signing_key = test_signing_key();

        let jwks = jwks_response(&signing_key, None).unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty.as_str(), "EC");
        assert_eq!(jwks.keys[0].key_use.as_str(), "sig");
        assert_eq!(jwks.keys[0].kid.as_str(), "test-key");
        assert_eq!(jwks.keys[0].alg.as_str(), "ES256");
        assert_eq!(jwks.keys[0].crv.as_str(), "P-256");
        assert!(!jwks.keys[0].x.is_empty());
        assert!(!jwks.keys[0].y.is_empty());
    }

    #[test]
    fn jwks_response_includes_previous_public_keys_for_rotation() {
        let active_signing_key = test_signing_key();
        let previous_signing_key = es256_signing_key_from_config(
            "previous-key",
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let previous_jwks = jwks_response(&previous_signing_key, None).unwrap();
        let previous_json = serde_json::to_string(&previous_jwks).unwrap();

        let jwks = jwks_response(&active_signing_key, Some(&previous_json)).unwrap();

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid.as_str(), "test-key");
        assert_eq!(jwks.keys[1].kid.as_str(), "previous-key");
    }

    #[test]
    fn jwks_response_deduplicates_previous_active_kid() {
        let signing_key = test_signing_key();
        let previous_jwks = jwks_response(&signing_key, None).unwrap();
        let previous_json = serde_json::to_string(&previous_jwks).unwrap();

        let jwks = jwks_response(&signing_key, Some(&previous_json)).unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid.as_str(), "test-key");
    }

    #[test]
    fn jwks_response_rejects_private_previous_jwk() {
        let signing_key = test_signing_key();
        let previous_jwks = serde_json::json!({
            "keys": [{
                "kty": "EC",
                "use": "sig",
                "kid": "previous-key",
                "alg": "ES256",
                "crv": "P-256",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }]
        });

        let error = jwks_response(&signing_key, Some(&previous_jwks.to_string())).unwrap_err();

        assert!(error.contains("invalid JWT_PREVIOUS_PUBLIC_JWKS_JSON JWKS JSON"));
    }

    #[test]
    fn sign_jwt_produces_es256_jwt() {
        let signing_key = test_signing_key();
        let claims = JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "ios".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: None,
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("ios".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: Vec::new(),
        };

        let jwt = sign_jwt(&signing_key, &claims).unwrap();
        let segments = jwt.split('.').collect::<Vec<_>>();
        let header = decode_jwt_json_segment::<serde_json::Value>(segments[0]);
        let payload = decode_jwt_json_segment::<serde_json::Value>(segments[1]);

        assert_eq!(segments.len(), 3);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "test-key");
        assert_eq!(payload["iss"], "https://id.example.com");
        assert_eq!(payload["sub"], "usr_123");
        assert_eq!(payload["token_use"], "access");
        assert_eq!(URL_SAFE_NO_PAD.decode(segments[2]).unwrap().len(), 64);
    }

    #[test]
    fn issuer_access_token_signing_verifies_with_public_jwks() {
        let signing_key = test_signing_key();
        let jwks = jwks_response(&signing_key, None).unwrap();
        let jwks =
            serde_json::from_value::<zeroth_oidc::ZerothJwks>(serde_json::to_value(&jwks).unwrap())
                .unwrap();
        let claims = build_issuer_access_token_claims(
            "https://id.example.com",
            "usr_123",
            "yl-web",
            "yl-record-issuer",
            1_780_000_000,
            300,
            "jti-123".to_owned(),
        );
        let token = sign_jwt(&signing_key, &claims).unwrap();

        let verified = zeroth_oidc::verify_zeroth_issued_access_token(
            &token,
            &jwks,
            "https://id.example.com",
            "yl-record-issuer",
            1_780_000_100,
        )
        .unwrap();

        assert_eq!(verified.iss, "https://id.example.com");
        assert_eq!(verified.sub, "usr_123");
        assert_eq!(verified.aud, "yl-record-issuer");
        assert_eq!(verified.client_id, "yl-web");
        assert_eq!(verified.jti, "jti-123");
        assert_eq!(verified.exp - verified.iat, 300);
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn json_status_no_store_sets_cache_control_header() {
        let response = json_status_no_store(&serde_json::json!({ "ok": true }), 200).unwrap();
        let cache_control = response.headers().get("Cache-Control").unwrap();

        assert_eq!(cache_control.as_deref(), Some("no-store"));
    }

    #[test]
    fn apple_client_secret_signs_expected_claims() {
        let signing_key = test_signing_key();
        let config = AppleClientSecretConfig {
            team_id: "TEAM12345".to_owned(),
            key_id: "KEY12345".to_owned(),
            client_id: "ai.wavey.service".to_owned(),
            private_key_pem: String::new(),
            ttl_seconds: 3_600,
        };

        let jwt = apple_client_secret_from_signing_key(
            &signing_key.signing_key,
            &config,
            1_780_000_000,
            1_780_003_600,
        )
        .unwrap();
        let segments = jwt.split('.').collect::<Vec<_>>();
        let header = decode_jwt_json_segment::<serde_json::Value>(segments[0]);
        let payload = decode_jwt_json_segment::<serde_json::Value>(segments[1]);

        assert_eq!(segments.len(), 3);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY12345");
        assert!(header.get("typ").is_none());
        assert_eq!(payload["iss"], "TEAM12345");
        assert_eq!(payload["sub"], "ai.wavey.service");
        assert_eq!(payload["aud"], "https://appleid.apple.com");
        assert_eq!(payload["iat"], 1_780_000_000);
        assert_eq!(payload["exp"], 1_780_003_600);
        assert_eq!(URL_SAFE_NO_PAD.decode(segments[2]).unwrap().len(), 64);
    }

    #[test]
    fn apple_client_secret_from_config_accepts_pkcs8_pem() {
        let signing_key = test_signing_key();
        let private_key_pem = signing_key
            .signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let config = AppleClientSecretConfig {
            team_id: "TEAM12345".to_owned(),
            key_id: "KEY12345".to_owned(),
            client_id: "ai.wavey.service".to_owned(),
            private_key_pem,
            ttl_seconds: 600,
        };

        let (jwt, expires_at) = apple_client_secret_from_config(&config, 1_780_000_000).unwrap();

        assert_eq!(expires_at, 1_780_000_600);
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn apple_client_secret_ttl_seconds_is_bounded() {
        assert_eq!(apple_client_secret_ttl_seconds(None).unwrap(), 15_552_000);
        assert_eq!(apple_client_secret_ttl_seconds(Some("600")).unwrap(), 600);

        let error = apple_client_secret_ttl_seconds(Some("31536000")).unwrap_err();

        assert_eq!(
            error,
            "APPLE_CLIENT_SECRET_TTL_SECONDS must be between 60 and 15552000"
        );
    }

    #[test]
    fn apple_private_key_secret_normalizes_escaped_newlines() {
        assert_eq!(
            normalize_private_key_pem_secret("-----BEGIN\\nKEY\\n-----END-----"),
            "-----BEGIN\nKEY\n-----END-----"
        );
    }

    #[test]
    fn token_response_mints_access_id_and_refresh_tokens() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.scope = "openid profile email offline_access".to_owned();
        let user_claims = valid_user_token_claims_row();
        let issue = TokenIssue::from_auth_code(&code).with_user_claims(&user_claims);

        let response = token_response(
            &config,
            &signing_key,
            &issue,
            Some("refresh-token".to_owned()),
            1_780_000_000,
        )
        .unwrap();
        let access_claims = decode_jwt_claims(&response.access_token);
        let id_claims = decode_jwt_claims(&response.id_token);

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, ACCESS_TOKEN_TTL_SECONDS);
        assert_eq!(response.refresh_token, Some("refresh-token".to_owned()));
        assert_eq!(response.scope, "openid profile email offline_access");
        assert_eq!(access_claims["token_use"], "access");
        assert_eq!(
            access_claims["scope"],
            "openid profile email offline_access"
        );
        assert_eq!(access_claims["client_id"], "ios");
        assert_eq!(access_claims["sid"], "sess_123");
        assert_eq!(access_claims["roles"][0], "user");
        assert!(access_claims.get("email").is_none());
        assert!(access_claims.get("name").is_none());
        assert_eq!(id_claims["token_use"], "id");
        assert_eq!(id_claims["nonce"], "nonce-1");
        assert_eq!(id_claims["auth_time"], 1_780_000_000);
        assert_eq!(id_claims["sid"], "sess_123");
        assert_eq!(id_claims["roles"][0], "user");
        assert_eq!(id_claims["email"], "user@example.com");
        assert_eq!(id_claims["email_verified"], true);
        assert_eq!(id_claims["name"], "Example User");
        assert_eq!(id_claims["picture"], "https://example.com/avatar.png");
    }

    #[test]
    fn token_response_includes_admin_role_for_admin_memberships() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let code = valid_auth_code_row("challenge".to_owned());
        let mut user_claims = valid_user_token_claims_row();
        user_claims.admin_membership_active = 1;
        let issue = TokenIssue::from_auth_code(&code).with_user_claims(&user_claims);

        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_000).unwrap();
        let access_claims = decode_jwt_claims(&response.access_token);

        assert_eq!(access_claims["roles"][0], "user");
        assert_eq!(access_claims["roles"][1], "admin");
    }

    #[test]
    fn token_response_omits_id_claims_outside_requested_scopes() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.scope = "openid".to_owned();
        let user_claims = valid_user_token_claims_row();
        let issue = TokenIssue::from_auth_code(&code).with_user_claims(&user_claims);

        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_000).unwrap();
        let id_claims = decode_jwt_claims(&response.id_token);

        assert_eq!(id_claims["token_use"], "id");
        assert!(id_claims.get("email").is_none());
        assert!(id_claims.get("email_verified").is_none());
        assert!(id_claims.get("name").is_none());
        assert!(id_claims.get("picture").is_none());
    }

    #[test]
    fn verify_zeroth_access_token_accepts_current_es256_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let issue = TokenIssue {
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email".to_owned(),
            auth_time: Some(1_780_000_000),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned()],
        };
        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_100).unwrap();
        let jwks = jwks_response(&signing_key, None).unwrap();

        let claims =
            verify_zeroth_access_token(&response.access_token, &config, &jwks, 1_780_000_200)
                .unwrap();

        assert_eq!(claims.sub, "usr_123");
        assert_eq!(claims.token_use, "access");
        assert_eq!(claims.scope, Some("openid profile email".to_owned()));
    }

    #[test]
    fn verify_zeroth_access_token_accepts_previous_es256_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let active_signing_key = test_signing_key();
        let previous_signing_key = es256_signing_key_from_config(
            "previous-key",
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let previous_jwks = jwks_response(&previous_signing_key, None).unwrap();
        let previous_json = serde_json::to_string(&previous_jwks).unwrap();
        let jwks = jwks_response(&active_signing_key, Some(&previous_json)).unwrap();
        let issue = TokenIssue {
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email".to_owned(),
            auth_time: Some(1_780_000_000),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned()],
        };
        let response =
            token_response(&config, &previous_signing_key, &issue, None, 1_780_000_100).unwrap();

        let claims =
            verify_zeroth_access_token(&response.access_token, &config, &jwks, 1_780_000_200)
                .unwrap();

        assert_eq!(claims.sub, "usr_123");
        assert_eq!(claims.token_use, "access");
    }

    #[test]
    fn verify_zeroth_access_token_rejects_id_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let issue = TokenIssue {
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email".to_owned(),
            auth_time: Some(1_780_000_000),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned()],
        };
        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_100).unwrap();
        let jwks = jwks_response(&signing_key, None).unwrap();

        let error = verify_zeroth_access_token(&response.id_token, &config, &jwks, 1_780_000_200)
            .unwrap_err();

        assert_eq!(error, "token is not an access token");
    }

    #[test]
    fn verify_zeroth_id_token_hint_accepts_id_token_and_rejects_access_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.scope = "openid profile email".to_owned();
        let issue =
            TokenIssue::from_auth_code(&code).with_user_claims(&valid_user_token_claims_row());
        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_100).unwrap();
        let jwks = jwks_response(&signing_key, None).unwrap();

        let claims =
            verify_zeroth_id_token_hint(&response.id_token, &config, &jwks, 1_780_000_200).unwrap();
        assert_eq!(claims.token_use, "id");
        assert_eq!(claims.aud, "ios");
        assert_eq!(claims.sub, "usr_123");

        let error =
            verify_zeroth_id_token_hint(&response.access_token, &config, &jwks, 1_780_000_200)
                .unwrap_err();
        assert_eq!(error, "id_token_hint is not an ID token");
    }

    #[test]
    fn bearer_token_from_authorization_header_accepts_bearer_token() {
        let token = bearer_token_from_authorization_header(Some("Bearer access-token")).unwrap();

        assert_eq!(token, Some("access-token".to_owned()));
    }

    #[test]
    fn bearer_token_from_authorization_header_allows_missing_header() {
        let token = bearer_token_from_authorization_header(None).unwrap();

        assert_eq!(token, None);
    }

    #[test]
    fn bearer_token_from_authorization_header_rejects_malformed_header() {
        let error = bearer_token_from_authorization_header(Some("Basic abc")).unwrap_err();

        assert_eq!(error, "missing bearer token");
    }

    #[test]
    fn validate_response_for_access_token_respects_scopes() {
        let user = valid_user_row();
        let claims = JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "ios".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: Some("sess_123".to_owned()),
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("ios".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned()],
        };

        let value = serde_json::to_value(validate_access_token_response(&claims, &user)).unwrap();

        assert_eq!(value["valid"], true);
        assert_eq!(value["kind"], "access_token");
        assert_eq!(value["clientId"], "ios");
        assert_eq!(value["expiresAt"], 1_780_003_600);
        assert_eq!(value["sessionId"], "sess_123");
        assert_eq!(value["user"]["email"], "user@example.com");
        assert!(value["user"].get("name").is_none());
        assert!(value.get("session").is_none());
    }

    #[test]
    fn access_token_session_claim_validation_allows_sessionless_tokens() {
        let mut claims = valid_access_token_claims();
        claims.sid = None;

        validate_access_token_session_claims(&claims, None, 1_780_000_100).unwrap();
    }

    #[test]
    fn access_token_session_claim_validation_requires_active_matching_session() {
        let claims = valid_access_token_claims();
        let session = valid_session_row();

        validate_access_token_session_claims(&claims, Some(&session), 1_780_000_100).unwrap();

        let error = validate_access_token_session_claims(&claims, None, 1_780_000_100).unwrap_err();
        assert_eq!(error, "access token session was not found");

        let mut mismatched_user = valid_session_row();
        mismatched_user.user_id = "usr_other".to_owned();
        let error =
            validate_access_token_session_claims(&claims, Some(&mismatched_user), 1_780_000_100)
                .unwrap_err();
        assert_eq!(error, "access token session user did not match subject");

        let mut mismatched_client = valid_session_row();
        mismatched_client.client_id = Some("web".to_owned());
        let error =
            validate_access_token_session_claims(&claims, Some(&mismatched_client), 1_780_000_100)
                .unwrap_err();
        assert_eq!(error, "access token session client did not match audience");

        let mut revoked = valid_session_row();
        revoked.revoked_at = Some(1_780_000_050);
        let error = validate_access_token_session_claims(&claims, Some(&revoked), 1_780_000_100)
            .unwrap_err();
        assert_eq!(error, "access token session is no longer active");
    }

    #[test]
    fn validate_response_for_session_includes_session_and_profile() {
        let session = valid_session_row();
        let user = valid_user_row();

        let value = serde_json::to_value(validate_session_response(&session, &user)).unwrap();

        assert_eq!(value["valid"], true);
        assert_eq!(value["kind"], "session");
        assert_eq!(value["clientId"], "ios");
        assert_eq!(value["expiresAt"], session.expires_at);
        assert_eq!(value["session"]["id"], "sess_123");
        assert_eq!(value["user"]["name"], "Example User");
    }

    #[test]
    fn userinfo_response_respects_access_token_scopes() {
        let user = UserRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/avatar.png".to_owned()),
            disabled_at: None,
        };

        let response = userinfo_response(&user, Some("openid email"));

        assert_eq!(response.sub, "usr_123");
        assert_eq!(response.email, Some("user@example.com".to_owned()));
        assert_eq!(response.name, None);
        assert_eq!(response.picture, None);
    }

    #[test]
    fn session_cookie_is_secure_http_only_and_cross_site() {
        let cookie = session_cookie("zeroth_session", "sess_123", SESSION_TTL_SECONDS, None);

        assert!(cookie.starts_with("zeroth_session=sess_123; Path=/;"));
        assert!(cookie.contains("Max-Age=2592000"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=None"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn session_cookie_can_target_parent_domain() {
        let cookie = session_cookie(
            "zeroth_session",
            "sess_123",
            SESSION_TTL_SECONDS,
            Some(".wavey.ai"),
        );

        assert!(cookie.contains("Domain=.wavey.ai"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=None"));
    }

    #[test]
    fn clear_session_cookie_expires_browser_cookie() {
        let cookie = clear_session_cookie("zeroth_session", None);

        assert_eq!(
            cookie,
            "zeroth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
        );
    }

    #[test]
    fn clear_session_cookie_uses_parent_domain_when_configured() {
        let cookie = clear_session_cookie("zeroth_session", Some(".wavey.ai"));

        assert_eq!(
            cookie,
            "zeroth_session=; Path=/; Max-Age=0; Domain=.wavey.ai; HttpOnly; Secure; SameSite=None"
        );
    }

    #[test]
    fn cookie_domain_attribute_rejects_header_delimiters() {
        assert_eq!(
            cookie_domain_attribute(Some(".wavey.ai")),
            " Domain=.wavey.ai;"
        );
        assert_eq!(cookie_domain_attribute(Some("bad.example; Secure")), "");
        assert_eq!(cookie_domain_attribute(Some("bad.example\r\nX: y")), "");
    }

    #[test]
    fn transaction_cookie_is_host_scoped_and_cross_site_post_safe() {
        let cookie =
            transaction_cookie("zeroth_tx", "provider-state", AUTH_TRANSACTION_TTL_SECONDS);

        assert!(cookie.starts_with("zeroth_tx=provider-state; Path=/;"));
        assert!(cookie.contains("Max-Age=600"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=None"));
    }

    #[test]
    fn clear_transaction_cookie_expires_host_scoped_cookie() {
        let cookie = clear_transaction_cookie("zeroth_tx");

        assert_eq!(
            cookie,
            "zeroth_tx=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
        );
    }

    #[test]
    fn known_route_path_covers_canonical_routes() {
        assert!(known_route_path("/ready"));
        assert!(known_route_path("/admin"));
        assert!(known_route_path("/profile-menu.js"));
        assert!(known_route_path("/profile-panel.js"));
        assert!(known_route_path("/client-branding"));
        assert!(known_route_path("/oauth2/callback"));
        assert!(known_route_path("/passkeys/authenticate/options"));
        assert!(known_route_path("/magic-links"));
        assert!(known_route_path("/.well-known/assetlinks.json"));
        assert!(!known_route_path("/admin/users/export"));
        assert!(!known_route_path("/api/client-branding"));
        assert!(!known_route_path("/magic_link"));
    }

    #[test]
    fn profile_menu_script_exposes_profile_menu_api() {
        assert!(ZEROTH_PROFILE_MENU_JS.contains("ZerothProfileMenu"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-profile-menu"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-mark"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("ZEROTH_COOKIE_NAME = \"zeroth\""));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("cookieValue(ZEROTH_COOKIE_NAME)"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("ZEROTH_COOKIE_MAX_AGE_SECONDS = 31536000"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("anonId"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("userIcon"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("setUserIcon"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("setAnonymousName"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("nameSource"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("clearAnonymousIdentity"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth:identity-cleared"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("data-zeroth-menu-clear"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-menu-actions"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("Reset Anon"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("anonymousIdentity"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("/client-branding"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-menu-item-primary"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("compactMenuOption"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-menu-button-compact"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-menu-link-compact"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("zeroth-menu-loading"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("data-compact"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("data-zeroth-menu-open"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("data-zeroth-popover-portal"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("data-zeroth-portal-popover"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("positionPopoverPortal"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("/session"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("/profile"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("/logout"));
        assert!(ZEROTH_PROFILE_MENU_JS.contains("[data-zeroth-profile-menu]"));
        let blocked_term = ["wid", "get"].concat();
        assert!(!ZEROTH_PROFILE_MENU_JS
            .to_ascii_lowercase()
            .contains(&blocked_term));
    }

    #[test]
    fn profile_panel_script_exposes_profile_panel_api() {
        assert!(ZEROTH_PROFILE_PANEL_JS.contains("ZerothProfilePanel"));
        assert!(ZEROTH_PROFILE_PANEL_JS.contains("zeroth-profile-panel"));
        assert!(ZEROTH_PROFILE_PANEL_JS.contains("/profile"));
        assert!(ZEROTH_PROFILE_PANEL_JS.contains("/identities"));
        assert!(ZEROTH_PROFILE_PANEL_JS.contains("/sessions"));
        let blocked_term = ["wid", "get"].concat();
        assert!(!ZEROTH_PROFILE_PANEL_JS
            .to_ascii_lowercase()
            .contains(&blocked_term));
    }

    #[test]
    fn cookie_value_extracts_named_cookie() {
        let cookie = cookie_value(
            Some("theme=dark; zeroth_session=sess_123; other=value"),
            "zeroth_session",
        );

        assert_eq!(cookie, Some("sess_123".to_owned()));
    }

    #[test]
    fn provider_callback_state_requires_matching_transaction_cookie() {
        provider_callback_state_matches_transaction_cookie("state-1", Some("state-1")).unwrap();

        let error = provider_callback_state_matches_transaction_cookie("state-1", Some("state-2"))
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "provider callback state did not match browser transaction"
        );

        let error =
            provider_callback_state_matches_transaction_cookie("state-1", None).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn session_row_is_inactive_when_revoked_or_expired() {
        let mut session = valid_session_row();

        assert!(session_row_is_active(&session, 1_780_000_100));

        session.revoked_at = Some(1_780_000_200);
        assert!(!session_row_is_active(&session, 1_780_000_300));

        session.revoked_at = None;
        session.expires_at = 1_780_000_300;
        assert!(!session_row_is_active(&session, 1_780_000_300));
    }

    #[test]
    fn authorization_request_session_reuse_respects_prompt_login_and_max_age() {
        let session = valid_session_row();
        let mut request = valid_authorization_request();

        assert!(authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));

        request.max_age = Some(120);
        assert!(authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_120
        ));
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_121
        ));

        request.max_age = Some(0);
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_001
        ));

        request.max_age = None;
        request.prompt = AuthorizationPrompt::Login;
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));

        request.prompt = AuthorizationPrompt::SelectAccount;
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));

        request.prompt = AuthorizationPrompt::Consent;
        assert!(authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));
    }

    #[test]
    fn session_response_includes_authenticated_user_profile() {
        let session = valid_session_row();
        let user = valid_user_row();

        let value = serde_json::to_value(session_response(Some((&session, &user)))).unwrap();

        assert_eq!(value["authenticated"], true);
        assert_eq!(value["session"]["id"], "sess_123");
        assert_eq!(value["session"]["clientId"], "ios");
        assert_eq!(value["user"]["sub"], "usr_123");
        assert_eq!(value["user"]["email"], "user@example.com");
        assert_eq!(value["user"]["name"], "Example User");
    }

    #[test]
    fn session_response_omits_session_and_user_when_anonymous() {
        let value = serde_json::to_value(session_response(None)).unwrap();

        assert_eq!(value["authenticated"], false);
        assert!(value.get("session").is_none());
        assert!(value.get("user").is_none());
    }

    #[test]
    fn profile_patch_accepts_aliases_and_null_clears_picture() {
        let patch = profile_patch_from_value(serde_json::json!({
            "displayName": "  New Name  ",
            "picture": null
        }))
        .unwrap();

        assert_eq!(
            patch,
            ProfilePatch {
                display_name: Some(Some("New Name".to_owned())),
                picture_url: Some(None),
            }
        );
    }

    #[test]
    fn profile_patch_rejects_unknown_and_invalid_fields() {
        let error = profile_patch_from_value(serde_json::json!({ "email": "new@example.com" }))
            .unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error
            .description
            .contains("unsupported profile patch field"));

        let error = profile_patch_from_value(serde_json::json!({ "picture": "ftp://x.test/a" }))
            .unwrap_err();
        assert_eq!(error.description, "picture must use http or https");
    }

    #[test]
    fn local_auth_forms_accept_snake_case_field_aliases() {
        let magic_link: MagicLinkRequest = serde_urlencoded::from_str(
            "email=user%40example.com&client_id=ios&return_to=https%3A%2F%2Fapp.example.com%2Fhome",
        )
        .unwrap();

        assert_eq!(magic_link.email, "user@example.com");
        assert_eq!(magic_link.client_id.as_deref(), Some("ios"));
        assert_eq!(
            magic_link.return_to.as_deref(),
            Some("https://app.example.com/home")
        );

        let login: PasswordLoginRequest = serde_urlencoded::from_str(
            "email=user%40example.com&password=correct-horse&client_id=ios&return_to=wavey%3A%2F%2Fauth%2Fcallback",
        )
        .unwrap();

        assert_eq!(login.client_id.as_deref(), Some("ios"));
        assert_eq!(login.return_to.as_deref(), Some("wavey://auth/callback"));
    }

    #[test]
    fn local_auth_registration_existing_user_requires_login() {
        let existing_user = valid_user_row();

        let error = local_auth_registration_user_id(None, Some(&existing_user), "user@example.com")
            .unwrap_err();

        assert_eq!(error, "account already exists; sign in instead");
        assert_eq!(local_auth_registration_error_code(&error), "account_exists");
        assert_eq!(
            local_auth_registration_user_id(None, None, "new@example.com").unwrap(),
            None
        );
    }

    #[test]
    fn local_auth_accepts_plus_addressing() {
        assert_eq!(
            validate_local_auth_email("Jamie+Zeroth@Wavey.ai").unwrap(),
            "jamie+zeroth@wavey.ai"
        );
        assert_eq!(
            validate_local_auth_email("jame1612+test123@gmail.com").unwrap(),
            "jame1612+test123@gmail.com"
        );
        assert_eq!(
            validate_passkey_email("person+product@example.com").unwrap(),
            "person+product@example.com"
        );
    }

    #[test]
    fn evm_wallet_validation_accepts_common_address_and_chain_values() {
        assert_eq!(
            validate_evm_wallet_address("0xAbCDEFabcdefABCDEFabcdefABCDEFabcdefABCD").unwrap(),
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );
        assert_eq!(normalize_evm_chain_id("0x1").unwrap(), "1");
        assert_eq!(normalize_evm_chain_id("0x2105").unwrap(), "8453");
        assert_eq!(normalize_evm_chain_id("84532").unwrap(), "84532");
        assert_eq!(
            validate_evm_wallet_address("abcdef").unwrap_err(),
            "wallet address must start with 0x"
        );
        assert_eq!(
            normalize_evm_chain_id("0").unwrap_err(),
            "wallet chain_id must be positive"
        );
    }

    #[test]
    fn evm_wallet_request_bodies_accept_snake_case_chain_id() {
        let challenge: WalletChallengeRequest = serde_json::from_value(serde_json::json!({
            "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "chain_id": "0x2105",
            "client_id": "browser",
            "return_to": "https://app.example.com/callback"
        }))
        .unwrap();

        assert_eq!(challenge.chain_id, "0x2105");
        assert_eq!(challenge.client_id.as_deref(), Some("browser"));
        assert_eq!(
            challenge.return_to.as_deref(),
            Some("https://app.example.com/callback")
        );

        let verify: WalletVerifyRequest = serde_json::from_value(serde_json::json!({
            "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "chain_id": "8453",
            "nonce": "a".repeat(64),
            "message": "message",
            "signature": format!("0x{}", "1".repeat(130))
        }))
        .unwrap();

        assert_eq!(verify.chain_id, "8453");
    }

    #[test]
    fn evm_wallet_challenge_validation_rejects_consumed_or_expired_rows() {
        let mut row = WalletChallengeRow {
            challenge_hash: "hash".to_owned(),
            provider_id: EVM_WALLET_PROVIDER_ID.to_owned(),
            address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned(),
            chain_id: "8453".to_owned(),
            client_id: "browser".to_owned(),
            return_to: "https://app.example.com/callback".to_owned(),
            account_namespace: "global".to_owned(),
            message: "message".to_owned(),
            created_at: 1_780_000_000,
            expires_at: 1_780_000_300,
            consumed_at: None,
            ip_hash: None,
            user_agent: None,
        };

        validate_wallet_challenge(&row, 1_780_000_100).unwrap();
        row.consumed_at = Some(1_780_000_050);
        assert_eq!(
            validate_wallet_challenge(&row, 1_780_000_100).unwrap_err(),
            "wallet challenge was already used"
        );
        row.consumed_at = None;
        assert_eq!(
            validate_wallet_challenge(&row, 1_780_000_300).unwrap_err(),
            "wallet challenge expired"
        );
    }

    #[test]
    fn evm_wallet_signature_recovers_signed_address() {
        use k256::ecdsa::SigningKey as K256SigningKey;

        let signing_key = K256SigningKey::from_slice(&[7u8; 32]).unwrap();
        let address = evm_address_from_verifying_key(signing_key.verifying_key());
        let nonce = "a".repeat(64);
        let message = evm_wallet_signin_message(
            "id.example.com",
            "https://id.example.com",
            "Zeroth",
            &address,
            "8453",
            &nonce,
            1_780_000_000,
        );
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.as_bytes().len());
        let digest = Keccak256::new()
            .chain_update(prefix.as_bytes())
            .chain_update(message.as_bytes());
        let (signature, recovery_id) = signing_key.sign_digest_recoverable(digest).unwrap();
        let mut signature_bytes = [0u8; EVM_WALLET_SIGNATURE_HEX_BYTES];
        signature_bytes[..64].copy_from_slice(signature.to_bytes().as_slice());
        signature_bytes[64] = recovery_id.to_byte() + 27;
        let signature_hex = format!("0x{}", bytes_to_hex(&signature_bytes));

        assert_eq!(
            recover_evm_wallet_address(&message, &signature_hex).unwrap(),
            address
        );
        assert_eq!(
            recover_evm_wallet_address(&message, &signature_hex[..130]).unwrap_err(),
            "wallet signature must be a 65 byte hex value"
        );
    }

    #[test]
    fn passkey_json_accepts_snake_case_field_aliases() {
        let register: PasskeyRegisterOptionsRequest = serde_json::from_value(serde_json::json!({
            "email": "user@example.com",
            "display_name": "Example User",
            "client_id": "ios",
            "return_to": "wavey://auth/callback"
        }))
        .unwrap();

        assert_eq!(register.display_name.as_deref(), Some("Example User"));
        assert_eq!(register.client_id.as_deref(), Some("ios"));
        assert_eq!(register.return_to.as_deref(), Some("wavey://auth/callback"));

        let authenticate: PasskeyAuthenticateOptionsRequest =
            serde_json::from_value(serde_json::json!({
                "client_id": "ios",
                "return_to": "wavey://auth/callback"
            }))
            .unwrap();

        assert_eq!(authenticate.client_id.as_deref(), Some("ios"));
        assert_eq!(
            authenticate.return_to.as_deref(),
            Some("wavey://auth/callback")
        );
    }

    #[test]
    fn user_with_profile_patch_applies_local_profile_changes() {
        let user = valid_user_row();
        let patch = ProfilePatch {
            display_name: Some(Some("Local Name".to_owned())),
            picture_url: Some(None),
        };

        let updated = user_with_profile_patch(&user, &patch);

        assert_eq!(updated.primary_email, user.primary_email);
        assert_eq!(updated.display_name.as_deref(), Some("Local Name"));
        assert_eq!(updated.picture_url, None);
    }

    #[test]
    fn identity_reference_from_url_requires_provider_identity() {
        let url = url::Url::parse(
            "https://id.example.com/identities?provider_id=google&provider_subject=sub_123",
        )
        .unwrap();

        assert_eq!(
            identity_reference_from_url(&url).unwrap(),
            IdentityReference {
                provider_id: "google".to_owned(),
                provider_subject: "sub_123".to_owned(),
            }
        );

        let url = url::Url::parse(
            "https://id.example.com/identities?provider_id=google.com&provider_subject=sub_123",
        )
        .unwrap();
        let error = identity_reference_from_url(&url).unwrap_err();
        assert_eq!(error, "provider_id contains unsupported characters");
    }

    #[test]
    fn sessions_response_marks_current_session() {
        let current = valid_session_row();
        let mut other = valid_session_row();
        other.id = "sess_other".to_owned();
        other.client_id = Some("web".to_owned());
        other.created_at = 1_780_000_050;

        let value = serde_json::to_value(sessions_response(&[other, current], "sess_123")).unwrap();

        assert_eq!(value["sessions"][0]["id"], "sess_other");
        assert_eq!(value["sessions"][0]["clientId"], "web");
        assert_eq!(value["sessions"][0]["current"], false);
        assert_eq!(value["sessions"][1]["id"], "sess_123");
        assert_eq!(value["sessions"][1]["current"], true);
    }

    #[test]
    fn identities_response_serializes_linked_provider_identities() {
        let value = serde_json::to_value(identities_response(&[valid_identity_row()])).unwrap();

        assert_eq!(value["identities"][0]["providerId"], "google");
        assert_eq!(value["identities"][0]["providerSubject"], "google-sub-123");
        assert_eq!(value["identities"][0]["email"], "user@example.com");
        assert_eq!(value["identities"][0]["emailVerified"], true);
        assert_eq!(value["identities"][0]["displayName"], "Example User");
        assert_eq!(
            value["identities"][0]["pictureUrl"],
            "https://example.com/user.jpg"
        );
        assert_eq!(value["identities"][0]["createdAt"], 1_780_000_000);
        assert_eq!(value["identities"][0]["updatedAt"], 1_780_000_100);
    }

    #[test]
    fn cors_policy_allows_expected_paths_and_methods() {
        assert!(cors_path("/oauth/token"));
        assert!(cors_path("/oauth/revoke"));
        assert!(cors_path("/oauth/introspect"));
        assert!(cors_path("/tokens"));
        assert!(cors_path("/client-branding"));
        assert!(cors_path("/userinfo"));
        assert!(cors_path("/session"));
        assert!(cors_path("/sessions"));
        assert!(cors_path("/profile"));
        assert!(cors_path("/identities"));
        assert!(cors_path("/passkeys/register/options"));
        assert!(cors_path("/passkeys/authenticate/options"));
        assert!(cors_path("/password/register"));
        assert!(cors_path("/password/login"));
        assert!(cors_path("/wallet/challenge"));
        assert!(cors_path("/wallet/verify"));
        assert!(cors_path("/magic-links"));
        assert!(cors_path("/magic-links/consume"));
        assert!(cors_path("/magic-link/confirm"));
        assert!(cors_path("/validate"));
        assert!(cors_path("/logout"));
        assert!(!cors_path("/authorize"));

        assert!(cors_method_allowed("/oauth/token", "POST"));
        assert!(cors_method_allowed("/oauth/revoke", "POST"));
        assert!(cors_method_allowed("/oauth/introspect", "POST"));
        assert!(cors_method_allowed("/tokens", "POST"));
        assert!(!cors_method_allowed("/oauth/token", "GET"));
        assert!(!cors_method_allowed("/oauth/revoke", "GET"));
        assert!(!cors_method_allowed("/oauth/introspect", "GET"));
        assert!(cors_method_allowed("/client-branding", "GET"));
        assert!(!cors_method_allowed("/client-branding", "POST"));
        assert!(cors_method_allowed("/userinfo", "GET"));
        assert!(cors_method_allowed("/profile", "GET"));
        assert!(cors_method_allowed("/profile", "PATCH"));
        assert!(!cors_method_allowed("/profile", "DELETE"));
        assert!(cors_method_allowed("/sessions", "GET"));
        assert!(cors_method_allowed("/sessions", "DELETE"));
        assert!(!cors_method_allowed("/sessions", "POST"));
        assert!(cors_method_allowed("/identities", "GET"));
        assert!(cors_method_allowed("/identities", "DELETE"));
        assert!(!cors_method_allowed("/identities", "POST"));
        assert!(cors_method_allowed("/passkeys/register/options", "POST"));
        assert!(cors_method_allowed(
            "/passkeys/authenticate/options",
            "POST"
        ));
        assert!(cors_method_allowed("/password/register", "POST"));
        assert!(!cors_method_allowed("/password/register", "GET"));
        assert!(cors_method_allowed("/password/login", "POST"));
        assert!(!cors_method_allowed("/password/login", "GET"));
        assert!(cors_method_allowed("/wallet/challenge", "POST"));
        assert!(!cors_method_allowed("/wallet/challenge", "GET"));
        assert!(cors_method_allowed("/wallet/verify", "POST"));
        assert!(!cors_method_allowed("/wallet/verify", "GET"));
        assert!(cors_method_allowed("/magic-links", "POST"));
        assert!(!cors_method_allowed("/magic-links", "GET"));
        let magic_links_trailing_slash = canonical_route_path("/magic-links/");
        assert!(cors_path(magic_links_trailing_slash.as_ref()));
        assert!(cors_method_allowed(
            magic_links_trailing_slash.as_ref(),
            "POST"
        ));
        assert!(cors_method_allowed("/magic-link/confirm", "GET"));
        assert!(!cors_method_allowed("/magic-link/confirm", "POST"));
        assert!(!cors_method_allowed("/magic-links/consume", "GET"));
        assert!(cors_method_allowed("/magic-links/consume", "POST"));
        assert!(!cors_method_allowed("/magic-links/consume", "DELETE"));
        assert!(cors_method_allowed("/validate", "GET"));
        assert!(cors_method_allowed("/logout", "GET"));
        assert!(cors_method_allowed("/logout", "POST"));
        assert!(!cors_method_allowed("/logout", "PUT"));
    }

    #[test]
    fn validate_cors_origin_allows_native_requests_without_origin() {
        validate_cors_origin(None, &[]).unwrap();
    }

    #[test]
    fn validate_cors_origin_requires_exact_registered_origin() {
        let allowed_origins = vec!["https://app.example.com".to_owned()];

        validate_cors_origin(Some("https://app.example.com"), &allowed_origins).unwrap();
        let error =
            validate_cors_origin(Some("https://evil.example.com"), &allowed_origins).unwrap_err();

        assert_eq!(
            error,
            "Origin is not allowed for this client: https://evil.example.com"
        );
    }

    #[test]
    fn origin_allowed_in_client_origin_rows_reads_registered_origins() {
        let rows = vec![
            ClientOriginsRow {
                allowed_origins_json: "[]".to_owned(),
            },
            ClientOriginsRow {
                allowed_origins_json: r#"["https://app.example.com"]"#.to_owned(),
            },
        ];

        assert!(origin_allowed_in_client_origin_rows(&rows, "https://app.example.com").unwrap());
        assert!(!origin_allowed_in_client_origin_rows(&rows, "https://other.example.com").unwrap());
    }

    #[test]
    fn provider_jwks_cache_reuses_replaces_and_expires_entries() {
        let mut cache = ProviderJwksCache::default();

        assert_eq!(cache.get(well_known::GOOGLE, 100), None);

        cache.put(well_known::GOOGLE, provider_jwks_with_kid("google-1"), 100);
        cache.put(well_known::APPLE, provider_jwks_with_kid("apple-1"), 110);

        assert_eq!(
            cached_provider_kid(cache.get(well_known::GOOGLE, 120)),
            Some("google-1".to_owned())
        );
        assert_eq!(
            cached_provider_kid(cache.get(well_known::APPLE, 120)),
            Some("apple-1".to_owned())
        );
        assert_eq!(cache.entries.len(), 2);

        cache.put(well_known::GOOGLE, provider_jwks_with_kid("google-2"), 130);

        assert_eq!(
            cached_provider_kid(cache.get(well_known::GOOGLE, 131)),
            Some("google-2".to_owned())
        );
        assert_eq!(cache.entries.len(), 2);

        assert_eq!(
            cache.get(well_known::APPLE, 110 + PROVIDER_JWKS_CACHE_TTL_SECONDS),
            None
        );
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn provider_id_token_verification_accepts_google_rs256_jwt() {
        let now = 1_780_000_000_i32;
        let (id_token, jwks) = signed_provider_id_token(
            well_known::GOOGLE,
            "google-client",
            "nonce-1",
            provider_id_token_claims(
                "https://accounts.google.com",
                "google-client",
                Some("nonce-1"),
                i64::from(now) + 600,
            ),
        );

        let verified = verify_provider_id_token(
            &id_token,
            &jwks,
            ProviderIdTokenValidation {
                provider_id: well_known::GOOGLE,
                client_id: "google-client",
                nonce: Some("nonce-1"),
                now,
            },
        )
        .unwrap();

        assert_eq!(verified.claims.sub, "provider-sub");
        assert_eq!(verified.claims.email, Some("user@example.com".to_owned()));
        assert!(verified.raw_claims_json.contains("user@example.com"));
    }

    #[test]
    fn provider_id_token_claim_validation_rejects_wrong_audience() {
        let claims = provider_id_token_claims(
            "https://appleid.apple.com",
            "apple-service-id",
            Some("nonce-1"),
            1_780_000_600,
        );

        let error = validate_provider_id_token_claims(
            &claims,
            ProviderIdTokenValidation {
                provider_id: well_known::APPLE,
                client_id: "different-client",
                nonce: Some("nonce-1"),
                now: 1_780_000_000,
            },
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_response");
        assert_eq!(
            error.description,
            "id_token audience did not include provider client_id"
        );
    }

    #[test]
    fn provider_id_token_claim_validation_rejects_wrong_nonce() {
        let claims = provider_id_token_claims(
            "https://accounts.google.com",
            "google-client",
            Some("nonce-1"),
            1_780_000_600,
        );

        let error = validate_provider_id_token_claims(
            &claims,
            ProviderIdTokenValidation {
                provider_id: well_known::GOOGLE,
                client_id: "google-client",
                nonce: Some("nonce-2"),
                now: 1_780_000_000,
            },
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_response");
        assert_eq!(
            error.description,
            "id_token nonce did not match authorization request"
        );
    }

    #[test]
    fn oidc_email_verified_claim_accepts_provider_string_bool() {
        assert_eq!(
            boolish_claim(Some(&serde_json::Value::String("true".to_owned()))),
            Some(true)
        );
        assert_eq!(
            boolish_claim(Some(&serde_json::Value::String("false".to_owned()))),
            Some(false)
        );
    }

    #[test]
    fn callback_values_accept_code_and_state() {
        let callback = provider_callback_from_values(
            Some("provider-code".to_owned()),
            Some("provider-state".to_owned()),
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(callback.state, "provider-state");
        assert_eq!(callback.code, Some("provider-code".to_owned()));
        assert_eq!(callback.provider_error, None);
        assert_eq!(callback.apple_user_json, None);
    }

    #[test]
    fn callback_values_preserve_apple_user_json() {
        let callback = provider_callback_from_values(
            Some("provider-code".to_owned()),
            Some("provider-state".to_owned()),
            None,
            None,
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#.to_owned()),
        )
        .unwrap();

        assert_eq!(
            callback.apple_user_json.as_deref(),
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#)
        );
    }

    #[test]
    fn callback_values_preserve_provider_errors_with_state() {
        let callback = provider_callback_from_values(
            None,
            Some("provider-state".to_owned()),
            Some("access_denied".to_owned()),
            Some("User cancelled".to_owned()),
            Some(r#"{"name":{"firstName":"Ada"}}"#.to_owned()),
        )
        .unwrap();
        let error = callback.provider_error.unwrap();

        assert_eq!(callback.state, "provider-state");
        assert_eq!(callback.code, None);
        assert_eq!(error.code, "access_denied");
        assert_eq!(error.description, "User cancelled");
    }

    #[test]
    fn callback_values_reject_provider_errors_without_state() {
        let error = provider_callback_from_values(
            None,
            None,
            Some("access_denied".to_owned()),
            Some("User cancelled".to_owned()),
            None,
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.description, "missing state");
    }

    #[test]
    fn apple_callback_user_display_name_joins_name_parts() {
        let user = apple_callback_user_from_json(
            r#"{"name":{"firstName":"  Ada ","lastName":" Lovelace "},"email":"ada@example.com"}"#,
        )
        .unwrap();

        assert_eq!(
            apple_callback_user_display_name(&user),
            Some("Ada Lovelace".to_owned())
        );
    }

    #[test]
    fn apple_callback_user_display_name_accepts_single_name_part() {
        let user = apple_callback_user_from_json(r#"{"name":{"firstName":"Ada"}}"#).unwrap();
        assert_eq!(
            apple_callback_user_display_name(&user),
            Some("Ada".to_owned())
        );

        let user = apple_callback_user_from_json(r#"{"name":{"lastName":"Lovelace"}}"#).unwrap();
        assert_eq!(
            apple_callback_user_display_name(&user),
            Some("Lovelace".to_owned())
        );
    }

    #[test]
    fn oidc_raw_profile_json_preserves_apple_callback_user() {
        let raw = merge_oidc_raw_profile_json(
            r#"{"sub":"apple-sub","email":"ada@example.com"}"#,
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(value["id_token_claims"]["sub"], "apple-sub");
        assert_eq!(value["apple_user"]["name"]["firstName"], "Ada");
    }

    #[test]
    fn transaction_row_hydrates_stored_transaction() {
        let record = auth_transaction_from_row(AuthTransactionRow {
            provider_state: "provider-state".to_owned(),
            client_id: "ios".to_owned(),
            provider_id: well_known::GOOGLE.to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid email".to_owned(),
            link_user_id: Some("usr_123".to_owned()),
            link_session_id: Some("sess_123".to_owned()),
            session_return_to: Some("https://app.example.com/dashboard".to_owned()),
            created_at: 1_780_000_000,
            expires_at: 1_780_000_600,
            consumed_at: None,
        })
        .unwrap();

        assert_eq!(record.transaction.client_id, ClientId("ios".to_owned()));
        assert_eq!(
            record.transaction.provider_id,
            ProviderId(well_known::GOOGLE.to_owned())
        );
        assert!(record.transaction.scope.contains("email"));
        assert_eq!(
            record.transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(
            record.transaction.link_user_id,
            Some(UserId("usr_123".to_owned()))
        );
        assert_eq!(
            record.transaction.link_session_id,
            Some("sess_123".to_owned())
        );
        assert_eq!(
            record.transaction.session_return_to,
            Some("https://app.example.com/dashboard".to_owned())
        );
        assert_eq!(record.consumed_at, None);
    }

    #[test]
    fn expired_transactions_are_rejected() {
        let record = auth_transaction_from_row(AuthTransactionRow {
            provider_state: "provider-state".to_owned(),
            client_id: "ios".to_owned(),
            provider_id: well_known::GOOGLE.to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: None,
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid".to_owned(),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: 1_780_000_000,
            expires_at: 1_780_000_100,
            consumed_at: None,
        })
        .unwrap();

        let error = validate_stored_auth_transaction(&record, 1_780_000_100).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.description, "provider callback state has expired");
    }

    #[test]
    fn consumed_transactions_are_rejected() {
        let record = auth_transaction_from_row(AuthTransactionRow {
            provider_state: "provider-state".to_owned(),
            client_id: "ios".to_owned(),
            provider_id: well_known::GOOGLE.to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: None,
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid".to_owned(),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: 1_780_000_000,
            expires_at: 1_780_000_600,
            consumed_at: Some(1_780_000_050),
        })
        .unwrap();

        let error = validate_stored_auth_transaction(&record, 1_780_000_100).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "provider callback state has already been consumed"
        );
    }

    #[test]
    fn provider_token_request_body_is_form_encoded() {
        let request = TokenExchangeRequest {
            endpoint: "https://oauth2.googleapis.com/token".to_owned(),
            params: vec![
                ("grant_type".to_owned(), "authorization_code".to_owned()),
                ("client_id".to_owned(), "client id".to_owned()),
                ("code".to_owned(), "code+value".to_owned()),
                (
                    "redirect_uri".to_owned(),
                    "https://id.example.com/oauth2/callback".to_owned(),
                ),
                ("client_secret".to_owned(), "secret/value".to_owned()),
            ],
            token_auth: TokenAuth::ClientSecretPost,
        };

        let body = provider_token_request_body(&request);

        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("client_id=client+id"));
        assert!(body.contains("code=code%2Bvalue"));
        assert!(body.contains("client_secret=secret%2Fvalue"));
    }

    #[test]
    fn provider_token_response_maps_to_token_set() {
        let token_set = provider_token_response_to_set(ProviderTokenResponse {
            access_token: Some("access".to_owned()),
            id_token: Some("id".to_owned()),
            refresh_token: Some("refresh".to_owned()),
            expires_in: Some(3600),
            error: None,
            error_description: None,
        })
        .unwrap();

        assert_eq!(token_set.access_token, Some("access".to_owned()));
        assert_eq!(token_set.id_token, Some("id".to_owned()));
        assert_eq!(token_set.refresh_token, Some("refresh".to_owned()));
        assert_eq!(token_set.expires_in, Some(3600));
    }

    #[test]
    fn provider_token_response_surfaces_provider_errors() {
        let error = provider_token_response_to_set(ProviderTokenResponse {
            access_token: None,
            id_token: None,
            refresh_token: None,
            expires_in: None,
            error: Some("invalid_grant".to_owned()),
            error_description: Some("Code was already used".to_owned()),
        })
        .unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(error.description, "Code was already used");
    }

    #[test]
    fn spotify_profile_source_uses_first_image() {
        let source = spotify_profile_source(SpotifyApiProfile {
            account_id: Some("spotify-account".to_owned()),
            id: "spotify-user".to_owned(),
            email: Some("listener@example.com".to_owned()),
            display_name: Some("Listener".to_owned()),
            images: vec![
                SpotifyApiImage {
                    url: Some("https://i.scdn.co/image/1".to_owned()),
                },
                SpotifyApiImage {
                    url: Some("https://i.scdn.co/image/2".to_owned()),
                },
            ],
        })
        .unwrap();

        assert_eq!(
            source,
            ProviderProfileSource::SpotifyProfile {
                id: "spotify-account".to_owned(),
                email: Some("listener@example.com".to_owned()),
                display_name: Some("Listener".to_owned()),
                image_url: Some("https://i.scdn.co/image/1".to_owned()),
            }
        );
    }

    #[test]
    fn spotify_profile_json_allows_null_images() {
        let profile = serde_json::from_str::<SpotifyApiProfile>(
            r#"{
                "account_id": "spotify-account",
                "id": "spotify-user",
                "email": "listener@example.com",
                "display_name": "Listener",
                "images": null
            }"#,
        )
        .unwrap();

        assert_eq!(profile.account_id.as_deref(), Some("spotify-account"));
        assert_eq!(profile.id, "spotify-user");
        assert_eq!(profile.email.as_deref(), Some("listener@example.com"));
        assert!(profile.images.is_empty());
    }

    #[test]
    fn spotify_profile_source_falls_back_to_legacy_id() {
        let source = spotify_profile_source(SpotifyApiProfile {
            account_id: None,
            id: "spotify-user".to_owned(),
            email: None,
            display_name: None,
            images: vec![],
        })
        .unwrap();

        assert_eq!(
            source,
            ProviderProfileSource::SpotifyProfile {
                id: "spotify-user".to_owned(),
                email: None,
                display_name: None,
                image_url: None,
            }
        );
    }

    #[test]
    fn response_body_excerpt_bounds_provider_error_details() {
        assert_eq!(response_body_excerpt(" \n "), "empty response body");
        assert_eq!(response_body_excerpt(" short body "), "short body");

        let long = "a".repeat(600);
        let excerpt = response_body_excerpt(&long);
        assert_eq!(excerpt.chars().count(), 515);
        assert!(excerpt.ends_with("..."));
    }

    #[test]
    fn spotify_profile_source_requires_id() {
        let error = spotify_profile_source(SpotifyApiProfile {
            account_id: None,
            id: String::new(),
            email: None,
            display_name: None,
            images: vec![],
        })
        .unwrap_err();

        assert_eq!(error.code, "invalid_response");
        assert_eq!(
            error.description,
            "Spotify profile did not include an account_id or id"
        );
    }

    fn valid_token_exchange_form() -> TokenExchangeForm {
        TokenExchangeForm {
            grant_type: "authorization_code".to_owned(),
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            redirect_uri: Some("wavey://auth/callback".to_owned()),
            code: Some("zeroth-code".to_owned()),
            code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned()),
            refresh_token: None,
            scope: None,
            subject_token: None,
            subject_token_type: None,
            provider: None,
            provider_client_id: None,
            nonce: None,
        }
    }

    fn valid_native_apple_token_exchange_form() -> TokenExchangeForm {
        TokenExchangeForm {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_owned(),
            client_id: "wavey-ios".to_owned(),
            client_auth: ClientAuth::None,
            redirect_uri: None,
            code: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            subject_token: Some("apple.id.token".to_owned()),
            subject_token_type: Some(ID_TOKEN_SUBJECT_TOKEN_TYPE.to_owned()),
            provider: Some(well_known::APPLE.to_owned()),
            provider_client_id: Some("ai.wavey.id".to_owned()),
            nonce: None,
        }
    }

    fn valid_authorization_request() -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: Some("downstream-pkce".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        }
    }

    fn registered_public_client() -> RegisteredClient {
        RegisteredClient {
            client: Client {
                id: ClientId("ios".to_owned()),
                name: "Wavey iOS".to_owned(),
                redirect_uris: vec!["wavey://auth/callback".to_owned()],
                allowed_origins: vec![],
                allowed_email_domains: vec![],
                confidential: false,
            },
            secret_hash: None,
            account_scope: client_account_scope_from_values(
                "ios",
                AccountSharingMode::Global,
                ACCOUNT_NAMESPACE_GLOBAL.to_owned(),
            ),
            visible_login_methods: Vec::new(),
        }
    }

    fn registered_confidential_client(secret: &str) -> RegisteredClient {
        RegisteredClient {
            client: Client {
                id: ClientId("web".to_owned()),
                name: "Wavey Web".to_owned(),
                redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
                allowed_origins: vec!["https://app.example.com".to_owned()],
                allowed_email_domains: vec![],
                confidential: true,
            },
            secret_hash: Some(format!("sha256:{}", hash_secret(secret))),
            account_scope: client_account_scope_from_values(
                "web",
                AccountSharingMode::Global,
                ACCOUNT_NAMESPACE_GLOBAL.to_owned(),
            ),
            visible_login_methods: Vec::new(),
        }
    }

    fn valid_auth_code_row(code_challenge: String) -> AuthCodeRow {
        AuthCodeRow {
            code_hash: hash_secret("zeroth-code"),
            client_id: "ios".to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            code_challenge: Some(code_challenge),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid email".to_owned(),
            auth_time: Some(1_780_000_000),
            created_at: 1_780_000_000,
            expires_at: 1_780_000_600,
            consumed_at: None,
        }
    }

    fn valid_refresh_token_row() -> RefreshTokenRow {
        RefreshTokenRow {
            token_hash: hash_secret("refresh-token"),
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email offline_access".to_owned(),
            auth_time: Some(1_780_000_000),
            created_at: 1_780_000_000,
            expires_at: 1_780_086_400,
            rotated_at: None,
            revoked_at: None,
        }
    }

    fn valid_session_row() -> SessionRow {
        SessionRow {
            id: "sess_123".to_owned(),
            user_id: "usr_123".to_owned(),
            client_id: Some("ios".to_owned()),
            created_at: 1_780_000_000,
            expires_at: 1_780_086_400,
            revoked_at: None,
            user_agent: Some("Zeroth Test".to_owned()),
            ip_hash: Some(hash_secret("127.0.0.1")),
        }
    }

    fn valid_identity_row() -> IdentityRow {
        IdentityRow {
            provider_id: "google".to_owned(),
            provider_subject: "google-sub-123".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: 1,
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/user.jpg".to_owned()),
            created_at: 1_780_000_000,
            updated_at: 1_780_000_100,
        }
    }

    fn valid_user_row() -> UserRow {
        UserRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/avatar.png".to_owned()),
            disabled_at: None,
        }
    }

    fn valid_user_token_claims_row() -> UserTokenClaimsRow {
        UserTokenClaimsRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/avatar.png".to_owned()),
            disabled_at: None,
            email_verified: 1,
            admin_membership_active: 0,
        }
    }

    fn valid_access_token_claims() -> JwtClaims {
        JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "ios".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: Some("sess_123".to_owned()),
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("ios".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned()],
        }
    }

    fn test_signing_key() -> Es256SigningKey {
        es256_signing_key_from_config(
            "test-key",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap()
    }

    fn decode_jwt_claims(jwt: &str) -> serde_json::Value {
        let payload = jwt.split('.').nth(1).unwrap();
        decode_jwt_json_segment(payload)
    }

    fn decode_jwt_json_segment<T: serde::de::DeserializeOwned>(segment: &str) -> T {
        let json = URL_SAFE_NO_PAD.decode(segment).unwrap();
        serde_json::from_slice(&json).unwrap()
    }

    fn provider_id_token_claims(
        issuer: &str,
        audience: &str,
        nonce: Option<&str>,
        expires_at: i64,
    ) -> ProviderIdTokenClaims {
        ProviderIdTokenClaims {
            iss: issuer.to_owned(),
            sub: "provider-sub".to_owned(),
            aud: AudienceClaim::One(audience.to_owned()),
            exp: expires_at,
            iat: Some(expires_at - 600),
            nonce: nonce.map(str::to_owned),
            email: Some("user@example.com".to_owned()),
            email_verified: Some(serde_json::Value::String("true".to_owned())),
            name: Some("Example User".to_owned()),
            picture: Some("https://example.com/avatar.png".to_owned()),
        }
    }

    fn signed_provider_id_token(
        provider_id: &str,
        client_id: &str,
        nonce: &str,
        claims: ProviderIdTokenClaims,
    ) -> (String, ProviderJwksResponse) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let key_id = format!("{provider_id}-{client_id}-{nonce}");
        let header = ProviderJwtHeader {
            alg: "RS256".to_owned(),
            kid: Some(key_id.clone()),
        };
        let signing_input = format!(
            "{}.{}",
            jwt_json_segment(&header).unwrap(),
            jwt_json_segment(&claims).unwrap()
        );
        let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
        let id_token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let jwks = ProviderJwksResponse {
            keys: vec![ProviderJwk {
                kty: "RSA".to_owned(),
                key_use: Some("sig".to_owned()),
                kid: Some(key_id),
                alg: Some("RS256".to_owned()),
                n: Some(URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be())),
                e: Some(URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())),
            }],
        };

        (id_token, jwks)
    }

    fn provider_jwks_with_kid(kid: &str) -> ProviderJwksResponse {
        ProviderJwksResponse {
            keys: vec![ProviderJwk {
                kty: "RSA".to_owned(),
                key_use: Some("sig".to_owned()),
                kid: Some(kid.to_owned()),
                alg: Some("RS256".to_owned()),
                n: Some("n".to_owned()),
                e: Some("e".to_owned()),
            }],
        }
    }

    fn test_passkey_client_data(ceremony_type: &str, challenge: &str, origin: &str) -> String {
        URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "type": ceremony_type,
                "challenge": passkey_challenge_for_browser(challenge),
                "origin": origin,
                "crossOrigin": false
            })
            .to_string()
            .as_bytes(),
        )
    }

    fn test_passkey_authenticator_data(
        rp_id: &str,
        flags: u8,
        sign_count: i32,
        credential_id: &[u8],
        cose_key: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(cose_key);
        data
    }

    fn test_passkey_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0xa3);
        cbor_text(&mut out, "fmt");
        cbor_text(&mut out, "none");
        cbor_text(&mut out, "authData");
        cbor_bytes(&mut out, auth_data);
        cbor_text(&mut out, "attStmt");
        out.push(0xa0);
        out
    }

    fn test_passkey_cose_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0xa5);
        out.push(0x01);
        out.push(0x02);
        out.push(0x03);
        out.push(0x26);
        out.push(0x20);
        out.push(0x01);
        out.push(0x21);
        cbor_bytes(&mut out, x);
        out.push(0x22);
        cbor_bytes(&mut out, y);
        out
    }

    fn cbor_text(out: &mut Vec<u8>, value: &str) {
        cbor_len(out, 0x60, value.len());
        out.extend_from_slice(value.as_bytes());
    }

    fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
        cbor_len(out, 0x40, value.len());
        out.extend_from_slice(value);
    }

    fn cbor_len(out: &mut Vec<u8>, major: u8, len: usize) {
        if len < 24 {
            out.push(major | (len as u8));
        } else if len <= u8::MAX as usize {
            out.push(major | 24);
            out.push(len as u8);
        } else {
            out.push(major | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }

    fn cached_provider_kid(jwks: Option<ProviderJwksResponse>) -> Option<String> {
        jwks.and_then(|jwks| jwks.keys.into_iter().next()?.kid)
    }
}

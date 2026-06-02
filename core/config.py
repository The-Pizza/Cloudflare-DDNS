"""Application configuration via environment variables.

All settings can be overridden by env vars (no prefix) or a .env file.
Runtime-mutable settings can ALSO be set in the DB via the Settings page,
but the env / ConfigMap value always wins — `env_locked()` reports which
keys are pinned by env so the UI can grey them out.
"""
import logging
import os
from typing import Optional, Set

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- Cloudflare ----
    cf_api_token: str = ""           # CF_API_TOKEN
    cf_api_url: str = "https://api.cloudflare.com/client/v4"

    # ---- DDNS engine ----
    poll_interval_seconds: int = 60
    cf_resync_interval_seconds: int = 3600
    request_timeout_seconds: int = 10
    ipv4_endpoint: str = "https://ipinfo.io/ip"
    ipv6_endpoint: str = ""           # leave blank to disable AAAA
    default_ttl: int = 1
    default_proxied: bool = False

    # ---- Persistence ----
    database_url: str = "sqlite:////app/data/cloudflare-ddns.db"

    # ---- Discovery features ----
    enable_annotation_discovery: bool = True
    enable_traefik_discovery: bool = True
    # Annotation(s) the discovery loop looks up on Services/Deployments/Ingresses.
    # Accepts a single key or a comma-separated list — handy when migrating from
    # an old annotation key to a new one: list both, re-annotate your workloads,
    # then drop the old key. The default is a vendor-neutral domain-style key.
    annotation_key: str = "cloudflare-ddns.io/dns-name"

    # ---- Legacy: read static records.json on startup, import into DB once ----
    config_path: str = "/etc/config/records.json"
    import_legacy_config: bool = True

    # ---- Auth ----
    # auth_mode: none | oidc | forward-auth
    #   none         → app is fully open (default; matches existing behavior)
    #   oidc         → built-in OIDC/OAuth2 Authorization Code flow handled by the app itself
    #   forward-auth → app trusts a reverse-proxy (Traefik/nginx + Authentik/Authelia/oauth2-proxy)
    #                  to perform authn and forward identity headers
    auth_mode: str = "none"

    # ---- Built-in OIDC client (auth_mode=oidc) ----
    # Discovery: oidc_issuer/.well-known/openid-configuration. Standard params apply
    # to ANY OIDC provider — Authentik, Keycloak, Authelia, Google, Okta, Dex, Zitadel, etc.
    oidc_issuer: str = ""              # e.g. https://auth.example.com/application/o/cloudflare-ddns/
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email groups"
    oidc_redirect_url: str = ""        # if blank, computed from request: <scheme>://<host>/auth/callback
    oidc_username_claim: str = "preferred_username"
    oidc_email_claim: str = "email"
    oidc_groups_claim: str = "groups"
    # Comma-separated; user must be in at least one to enter. Empty = any authenticated user.
    oidc_allowed_groups: str = ""
    oidc_allowed_emails: str = ""      # comma-separated allow-list of full emails (optional)
    # Random string for signing the session cookie. Auto-generated on startup if blank.
    session_secret: str = ""
    session_cookie_name: str = "cfddns_session"
    # Set the Secure flag on the session cookie (cookie only sent over HTTPS).
    # Defaults to True because the app is intended to run behind TLS; set to
    # False only for local HTTP development.
    session_cookie_secure: bool = True
    session_max_age_seconds: int = 60 * 60 * 8        # 8h

    # ---- Forward-auth (auth_mode=forward-auth) ----
    # The reverse proxy is trusted to set these headers after authenticating the user.
    # Authentik defaults: X-authentik-username / X-authentik-email / X-authentik-groups.
    # oauth2-proxy defaults: X-Forwarded-User / X-Forwarded-Email / X-Forwarded-Groups.
    forward_auth_user_header: str = "X-authentik-username"
    forward_auth_email_header: str = "X-authentik-email"
    forward_auth_groups_header: str = "X-authentik-groups"
    forward_auth_groups_separator: str = "|"

    # ---- HTTP server ----
    log_level: str = "INFO"


settings = Settings()


def annotation_keys() -> list[str]:
    """Return the configured annotation key(s) as a list.

    `annotation_key` may be a single key or a comma-separated list. Discovery
    matches a workload carrying ANY of these keys, which makes migrating from an
    old key to a new one a non-breaking, two-step operation (list both keys,
    re-annotate, then drop the old one). Whitespace around entries is ignored
    and empty entries are skipped.
    """
    raw = get_effective("annotation_key")
    return [k.strip() for k in str(raw).split(",") if k.strip()]

# Keys exposed/editable on the Settings page. Anything in env wins.
RUNTIME_SETTINGS_KEYS = (
    "cf_api_token",
    "ipv4_endpoint",
    "ipv6_endpoint",
    "poll_interval_seconds",
    "default_proxied",
    "default_ttl",
    "annotation_key",
    # Auth
    "auth_mode",
    "oidc_issuer",
    "oidc_client_id",
    "oidc_client_secret",
    "oidc_scopes",
    "oidc_redirect_url",
    "oidc_username_claim",
    "oidc_email_claim",
    "oidc_groups_claim",
    "oidc_allowed_groups",
    "oidc_allowed_emails",
    "forward_auth_user_header",
    "forward_auth_email_header",
    "forward_auth_groups_header",
    "forward_auth_groups_separator",
    "session_cookie_secure",
)

SECRET_KEYS = {"cf_api_token", "oidc_client_secret", "session_secret"}


def env_locked() -> Set[str]:
    """Return the runtime-setting keys whose value was provided via env / ConfigMap.

    Env vars are upper-case; we also look at os.environ directly because
    pydantic-settings strips env_file values too.
    """
    locked: Set[str] = set()
    for key in RUNTIME_SETTINGS_KEYS:
        env_name = key.upper()
        if env_name in os.environ and os.environ[env_name] != "":
            locked.add(key)
    return locked


def _db_value(key: str) -> Optional[str]:
    """Look up the persisted value of a runtime setting from the DB.

    Returns None on any error so this can be called from middleware before
    the DB is fully initialized (and so a missing `setting` table is a
    soft-fail).
    """
    try:
        from core.database import get_session
        from core.models import Setting
    except Exception:
        return None
    try:
        sess = get_session()
        try:
            row = sess.query(Setting).filter(Setting.key == key).first()
            return row.value if row else None
        finally:
            sess.close()
    except Exception:
        return None


def get_effective(key: str, db_value: Optional[str] = None):
    """Return the active value for a runtime-tunable setting.

    Order: env (already absorbed into `settings`) wins; otherwise DB value
    (looked up here if the caller didn't pre-fetch one); otherwise the
    dataclass default.
    """
    if key in env_locked():
        return getattr(settings, key)
    if db_value is None:
        db_value = _db_value(key)
    if db_value is not None and db_value != "":
        # Coerce to the expected type based on the dataclass default
        default = getattr(settings, key)
        if isinstance(default, bool):
            return db_value.lower() in ("1", "true", "yes", "on")
        if isinstance(default, int):
            try:
                return int(db_value)
            except ValueError:
                return default
        return db_value
    return getattr(settings, key)


# Initialise logging once
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

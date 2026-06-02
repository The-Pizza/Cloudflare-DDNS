"""Authentication for the Cloudflare DDNS web UI.

Three modes (selected via auth_mode setting / AUTH_MODE env):

    none          - app is fully open. Default.
    oidc          - built-in OIDC Authorization Code flow (PKCE).
                    Works against any OpenID-Connect provider via discovery:
                    Authentik, Keycloak, Authelia, Dex, Google, Okta, Zitadel...
    forward-auth  - app trusts the reverse proxy (Traefik/nginx) and an
                    upstream auth service (Authentik/Authelia/oauth2-proxy)
                    to perform authentication and forward identity headers.

The middleware:
    1. Looks up the effective auth_mode at request time (so settings page
       changes take effect without a restart).
    2. Always allows /health/*, /api/status, /static/*, and the /auth/* flow.
    3. For 'oidc': checks the session cookie; redirects to /auth/login if absent.
       For 'forward-auth': requires the configured user header.
    4. Enforces group/email allow-lists when present.
"""
from __future__ import annotations

import logging
import secrets
from typing import Iterable, Optional, Tuple
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, TimestampSigner
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import get_effective, settings
from core.database import get_session
from core.models import Setting

log = logging.getLogger("cfddns.auth")

# Endpoints that must always be reachable, even when auth is on, because:
# - probes are called by k8s
# - the auth flow itself needs /auth/*
# - the login page needs to render
ALWAYS_ALLOW_PREFIXES = (
    "/health/",
    "/metrics",         # Prometheus scrape — no session; protect at network layer
    "/auth/",
    "/static/",
    "/api/status",      # status endpoint is harmless and used to render the footer
    "/favicon",
)


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def _current_session_secret() -> str:
    """Return a stable secret for signing session cookies.

    Order: env / DB setting > a value persisted in the `setting` table > newly
    generated random value (saved so subsequent restarts share it).
    """
    val = get_effective("session_secret") if "session_secret" in dir(settings) else None
    if val:
        return str(val)
    # Look up persisted value
    sess = get_session()
    try:
        row = sess.query(Setting).filter(Setting.key == "session_secret").first()
        if row and row.value:
            return row.value
        new = secrets.token_urlsafe(48)
        if row:
            row.value = new
        else:
            sess.add(Setting(key="session_secret", value=new))
        sess.commit()
        return new
    finally:
        sess.close()


def _signer() -> TimestampSigner:
    return TimestampSigner(_current_session_secret(), salt="cfddns-session")


def _set_session_cookie(response, username: str, email: str = "", groups: Iterable[str] = ()):
    """Store username|email|groups in a signed cookie (base64 payload to avoid control-char issues)."""
    import base64, json as _json
    cookie_name = str(get_effective("session_cookie_name") or "cfddns_session")
    payload = base64.urlsafe_b64encode(
        _json.dumps({"u": username, "e": email, "g": list(groups)}).encode()
    ).decode().rstrip("=")
    token = _signer().sign(payload.encode()).decode()
    max_age = int(get_effective("session_max_age_seconds") or 28800)
    secure = bool(get_effective("session_cookie_secure"))
    response.set_cookie(
        cookie_name, token,
        max_age=max_age, httponly=True, samesite="lax", secure=secure, path="/",
    )


def _read_session_cookie(request: Request) -> Optional[Tuple[str, str, list]]:
    import base64, json as _json
    cookie_name = str(get_effective("session_cookie_name") or "cfddns_session")
    raw = request.cookies.get(cookie_name)
    if not raw:
        return None
    max_age = int(get_effective("session_max_age_seconds") or 28800)
    try:
        payload_b64 = _signer().unsign(raw, max_age=max_age).decode()
    except BadSignature:
        return None
    try:
        pad = "=" * (-len(payload_b64) % 4)
        data = _json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode())
    except Exception:
        return None
    return str(data.get("u", "")), str(data.get("e", "")), [str(g) for g in data.get("g", [])]


# ---------------------------------------------------------------------------
# Allow-list enforcement (shared by OIDC + forward-auth)
# ---------------------------------------------------------------------------


def _csv(value: str) -> set:
    return {v.strip().lower() for v in (value or "").split(",") if v.strip()}


def _user_allowed(email: str, groups: Iterable[str]) -> Tuple[bool, str]:
    allowed_groups = _csv(str(get_effective("oidc_allowed_groups") or ""))
    allowed_emails = _csv(str(get_effective("oidc_allowed_emails") or ""))
    if not allowed_groups and not allowed_emails:
        return True, ""
    email_l = (email or "").lower()
    if allowed_emails and email_l in allowed_emails:
        return True, ""
    if allowed_groups and any(g.lower() in allowed_groups for g in groups):
        return True, ""
    return False, (
        f"Access denied. User '{email or 'unknown'}' is not in the allowed groups/emails. "
        f"Required groups: {sorted(allowed_groups) or '—'}; allowed emails: {sorted(allowed_emails) or '—'}."
    )


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in ALWAYS_ALLOW_PREFIXES):
            return await call_next(request)

        mode = str(get_effective("auth_mode") or "none").lower()

        if mode == "none":
            return await call_next(request)

        # --- forward-auth ---
        if mode == "forward-auth":
            user_h = str(get_effective("forward_auth_user_header") or "X-authentik-username")
            email_h = str(get_effective("forward_auth_email_header") or "X-authentik-email")
            groups_h = str(get_effective("forward_auth_groups_header") or "X-authentik-groups")
            sep = str(get_effective("forward_auth_groups_separator") or "|")
            user = request.headers.get(user_h, "")
            if not user:
                return JSONResponse(
                    {"error": "forward-auth: missing identity header",
                     "expected_header": user_h,
                     "hint": "Reverse-proxy must inject identity headers (Authentik / Authelia / oauth2-proxy)."},
                    status_code=401,
                )
            email = request.headers.get(email_h, "")
            groups = [g.strip() for g in request.headers.get(groups_h, "").split(sep) if g.strip()]
            ok, reason = _user_allowed(email, groups)
            if not ok:
                return JSONResponse({"error": reason}, status_code=403)
            request.state.user = {"username": user, "email": email, "groups": groups, "mode": "forward-auth"}
            return await call_next(request)

        # --- built-in OIDC ---
        if mode == "oidc":
            sess = _read_session_cookie(request)
            if not sess:
                # HTML browser request → redirect to login. API request → 401.
                if "text/html" in request.headers.get("accept", ""):
                    return RedirectResponse(f"/auth/login?next={request.url.path}", status_code=302)
                return JSONResponse({"error": "unauthenticated"}, status_code=401)
            username, email, groups = sess
            ok, reason = _user_allowed(email, groups)
            if not ok:
                return JSONResponse({"error": reason}, status_code=403)
            request.state.user = {"username": username, "email": email, "groups": groups, "mode": "oidc"}
            return await call_next(request)

        # Unknown mode — fail closed
        return JSONResponse({"error": f"Unknown auth_mode '{mode}'"}, status_code=500)


# ---------------------------------------------------------------------------
# OIDC routes (Authorization Code with PKCE)
# ---------------------------------------------------------------------------


router = APIRouter()
_pending_state: dict = {}  # state -> {next, code_verifier} (process-local, fine for single-replica)


async def _oidc_discovery(issuer: str) -> dict:
    import httpx
    issuer = issuer.rstrip("/")
    url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as cli:
        r = await cli.get(url)
    r.raise_for_status()
    return r.json()


# Cache JWKS per jwks_uri so we don't refetch the IdP's keys on every login.
_jwks_cache: dict = {}  # jwks_uri -> {"keys": [...]}


async def _fetch_jwks(jwks_uri: str) -> dict:
    if jwks_uri in _jwks_cache:
        return _jwks_cache[jwks_uri]
    import httpx
    async with httpx.AsyncClient(timeout=10) as cli:
        r = await cli.get(jwks_uri)
    r.raise_for_status()
    jwks = r.json()
    _jwks_cache[jwks_uri] = jwks
    return jwks


async def _verify_id_token(id_token: str, meta: dict, client_id: str) -> dict:
    """Verify an OIDC id_token's signature and standard claims via the IdP's JWKS.

    Validates signature (against the provider's published keys), issuer, audience
    (must include our client_id) and expiry. Raises on any failure — the caller
    treats an exception as an authentication failure. Returns the verified claims.

    On a JWKS miss (e.g. the IdP rotated keys), the cache is refreshed once and
    validation retried before giving up.
    """
    from authlib.jose import jwt as jose_jwt
    from authlib.jose.errors import JoseError

    jwks_uri = meta.get("jwks_uri")
    if not jwks_uri:
        raise ValueError("OIDC provider metadata has no jwks_uri; cannot verify id_token")
    issuer = meta.get("issuer")

    claims_options = {
        "iss": {"essential": True, "value": issuer} if issuer else {"essential": False},
        "aud": {"essential": True, "value": client_id},
        "exp": {"essential": True},
    }

    last_err: Optional[Exception] = None
    for attempt in range(2):
        jwks = await _fetch_jwks(jwks_uri)
        try:
            claims = jose_jwt.decode(id_token, jwks, claims_options=claims_options)
            claims.validate()   # checks exp / iss / aud per claims_options
            return dict(claims)
        except JoseError as e:
            last_err = e
            # Possible key rotation — bust cache and retry once.
            _jwks_cache.pop(jwks_uri, None)
    raise last_err or ValueError("id_token validation failed")


def _redirect_uri(request: Request) -> str:
    configured = str(get_effective("oidc_redirect_url") or "").strip()
    if configured:
        return configured
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"{scheme}://{host}/auth/callback"


@router.get("/auth/login")
async def auth_login(request: Request, next: str = "/"):
    if str(get_effective("auth_mode") or "none").lower() != "oidc":
        return RedirectResponse("/")
    issuer = str(get_effective("oidc_issuer") or "").strip()
    client_id = str(get_effective("oidc_client_id") or "").strip()
    if not issuer or not client_id:
        return HTMLResponse(
            "<h1>OIDC not configured</h1>"
            "<p>Set <code>oidc_issuer</code> and <code>oidc_client_id</code> in Settings "
            "(or via env vars OIDC_ISSUER / OIDC_CLIENT_ID), then reload.</p>"
            f"<p><a href='/'>Back</a></p>",
            status_code=503,
        )
    try:
        meta = await _oidc_discovery(issuer)
    except Exception as e:
        return HTMLResponse(f"<h1>OIDC discovery failed</h1><pre>{e}</pre>", status_code=502)

    import base64, hashlib
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    state = secrets.token_urlsafe(24)
    _pending_state[state] = {"next": next or "/", "verifier": code_verifier, "meta": meta}

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _redirect_uri(request),
        "scope": str(get_effective("oidc_scopes") or "openid profile email"),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{meta['authorization_endpoint']}?{urlencode(params)}")


@router.get("/auth/callback")
async def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return HTMLResponse(f"<h1>Authentication error</h1><p>{error}</p><p><a href='/auth/login'>Try again</a></p>", status_code=400)
    pending = _pending_state.pop(state, None)
    if not pending:
        return HTMLResponse("<h1>Invalid state</h1><p>Please <a href='/auth/login'>try again</a>.</p>", status_code=400)
    meta = pending["meta"]
    client_id = str(get_effective("oidc_client_id") or "").strip()
    client_secret = str(get_effective("oidc_client_secret") or "").strip()
    redirect_uri = _redirect_uri(request)

    import httpx
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": pending["verifier"],
    }
    auth = None
    if client_secret:
        auth = (client_id, client_secret)
    try:
        async with httpx.AsyncClient(timeout=10) as cli:
            if auth is not None:
                r = await cli.post(meta["token_endpoint"], data=data, auth=auth)
            else:
                r = await cli.post(meta["token_endpoint"], data=data)
        if r.status_code >= 400:
            return HTMLResponse(f"<h1>Token exchange failed</h1><pre>{r.status_code} {r.text}</pre>", status_code=502)
        token = r.json()
    except Exception as e:
        return HTMLResponse(f"<h1>Token exchange failed</h1><pre>{e}</pre>", status_code=502)

    # Validate the id_token signature against the IdP's JWKS (do NOT trust
    # unverified claims — we make authz decisions on `groups`/`email`).
    # Falls back to userinfo for any claims missing from a verified id_token.
    claims = {}
    if token.get("id_token"):
        try:
            claims = await _verify_id_token(token["id_token"], meta, client_id)
        except Exception as e:
            log.warning("id_token validation failed: %s", e)
            return HTMLResponse(
                f"<h1>Authentication failed</h1><p>Could not validate the identity token: {e}</p>"
                "<p><a href='/auth/login'>Try again</a></p>",
                status_code=401,
            )

    # userinfo as a fallback to fill missing claims
    if (not claims or "userinfo_endpoint" in meta) and token.get("access_token"):
        try:
            async with httpx.AsyncClient(timeout=10) as cli:
                ur = await cli.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {token['access_token']}"})
            if ur.status_code < 400:
                ui = ur.json()
                for k, v in ui.items():
                    claims.setdefault(k, v)
        except Exception as e:
            log.warning("userinfo failed: %s", e)

    uname_claim = str(get_effective("oidc_username_claim") or "preferred_username")
    email_claim = str(get_effective("oidc_email_claim") or "email")
    groups_claim = str(get_effective("oidc_groups_claim") or "groups")
    username = str(claims.get(uname_claim) or claims.get("sub") or "user")
    email = str(claims.get(email_claim) or "")
    raw_groups = claims.get(groups_claim) or []
    if isinstance(raw_groups, str):
        raw_groups = [g.strip() for g in raw_groups.split(",") if g.strip()]
    groups = [str(g) for g in raw_groups]

    ok, reason = _user_allowed(email, groups)
    if not ok:
        return HTMLResponse(
            f"<h1>Access denied</h1><p>{reason}</p><p><a href='/auth/logout'>Sign out</a></p>",
            status_code=403,
        )

    target = pending.get("next") or "/"
    if not target.startswith("/"):
        target = "/"
    resp = RedirectResponse(target, status_code=302)
    _set_session_cookie(resp, username, email, groups)
    log.info("OIDC login: %s <%s> groups=%s", username, email, groups)
    return resp


@router.get("/auth/logout")
async def auth_logout(request: Request):
    cookie_name = str(get_effective("session_cookie_name") or "cfddns_session")
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(cookie_name, path="/")
    return resp


@router.get("/auth/whoami")
async def auth_whoami(request: Request):
    """Public endpoint (allow-listed) — read identity directly from cookie/headers
    so the UI can show 'signed in as …' without forcing this through the
    auth-required path. Falls back to whatever AuthMiddleware put on
    request.state for parity with protected routes."""
    mode = str(get_effective("auth_mode") or "none").lower()
    user = getattr(request.state, "user", None)
    if user is None and mode == "oidc":
        sess = _read_session_cookie(request)
        if sess:
            username, email, groups = sess
            user = {"username": username, "email": email, "groups": groups, "mode": "oidc"}
    if user is None and mode == "forward-auth":
        user_h = str(get_effective("forward_auth_user_header") or "X-authentik-username")
        email_h = str(get_effective("forward_auth_email_header") or "X-authentik-email")
        groups_h = str(get_effective("forward_auth_groups_header") or "X-authentik-groups")
        sep = str(get_effective("forward_auth_groups_separator") or "|")
        un = request.headers.get(user_h)
        if un:
            user = {
                "username": un,
                "email": request.headers.get(email_h, ""),
                "groups": [g.strip() for g in request.headers.get(groups_h, "").split(sep) if g.strip()],
                "mode": "forward-auth",
            }
    return {"auth_mode": mode, "user": user}

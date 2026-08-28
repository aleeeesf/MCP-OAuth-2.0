import secrets
import base64
import hashlib

# from pydantic import EmailStr, Field

from datetime import datetime, timedelta, timezone

from fastapi import Cookie
from fastapi import FastAPI, Form, HTTPException, Header
from fastapi.responses import HTMLResponse, RedirectResponse



app = FastAPI(title="OAuth Authorization Server")

AUTH_SERVER = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Datos temporales
# ---------------------------------------------------------------------------
#
# TODO:
# Esto es solamente para aprender.
# Más adelante sustituiremos todo esto por una base de datos.
#
clients = {
    "my-mcp-client": {
        "redirect_uris": [
            "http://localhost:9100/callback"
        ],
        "allowed_scopes": [
            "profile"
        ],
        "allowed_resources": [
            "http://localhost:9000/mcp"
        ],
    },

    "mcp-resource-server": {
        "client_secret": "super-secret-development-value",
        "allowed_operations": [
            "introspection"
        ],
    },
}


# Solicitudes OAuth pendientes.
#
# session_id -> datos de la solicitud OAuth
#
oauth_requests = {}


# Sesiones de usuarios autenticados.
#
# user_session_id -> datos del usuario
#
user_sessions = {}


# Authorization codes.
#
# Todavía no los utilizamos completamente.
# Los utilizaremos en el siguiente paso para /token.
#
authorization_codes = {}

access_tokens = {}



def authenticate_client(
    authorization: str | None,
):
    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail="Client authentication required",
        )

    try:
        scheme, encoded_credentials = authorization.split(
            " ",
            1,
        )
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header",
        )

    if scheme.lower() != "basic":
        raise HTTPException(
            status_code=401,
            detail="Unsupported authentication scheme",
        )

    try:
        decoded = base64.b64decode(
            encoded_credentials
        ).decode("utf-8")

        client_id, client_secret = decoded.split(
            ":",
            1,
        )
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid client credentials",
        )

    client = clients.get(client_id)

    if client is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid client",
        )

    if client.get("client_secret") != client_secret:
        raise HTTPException(
            status_code=401,
            detail="Invalid client credentials",
        )

    return client_id


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "message": "OAuth Authorization Server"
    }


@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():

    return {
        "issuer": AUTH_SERVER,
        "authorization_endpoint": (
            f"{AUTH_SERVER}/authorize"
        ),
        "token_endpoint": (
            f"{AUTH_SERVER}/token"
        ),
        "introspection_endpoint": (
            f"{AUTH_SERVER}/introspect"
        ),
        "response_types_supported": [
            "code"
        ],
        "grant_types_supported": [
            "authorization_code"
        ],
        "code_challenge_methods_supported": [
            "S256"
        ],
        "scopes_supported": [
            "profile"
        ],
    }

# @app.post("/signup")
# async def signup(
#     email: EmailStr,
#     password: str = Field(..., min_length=8, description="La contraseña debe tener al menos 8 caracteres")
# ):


# ---------------------------------------------------------------------------
# OAuth Authorization Endpoint
# ---------------------------------------------------------------------------

@app.get("/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    resource: str
):
    # ---------------------------------------------------------------
    # 1. Comprobar que el cliente existe
    # ---------------------------------------------------------------
    
    client = clients.get(client_id)

    if client is None:
        raise HTTPException(
            status_code=400,
            detail="Unknown client",
        )

    # ---------------------------------------------------------------
    # 2. Comprobar que el cliente puede solicitar tokens al recurso
    # ---------------------------------------------------------------

    if resource not in client.get("allowed_resources", []):
        raise HTTPException(
            status_code=400,
            detail="Client is not allowed to request this resource",
        )

    # ---------------------------------------------------------------
    # 3. Comprobar que tiene permiso para los scopes que solicita
    # ---------------------------------------------------------------

    requested_scopes = scope.split()

    for requested_scope in requested_scopes:
        if requested_scope not in client["allowed_scopes"]:
            raise HTTPException(
                status_code=400,
                detail=f"Scope not allowed: {requested_scope}",
            )
    
    # ---------------------------------------------------------------
    # 3. Comprobar que la redirect_uri está registrada
    # ---------------------------------------------------------------

    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid redirect_uri",
        )
    
    

    # ---------------------------------------------------------------
    # 4. Guardar la solicitud OAuth
    # ---------------------------------------------------------------
    #
    # Creamos un identificador aleatorio para relacionar
    # esta solicitud OAuth con el proceso de login.
    #

    session_id = secrets.token_urlsafe(32)

    print(str.upper(code_challenge_method))
    oauth_requests[session_id] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": str.upper(code_challenge_method),
        "resource": resource
    }

    # ---------------------------------------------------------------
    # 5. Enviar al usuario al login
    # ---------------------------------------------------------------

    return RedirectResponse(
        url=f"/login?session_id={session_id}",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Login page
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(session_id: str):
    # Comprobamos que la solicitud OAuth exista.

    if session_id not in oauth_requests:
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth session",
        )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
    </head>

    <body>
        <h1>Login</h1>

        <form method="post" action="/login">

            <input
                type="hidden"
                name="session_id"
                value="{session_id}"
            >

            <div>
                <label>
                    Email:
                    <input
                        name="email"
                        type="email"
                        required
                    >
                </label>
            </div>

            <br>

            <div>
                <label>
                    Password:
                    <input
                        name="password"
                        type="password"
                        required
                    >
                </label>
            </div>

            <br>

            <button type="submit">
                Login
            </button>

        </form>
    </body>
    </html>
    """


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@app.post("/login")
async def login(
    session_id: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    # ---------------------------------------------------------------
    # 1. Recuperar la solicitud OAuth
    # ---------------------------------------------------------------

    oauth_request = oauth_requests.get(session_id)

    if oauth_request is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth session",
        )

    # ---------------------------------------------------------------
    # 2. AUTENTICACIÓN TEMPORAL
    # ---------------------------------------------------------------
    #
    # Esto es solamente para aprender.
    #
    # NO debemos tener una contraseña hardcodeada en producción.
    #

    if email != "juan@example.com":
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    if password != "password":
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    # ---------------------------------------------------------------
    # 3. Crear sesión de usuario
    # ---------------------------------------------------------------

    user_session_id = secrets.token_urlsafe(32)

    user_sessions[user_session_id] = {
        "user_id": "user-123",
        "email": email,
    }

    # ---------------------------------------------------------------
    # 4. Ir a la pantalla de consentimiento
    # ---------------------------------------------------------------

    response = RedirectResponse(
        url=f"/consent?session_id={session_id}",
        status_code=303,
    )

    # ---------------------------------------------------------------
    # 5. Guardar la sesión del usuario en una cookie
    # ---------------------------------------------------------------

    response.set_cookie(
        key="session",
        value=user_session_id,
        httponly=True,
        secure=False,  # En producción con HTTPS será True
        samesite="lax",
    )

    return response


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------

@app.get("/consent", response_class=HTMLResponse)
async def consent_page(session_id: str):
    # ---------------------------------------------------------------
    # 1. Recuperar solicitud OAuth
    # ---------------------------------------------------------------

    oauth_request = oauth_requests.get(session_id)

    if oauth_request is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth session",
        )

    # ---------------------------------------------------------------
    # 2. Mostrar consentimiento
    # ---------------------------------------------------------------

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authorization</title>
    </head>

    <body>
        <h1>Authorization required</h1>

        <p>
            The application
            <strong>{oauth_request["client_id"]}</strong>
            wants access to:
        </p>

        <ul>
            <li>{oauth_request["scope"]}</li>
        </ul>

        <form method="post" action="/consent">

            <input
                type="hidden"
                name="session_id"
                value="{session_id}"
            >

            <button
                type="submit"
                name="decision"
                value="deny"
            >
                Deny
            </button>

            <button
                type="submit"
                name="decision"
                value="allow"
            >
                Allow
            </button>

        </form>
    </body>
    </html>
    """


# ---------------------------------------------------------------------------
# Consent decision
# ---------------------------------------------------------------------------

@app.post("/consent")
async def consent(
    session_id: str = Form(...),
    decision: str = Form(...),
    session: str | None = Cookie(default=None),
):
    oauth_request = oauth_requests.get(session_id)

    if oauth_request is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth session",
        )

    user_session = user_sessions.get(session)

    if user_session is None:
        raise HTTPException(
            status_code=401,
            detail="User is not authenticated",
        )

    if decision == "deny":
        redirect_uri = oauth_request["redirect_uri"]
        state = oauth_request["state"]

        redirect_url = (
            f"{redirect_uri}"
            f"?error=access_denied"
            f"&state={state}"
        )

        return RedirectResponse(
            url=redirect_url,
            status_code=303,
        )

    if decision != "allow":
        raise HTTPException(
            status_code=400,
            detail="Invalid consent decision",
        )

    code = secrets.token_urlsafe(32)
    print(code)

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=5)
    )

    authorization_codes[code] = {
        "client_id": oauth_request["client_id"],
        "user_id": user_session["user_id"],
        "redirect_uri": oauth_request["redirect_uri"],
        "scope": oauth_request["scope"],
        "code_challenge": oauth_request["code_challenge"],
        "code_challenge_method": (
            oauth_request["code_challenge_method"]
        ),
        "resource": oauth_request["resource"],
        "expires_at": expires_at,
        "used": False,
    }

    redirect_uri = oauth_request["redirect_uri"]
    state = oauth_request["state"]

    redirect_url = (
        f"{redirect_uri}"
        f"?code={code}"
        f"&state={state}"
    )

    return RedirectResponse(
        url=redirect_url,
        status_code=303,
    )


@app.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    code_verifier: str = Form(...),
    resource: str = Form(...)
):
    # 1. Grant type

    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=400,
            detail="Unsupported grant_type",
        )

    # 2. Buscar authorization code

    authorization = authorization_codes.get(code)
    if authorization is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid authorization code",
        )

    # 3. Comprobar uso único

    if authorization["used"]:
        raise HTTPException(
            status_code=400,
            detail="Authorization code already used",
        )

    # 4. Comprobar expiración

    if datetime.now(timezone.utc) >= authorization["expires_at"]:
        raise HTTPException(
            status_code=400,
            detail="Authorization code expired",
        )

    # 5. Comprobar que es del resource server permitido

    if authorization["resource"] != resource:
        raise HTTPException(
            status_code=400,
            detail="Resource mismatch",
        )

    # 6. Comprobar client_id

    if authorization["client_id"] != client_id:
        raise HTTPException(
            status_code=400,
            detail="Client mismatch",
        )

    # 7. Comprobar redirect_uri

    if authorization["redirect_uri"] != redirect_uri:
        raise HTTPException(
            status_code=400,
            detail="Redirect URI mismatch",
        )

    # 8. Comprobar PKCE method

    if authorization["code_challenge_method"] != "S256":
        raise HTTPException(
            status_code=400,
            detail="Unsupported code_challenge_method",
        )

    # 9. Calcular challenge a partir del verifier

    digest = hashlib.sha256(
        code_verifier.encode("ascii")
    ).digest()

    calculated_challenge = (
        base64.urlsafe_b64encode(digest)
        .rstrip(b"=")
        .decode("ascii")
    )

    # 10. Comparar PKCE

    if calculated_challenge != authorization["code_challenge"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid code_verifier",
        )

    # 11. Marcar code como utilizado

    authorization["used"] = True

    # 12. Crear access token

    access_token = secrets.token_urlsafe(32)

    # 13. Añadir expiración al token

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=2)
    )

    access_tokens[access_token] = {
        "user_id": authorization["user_id"],
        "client_id": authorization["client_id"],
        "scope": authorization["scope"],
        "resource": authorization["resource"],
        "expires_at": expires_at
    }

    # 13. Responder

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "scope": access_tokens[access_token]["scope"],
        "resource": access_tokens[access_token]["resource"],
        "expires_at": access_tokens[access_token]["expires_at"]
    }


@app.post("/introspect")
async def introspect(
    token: str = Form(...),
    authorization: str | None = Header(default=None),
):
    client_id = authenticate_client(authorization)

    if client_id != "mcp-resource-server":
        raise HTTPException(
            status_code=403,
            detail="Client is not allowed to introspect tokens",
        )

    access_token = access_tokens.get(token)

    if access_token is None:
        return {
            "active": False
        }

    # Verify is not expired
    if datetime.now(timezone.utc) >= access_token["expires_at"]:
        return {
            "active": False
        }

    return {
        "active": True,
        "client_id": access_token["client_id"],
        "user_id": access_token["user_id"],
        "scope": access_token["scope"],
        "resource": access_token["resource"],
        "exp": int(
            access_token["expires_at"].timestamp()
        ),
    }
"""
Un pequeño servidor de autorización OAuth que opera en memoria. Diseñado con fines educativos.

Los registros y las credenciales de demostración se almacenan deliberadamente en memoria. 
Para facilitar la exploración del flujo de código de autorización de OAuth. No adecuado para un entorno de producción.
"""

import hmac
import base64
import hashlib
import secrets
from typing import Annotated
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

# ---------------------------------------------------------------------------
#                           SERVIDOR FASTAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="OAuth Authorization Server")
basic_security = HTTPBasic(auto_error=False)

# ---------------------------------------------------------------------------
#                           CONFIGURACIÓN
# ---------------------------------------------------------------------------

AUTH_SERVER = "http://localhost:8000"
USER_EMAIL = "juan@example.com"
USER_PASSWORD = "password"
USER_ID = "user-123"

# ---------------------------------------------------------------------------
#                           DATOS TEMPORALES
# ---------------------------------------------------------------------------

# Clientes almacenados en diccionarios por facilidad.
# Se debe sustituir por una base de datos permanente


# Clientes MCPs permitidos para solicitar el bearer
MCP_CLIENTS = {
    "my-mcp-client": {
        "redirect_uris": [
            "http://localhost:9100/callback"
        ],
        "allowed_scopes": [
            "profile"
        ],
        "allowed_resources": [
            "http://localhost:9000/mcp/"
        ],
    },
}

# Servidores MCP registrados para acceder a los recursos protegidos
RESOURCE_SERVER_CLIENTS = {
    "mcp-resource-server": {
        "client_secret": "super-secret-development-value",
        "allowed_operations": [
            "introspection"
        ],
    },
}


# ---------------------------------------------------------------------------
#                                   MODELOS
# ---------------------------------------------------------------------------

class OAuthRequest(BaseModel):
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    resource: str


class UserSession(BaseModel):
    user_id: str
    email: str


class AuthorizationCode(BaseModel):
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    resource: str
    expires_at: datetime
    used: bool = False


class AccessToken(BaseModel):
    user_id: str
    client_id: str
    scope: str
    resource: str
    expires_at: datetime


class RootResponse(BaseModel):
    message: str


class AuthorizationServerMetadata(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: str
    response_types_supported: list[str]
    grant_types_supported: list[str]
    code_challenge_methods_supported: list[str]
    scopes_supported: list[str]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    scope: str
    resource: str
    expires_at: datetime


class InactiveTokenResponse(BaseModel):
    active: bool = False


class ActiveTokenResponse(BaseModel):
    active: bool = True
    client_id: str
    user_id: str
    scope: str
    resource: str
    exp: int
    iss: str


# ---------------------------------------------------------------------------
#                          ALMACENAMIENTO DEMO
# ---------------------------------------------------------------------------

# Solicitudes OAuth pendientes.
#
# session_id -> datos de la solicitud OAuth
#
oauth_requests: dict[str, OAuthRequest] = {}


# Sesiones de usuarios autenticados.
#
# user_session_id -> datos del usuario
#
user_sessions: dict[str, UserSession] = {}


# Authorization codes.
#
# Códigos de autorización para poder obtener luego el token
# 
authorization_codes: dict[str, AuthorizationCode] = {}

# Tokens de autenticación
#
# Bearer tokens para solicitar peticiones protegidas
# 
access_tokens: dict[str, AccessToken] = {}


# ---------------------------------------------------------------------------
#                            HELPERS
# ---------------------------------------------------------------------------

def get_resource_server_client(
    credentials: Annotated[
        HTTPBasicCredentials | None,
        Depends(basic_security),
    ],) -> str:
    """Authenticate an introspection caller and return its client ID."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )

    client = RESOURCE_SERVER_CLIENTS.get(credentials.username)
    if client is None or not hmac.compare_digest(
        credentials.password,
        client["client_secret"],
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if "introspection" not in client["allowed_operations"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Client is not allowed to introspect tokens",
        )
    return credentials.username

def require_oauth_request(session_id: str) -> OAuthRequest:
    oauth_request = oauth_requests.get(session_id)
    if oauth_request is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth session")
    return oauth_request

# ---------------------------------------------------------------------------
#                            RUTAS API
# ---------------------------------------------------------------------------

# ----------- Root -----------
@app.get("/", response_model=RootResponse)
async def root() -> RootResponse:
    return RootResponse(message="OAuth Authorization Server")

# ----------- Información de este Auth Server -----------
@app.get(
    "/.well-known/oauth-authorization-server",
    response_model=AuthorizationServerMetadata,
)
async def authorization_server_metadata() -> AuthorizationServerMetadata:
    return AuthorizationServerMetadata(
        issuer=AUTH_SERVER,
        authorization_endpoint=f"{AUTH_SERVER}/authorize",
        token_endpoint=f"{AUTH_SERVER}/token",
        introspection_endpoint=f"{AUTH_SERVER}/introspect",
        response_types_supported=["code"],
        grant_types_supported=["authorization_code"],
        code_challenge_methods_supported=["S256"],
        scopes_supported=sorted({
            scope
            for client in MCP_CLIENTS.values()
            for scope in client["allowed_scopes"]
        }),
    )


# -----------  OAuth Authorization Endpoint. -----------
@app.get("/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    resource: str,
) -> RedirectResponse:
    # 1. Comprobar que el cliente existe
    mcp_client = MCP_CLIENTS.get(client_id)

    if mcp_client is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown client")

    # 2. Comprobar que el tipo de respuesta es válido
    if response_type != "code":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported response_type")

    # 3. Comprobar que el cliente puede solicitar tokens al recurso que solicta
    if resource not in mcp_client.get("allowed_resources", []):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client is not allowed to request this resource")

    # 4. Comprobar que la redirect_uri está registrada
    if redirect_uri not in mcp_client["redirect_uris"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid redirect_uri")

    # 5. Comprobar que el método está soportado
    if code_challenge_method.upper() != "S256":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported code_challenge_method")

    # 6. Comprobar que incluye code_challenge
    if not code_challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="code_challenge is required")

    # 7. Comprobar que solicita al menos un scope
    requested_scopes = set(scope.split())
    if not requested_scopes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one scope is required")

    # 8. Comprobar que tiene permiso para los scopes que solicita
    disallowed_scopes = requested_scopes - set(mcp_client["allowed_scopes"])
    if disallowed_scopes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Scope not allowed: {', '.join(sorted(disallowed_scopes))}")

    # 9. Guardar la solicitud OAuth
    #
    # Creamos un identificador aleatorio para relacionar
    # esta solicitud OAuth con el proceso de login.
    session_id = secrets.token_urlsafe(32)
    print(f"Session ID: {session_id}")

    oauth_requests[session_id] = OAuthRequest(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(sorted(requested_scopes)),
        state=state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        resource=resource,
    )

    # 10. Enviar al usuario al login
    return RedirectResponse(
        url=f"/login?session_id={session_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ----------- Login Page -----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(session_id: str) -> HTMLResponse:
    
    # Comprobamos que la solicitud OAuth exista.
    require_oauth_request(session_id)
    
    return HTMLResponse(f"""
        <!doctype html>
        <html><head><title>Login</title></head><body>
        <h1>Login</h1>
        <form method="post" action="/login">
        <input type="hidden" name="session_id" value="{session_id}">
        <label>Email: <input name="email" type="email" required></label><br><br>
        <label>Password: <input name="password" type="password" required></label><br><br>
        <button type="submit">Login</button>
        </form></body></html>
    """)

# -----------  Login -----------
@app.post("/login")
async def login(
    session_id: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> RedirectResponse:
    
    # 1. Recuperar la solicitud OAuth abierta del /authorize
    require_oauth_request(session_id)

    # ! 2. AUTENTICACIÓN TEMPORAL
    if email != USER_EMAIL or password != USER_PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # 3. Crear sesión de usuario
    # El usuario nos ha enviado su email y contraseña,
    # almacenamos en cache y enviamos cookie para identificarlo
    # después en el consent
    user_session_id = secrets.token_urlsafe(32)
    user_sessions[user_session_id] = UserSession(user_id=USER_ID, email=email)

    # 4. Ir a la pantalla de consentimiento
    response = RedirectResponse(
        url=f"/consent?session_id={session_id}",
        status_code=303,
    )

    # 5. Guardar la sesión del usuario en una cookie
    response.set_cookie(
        key="user_session_id",
        value=user_session_id,
        httponly=True,
        secure=False,  #! En producción con HTTPS será True
        samesite="lax",
    )

    return response


# ----------- Página de consentimiento -----------
@app.get("/consent", response_class=HTMLResponse)
async def consent_page(session_id: str) -> HTMLResponse:

    def html_escape(value: str) -> str:
        """Valores de escape insertados en las pequeñas páginas HTML escritas a mano"""
        from html import escape
        return escape(value, quote=True)

    # 1. Recuperar solicitud OAuth
    oauth_request = require_oauth_request(session_id)

    # 2. Mostrar consentimiento
    client_name = html_escape(oauth_request.client_id)
    requested_scope = html_escape(oauth_request.scope)

    return HTMLResponse(f"""
        <!doctype html>
        <html><head><title>Authorization</title></head><body>
        <h1>Authorization required</h1>
        <p>The application <strong>{client_name}</strong> wants access to:</p>
        <ul><li>{requested_scope}</li></ul>
        <form method="post" action="/consent">
        <input type="hidden" name="session_id" value="{html_escape(session_id)}">
        <button type="submit" name="decision" value="deny">Deny</button>
        <button type="submit" name="decision" value="allow">Allow</button>
        </form></body></html>"""
    )


# -----------  Decisión del consentimiento -----------
@app.post("/consent")
async def consent(
    session_id: Annotated[str, Form()],
    decision: Annotated[str, Form()],
    user_session_id: Annotated[str | None, Cookie(alias="user_session_id")] = None,
) -> RedirectResponse:

    def authorization_redirect(
        redirect_uri: str,
        **parameters: str,
    ) -> RedirectResponse:
        return RedirectResponse(
            url=f"{redirect_uri}?{urlencode(parameters)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    
    # 1. Asegurar que es una request abierta
    oauth_request = require_oauth_request(session_id)

    # 2. Buscar la información del usuario que consiente
    user_session = user_sessions.get(user_session_id)

    if user_session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not authenticated")

    # 3. Obtener la decisión del usuario
    if decision == "deny":
        oauth_requests.pop(session_id, None)
        return authorization_redirect(
            oauth_request.redirect_uri,
            error="access_denied",
            state=oauth_request.state,
            iss=AUTH_SERVER
        )

    if decision != "allow":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid consent decision")

    # 4. Generar el code con el que se obtendrá el token
    code = secrets.token_urlsafe(32)
    print(f"Code: {code}")

    # 5. Generar el modelo de autenticación. Código de expiración de 5 minutos
    authorization_codes[code] = AuthorizationCode(
        client_id=oauth_request.client_id,
        user_id=user_session.user_id,
        redirect_uri=oauth_request.redirect_uri,
        scope=oauth_request.scope,
        code_challenge=oauth_request.code_challenge,
        code_challenge_method=oauth_request.code_challenge_method,
        resource=oauth_request.resource,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    oauth_requests.pop(session_id, None)
    return authorization_redirect(
        oauth_request.redirect_uri,
        code=code,
        state=oauth_request.state,
        iss=AUTH_SERVER
    )

# -----------  Obtener Bearer Token  -----------
@app.post("/token", response_model=TokenResponse)
async def token(
    grant_type: Annotated[str, Form()],
    code: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    code_verifier: Annotated[str, Form()],
    resource: Annotated[str, Form()],
) -> TokenResponse:

    # 1. Buscar authorization code
    authorization = authorization_codes.get(code)
    
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authorization code")
    
    # 2. Grant type
    if grant_type != "authorization_code":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported grant_type")

    # 3. Comprobar uso único
    if authorization.used:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization code already used")

    # 4. Comprobar expiración
    if datetime.now(timezone.utc) >= authorization.expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization code expired")

    # 5. Comprobar que es del resource server permitido
    if authorization.resource != resource:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Resource mismatch")

    # 6. Comprobar client_id
    if authorization.client_id != client_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client mismatch")

    # 7. Comprobar redirect_uri
    if authorization.redirect_uri != redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI mismatch")

    # 8. Comprobar PKCE method
    if authorization.code_challenge_method != "S256":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported code_challenge_method")

    # 9. Calcular challenge a partir del verifier
    try:
        verifier_bytes = code_verifier.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code_verifier") from exc
    
    digest = hashlib.sha256(verifier_bytes).digest()
    calculated_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    # 10. Comparar PKCE
    if not hmac.compare_digest(calculated_challenge, authorization.code_challenge):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code_verifier")

    # 11. Marcar como usado
    authorization.used = True 

    # 12. Generar access token
    access_token = secrets.token_urlsafe(32)
    token_record = AccessToken(
        user_id=authorization.user_id,
        client_id=authorization.client_id,
        scope=authorization.scope,
        resource=authorization.resource,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
    )

    # 13. Guardar y devolver token
    access_tokens[access_token] = token_record

    return TokenResponse(
        access_token=access_token,
        scope=token_record.scope,
        resource=token_record.resource,
        expires_at=token_record.expires_at,
    )


# -----------  Inspeccionar Token  -----------
@app.post(
    "/introspect",
    response_model=ActiveTokenResponse | InactiveTokenResponse,
)
async def introspect(
    token: Annotated[str, Form()],
    # Se ejecuta la validación HTTP Basic. Si falla, lanza 401/403.
    # Si pasa, la variable 'authenticated_rs' simplemente confirma quién hizo la llamada.
    authenticated_rs: Annotated[str, Depends(get_resource_server_client)],
) -> ActiveTokenResponse | InactiveTokenResponse:

    access_token = access_tokens.get(token)
    if access_token is None or datetime.now(timezone.utc) >= access_token.expires_at:
        return InactiveTokenResponse()

    return ActiveTokenResponse(
        client_id=access_token.client_id,  # <-- 'my-mcp-client' (el dueño del token)
        user_id=access_token.user_id,
        scope=access_token.scope,
        resource=access_token.resource,
        exp=int(access_token.expires_at.timestamp()),
        iss=AUTH_SERVER
    )
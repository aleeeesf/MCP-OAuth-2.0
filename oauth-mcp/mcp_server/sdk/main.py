"""
Servidor MCP montado en FastAPI utilizando el SDK oficial de Python.

Actúa como Servidor de Recursos (Resource Server) protegido con OAuth 2.0.
Protege las rutas MCP montadas mediante un middleware ASGI que valida el
Bearer token contra el servidor de autorización (RFC 7662) comprobando validez,
recurso de destino y permisos de ámbito (scopes). Diseñado con fines educativos.
"""

import httpx
from pydantic import BaseModel
from fastapi import FastAPI, status
from contextlib import asynccontextmanager

from .server import mcp

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
#                           CONFIGURACIÓN
# ---------------------------------------------------------------------------

AUTH_SERVER = "http://localhost:8000"
MCP_RESOURCE = "http://localhost:9000/mcp/"
RESOURCE_SERVER_CLIENT_ID = "mcp-resource-server"
RESOURCE_SERVER_CLIENT_SECRET = "super-secret-development-value"


# ---------------------------------------------------------------------------
#                               MODELOS
# ---------------------------------------------------------------------------


class RootResponse(BaseModel):
    message: str


class ProtectedResourceMetadata(BaseModel):
    """Metadatos del recurso protegido según RFC 9728."""

    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str]
    bearer_methods_supported: list[str]


class TokenIntrospection(BaseModel):
    """Respuesta del endpoint de introspección del servidor OAuth."""

    active: bool = False
    client_id: str | None = None
    user_id: str | None = None
    scope: str = ""
    resource: str | None = None
    exp: int | None = None
    iss: str | None = None


# ---------------------------------------------------------------------------
#                               HELPERS
# ---------------------------------------------------------------------------

async def introspect_token(token: str) -> TokenIntrospection:
    """
    Consulta al servidor de autorización la validez y metadatos de un Bearer token.
    Utiliza HTTP Basic con las credenciales registradas del Resource Server.
    """
    global http_client
    if http_client is None:
        raise RuntimeError("El cliente HTTP global no ha sido inicializado en el lifespan")
        
    try:
        response = await http_client.post(
            f"{AUTH_SERVER}/introspect",
            data={"token": token},
            auth=(
                RESOURCE_SERVER_CLIENT_ID,
                RESOURCE_SERVER_CLIENT_SECRET,
            ),
        )
        response.raise_for_status()
        return TokenIntrospection(**response.json())
        
    except httpx.HTTPStatusError as e:
        # Si el servidor OAuth responde con un 400 (ej. token malformado o revocado explícitamente),
        # el token es efectivamente inactivo.
        if e.response.status_code == 400:
            return TokenIntrospection(active=False)
        # Si el servidor OAuth da un error 5xx, relanzamos para que se convierta en un 500 en nuestra API
        raise
    except httpx.HTTPError as e:
        # Errores de red, timeouts o caída total del servidor de autorización
        raise RuntimeError(f"Error de comunicación con el servidor de autorización: {e}")

# ---------------------------------------------------------------------------
#                         LIFESPAN DE LA APLICACIÓN
# ---------------------------------------------------------------------------


# streamable_http_app() utiliza un gestor de sesiones en segundo plano que
# necesita estar activo durante todo el ciclo de vida del proceso FastAPI.
# Al montar el MCP como sub-aplicación ASGI, el lifespan debe gestionarse aquí.
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    # Inicializamos el cliente al arrancar la app (con soporte de keep-alive)
    http_client = httpx.AsyncClient(timeout=5.0)
    
    async with mcp.session_manager.run():
        yield
        
    # Cerramos el cliente al apagar la app
    await http_client.aclose()


# ---------------------------------------------------------------------------
#                           SERVIDOR FASTAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="MCP Server (SDK)",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
#                           CLIENTE HTTP
# ---------------------------------------------------------------------------

http_client: httpx.AsyncClient | None = None

# ---------------------------------------------------------------------------
#                            RUTAS API
# ---------------------------------------------------------------------------


# ----------- Root -----------
@app.get("/", response_model=RootResponse)
async def root() -> RootResponse:
    return RootResponse(message="MCP Server (SDK)")


# ----------- Metadatos de Recursos Protegidos (RFC 9728) -----------
@app.get(
    "/.well-known/oauth-protected-resource/mcp",
    response_model=ProtectedResourceMetadata,
)
@app.get(
    "/.well-known/oauth-protected-resource",
    response_model=ProtectedResourceMetadata,
)
async def protected_resource_metadata() -> ProtectedResourceMetadata:
    """Proporciona información sobre el servidor de autorización y scopes necesarios."""
    return ProtectedResourceMetadata(
        resource=MCP_RESOURCE,
        authorization_servers=[AUTH_SERVER],
        scopes_supported=["profile"],
        bearer_methods_supported=["header"],
    )


# ---------------------------------------------------------------------------
#                         MIDDLEWARE OAUTH (ASGI)
# ---------------------------------------------------------------------------


class OAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware ASGI que intercepta las peticiones dirigidas al MCP Server
    para validar la presencia, vigencia, destino y permisos del Bearer token.
    """

    async def dispatch(self, request: Request, call_next):
        # 1. Extraer cabecera Authorization de forma limpia
        auth_header = request.headers.get("authorization")

        if not auth_header:
            return JSONResponse(
                {"error": "unauthorized", "message": "Missing Authorization header"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 2. Validar esquema Bearer
        try:
            scheme, token = auth_header.split(" ", 1)
        except ValueError:
            return JSONResponse(
                {"error": "unauthorized", "message": "Invalid Authorization header"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )

        if scheme.lower() != "bearer" or not token.strip():
            return JSONResponse(
                {"error": "unauthorized", "message": "Unsupported authentication scheme"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 3. Introspección del token
        token_info = await introspect_token(token.strip())

        if not token_info.active:
            return JSONResponse(
                {"error": "unauthorized", "message": "Invalid or expired access token"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 4. Validar recurso de destino
        token_resource = (token_info.resource or "").rstrip("/")
        expected_resource = MCP_RESOURCE.rstrip("/")
        if token_resource != expected_resource:
            return JSONResponse(
                {"error": "unauthorized", "message": "Token was not issued for this resource"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 5. Validar scopes requeridos
        if "profile" not in token_info.scope.split():
            return JSONResponse(
                {"error": "forbidden", "message": "Insufficient scope: requires 'profile'"},
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # Token válido -> call_next(request) pasa la petición al servidor MCP
        response = await call_next(request)
        return response


# ---------------------------------------------------------------------------
#                         MONTAJE DE SUB-APLICACIÓN
# ---------------------------------------------------------------------------

mcp_app = mcp.streamable_http_app(streamable_http_path="/")

app.mount(
    "/mcp",
    OAuthMiddleware(mcp_app),
)

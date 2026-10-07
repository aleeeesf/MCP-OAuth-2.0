"""
Cliente MCP implementado directamente con FastAPI sin utilizar el SDK oficial.

Demuestra el flujo completo de cliente OAuth 2.0 con PKCE:
1. Autodescubrimiento de endpoints y autorización mediante redirección.
2. Recepción del callback y canje de código por token de acceso Bearer.
3. Consumo de recursos protegidos HTTP y sesión de protocolo MCP sobre JSON-RPC.
Diseñado con fines educativos.
"""

import secrets
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from .oauth import (
    TokenResponse,
    AuthorizationServerMetadata,
    build_authorization_url,
    call_mcp,
    call_protected_resource,
    exchange_code_for_token,
    generate_code_challenge,
    generate_code_verifier,
    get_authorization_server_metadata,
    get_protected_resource_metadata,
)

# ---------------------------------------------------------------------------
#                           SERVIDOR FASTAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="MCP Client")


# ---------------------------------------------------------------------------
#                           CONFIGURACIÓN
# ---------------------------------------------------------------------------

CLIENT_ID = "my-mcp-client"
REDIRECT_URI = "http://localhost:9100/callback"
RESOURCE_URL = "http://localhost:9000/mcp/"
PROFILE_URL = "http://localhost:9000/profile"
MCP_ENDPOINT = "http://localhost:9000/mcp/"
PROTECTED_RESOURCE_METADATA_URL = (
    "http://localhost:9000/.well-known/oauth-protected-resource/mcp"
)


# ---------------------------------------------------------------------------
#                               MODELOS
# ---------------------------------------------------------------------------


class RootResponse(BaseModel):
    message: str


class OAuthClientSession(BaseModel):
    code_verifier: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TokenCallbackResponse(BaseModel):
    message: str
    token_type: str
    scope: str
    expires_at: str | None = None # es un datetime


class ProfileResponse(BaseModel):
    user_id: str | None
    message: str


class McpTestResponse(BaseModel):
    initialize: dict[str, Any]
    tools: dict[str, Any]
    call: dict[str, Any]


# ---------------------------------------------------------------------------
#                          ALMACENAMIENTO DEMO
# ---------------------------------------------------------------------------

# Sesiones OAuth pendientes de resolver el callback.
# state -> datos de la sesión (code_verifier, timestamp)
oauth_sessions: dict[str, OAuthClientSession] = {}

# Último Bearer token obtenido (almacenado en memoria para la demostración).
stored_token: TokenResponse | None = None


# ---------------------------------------------------------------------------
#                               HELPERS
# ---------------------------------------------------------------------------


def get_authenticated_token() -> TokenResponse:
    """Valida que exista un token de acceso guardado en memoria."""
    if stored_token is None or not stored_token.access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client is not authenticated. Please visit /login first.",
        )
    return stored_token


# ---------------------------------------------------------------------------
#                            RUTAS API
# ---------------------------------------------------------------------------


# ----------- Root -----------
@app.get("/", response_model=RootResponse)
async def root() -> RootResponse:
    return RootResponse(message="MCP Client")


# ----------- Iniciar Flujo OAuth (Login) -----------
@app.get("/login")
async def login() -> RedirectResponse:
    """
    Inicia el flujo de autorización OAuth 2.0:
    1. Descubre el servidor de autorización leyendo los metadatos del recurso protegido.
    2. Lee los metadatos del servidor de autorización para obtener el endpoint /authorize.
    3. Genera el par PKCE (verifier / challenge) y el parámetro state.
    4. Guarda la sesión temporalmente y redirige al usuario para autenticarse y consentir.
    """
    # 1. Obtener metadatos del recurso MCP (RFC 9728)
    resource_metadata = await get_protected_resource_metadata(
        PROTECTED_RESOURCE_METADATA_URL
    )
    if not resource_metadata.authorization_servers:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No authorization servers found in protected resource metadata",
        )

    # 2. Obtener metadatos del servidor de autorización (RFC 8414)
    auth_server_url = resource_metadata.authorization_servers[0]
    auth_metadata: AuthorizationServerMetadata = await get_authorization_server_metadata(auth_server_url)

    # 3. Generar parámetros PKCE y state anti-CSRF
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(32)

    # 4. Guardar sesión temporal en memoria
    oauth_sessions[state] = OAuthClientSession(code_verifier=code_verifier)

    # 5. Construir URL de autorización completa
    authorization_url = build_authorization_url(
        authorization_endpoint=auth_metadata.authorization_endpoint,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope="profile",
        state=state,
        code_challenge=code_challenge,
        resource=RESOURCE_URL,
    )

    # 6. Redirigir al usuario al Authorization Server
    return RedirectResponse(
        url=authorization_url, status_code=status.HTTP_303_SEE_OTHER
    )


# ----------- Callback de Autorización -----------
@app.get("/callback", response_model=TokenCallbackResponse)
async def callback(
    code: Annotated[
        str, Query(description="Código de autorización devuelto por el Auth Server")
    ],
    state: Annotated[
        str,
        Query(description="Estado de la petición devuelto para validación anti-CSRF"),
    ],
) -> TokenCallbackResponse:
    """
    Endpoint de retorno tras el consentimiento en el servidor de autorización:
    1. Valida el parámetro state contra las sesiones abiertas.
    2. Recupera el code_verifier asociado para completar PKCE.
    3. Intercambia el código por el token de acceso Bearer.
    4. Guarda el token en memoria para peticiones posteriores.
    """
    global stored_token

    # 1. Validar el estado de la sesión
    session = oauth_sessions.pop(state, None)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter",
        )

    # 2. Descubrir endpoints a través de los metadatos
    resource_metadata = await get_protected_resource_metadata(
        PROTECTED_RESOURCE_METADATA_URL
    )
    auth_server_url = resource_metadata.authorization_servers[0]
    auth_metadata = await get_authorization_server_metadata(auth_server_url)

    # 3. Canjear el código por el token de acceso
    token_data = await exchange_code_for_token(
        token_endpoint=auth_metadata.token_endpoint,
        code=code,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        code_verifier=session.code_verifier,
        resource=RESOURCE_URL,
    )

    # 4. Almacenar el token en memoria
    stored_token = token_data

    # 5. Devolver confirmación al usuario
    return TokenCallbackResponse(
        message="Authorization successful",
        token_type=token_data.token_type,
        scope=token_data.scope,
        expires_at=str(token_data.expires_at) if token_data.expires_at else None,
    )


# ----------- Llamar a Recurso Protegido Estándar -----------
@app.get("/call-profile", response_model=ProfileResponse)
async def call_profile() -> ProfileResponse:
    """
    Consume el endpoint protegido /profile del MCP Server usando el Bearer Token almacenado.
    """
    token = get_authenticated_token()
    data = await call_protected_resource(
        resource_url=PROFILE_URL,
        access_token=token.access_token,
    )
    return ProfileResponse(**data)


# ----------- Probar Sesión MCP Completa -----------
@app.get("/mcp-test", response_model=McpTestResponse)
async def mcp_test() -> McpTestResponse:
    """
    Ejecuta una secuencia completa de peticiones MCP con el servidor mediante JSON-RPC:
    1. initialize: Negociación de versión de protocolo y capacidades.
    2. notifications/initialized: Confirmación de inicio.
    3. tools/list: Consulta del catálogo de herramientas disponibles.
    4. tools/call: Invocación de la herramienta 'add' con argumentos (a=10, b=20).
    """
    token = get_authenticated_token()

    # 1. Mensaje initialize
    initialize_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "my-mcp-client",
                "version": "1.0.0",
            },
        },
    }
    initialize_res = await call_mcp(
        mcp_url=MCP_ENDPOINT,
        access_token=token.access_token,
        message=initialize_payload,
    )

    # 2. Notificación initialized (no espera respuesta de datos)
    notification_payload = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }
    await call_mcp(
        mcp_url=MCP_ENDPOINT,
        access_token=token.access_token,
        message=notification_payload,
    )

    # 3. Listar herramientas
    tools_list_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    }
    tools_res = await call_mcp(
        mcp_url=MCP_ENDPOINT,
        access_token=token.access_token,
        message=tools_list_payload,
    )

    # 4. Invocar herramienta 'add'
    tools_call_payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "add",
            "arguments": {
                "a": 10,
                "b": 20,
            },
        },
    }
    call_res = await call_mcp(
        mcp_url=MCP_ENDPOINT,
        access_token=token.access_token,
        message=tools_call_payload,
    )

    return McpTestResponse(
        initialize=initialize_res,
        tools=tools_res,
        call=call_res,
    )

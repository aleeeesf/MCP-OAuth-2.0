"""
Servidor MCP (Model Context Protocol) implementado directamente en FastAPI sin SDK.

Actúa como Servidor de Recursos (Resource Server) protegido con OAuth 2.0.
Implementa el protocolo JSON-RPC 2.0 para operaciones MCP (inicialización, listado
y ejecución de herramientas) y expone metadatos RFC 9728. Diseñado con fines educativos.
"""

from typing import Annotated, Any

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from .auth import (
    AUTH_SERVER,
    MCP_RESOURCE,
    TokenIntrospection,
    get_current_token_info,
    require_scope,
)

# ---------------------------------------------------------------------------
#                           SERVIDOR FASTAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="MCP Server")


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


class JsonRpcError(BaseModel):
    """Estructura de error estándar en JSON-RPC 2.0."""

    code: int
    message: str
    data: Any | None = None


class JsonRpcRequest(BaseModel):
    """Mensaje de petición o notificación en JSON-RPC 2.0."""

    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcResponse(BaseModel):
    """Mensaje de respuesta en JSON-RPC 2.0."""

    jsonrpc: str = "2.0"
    id: int | str | None = None
    result: Any | None = None
    error: JsonRpcError | None = None


class ProfileResponse(BaseModel):
    user_id: str | None
    message: str


# ---------------------------------------------------------------------------
#                        CATÁLOGO DE HERRAMIENTAS
# ---------------------------------------------------------------------------

TOOLS_REGISTRY = [
    {
        "name": "add",
        "description": "Suma dos números",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "Primer número"},
                "b": {"type": "number", "description": "Segundo número"},
            },
            "required": ["a", "b"],
        },
    }
]


# ---------------------------------------------------------------------------
#                            RUTAS API
# ---------------------------------------------------------------------------

# ----------- Root -----------
@app.get("/", response_model=RootResponse)
async def root() -> RootResponse:
    return RootResponse(message="MCP Server")


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


# ----------- Endpoint MCP (JSON-RPC 2.0 sobre HTTP) -----------
@app.post(
    "/mcp",
    response_model=JsonRpcResponse | dict[str, Any],
    response_model_exclude_none=True,
)
@app.post(
    "/mcp/",
    response_model=JsonRpcResponse | dict[str, Any],
    response_model_exclude_none=True,
)
async def mcp_endpoint(
    request_data: JsonRpcRequest,
    token_info: Annotated[TokenIntrospection, Depends(get_current_token_info)],
) -> JsonRpcResponse | dict[str, Any]:
    """
    Endpoint principal para interactuar con el servidor MCP mediante JSON-RPC.
    Valida y procesa las peticiones usando los modelos JsonRpcRequest, JsonRpcResponse y JsonRpcError.
    Requiere un Bearer Token válido obtenido del Servidor de Autorización.
    """
    method = request_data.method
    req_id = request_data.id

    # 1. Negociación inicial del protocolo MCP
    if method == "initialize":
        return JsonRpcResponse(
            id=req_id,
            result={
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "my-mcp-server",
                    "version": "1.0.0",
                },
            },
        )

    # 2. Notificación del cliente confirmando inicialización (sin respuesta esperada)
    if method == "notifications/initialized":
        return {}

    # 3. Listar herramientas disponibles
    if method == "tools/list":
        return JsonRpcResponse(
            id=req_id,
            result={
                "tools": TOOLS_REGISTRY,
            },
        )

    # 4. Invocar una herramienta MCP
    if method == "tools/call":
        params = request_data.params
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        # Validar existencia de la herramienta
        if tool_name != "add":
            return JsonRpcResponse(
                id=req_id,
                error=JsonRpcError(
                    code=-32602,
                    message=f"Unknown tool: '{tool_name}'",
                ),
            )

        # Validar argumentos numéricos de la herramienta 'add'
        a = arguments.get("a")
        b = arguments.get("b")

        if not isinstance(a, (int, float)):
            return JsonRpcResponse(
                id=req_id,
                error=JsonRpcError(
                    code=-32602,
                    message="Invalid argument: 'a' must be a number",
                ),
            )

        if not isinstance(b, (int, float)):
            return JsonRpcResponse(
                id=req_id,
                error=JsonRpcError(
                    code=-32602,
                    message="Invalid argument: 'b' must be a number",
                ),
            )

        # Ejecución de la herramienta
        result = a + b
        return JsonRpcResponse(
            id=req_id,
            result={
                "content": [
                    {
                        "type": "text",
                        "text": str(result),
                    }
                ],
            },
        )

    # 5. Método no reconocido por JSON-RPC
    return JsonRpcResponse(
        id=req_id,
        error=JsonRpcError(
            code=-32601,
            message=f"Method not found: '{method}'",
        ),
    )


# ----------- Endpoint Protegido con Scope Específico -----------
@app.get("/profile", response_model=ProfileResponse)
async def profile(
    token_info: Annotated[TokenIntrospection, Depends(require_scope("profile"))],
) -> ProfileResponse:
    """
    Endpoint de ejemplo de recurso protegido que requiere el scope 'profile'.
    """
    return ProfileResponse(
        user_id=token_info.user_id,
        message="This is a protected resource",
    )

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from mcp.server import MCPServer


AUTH_SERVER = "http://localhost:8000"
MCP_RESOURCE = "http://localhost:9000/mcp/"


# ---------------------------------------------------------
# MCP SDK
# ---------------------------------------------------------

mcp = MCPServer("My MCP Server")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Suma dos números."""
    return a + b


# ---------------------------------------------------------
# OAuth
# ---------------------------------------------------------

async def introspect_token(token: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{AUTH_SERVER}/introspect",
            data={"token": token},
            auth=(
                "mcp-resource-server",
                "super-secret-development-value",
            ),
        )

    response.raise_for_status()

    return response.json()


# ---------------------------------------------------------
# Lifespan
# ---------------------------------------------------------
# ¿Por qué?

# Porque streamable_http_app() utiliza un gestor de sesiones que necesita estar arrancado durante la vida de nuestra aplicación. 
# Cuando el MCP está montado dentro de otra aplicación, el lifespan de la subaplicación no se ejecuta automáticamente.
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(
    title="MCP Server",
    lifespan=lifespan,
)


# ---------------------------------------------------------
# OAuth Protected Resource Metadata
# ---------------------------------------------------------

@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata():

    return {
        "resource": MCP_RESOURCE,
        "authorization_servers": [
            AUTH_SERVER
        ],
        "scopes_supported": [
            "profile"
        ],
        "bearer_methods_supported": [
            "header"
        ],
    }


# ---------------------------------------------------------
# OAuth Middleware
# ---------------------------------------------------------

class OAuthMiddleware:

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]

        # Solo protegemos MCP
        if not (path == "/mcp" or path.startswith("/mcp/")):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))

        authorization = headers.get(b"authorization")

        if authorization is None:
            response = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "Missing Authorization header",
                },
                status_code=401,
                headers={
                    "WWW-Authenticate": "Bearer",
                },
            )

            await response(scope, receive, send)
            return

        try:
            scheme, token = authorization.decode().split(" ", 1)
        except ValueError:

            response = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "Invalid Authorization header",
                },
                status_code=401,
            )

            await response(scope, receive, send)
            return

        if scheme.lower() != "bearer":

            response = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "Unsupported authentication scheme",
                },
                status_code=401,
            )

            await response(scope, receive, send)
            return

        token_info = await introspect_token(token)

        if not token_info.get("active"):

            response = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "Invalid access token",
                },
                status_code=401,
                headers={
                    "WWW-Authenticate": "Bearer",
                },
            )

            await response(scope, receive, send)
            return

        scopes = token_info.get("scope", "").split()

        if "profile" not in scopes:

            response = JSONResponse(
                {
                    "error": "forbidden",
                    "message": "Insufficient scope",
                },
                status_code=403,
            )

            await response(scope, receive, send)
            return

        # Token válido → MCP SDK
        await self.app(scope, receive, send)


# ---------------------------------------------------------
# Mount MCP
# ---------------------------------------------------------

mcp_app = mcp.streamable_http_app(
    streamable_http_path="/"
)

app.mount(
    "/mcp",
    OAuthMiddleware(mcp_app),
)
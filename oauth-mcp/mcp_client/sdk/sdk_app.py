import asyncio
import webbrowser

import httpx2
import uvicorn

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

from pydantic import AnyUrl

from mcp import Client

from mcp.client.auth import (
    AuthorizationCodeResult,
    OAuthClientProvider,
)

from mcp.client.streamable_http import (
    streamable_http_client,
)

from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)


# =========================================================
# CONFIGURACIÓN
# =========================================================

# TODO: mover a un pydantic settings

MCP_ENDPOINT = (
    "http://localhost:9000/mcp/"
)

MCP_RESOURCE = (
    "http://localhost:9000/mcp/"
)

AUTH_SERVER = (
    "http://localhost:8000"
)

CLIENT_ID = (
    "my-mcp-client"
)

REDIRECT_URI = (
    "http://localhost:9100/callback"
)

SCOPE = "profile"


# =========================================================
# APP HTTP PARA EL CALLBACK
# =========================================================

app = FastAPI(
    title="MCP OAuth Callback"
)


# =========================================================
# ESTADO DEL LOGIN
# =========================================================

authorization_future = None


# =========================================================
# TOKEN STORAGE
# =========================================================
#
# El SDK necesita un almacenamiento con cuatro métodos:
#
# get_tokens()
# set_tokens()
# get_client_info()
# set_client_info()
#
# De momento vamos a guardar todo en memoria.
#
# IMPORTANTE:
# Al cerrar el proceso se pierde el token.
#
# TODO sustituir esto por:
# - archivo
# - SQLite
# - keyring
# - secret manager
#
# =========================================================

class InMemoryTokenStorage:

    def __init__(self):

        self.tokens: OAuthToken | None = None

        self.client_info: (
            OAuthClientInformationFull | None
        ) = OAuthClientInformationFull(
            client_id=CLIENT_ID,
            redirect_uris=[
                AnyUrl(REDIRECT_URI)
            ],
            scope=SCOPE,
            grant_types=[
                "authorization_code"
            ],
            token_endpoint_auth_method="none",
            application_type="native",
            issuer=AUTH_SERVER,
        )


    async def get_tokens(
        self,
    ) -> OAuthToken | None:

        return self.tokens


    async def set_tokens(
        self,
        tokens: OAuthToken,
    ) -> None:

        self.tokens = tokens


    async def get_client_info(
        self,
    ) -> OAuthClientInformationFull | None:

        return self.client_info


    async def set_client_info(
        self,
        client_info: OAuthClientInformationFull,
    ) -> None:

        self.client_info = client_info


# =========================================================
# CALLBACK HTTP
# =========================================================

@app.get(
    "/callback",
    response_class=HTMLResponse,
)
async def callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    iss: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
):

    global authorization_future

    # -----------------------------------------------------
    # Error OAuth
    # -----------------------------------------------------

    if error is not None:

        if authorization_future is not None:

            if not authorization_future.done():

                authorization_future.set_exception(
                    RuntimeError(
                        f"OAuth error: "
                        f"{error}"
                        + (
                            f" - {error_description}"
                            if error_description
                            else ""
                        )
                    )
                )

        return HTMLResponse(
            """
            <h1>OAuth error</h1>
            <p>Puedes cerrar esta ventana.</p>
            """,
            status_code=400,
        )


    # -----------------------------------------------------
    # Comprobar code
    # -----------------------------------------------------

    if code is None:

        return HTMLResponse(
            """
            <h1>Missing authorization code</h1>
            """,
            status_code=400,
        )


    # -----------------------------------------------------
    # Entregar el resultado al OAuthClientProvider
    # -----------------------------------------------------

    result = AuthorizationCodeResult(
        code=code,
        state=state,
        iss=iss,
    )


    if authorization_future is not None:

        if not authorization_future.done():

            authorization_future.set_result(
                result
            )


    return HTMLResponse(
        """
        <!DOCTYPE html>

        <html>

        <head>
            <title>OAuth successful</title>
        </head>

        <body>

            <h1>Authorization successful</h1>

            <p>
                Ya puedes cerrar esta ventana.
            </p>

        </body>

        </html>
        """
    )


# =========================================================
# REDIRECT HANDLER
# =========================================================
#
# El OAuthClientProvider construye la URL completa:
#
# /authorize?
#   client_id=...
#   redirect_uri=...
#   state=...
#   code_challenge=...
#   ...
#
# Nosotros solamente abrimos el navegador.
#
# =========================================================

async def redirect_handler(
    authorization_url: str,
) -> None:

    print()
    print("=" * 60)
    print("OAuth necesita autenticación")
    print("=" * 60)
    print()
    print(
        "Abriendo navegador..."
    )
    print()

    print(authorization_url)
    webbrowser.open(
        authorization_url
    )


# =========================================================
# CALLBACK HANDLER
# =========================================================
#
# Este handler espera a que el navegador vuelva a:
#
# http://localhost:9100/callback
#
# =========================================================

async def callback_handler() -> AuthorizationCodeResult:

    global authorization_future

    loop = asyncio.get_running_loop()

    authorization_future = (
        loop.create_future()
    )

    print()
    print(
        "Esperando callback OAuth..."
    )
    print(
        f"Callback: {REDIRECT_URI}"
    )
    print()

    try:

        result = await authorization_future

        return result

    finally:

        authorization_future = None


# =========================================================
# CREAR OAUTH PROVIDER
# =========================================================

def create_oauth_provider():

    storage = (
        InMemoryTokenStorage()
    )


    # -----------------------------------------------------
    # Metadata del cliente
    # -----------------------------------------------------
    #
    # Esto describe nuestro cliente OAuth.
    #
    # Como nosotros ya lo tenemos registrado manualmente
    # en el Authorization Server:
    #
    #     my-mcp-client
    #
    # precargamos OAuthClientInformationFull en storage.
    #
    # -----------------------------------------------------

    client_metadata = (
        OAuthClientMetadata(
            client_name=(
                "My MCP Client"
            ),

            redirect_uris=[
                AnyUrl(
                    REDIRECT_URI
                )
            ],

            scope=SCOPE,

            grant_types=[
                "authorization_code"
            ],

            application_type="native",
        )
    )


    oauth = OAuthClientProvider(
        server_url=MCP_ENDPOINT,

        client_metadata=(
            client_metadata
        ),

        storage=storage,

        redirect_handler=(
            redirect_handler
        ),

        callback_handler=(
            callback_handler
        ),
    )


    return oauth


# =========================================================
# ARRANCAR SERVIDOR HTTP DEL CALLBACK
# =========================================================

async def start_callback_server():

    config = uvicorn.Config(
        app,
        host="localhost",
        port=9100,
        log_level="warning",
    )

    server = uvicorn.Server(
        config
    )

    await server.serve()


# =========================================================
# MCP
# =========================================================

async def run_mcp():

    print()
    print(
        "Conectando al servidor MCP..."
    )
    print()


    # -----------------------------------------------------
    # OAuth
    # -----------------------------------------------------

    oauth = (
        create_oauth_provider()
    )


    # -----------------------------------------------------
    # HTTP CLIENT
    # -----------------------------------------------------
    #
    # MUY IMPORTANTE:
    #
    # No ponemos:
    #
    #     Authorization: Bearer ...
    #
    # nosotros.
    #
    # OAuthClientProvider es quien lo hará.
    #
    # -----------------------------------------------------

    async with httpx2.AsyncClient(
        auth=oauth,

        timeout=httpx2.Timeout(
            30.0,
            read=300.0,
        ),
    ) as http_client:


        # -------------------------------------------------
        # Streamable HTTP
        # -------------------------------------------------

        transport = (
            streamable_http_client(
                MCP_ENDPOINT,
                http_client=http_client,
            )
        )


        # -------------------------------------------------
        # MCP Client
        # -------------------------------------------------

        async with Client(
            transport
        ) as client:

            print()
            print(
                "========================================"
            )
            print(
                "Conectado al servidor MCP"
            )
            print(
                "========================================"
            )

            print()

            print(
                "Servidor:",
                client.server_info,
            )

            print(
                "Versión MCP:",
                client.protocol_version,
            )


            # ---------------------------------------------
            # TOOLS LIST
            # ---------------------------------------------

            result = (
                await client.list_tools()
            )


            print()
            print(
                "Tools disponibles:"
            )


            for tool in result.tools:

                print(
                    "-",
                    tool.name,
                )

                print(
                    " ",
                    tool.description,
                )


# =========================================================
# MAIN
# =========================================================

async def main():

    print()
    print(
        "========================================"
    )
    print(
        "       MCP CLIENT"
    )
    print(
        "========================================"
    )
    print()


    # -----------------------------------------------------
    # Arrancamos el servidor HTTP local.
    #
    # Lo necesitamos porque OAuth redirigirá el navegador
    # a:
    #
    # http://localhost:9100/callback
    #
    # -----------------------------------------------------

    callback_server_task = (
        asyncio.create_task(
            start_callback_server()
        )
    )


    # -----------------------------------------------------
    # Esperamos un poco para que Uvicorn arranque.
    # -----------------------------------------------------

    await asyncio.sleep(0.5)


    try:

        # ---------------------------------------------
        # Aquí comienza realmente MCP.
        #
        # Si no existe token:
        #
        #   MCP -> 401
        #        ↓
        #   OAuthClientProvider
        #        ↓
        #   navegador
        #        ↓
        #   login
        #        ↓
        #   consentimiento
        #        ↓
        #   callback
        #        ↓
        #   token
        #        ↓
        #   repetir MCP
        #
        # ---------------------------------------------

        await run_mcp()

    finally:

        callback_server_task.cancel()

        try:

            await callback_server_task

        except asyncio.CancelledError:

            pass


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    asyncio.run(
        main()
    )
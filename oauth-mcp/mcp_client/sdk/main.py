"""
Cliente MCP implementado utilizando el SDK oficial de Python (mcp).

Demuestra la integración nativa de OAuth 2.0 PKCE mediante OAuthClientProvider:
1. Servidor FastAPI local en el puerto 9100 para capturar el callback de autorización.
2. Manejo automático del ciclo de autenticación y renovación de tokens Bearer.
3. Conexión mediante streamable_http_client hacia el servidor MCP protegido.
4. Listado y llamada a herramientas (tools) del servidor.
Diseñado con fines educativos.
"""

import asyncio
import webbrowser

import httpx2
import uvicorn
from fastapi import FastAPI, Query, status
from fastapi.responses import HTMLResponse
from mcp import Client
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)
from pydantic import AnyUrl, BaseModel

# ---------------------------------------------------------------------------
#                           CONFIGURACIÓN
# ---------------------------------------------------------------------------

MCP_ENDPOINT = "http://localhost:9000/mcp/"
CLIENT_ID = "my-mcp-client"
REDIRECT_URI = "http://localhost:9100/callback"
CALLBACK_PORT = 9100
SCOPE = "profile"


# ---------------------------------------------------------------------------
#                               MODELOS
# ---------------------------------------------------------------------------


class RootResponse(BaseModel):
    message: str


# ---------------------------------------------------------------------------
#                    ALMACENAMIENTO DE TOKENS EN MEMORIA
# ---------------------------------------------------------------------------


class InMemoryTokenStorage:
    """
    Almacenamiento en memoria para tokens y datos del cliente OAuth.
    Implementa la interfaz requerida por OAuthClientProvider del SDK.
    """

    def __init__(self):
        self.tokens: OAuthToken | None = None
        # No fijamos el issuer (servidor de autorización):
        # OAuthClientProvider lo descubre dinámicamente consultando los
        # metadatos del recurso protegido (RFC 9728) en el servidor MCP.
        self.client_info: OAuthClientInformationFull | None = (
            OAuthClientInformationFull(
                client_id=CLIENT_ID,
                redirect_uris=[AnyUrl(REDIRECT_URI)],
                scope=SCOPE,
                grant_types=["authorization_code"],
                token_endpoint_auth_method="none",
                application_type="native",
                issuer=None,
            )
        )

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


# ---------------------------------------------------------------------------
#                      APP FASTAPI PARA EL CALLBACK
# ---------------------------------------------------------------------------

app = FastAPI(title="MCP OAuth Callback Server")

# Futuro asíncrono para coordinar la recepción del código OAuth en el callback
authorization_future: asyncio.Future[AuthorizationCodeResult] | None = None
callback_server: uvicorn.Server | None = None


@app.get("/", response_model=RootResponse)
async def root() -> RootResponse:
    return RootResponse(message="MCP OAuth Callback Server")


@app.get("/callback", response_class=HTMLResponse)
async def callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    iss: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
) -> HTMLResponse:
    """
    Recibe la redirección del Servidor de Autorización tras el inicio de sesión
    y consentimiento del usuario.
    """
    # 1. Comprobar si el servidor devolvió un error de autorización
    if error is not None:
        if authorization_future is not None and not authorization_future.done():
            detail = f"{error}: {error_description}" if error_description else error
            authorization_future.set_exception(RuntimeError(f"OAuth error: {detail}"))

        return HTMLResponse(
            f"""
            <!DOCTYPE html>
            <html>
            <head><title>Error OAuth</title></head>
            <body style="font-family: sans-serif; padding: 2rem;">
                <h1 style="color: #d32f2f;">Error en la autorización</h1>
                <p>El servidor devolvió el error: <strong>{error}</strong></p>
                <p>Puedes cerrar esta ventana.</p>
            </body>
            </html>
            """,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 2. Comprobar que el código de autorización esté presente
    if code is None:
        return HTMLResponse(
            """
            <!DOCTYPE html>
            <html>
            <head><title>Error</title></head>
            <body style="font-family: sans-serif; padding: 2rem;">
                <h1 style="color: #d32f2f;">Código de autorización no recibido</h1>
            </body>
            </html>
            """,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 3. Entregar el código obtenido al OAuthClientProvider a través del futuro
    result = AuthorizationCodeResult(code=code, state=state, iss=iss)

    if authorization_future is not None and not authorization_future.done():
        authorization_future.set_result(result)

    return HTMLResponse(
        """
        <!DOCTYPE html>
        <html>
        <head><title>Autorización Exitosa</title></head>
        <body style="font-family: sans-serif; padding: 2rem; text-align: center;">
            <h1 style="color: #2e7d32;">¡Autorización completada con éxito!</h1>
            <p>El cliente MCP ha recibido las credenciales necesarias.</p>
            <p>Ya puedes cerrar esta ventana.</p>
        </body>
        </html>
        """
    )


# ---------------------------------------------------------------------------
#                       HANDLERS DEL CLIENTE OAUTH
# ---------------------------------------------------------------------------


async def redirect_handler(authorization_url: str) -> None:
    """Abre el navegador web predeterminado en la URL de autorización generada."""
    print("\n" + "=" * 60)
    print("OAuth 2.0 requiere autenticación.")
    print("Abriendo navegador en:")
    print(authorization_url)
    print("=" * 60 + "\n")
    webbrowser.open(authorization_url)


async def callback_handler() -> AuthorizationCodeResult:
    """Espera de forma asíncrona a que el usuario complete el flujo en el navegador."""
    global authorization_future

    loop = asyncio.get_running_loop()
    authorization_future = loop.create_future()

    print(f"Esperando callback OAuth en: {REDIRECT_URI}...")

    try:
        return await authorization_future
    finally:
        authorization_future = None


def create_oauth_provider() -> OAuthClientProvider:
    """Configura el proveedor de autenticación OAuth del SDK de MCP."""
    storage = InMemoryTokenStorage()

    client_metadata = OAuthClientMetadata(
        client_name="My MCP Client",
        redirect_uris=[AnyUrl(REDIRECT_URI)],
        scope=SCOPE,
        grant_types=["authorization_code"],
        application_type="native",
    )

    return OAuthClientProvider(
        server_url=MCP_ENDPOINT,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )


# ---------------------------------------------------------------------------
#                      EJECUCIÓN DEL CLIENTE MCP
# ---------------------------------------------------------------------------


async def start_callback_server() -> None:
    """Arranca el servidor Uvicorn local para escuchar en /callback."""
    global callback_server

    config = uvicorn.Config(
        app,
        host="localhost",
        port=CALLBACK_PORT,
        log_level="warning",
    )
    callback_server = uvicorn.Server(config)
    await callback_server.serve()


async def run_mcp() -> None:
    """
    Ejecuta el cliente MCP conectando al servidor mediante HTTP streamable y OAuth:
    1. Negocia la autenticación Bearer de forma transparente con OAuthClientProvider.
    2. Conecta mediante el transporte streamable_http_client.
    3. Inspecciona información del servidor y lista las herramientas disponibles.
    4. Ejecuta una llamada de prueba a la herramienta 'add'.
    """
    print("\nIniciando conexión con el servidor MCP...")

    oauth = create_oauth_provider()

    # NOTA: streamable_http_client requiere explícitamente una instancia de httpx2.AsyncClient
    async with httpx2.AsyncClient(
        auth=oauth,
        timeout=httpx2.Timeout(30.0, read=300.0),
    ) as http_client:
        print("Método de transporte streamable http client")
        transport = streamable_http_client(
            MCP_ENDPOINT,
            http_client=http_client,
        )

        async with Client(transport) as client:
            print("\n" + "=" * 50)
            print("Conectado con éxito al servidor MCP")
            print("=" * 50)
            print(f"Servidor: {client.server_info}")
            print(f"Versión de protocolo: {client.protocol_version}")

            # 1. Listar herramientas
            tools_result = await client.list_tools()
            print("\nHerramientas disponibles:")
            for tool in tools_result.tools:
                print(f" - {tool.name}: {tool.description}")

            # 2. Invocar herramienta 'add' si está disponible
            tool_names = [t.name for t in tools_result.tools]
            if "add" in tool_names:
                print("\nProbando ejecución de herramienta 'add' (a=10, b=20)...")
                call_result = await client.call_tool(
                    "add", arguments={"a": 10, "b": 20}
                )
                content_text = (
                    call_result.content[0].text
                    if call_result.content
                    else "Sin contenido"
                )
                print(f"Resultado de la suma: {content_text}")


# ---------------------------------------------------------------------------
#                              ENTRYPOINT
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=" * 50)
    print("      MCP CLIENT (PYTHON SDK)")
    print("=" * 50)

    # 1. Arrancar el servidor de callback en segundo plano
    callback_server_task = asyncio.create_task(start_callback_server())

    # Esperar brevemente a que el servidor callback esté listo
    await asyncio.sleep(0.5)

    try:
        # 2. Iniciar el cliente MCP y el flujo OAuth
        await run_mcp()
    finally:
        # 3. Limpiar el servidor de callback notificando un apagado limpio
        if callback_server is not None:
            callback_server.should_exit = True

        await callback_server_task


if __name__ == "__main__":
    asyncio.run(main())

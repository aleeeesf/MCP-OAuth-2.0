"""
Módulo de autenticación y autorización para el MCP Server (Resource Server).

Valida los tokens Bearer entrantes contra el Servidor de Autorización OAuth
mediante el endpoint de introspección (RFC 7662) y verifica los permisos (scopes)
y recursos asociados. Diseñado con fines educativos.
"""

from typing import Annotated

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# ---------------------------------------------------------------------------
#                           CONFIGURACIÓN
# ---------------------------------------------------------------------------

AUTH_SERVER = "http://localhost:8000"
MCP_RESOURCE = "http://localhost:9000/mcp/"
RESOURCE_SERVER_CLIENT_ID = "mcp-resource-server"
RESOURCE_SERVER_CLIENT_SECRET = "super-secret-development-value"

# Esquema de seguridad Bearer de FastAPI
bearer_security = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
#                               MODELOS
# ---------------------------------------------------------------------------


class TokenIntrospection(BaseModel):
    """Información del token devuelta por el endpoint de introspección de OAuth."""

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
    Solicita al servidor de autorización la información e introspección de un token.
    Utiliza autenticación HTTP Basic con las credenciales del Resource Server.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{AUTH_SERVER}/introspect",
                data={"token": token},
                auth=(
                    RESOURCE_SERVER_CLIENT_ID,
                    RESOURCE_SERVER_CLIENT_SECRET,
                ),
                timeout=5.0,
            )
            response.raise_for_status()
            data = response.json()
            return TokenIntrospection(**data)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Error al conectar con el servidor de autorización",
        ) from exc


# ---------------------------------------------------------------------------
#                      DEPENDENCIAS DE FASTAPI
# ---------------------------------------------------------------------------


async def get_current_token_info(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_security),
    ],
) -> TokenIntrospection:
    """
    Dependencia de FastAPI que extrae e inspecciona el Bearer token de la cabecera HTTP.
    Verifica que el token sea válido, esté activo y pertenezca a este recurso.
    """
    # 1. Comprobar que se ha proporcionado la cabecera Authorization con esquema Bearer
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not credentials.credentials
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Introspección del token en el Servidor de Autorización
    token_info = await introspect_token(credentials.credentials)

    # 3. Comprobar si el token está activo
    if not token_info.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Comprobar que el token fue emitido para este recurso MCP
    # Normalizamos eliminando posibles barras finales para comparación robusta
    token_resource = (token_info.resource or "").rstrip("/")
    expected_resource = MCP_RESOURCE.rstrip("/")
    if token_resource != expected_resource:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token was not issued for this resource",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_info


def require_scope(required_scope: str):
    """
    Generador de dependencias para validar que el token contenga el scope requerido.
    """

    async def _scope_checker(
        token_info: Annotated[TokenIntrospection, Depends(get_current_token_info)],
    ) -> TokenIntrospection:
        scopes = token_info.scope.split()
        if required_scope not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient scope: required '{required_scope}'",
            )
        return token_info

    return _scope_checker
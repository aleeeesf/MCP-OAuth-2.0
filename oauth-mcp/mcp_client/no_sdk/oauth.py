"""
Módulo de utilidades OAuth 2.0 y cliente MCP para el cliente sin SDK.

Proporciona funciones para el flujo de autorización con PKCE (RFC 7636),
descubrimiento de metadatos de recursos protegidos (RFC 9728) y servidores
de autorización (RFC 8414), intercambio de códigos por tokens y llamadas
autenticadas. Diseñado con fines educativos.
"""

import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status
from pydantic import BaseModel

# ---------------------------------------------------------------------------
#                               MODELOS
# ---------------------------------------------------------------------------


class ProtectedResourceMetadata(BaseModel):
    """Metadatos de recurso protegido según RFC 9728."""

    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str] = []
    bearer_methods_supported: list[str] = ["header"]


class AuthorizationServerMetadata(BaseModel):
    """Metadatos del servidor de autorización según RFC 8414."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: str | None = None
    response_types_supported: list[str] = []
    grant_types_supported: list[str] = []
    code_challenge_methods_supported: list[str] = []
    scopes_supported: list[str] = []


class TokenResponse(BaseModel):
    """Respuesta del endpoint de emisión de tokens según RFC 6749."""

    access_token: str
    token_type: str = "Bearer"
    scope: str = ""
    resource: str | None = None
    expires_in: int | None = None  # Tiempo de vida en segundos


# ---------------------------------------------------------------------------
#                            HELPERS PKCE
# ---------------------------------------------------------------------------


def generate_code_verifier() -> str:
    """Genera un code_verifier criptográficamente seguro para PKCE."""
    return secrets.token_urlsafe(32)


def generate_code_challenge(code_verifier: str) -> str:
    """
    Calcula el code_challenge utilizando SHA-256 (método S256)
    codificado en Base64 URL-safe sin relleno ('=').
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    resource: str,
) -> str:
    """Construye la URL de redirección hacia el endpoint /authorize con parámetros PKCE."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


# ---------------------------------------------------------------------------
#                   DESCUBRIMIENTO DE METADATOS
# ---------------------------------------------------------------------------


async def get_protected_resource_metadata(
    metadata_url: str,
) -> ProtectedResourceMetadata:
    """Obtiene los metadatos del recurso protegido MCP (RFC 9728)."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(metadata_url, timeout=5.0)
            response.raise_for_status()
            return ProtectedResourceMetadata(**response.json())
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"No se pudieron obtener los metadatos del recurso protegido: {exc}",
        ) from exc


async def get_authorization_server_metadata(
    authorization_server: str,
) -> AuthorizationServerMetadata:
    """Obtiene los metadatos del servidor de autorización OAuth (RFC 8414)."""
    url = f"{authorization_server.rstrip('/')}/.well-known/oauth-authorization-server"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            response.raise_for_status()
            return AuthorizationServerMetadata(**response.json())
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"No se pudieron obtener los metadatos del servidor de autorización: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
#                  INTERCAMBIO DE TOKEN Y LLAMADAS
# ---------------------------------------------------------------------------


async def exchange_code_for_token(
    token_endpoint: str,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str,
) -> TokenResponse:
    """Intercambia el código de autorización y el code_verifier por un Bearer token."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "resource": resource,
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_endpoint, data=data, timeout=5.0)
            response.raise_for_status()
            return TokenResponse(**response.json())
    except httpx.HTTPStatusError as exc:
        detail_msg = exc.response.text
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=f"Error al canjear el código por token: {detail_msg}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error de conexión con el endpoint de token: {exc}",
        ) from exc


async def call_protected_resource(
    resource_url: str,
    access_token: str,
) -> dict[str, Any]:
    """Realiza una petición GET autenticada con Bearer token a un recurso protegido."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                resource_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5.0,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=f"Error al llamar al recurso protegido: {exc.response.text}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error de conexión con el recurso protegido: {exc}",
        ) from exc


async def call_mcp(
    mcp_url: str,
    access_token: str,
    message: dict[str, Any],
) -> dict[str, Any]:
    """Envía un mensaje JSON-RPC al servidor MCP con cabecera Bearer token."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                mcp_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json=message,
                timeout=5.0,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=f"Error en llamada MCP: {exc.response.text}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error de conexión con el endpoint MCP: {exc}",
        ) from exc

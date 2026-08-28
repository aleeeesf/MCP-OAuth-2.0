import httpx

import base64
import hashlib
import secrets

from urllib.parse import urlencode


RESOURCE_URL = "http://localhost:9000/mcp"

def generate_code_verifier() -> str:
    return secrets.token_urlsafe(32)


def generate_code_challenge(
    code_verifier: str,
) -> str:

    digest = hashlib.sha256(
        code_verifier.encode("ascii")
    ).digest()

    return base64.urlsafe_b64encode(
        digest
    ).rstrip(b"=").decode("ascii")


async def get_protected_resource_metadata():
    url = (
        "http://localhost:9000"
        "/.well-known/oauth-protected-resource/mcp"
    )

    async with httpx.AsyncClient() as client:
        response = await client.get(url)

    response.raise_for_status()

    return response.json()


async def get_authorization_server_metadata(
    authorization_server: str,
):
    url = (
        authorization_server
        + "/.well-known/oauth-authorization-server"
    )

    async with httpx.AsyncClient() as client:
        response = await client.get(url)

    response.raise_for_status()

    return response.json()


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    resource: str,
) -> str:
    """
    Builds the url to log in the Auth Server

    Example:
        http://localhost:8000/authorize?
        response_type=code&
        client_id=my-mcp-client&
        redirect_uri=http%3A%2F%2Flocalhost%3A9100%2Fcallback&
        scope=profile&
        state=abc123&
        code_challenge=xyz456&
        code_challenge_method=S256&
        resource=http%3A%2F%2Flocalhost%3A9000%2Fmcp
    """

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

    return (
        authorization_endpoint
        + "?"
        + urlencode(params)
    )


async def exchange_code_for_token(
    token_endpoint: str,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str,
) -> dict:

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "resource": resource,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_endpoint,
            data=data,
        )

    response.raise_for_status()

    return response.json()


async def call_protected_resource(
    resource_url: str,
    access_token: str,
) -> dict:

    async with httpx.AsyncClient() as client:
        response = await client.get(
            resource_url,
            headers={
                "Authorization": (
                    f"Bearer {access_token}"
                )
            },
        )

    response.raise_for_status()

    return response.json()


async def call_mcp(
    mcp_url: str,
    access_token: str,
    message: dict,
) -> dict:

    async with httpx.AsyncClient() as client:
        response = await client.post(
            mcp_url,
            headers={
                "Authorization": (
                    f"Bearer {access_token}"
                ),
                "Content-Type": (
                    "application/json"
                ),
            },
            json=message,
        )

    response.raise_for_status()

    return response.json()
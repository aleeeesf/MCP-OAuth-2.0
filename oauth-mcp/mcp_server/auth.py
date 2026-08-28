import httpx

from fastapi import HTTPException


AUTH_SERVER = "http://localhost:8000"

MCP_RESOURCE = "http://localhost:9000/mcp"

RESOURCE_SERVER_CLIENT_ID = "mcp-resource-server"

RESOURCE_SERVER_CLIENT_SECRET = (
    "super-secret-development-value"
)


def extract_bearer_token(
    authorization: str | None,
) -> str:

    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Unsupported authentication scheme",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing bearer token",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return token


async def introspect_token(
    token: str,
) -> dict:

    async with httpx.AsyncClient() as client:

        response = await client.post(
            f"{AUTH_SERVER}/introspect",
            data={
                "token": token,
            },
            auth=(
                RESOURCE_SERVER_CLIENT_ID,
                RESOURCE_SERVER_CLIENT_SECRET,
            ),
        )

    response.raise_for_status()

    return response.json()


async def authenticate_request(
    authorization: str | None,
) -> dict:

    token = extract_bearer_token(
        authorization
    )

    token_info = await introspect_token(
        token
    )

    if not token_info.get("active"):
        raise HTTPException(
            status_code=401,
            detail="Invalid access token",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if token_info.get("resource") != MCP_RESOURCE:
        raise HTTPException(
            status_code=401,
            detail="Token was not issued for this resource",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return token_info


def require_scope(
    token_info: dict,
    required_scope: str,
) -> None:

    scopes = token_info.get(
        "scope",
        "",
    ).split()

    if required_scope not in scopes:
        raise HTTPException(
            status_code=403,
            detail="Insufficient scope",
        )
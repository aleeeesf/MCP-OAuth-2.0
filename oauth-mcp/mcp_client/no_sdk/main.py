import secrets

from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse

from .oauth import (
    get_protected_resource_metadata,
    get_authorization_server_metadata,
    generate_code_verifier,
    generate_code_challenge,
    build_authorization_url,
    exchange_code_for_token,
    call_protected_resource,
    call_mcp,
)


app = FastAPI(
    title="MCP Client"
)


CLIENT_ID = "my-mcp-client"

REDIRECT_URI = (
    "http://localhost:9100/callback"
)

RESOURCE_URL = (
    "http://localhost:9000/mcp/"
)

PROFILE_URL = (
    "http://localhost:9000/profile"
)

MCP_ENDPOINT = (
    "http://localhost:9000/mcp/"
)

oauth_sessions = {}
access_token = None

@app.get("/")
async def root():

    return {
        "message": "MCP Client"
    }

@app.get("/login")
async def login():

    resource_metadata = (
        await get_protected_resource_metadata()
    )

    authorization_server = (
        resource_metadata[
            "authorization_servers"
        ][0]
    )

    auth_metadata = (
        await get_authorization_server_metadata(
            authorization_server
        )
    )

    code_verifier = generate_code_verifier()

    code_challenge = (
        generate_code_challenge(
            code_verifier
        )
    )

    state = secrets.token_urlsafe(32)

    oauth_sessions[state] = {
        "code_verifier": code_verifier,
    }

    authorization_url = (
        build_authorization_url(
            authorization_endpoint=(
                auth_metadata[
                    "authorization_endpoint"
                ]
            ),
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            scope="profile",
            state=state,
            code_challenge=code_challenge,
            resource=RESOURCE_URL,
        )
    )

    return RedirectResponse(
        authorization_url
    )


@app.get("/callback")
async def callback(
    code: str = Query(...),
    state: str = Query(...),
):
    global access_token

    session = oauth_sessions.get(state)

    if session is None:
        return {
            "error": "Invalid state"
        }

    code_verifier = session[
        "code_verifier"
    ]

    resource_metadata = (
        await get_protected_resource_metadata()
    )

    authorization_server = (
        resource_metadata[
            "authorization_servers"
        ][0]
    )

    auth_metadata = (
        await get_authorization_server_metadata(
            authorization_server
        )
    )

    token = await exchange_code_for_token(
        token_endpoint=auth_metadata[
            "token_endpoint"
        ],
        code=code,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        code_verifier=code_verifier,
        resource=RESOURCE_URL,
    )

    access_token = token[
        "access_token"
    ]

    del oauth_sessions[state]

    print("*** Access token: "+token["access_token"])
    return {
        "message": "Authorization successful",
        "token_type": token["token_type"],
        "scope": token["scope"],
        "expires_at": token["expires_at"],
    }

@app.get("/call-profile")
async def call_profile():

    if access_token is None:
        return {
            "error": "Not authenticated"
        }

    return await call_protected_resource(
        resource_url=PROFILE_URL,
        access_token=access_token,
    )
@app.get("/mcp-test")
async def mcp_test():
    print(access_token)
    if access_token is None:
        return {
            "error": "Not authenticated"
        }

    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "my-mcp-client",
                "version": "1.0.0"
            }
        }
    }

    initialize_response = await call_mcp(
        MCP_ENDPOINT,
        access_token,
        initialize,
    )

    initialized = {
        "jsonrpc": "2.0",
        "method": (
            "notifications/initialized"
        ),
    }

    await call_mcp(
        MCP_ENDPOINT,
        access_token,
        initialized,
    )

    tools_list = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    }

    tools_response = await call_mcp(
        MCP_ENDPOINT,
        access_token,
        tools_list,
    )

    tools_call = {
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

    call_response = await call_mcp(
        MCP_ENDPOINT,
        access_token,
        tools_call,
    )

    return {
        "initialize": initialize_response,
        "tools": tools_response,
        "call": call_response,
    }

# async def main():

#     print("1. Protected Resource Metadata")

#     resource_metadata = (
#         await get_protected_resource_metadata()
#     )

#     print(resource_metadata)

#     authorization_servers = (
#         resource_metadata[
#             "authorization_servers"
#         ]
#     )

#     authorization_server = (
#         authorization_servers[0]
#     )

#     print()
#     print(
#         "Authorization Server:",
#         authorization_server,
#     )

#     print()
#     print("2. Authorization Server Metadata")

#     auth_metadata = (
#         await get_authorization_server_metadata(
#             authorization_server
#         )
#     )

#     print(auth_metadata)


# if __name__ == "__main__":
#     asyncio.run(main())
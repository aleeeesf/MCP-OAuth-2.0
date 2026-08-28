from fastapi import FastAPI, Header, Request

from .auth import (
    authenticate_request,
    require_scope,
)


app = FastAPI(
    title="MCP Server"
)


@app.get("/")
async def root():
    return {
        "message": "MCP Server"
    }

@app.get(
    "/.well-known/oauth-protected-resource/mcp"
)
async def protected_resource_metadata():
    return {
        "resource": "http://localhost:9000/mcp",
        "authorization_servers": [
            "http://localhost:8000"
        ],
        "scopes_supported": [
            "profile"
        ],
        "bearer_methods_supported": [
            "header"
        ],
    }

@app.post("/mcp")
async def mcp(
    request: Request,
):
    token_info = await authenticate_request(
        request.headers.get("Authorization")
    )

    body = await request.json()

    method = body.get("method")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "my-mcp-server",
                    "version": "1.0.0"
                }
            }
        }

    if method == "notifications/initialized":
        return {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "tools": [
                    {
                        "name": "add",
                        "description": (
                            "Suma dos números"
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "a": {
                                    "type": "number"
                                },
                                "b": {
                                    "type": "number"
                                }
                            },
                            "required": [
                                "a",
                                "b"
                            ]
                        }
                    }
                ]
            }
        }

    if method == "tools/call":

        params = body.get(
            "params",
            {}
        )

        tool_name = params.get("name")

        arguments = params.get(
            "arguments",
            {}
        )

        if tool_name != "add":
            return {
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {
                    "code": -32602,
                    "message": "Unknown tool"
                }
            }

        a = arguments.get("a")
        b = arguments.get("b")

        if not isinstance(a, (int, float)):
            return {
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {
                    "code": -32602,
                    "message": (
                        "Invalid argument: a"
                    )
                }
            }

        if not isinstance(b, (int, float)):
            return {
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {
                    "code": -32602,
                    "message": (
                        "Invalid argument: b"
                    )
                }
            }

        result = a + b

        return {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": str(result)
                    }
                ]
            }
        }

    return {
        "jsonrpc": "2.0",
        "id": body.get("id"),
        "error": {
            "code": -32601,
            "message": "Method not found"
        }
    }

@app.get("/profile")
async def profile(
    authorization: str | None = Header(
        default=None
    ),
):

    token_info = await authenticate_request(
        authorization
    )

    require_scope(
        token_info,
        "profile",
    )

    user_id = token_info["user_id"]

    return {
        "user_id": user_id,
        "message": "This is a protected resource",
    }
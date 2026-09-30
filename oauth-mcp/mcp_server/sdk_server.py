from mcp.server import MCPServer


mcp = MCPServer("My MCP Server")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Suma dos números."""
    return a + b
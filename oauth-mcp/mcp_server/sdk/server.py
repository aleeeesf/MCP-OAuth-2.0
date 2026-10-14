"""
Definición del servidor MCP utilizando el SDK oficial de Python (mcp).

Registra la instancia principal del servidor y las herramientas (tools)
disponibles para los clientes conectados. Diseñado con fines educativos.
"""

from mcp.server import MCPServer

# ---------------------------------------------------------------------------
#                         SERVIDOR MCP (SDK)
# ---------------------------------------------------------------------------

mcp = MCPServer("My MCP Server")


# ---------------------------------------------------------------------------
#                      REGISTRO DE HERRAMIENTAS
# ---------------------------------------------------------------------------


@mcp.tool()
def add(a: int, b: int) -> int:
    """Suma dos números enteros."""
    return a + b

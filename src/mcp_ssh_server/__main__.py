"""Allow ``python -m mcp_ssh_server`` to start the MCP server."""

from .ssh_server import mcp

if __name__ == "__main__":
    mcp.run()

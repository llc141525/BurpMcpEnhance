"""Caido MCP Server — wraps Caido v0.56.2 GraphQL API as stdio MCP tools.

Start: python TOOLS/caido_mcp.py
Required env: CAIDO_API_KEY — Bearer token from Caido UI (Settings → API Keys)
"""

import json
import os
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

CAIDO_URL = os.environ.get("CAIDO_URL", "http://127.0.0.1:8181/graphql")
API_KEY = os.environ.get("CAIDO_API_KEY", "")

app = Server("caido")


def _gql(query: str, variables: dict | None = None) -> dict:
    """Execute a GraphQL query against Caido."""
    if not API_KEY:
        raise RuntimeError("CAIDO_API_KEY env var is not set")
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = httpx.post(CAIDO_URL, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data.get("data", {})


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="caido_list_requests",
            description="List recent HTTP requests from Caido proxy history. Returns method, URL, status, size.",
            inputSchema={
                "type": "object",
                "properties": {
                    "count": {
                        "type": "integer",
                        "description": "Max requests to return (default 20, max 100)",
                        "default": 20,
                    },
                    "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                    "host_filter": {"type": "string", "description": "Filter by host substring (optional)"},
                },
                "required": [],
            },
        ),
        Tool(
            name="caido_get_request",
            description="Get full request and response details for a specific Caido request ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Caido request ID"},
                },
                "required": ["id"],
            },
        ),
        Tool(
            name="caido_get_sitemap",
            description="Get the Caido sitemap — discovered hosts and paths from proxy traffic.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="caido_search_requests",
            description="Search Caido proxy history by HTTPQL query string (Caido's query language).",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "HTTPQL query, e.g. 'req.host.cont:example.com'"},
                    "count": {"type": "integer", "description": "Max results (default 20)", "default": 20},
                },
                "required": ["query"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "caido_list_requests":
            count = min(int(arguments.get("count", 20)), 100)
            offset = int(arguments.get("offset", 0))
            host_filter = arguments.get("host_filter", "")

            query = """
            query ListRequests($count: Int!, $offset: Int!, $filter: String) {
              requests(first: $count, offset: $offset, filter: $filter) {
                edges {
                  node {
                    id
                    method
                    host
                    port
                    path
                    query
                    response {
                      statusCode
                      length
                    }
                  }
                }
              }
            }
            """
            variables: dict[str, Any] = {"count": count, "offset": offset}
            if host_filter:
                variables["filter"] = f'req.host.cont:"{host_filter}"'
            else:
                variables["filter"] = None

            data = _gql(query, variables)
            edges = data.get("requests", {}).get("edges", [])
            rows = []
            for e in edges:
                n = e["node"]
                resp = n.get("response") or {}
                scheme = "https" if n.get("port") == 443 else "http"
                url = f"{scheme}://{n['host']}:{n.get('port', 80)}{n.get('path', '')}"
                if n.get("query"):
                    url += "?" + n["query"]
                rows.append(
                    {
                        "id": n["id"],
                        "method": n.get("method", "GET"),
                        "url": url,
                        "status": resp.get("statusCode"),
                        "size": resp.get("length"),
                    }
                )
            return [TextContent(type="text", text=json.dumps(rows, ensure_ascii=False, indent=2))]

        elif name == "caido_get_request":
            req_id = arguments["id"]
            query = """
            query GetRequest($id: ID!) {
              request(id: $id) {
                id
                method
                host
                port
                path
                query
                headers { name value }
                body
                response {
                  statusCode
                  headers { name value }
                  body
                  length
                }
              }
            }
            """
            data = _gql(query, {"id": req_id})
            return [TextContent(type="text", text=json.dumps(data.get("request", {}), ensure_ascii=False, indent=2))]

        elif name == "caido_get_sitemap":
            query = """
            query Sitemap {
              sitemapRootEntries {
                host
                entries {
                  path
                  requestCount
                }
              }
            }
            """
            data = _gql(query)
            return [
                TextContent(
                    type="text", text=json.dumps(data.get("sitemapRootEntries", []), ensure_ascii=False, indent=2)
                )
            ]

        elif name == "caido_search_requests":
            httpql = arguments["query"]
            count = min(int(arguments.get("count", 20)), 100)
            query = """
            query SearchRequests($query: String!, $count: Int!) {
              requests(first: $count, filter: $query) {
                edges {
                  node {
                    id
                    method
                    host
                    path
                    query
                    response { statusCode length }
                  }
                }
              }
            }
            """
            data = _gql(query, {"query": httpql, "count": count})
            edges = data.get("requests", {}).get("edges", [])
            rows = [e["node"] for e in edges]
            return [TextContent(type="text", text=json.dumps(rows, ensure_ascii=False, indent=2))]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:  # noqa: BLE001
        return [TextContent(type="text", text=f"Error: {e}")]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

#!/bin/bash
sed -i 's/| `--mcp-api` | | Enable WebUI dashboard and REST API |/| `--mcp-api` | | Enable agent REST API for MCP server integration |/g' README.md
sed -i 's/| `--webui` | `127.0.0.1:9090` | WebUI listen address (ip:port) |/| `--webui` | `127.0.0.1:9090` | Enable WebUI dashboard and optionally set listen address |/g' README.md
sed -i 's/Enabled with `--mcp-api` on the server/Enabled with `--webui` on the server/g' README.md

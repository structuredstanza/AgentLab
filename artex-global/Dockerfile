# syntax=docker/dockerfile:1
#
# Run-only image (do not compile inside the image): install only the commercial tools and place a **pre-compiled Linux single binary**.
# The binary is cross-compiled by the binaries job in CI (pure Go, no QEMU), and placed for each target architecture
# at dist/<TARGETARCH>/artex in the build context. This way, in a multi-architecture build, arm64 only needs emulation for the apt layer, and Next/Go compilation is no longer emulated, which is much faster.
# Emulating works, and Next/Go compilation no longer emulates, so it is much faster.
#
# When manually building the image locally, first prepare the binaries directly:
#   cd web && npm run build:static && cd ..
#   mkdir -p server/webui && cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Commercial tools: a bundle of commonly used recon tools in addition to ripgrep / curl / vim (add or remove as needed).
# Install Node 20.x from NodeSource: the default apt nodejs on bookworm is 18, and Playwright requires >=20.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Pre-install the Playwright MCP and CLI globally (so that npx does not download anything over the network at runtime).
# @playwright/mcp: the browser MCP runs directly with `npx @playwright/mcp` (globally installed, -y/@latest not needed).
# @playwright/cli: provides playwright-cli; after installation, check whether it can run via --help.
# Next, install playwright (provides browser management), and use --with-deps to pre-install chromium and its system dependencies.
# This way, the MCP/CLI inside the container can be used immediately on first startup, and the browser is not downloaded over the network.
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Pre-compiled binary for the matching architecture (dist/amd64/artex or dist/arm64/artex)
COPY dist/${TARGETARCH}/artex /app/artex
# Supervisor startup script: after the process exits, decides whether to restart it based on the exit code; the one-click update in the UI uses this script to complete the binary replacement.
# This script is also responsible for forwarding SIGTERM to artex: docker stop sends the signal only to PID 1,
# otherwise artex never receives it, cannot shut down gracefully, and is force-killed with SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# Persistence point for data/ (SQLite + jwt.key)
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]

# syntax=docker/dockerfile:1
#
# AgentLab guest image for microsandbox. Runtime only: nothing is compiled here.
# Build context is /mnt/Research/AgentLab (see Dockerfile.dockerignore). Requires the upstream binary first:
#   artex-global/dist/<TARGETARCH>/artex   (built with artex-global/build.sh)
#   docker build -f deployment/Dockerfile -t agentlab/artex:local /mnt/Research/AgentLab
#
# Tools mirror upstream artex-global/Dockerfile (python/curl/git/jq/ripgrep/nmap/dns/netcat/whois, Node + Playwright + Chromium),
# plus PostgreSQL server/client (Debian default, 15 on bookworm), tcpdump, strace and procps.
FROM node:22-bookworm-slim
ARG TARGETARCH
ARG PLAYWRIGHT_VERSION=1.64.1
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget unzip git jq ripgrep \
      python3 \
      postgresql postgresql-client \
      nmap dnsutils iputils-ping netcat-openbsd whois \
      tcpdump strace procps util-linux \
 && rm -rf /var/lib/apt/lists/*

# The postgresql package creates and starts a default cluster; guest-start.py owns /state/postgres instead.
RUN set -eu; for d in /etc/postgresql/*/main; do [ -d "$d" ] || continue; pg_dropcluster --stop "$(basename "$(dirname "$d")")" main; done

# Pin matching browser tooling so rebuilds retain the verified runtime.
RUN npm install -g "playwright@${PLAYWRIGHT_VERSION}" @playwright/mcp@0.0.83 @playwright/cli@0.1.22 \
 && playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* /root/.npm

COPY artex-global/dist/${TARGETARCH}/artex /opt/artex/artex
COPY artex-global/skills/ /opt/artex/skills/
COPY deployment/guest-start.py deployment/guest-export.py /opt/agentlab/
RUN chmod 0755 /opt/artex/artex /opt/agentlab/guest-start.py \
 && mkdir -p /state /run/secrets

EXPOSE 8787
# msb exec runs /opt/agentlab/guest-start.py explicitly; the image does not start the supervisor on create.
ENTRYPOINT ["/usr/bin/python3", "/opt/agentlab/guest-start.py"]

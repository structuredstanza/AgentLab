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
      python3 python-is-python3 python3-venv python3-pip \
      postgresql postgresql-client \
      nmap dnsutils iputils-ping netcat-openbsd whois \
      tcpdump strace procps util-linux \
 && rm -rf /var/lib/apt/lists/*

# The postgresql package creates and starts a default cluster; guest-start.py owns /state/postgres instead.
RUN set -eu; for d in /etc/postgresql/*/main; do [ -d "$d" ] || continue; pg_dropcluster --stop "$(basename "$(dirname "$d")")" main; done

# Web-recon toolbox (pinned release binaries in /usr/local/bin):
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG SUBFINDER_VERSION=v2.17.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0
ARG DALFOX_VERSION=v3.2.4
RUN set -eux; \
    base="https://github.com"; \
    pd_fetch() { repo="$1"; ver="$2"; name="$3"; nov="${ver#v}"; \
      curl -fsSL "$base/$repo/releases/download/$ver/${name}_${nov}_linux_${TARGETARCH}.zip" -o /tmp/t.zip \
      && unzip -o -q /tmp/t.zip -d /tmp/td \
      && find /tmp/td -type f -name "$name" -exec install -m 0755 {} /usr/local/bin/ \; \
      && rm -rf /tmp/t.zip /tmp/td; }; \
    case "$TARGETARCH" in amd64) FFUF_ARCH=amd64; DALFOX_ARCH=x86_64;; arm64) FFUF_ARCH=arm64; DALFOX_ARCH=aarch64;; esac; \
    pd_fetch projectdiscovery/nuclei "$NUCLEI_VERSION" nuclei; \
    pd_fetch projectdiscovery/httpx "$HTTPX_VERSION" httpx; \
    pd_fetch projectdiscovery/subfinder "$SUBFINDER_VERSION" subfinder; \
    pd_fetch projectdiscovery/katana "$KATANA_VERSION" katana; \
    tar_fetch() { url="$1"; name="$2"; \
      curl -fsSL "$url" -o /tmp/t.tgz \
      && mkdir -p /tmp/td && tar -xzf /tmp/t.tgz -C /tmp/td \
      && find /tmp/td -type f -name "$name" -exec install -m 0755 {} /usr/local/bin/ \; \
      && rm -rf /tmp/t.tgz /tmp/td; }; \
    tar_fetch "$base/ffuf/ffuf/releases/download/$FFUF_VERSION/ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz" ffuf; \
    tar_fetch "$base/hahwul/dalfox/releases/download/$DALFOX_VERSION/dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" dalfox; \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap; \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    nuclei -version >/dev/null; httpx -version; subfinder -version; katana -version; \
    ffuf -V >/dev/null; dalfox --version >/dev/null 2>&1 || true; sqlmap --version >/dev/null

# bbot recursive recon orchestrator: isolated venv with preinstalled dependencies
ARG BBOT_VERSION=3.0.2
RUN set -eux; \
    python3 -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    bbot -y --install-all-deps; \
    bbot --version >/dev/null; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness >/dev/null 2>&1 || true; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "Installing|ERRR|CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }

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

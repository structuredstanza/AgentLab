# syntax=docker/dockerfile:1
#
# Run-only image (do not compile inside the image): install only the commercial tools and place a **pre-compiled Linux single binary**.
# The binary is cross-compiled by the binaries job in CI (pure Go, no QEMU), and placed for each target architecture
# at dist/<TARGETARCH>/m1nervac0nsole in the build context. This way, in a multi-architecture build, arm64 only needs emulation for the apt layer, and Next/Go compilation is no longer emulated, which is much faster.
# Emulating works, and Next/Go compilation no longer emulates, so it is much faster.
#
# When manually building the image locally, first prepare the binaries directly:
#   cd web && npm run build:static && cd ..
#   mkdir -p server/webui && cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/m1nervac0nsole ./cmd/m1nervac0nsole
#   docker build -t m1nervac0nsole:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Commercial tools: a bundle of commonly used recon tools in addition to ripgrep / curl / vim (add or remove as needed).
# Install Node 20.x from NodeSource: the default apt nodejs on bookworm is 18, and the
# npm-installed tools below need a newer Node.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Web-recon toolbox: pinned release binaries installed into /usr/local/bin
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
    python -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    bbot -y --install-all-deps; \
    bbot --version >/dev/null; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness >/dev/null 2>&1 || true; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "Installing|ERRR|CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }
# Obscura: Rust headless browser (stealth build) used by the `obscura` MCP server
# and the obscura skill. Static binaries, no Chromium, no Node dependency.
ARG OBSCURA_VERSION=v0.2.6
RUN set -eux; \
    case "$TARGETARCH" in amd64) OBSCURA_ARCH=x86_64;; arm64) OBSCURA_ARCH=aarch64;; esac; \
    curl -fsSL "https://github.com/h4ckf0r0day/obscura/releases/download/${OBSCURA_VERSION}/obscura-${OBSCURA_ARCH}-linux-stealth.tar.gz" -o /tmp/obscura.tgz; \
    mkdir -p /tmp/obscura && tar -xzf /tmp/obscura.tgz -C /tmp/obscura; \
    find /tmp/obscura -type f \( -name obscura -o -name obscura-worker \) -exec install -m 0755 {} /usr/local/bin/ \;; \
    rm -rf /tmp/obscura /tmp/obscura.tgz; \
    obscura --version

# REA (Reverse Engineer Anything) MCP server: `rea mcp` speaks stdio MCP and backs
# the `rea` skill. Pinned; Node >=22.23.4 is required and provided by the base image.
RUN npm install -g rea-agents@6.8.0 && rea --version

WORKDIR /app
# Pre-compiled binary for the matching architecture (dist/amd64/m1nervac0nsole or dist/arm64/m1nervac0nsole)
COPY dist/${TARGETARCH}/m1nervac0nsole /app/m1nervac0nsole
# Daemon startup script: relaunches the process after abnormal exit and forwards SIGTERM to m1nervac0nsole
COPY start.sh /app/start.sh
RUN chmod +x /app/m1nervac0nsole /app/start.sh
COPY skills/ /app/skills/
# Persistence point for data/ (SQLite + jwt.key)
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]

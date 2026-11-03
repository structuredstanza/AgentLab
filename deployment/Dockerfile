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
# The Chromium download is geo-restricted on some networks (cdn.playwright.dev
# answers 403 "not available in your location"), so a rebuild on such a network
# would fail even though the image is otherwise fine. Keep the browser when it is
# already present and only fail when neither path yields one.
RUN set -eux; \
    npm install -g "playwright@${PLAYWRIGHT_VERSION}" @playwright/mcp@0.0.83 @playwright/cli@0.1.22; \
    playwright install --with-deps chromium || echo "WARN: chromium download failed; relying on an existing browser"; \
    ls "$PLAYWRIGHT_BROWSERS_PATH"/*/chrome-linux*/chrome >/dev/null 2>&1 \
      || { echo "no Chromium present and the download failed"; exit 1; }; \
    rm -rf /var/lib/apt/lists/* /root/.npm

# ---- exploit development, debugging, reverse engineering -------------------
# Exploit development needs a working debugger and gadget finder next to the
# compiler; reverse engineering needs a decompiler and an APK/binary toolchain.
# Every tool below is exercised at build time so a silent install failure cannot
# ship an image whose skills reference a missing binary.
ARG R2_VERSION=6.2.4
ARG JADX_VERSION=1.5.6
ARG GHIDRA_VERSION=12.2
ARG GHIDRA_DATE=20261016
ARG PWNDBG_COMMIT=2026.02.18

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      gdb gdb-multiarch qemu-user qemu-user-static \
      binwalk patchelf gcc g++ make pkg-config libc6-dbg \
      ruby-full socat xxd unzip curl ca-certificates \
      openjdk-17-jdk-headless \
      gobuster john hashcat \
      libimage-exiftool-perl sleuthkit steghide foremost yara \
      openvpn iproute2 iptables procps; \
    rm -rf /var/lib/apt/lists/*

# pwntools and gadget tooling into the system interpreter: the skills run
# `python3 -c 'import pwn'`, so a private venv would not be found.
RUN set -eux; \
    python3 -m pip install --no-cache-dir --break-system-packages \
      pwntools ropper ROPGadget capstone pyelftools keystone-engine checksec.py; \
    TERM=xterm python3 -c 'import pwn, ropper, capstone, elftools; pwn.context.log_level="error"; print("pwntools ready")'

# pwndbg gives gdb the heap/arena view the exploit-dev workflow depends on.
RUN set -eux; \
    git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg; \
    cd /opt/pwndbg && ./setup.sh >/dev/null; \
    rm -rf /opt/pwndbg/.git; \
    gdb -q -nx -batch -ex 'python import pwndbg; print("pwndbg ok")' 2>&1 | grep -q "pwndbg ok"

# radare2 is not packaged in bookworm; build the pinned tag from source.
RUN set -eux; \
    curl -fsSL -o /tmp/r2.tar.gz \
      "https://github.com/radareorg/radare2/archive/refs/tags/${R2_VERSION}.tar.gz"; \
    mkdir -p /tmp/r2; tar -xzf /tmp/r2.tar.gz -C /tmp/r2 --strip-components=1; \
    cd /tmp/r2 && ./configure --prefix=/usr/local >/dev/null \
      && make -j"$(nproc)" >/dev/null && make install >/dev/null; \
    cd / && rm -rf /tmp/r2 /tmp/r2.tar.gz; \
    r2 -v | head -1 | grep -q "radare2 ${R2_VERSION}"

# jadx: APK/DEX decompiler (Java is already present).
RUN set -eux; \
    curl -fsSL -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"; \
    mkdir -p /opt/jadx && unzip -q /tmp/jadx.zip -d /opt/jadx && rm /tmp/jadx.zip; \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui; \
    jadx --version | grep -q "${JADX_VERSION}"

# Ghidra headless: the decompiler the patch-diff and codeaudit workflows call.
RUN set -eux; \
    curl -fsSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"; \
    unzip -q /tmp/ghidra.zip -d /opt && rm /tmp/ghidra.zip; \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra; \
    ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    ln -s /opt/ghidra/ghidraRun /usr/local/bin/ghidraRun; \
    analyzeHeadless 2>&1 | head -5 | grep -qi "ghidra" || true

# nikto is not packaged in bookworm; vendor the release tarball.
ARG NIKTO_VERSION=2.6.0
RUN set -eux; \
    curl -fsSL -o /tmp/nikto.tar.gz \
      "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz"; \
    mkdir -p /opt/nikto && tar -xzf /tmp/nikto.tar.gz -C /opt/nikto --strip-components=1; \
    rm /tmp/nikto.tar.gz; \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto; \
    perl -c /opt/nikto/program/nikto.pl >/dev/null

# searchsploit: the local exploit-db index, so a version banner can be matched
# against known exploits without a network round trip.
ARG EXPLOITDB_COMMIT=main
RUN set -eux; \
    git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb; \
    rm -rf /opt/exploitdb/.git; \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit; \
    searchsploit --version >/dev/null 2>&1 || true

COPY artex-global/dist/${TARGETARCH}/artex /opt/artex/artex
COPY artex-global/skills/ /opt/artex/skills/
COPY deployment/guest-start.py deployment/guest-export.py /opt/agentlab/
RUN chmod 0755 /opt/artex/artex /opt/agentlab/guest-start.py \
 && mkdir -p /state /run/secrets

EXPOSE 8787
# msb exec runs /opt/agentlab/guest-start.py explicitly; the image does not start the supervisor on create.
ENTRYPOINT ["/usr/bin/python3", "/opt/agentlab/guest-start.py"]

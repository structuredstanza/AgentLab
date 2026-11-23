# syntax=docker/dockerfile:1
#
# AgentLab guest image for microsandbox. Runtime only: nothing is compiled here.
# Build context is /mnt/Research/AgentLab (see .dockerignore). Requires the upstream binary first:
#   m1nervac0nsole/dist/<TARGETARCH>/m1nervac0nsole   (built with m1nervac0nsole/build.sh)
# `./lab image-build` runs that build, then this Dockerfile, tagging <configured>-candidate.
#
# Tools mirror upstream m1nervac0nsole/Dockerfile (python/curl/git/jq/ripgrep/nmap/dns/netcat/whois, Node + Playwright + Chromium),
# plus PostgreSQL server/client (Debian default, 15 on bookworm), tcpdump, strace, procps,
# the ssh client, bc, and a certipy CLI shim for NetExec's console-script-less fork.
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
    nuclei -update-templates >/dev/null 2>&1 && test "$(find /root/nuclei-templates -name '*.yaml' | wc -l)" -gt 1000; \
    ffuf -V >/dev/null; dalfox --version >/dev/null 2>&1 || true; sqlmap --version >/dev/null

# Manifest toolbox: every `requires` in m1nervac0nsole/manifest/builtin must
# resolve here, or the agent's tool call fails at runtime. Bookworm packages
# what it can; the rest are pinned release binaries, git tags or interpreter
# packages. Each binary is exercised below so a silent install failure cannot
# ship an image whose manifests reference a missing tool.
ARG NAABU_VERSION=v2.7.0
ARG DNSX_VERSION=v1.3.1
ARG GAU_VERSION=v2.2.4
ARG AMASS_VERSION=v5.1.3
ARG GOWITNESS_VERSION=3.2.2
ARG FEROXBOOSTER_VERSION=v2.13.1
ARG RUSTSCAN_VERSION=2.4.1
ARG NIKTO_VERSION=2.6.1
ARG ENUM4LINUX_NG_VERSION=v1.3.10
# NetExec's v1.5.1 tag pulls certipy-ad, whose current releases require Python
# >=3.12; bookworm ships 3.11. Pin the commit verified against this image.
ARG NETEXEC_COMMIT=97b31bf1d017e12476a1082c30203d4c5febe85c
ARG IMPACKET_TAG=impacket_0_13_1
# The tag's commit, asserted at fetch time so a re-tag cannot silently move the
# pin. Install with .git still present so setuptools_scm describes the tag;
# stripping it first made the package report 0.14.0.dev0+<date>.<hash>.
ARG IMPACKET_COMMIT=c456746d7a0f0bb25e8968a59f25aae1ad519935
ARG WAFW00F_VERSION=2.4.2
ARG WPSCAN_VERSION=3.8.28
ARG SECLISTS_VERSION=2026.2
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      masscan hydra whatweb sslscan mtr-tiny traceroute nbtscan \
      smbclient ldap-utils testssl.sh libxml-writer-perl \
      ruby ruby-dev libxml2-dev libxslt1-dev zlib1g-dev python3-dev libffi-dev gcc make pkg-config; \
    rm -rf /var/lib/apt/lists/*; \
    ln -sf /usr/bin/testssl /usr/local/bin/testssl.sh; \
    gh="https://github.com"; \
    case "$TARGETARCH" in amd64) ARCH=amd64; RARCH=x86_64;; arm64) ARCH=arm64; RARCH=aarch64;; esac; \
    zip_install() { \
      curl -fsSL "$1" -o /tmp/t.zip \
      && unzip -o -q /tmp/t.zip -d /tmp/td \
      && find /tmp/td -type f -name "$2" -exec install -m 0755 {} /usr/local/bin/ \; \
      && rm -rf /tmp/t.zip /tmp/td; }; \
    tgz_install() { \
      curl -fsSL "$1" -o /tmp/t.tgz \
      && mkdir -p /tmp/td && tar -xzf /tmp/t.tgz -C /tmp/td \
      && find /tmp/td -type f -name "$2" -exec install -m 0755 {} /usr/local/bin/ \; \
      && rm -rf /tmp/t.tgz /tmp/td; }; \
    zip_install "$gh/projectdiscovery/naabu/releases/download/$NAABU_VERSION/naabu_${NAABU_VERSION#v}_linux_${ARCH}.zip" naabu; \
    zip_install "$gh/projectdiscovery/dnsx/releases/download/$DNSX_VERSION/dnsx_${DNSX_VERSION#v}_linux_${ARCH}.zip" dnsx; \
    tgz_install "$gh/lc/gau/releases/download/$GAU_VERSION/gau_${GAU_VERSION#v}_linux_${ARCH}.tar.gz" gau; \
    tgz_install "$gh/owasp-amass/amass/releases/download/$AMASS_VERSION/amass_linux_${ARCH}.tar.gz" amass; \
    curl -fsSL "$gh/sensepost/gowitness/releases/download/$GOWITNESS_VERSION/gowitness-${GOWITNESS_VERSION}-linux-${ARCH}" -o /usr/local/bin/gowitness; \
    chmod 0755 /usr/local/bin/gowitness; \
    tgz_install "$gh/epi052/feroxbuster/releases/download/$FEROXBOOSTER_VERSION/${RARCH}-linux-feroxbuster.tar.gz" feroxbuster; \
    if [ "$ARCH" = amd64 ]; then RS=x86_64-linux-rustscan.tar.gz.zip; else RS=aarch64-linux-rustscan.zip; fi; \
    curl -fsSL "$gh/RustScan/RustScan/releases/download/$RUSTSCAN_VERSION/$RS" -o /tmp/r.zip; \
    mkdir -p /tmp/r && unzip -o -q /tmp/r.zip -d /tmp/r; \
    find /tmp/r -name '*.tar.gz' -exec tar -xzf {} -C /tmp/r \; ; \
    find /tmp/r -type f -name rustscan -exec install -m 0755 {} /usr/local/bin/ \; ; \
    rm -rf /tmp/r /tmp/r.zip; \
    git clone --depth 1 --branch "$NIKTO_VERSION" https://github.com/sullo/nikto /opt/nikto; \
    rm -rf /opt/nikto/.git; \
    chmod 0755 /opt/nikto/program/nikto.pl; \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto; \
    git clone --depth 1 https://github.com/CiscoCXSecurity/enum4linux /opt/enum4linux; \
    rm -rf /opt/enum4linux/.git; \
    install -m 0755 /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux; \
    git init -q /opt/impacket; \
    cd /opt/impacket; \
    git remote add origin https://github.com/fortra/impacket; \
    git fetch -q --depth 1 origin "refs/tags/${IMPACKET_TAG}:refs/tags/${IMPACKET_TAG}"; \
    [ "$(git rev-parse "${IMPACKET_TAG}^{commit}")" = "$IMPACKET_COMMIT" ] \
      || { echo "impacket tag moved off the pinned commit"; exit 1; }; \
    git checkout -q --detach "$IMPACKET_COMMIT"; \
    python3 -m pip install --no-cache-dir --break-system-packages /opt/impacket; \
    rm -rf /opt/impacket/.git; \
    for f in /opt/impacket/examples/*.py; do \
      b=$(basename "$f" .py); \
      [ "$b" = __init__ ] && continue; \
      printf '#!/bin/sh\nexec python3 %s "$@"\n' "$f" > "/usr/local/bin/impacket-$b"; \
      chmod 0755 "/usr/local/bin/impacket-$b"; \
    done; \
    python3 -m pip install --no-cache-dir --break-system-packages \
      "git+https://github.com/Pennyw0rth/NetExec@${NETEXEC_COMMIT}" \
      "git+https://github.com/cddmp/enum4linux-ng@${ENUM4LINUX_NG_VERSION}" \
      "wafw00f==${WAFW00F_VERSION}"; \
    gem install --no-document nokogiri -- --use-system-libraries; \
    gem install --no-document wpscan -v "$WPSCAN_VERSION"; \
    git clone --depth 1 --branch "$SECLISTS_VERSION" https://github.com/danielmiessler/SecLists /usr/share/seclists; \
    rm -rf /usr/share/seclists/.git; \
    for t in masscan hydra whatweb sslscan mtr traceroute nbtscan smbclient ldapsearch \
             testssl.sh nikto enum4linux enum4linux-ng nxc impacket-secretsdump wpscan \
             wafw00f naabu dnsx gau amass feroxbuster rustscan gowitness; do \
      command -v "$t" >/dev/null || { echo "missing $t"; exit 1; }; \
    done; \
    masscan --version 2>&1 | grep -qi masscan; \
    whatweb --version 2>&1 | grep -qi whatweb; \
    nikto -Version 2>&1 | grep -qi nikto; \
    enum4linux-ng -h 2>&1 | grep -qi enum4linux; \
    impacket-secretsdump -h 2>&1 | grep -qi impacket; \
    wpscan --version 2>&1 | grep -q "$WPSCAN_VERSION"; \
    feroxbuster --version 2>&1 | grep -qi feroxbuster; \
    rustscan --version 2>&1 | grep -qi rustscan; \
    gau --version 2>&1 | grep -qi gau; \
    test -f /usr/share/seclists/Discovery/Web-Content/common.txt

# PEASS-ng: the privesc skill's enumeration suite. The Linux and macOS scripts and
# static binaries run inside the guest; the Windows executables are staged for
# transfer to a target, so they stay non-executable here.
ARG PEASS_VERSION=20261109-f4fdadd7
RUN set -eux; \
    mkdir -p /opt/peass; \
    for a in linpeas.sh linpeas_fat.sh linpeas_small.sh \
             linpeas_linux_amd64 linpeas_linux_arm64 linpeas_linux_arm linpeas_linux_386 \
             linpeas_darwin_amd64 linpeas_darwin_arm64 \
             winPEAS.bat winPEASany.exe winPEASany_ofs.exe winPEASx64.exe winPEASx64_ofs.exe \
             winPEASx86.exe winPEASx86_ofs.exe; do \
      curl -fsSL -o "/opt/peass/$a" \
        "https://github.com/peass-ng/PEASS-ng/releases/download/${PEASS_VERSION}/$a"; \
    done; \
    chmod 0755 /opt/peass/linpeas*.sh /opt/peass/linpeas_linux_* /opt/peass/linpeas_darwin_*; \
    chmod 0644 /opt/peass/winPEAS*; \
    ln -sf /opt/peass/linpeas.sh /usr/local/bin/linpeas; \
    ln -sf /opt/peass/linpeas_fat.sh /usr/local/bin/linpeas_fat; \
    ln -sf /opt/peass/linpeas_small.sh /usr/local/bin/linpeas_small; \
    linpeas -h 2>&1 | grep -qi "privilege escalation"

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
# Obscura: Rust headless browser (stealth build) for the obscura MCP server and skill.
ARG OBSCURA_VERSION=v0.2.6
RUN set -eux; \
    case "$TARGETARCH" in amd64) OBSCURA_ARCH=x86_64;; arm64) OBSCURA_ARCH=aarch64;; esac; \
    curl -fsSL "https://github.com/h4ckf0r0day/obscura/releases/download/${OBSCURA_VERSION}/obscura-${OBSCURA_ARCH}-linux-stealth.tar.gz" -o /tmp/obscura.tgz; \
    mkdir -p /tmp/obscura && tar -xzf /tmp/obscura.tgz -C /tmp/obscura; \
    find /tmp/obscura -type f \( -name obscura -o -name obscura-worker \) -exec install -m 0755 {} /usr/local/bin/ \;; \
    rm -rf /tmp/obscura /tmp/obscura.tgz; \
    obscura --version

# The Chromium download is geo-restricted on some networks (cdn.playwright.dev
# answers 403 "not available in your location"), so a rebuild on such a network
# would fail even though the image is otherwise fine. Keep the browser when it is
# already present and only fail when neither path yields one.
RUN set -eux; \
    npm install -g "playwright@${PLAYWRIGHT_VERSION}"; \
    playwright install --with-deps chromium || echo "WARN: chromium download failed; relying on an existing browser"; \
    ls "$PLAYWRIGHT_BROWSERS_PATH"/*/chrome-linux*/chrome >/dev/null 2>&1 \
      || { echo "no Chromium present and the download failed"; exit 1; }; \
    ln -sfn "$(ls -d "$PLAYWRIGHT_BROWSERS_PATH"/chromium-*/chrome-linux64 | sort -V | tail -1)" \
      "$PLAYWRIGHT_BROWSERS_PATH/current"; \
    rm -rf /var/lib/apt/lists/* /root/.npm

# The native browser driver launches $PLAYWRIGHT_BROWSERS_PATH/current/chrome
# (server/browser_registry.go): a stable link to whatever revision the install
# produced, so a Playwright upgrade does not strand the driver on a path that
# no longer exists. The Playwright MCP/CLI launchers are not installed; the
# driver talks CDP to this Chromium directly.

# REA reverse-engineering MCP (backs the `rea` skill). Pinned to the release
# verified against this image; Node >=22.23.4 is required.
RUN npm install -g rea-agents@6.8.0 && rea --version

# ---- exploit development, debugging, reverse engineering -------------------
# Exploit development needs a working debugger and gadget finder next to the
# compiler; reverse engineering needs a decompiler and an APK/binary toolchain.
# Every tool below is exercised at build time so a silent install failure cannot
# ship an image whose skills reference a missing binary.
ARG R2_VERSION=6.2.4
ARG JADX_VERSION=1.5.6
ARG GHIDRA_VERSION=12.2
ARG GHIDRA_DATE=20261016
ARG JDK_VERSION=25
# Ghidra 12.2 declares application.java.min=25, which bookworm does not package;
# jadx and the rest are happy with 25, so it becomes the image default.
ENV JAVA_HOME=/opt/jdk
# Ghidra resolves java from PATH before JAVA_HOME, and the distro's 17 is
# first there, so 21 must lead or every headless run aborts.
ENV PATH=/opt/jdk/bin:$PATH
ARG PWNDBG_COMMIT=2026.02.18

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      gdb gdb-multiarch qemu-user qemu-user-static \
      binwalk patchelf gcc g++ make pkg-config libc6-dbg patch \
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
      pwntools ropper ROPGadget pyelftools keystone-engine checksec.py 'capstone<6'; \
    TERM=xterm python3 -c 'import pwn, ropper, capstone, elftools; pwn.context.log_level="error"; print("pwntools ready")'; \
    # binwalk imports capstone's legacy API, which the 6.x alpha removed.
    binwalk --help >/dev/null

# pwndbg gives gdb the heap/arena view the exploit-dev workflow depends on.
# The declared pin is fetched by name (tag, branch or commit the server serves),
# so the branch tip is never what gets installed.
RUN set -eux; \
    git init -q /opt/pwndbg; \
    cd /opt/pwndbg; \
    git remote add origin https://github.com/pwndbg/pwndbg; \
    git fetch -q --depth 1 origin "$PWNDBG_COMMIT"; \
    git checkout -q --detach FETCH_HEAD; \
    ./setup.sh >/dev/null; \
    rm -rf /opt/pwndbg/.git; \
    TERM=xterm gdb -q -batch -ex 'python import pwndbg; print("pwndbg ok")' 2>&1 | grep -q "pwndbg ok"

# radare2 is not packaged in bookworm; build the pinned tag from source.
# ldconfig afterwards: the shared objects land in /usr/local/lib, which is
# not on the default loader path until the cache records it.
RUN set -eux; \
    curl -fsSL -o /tmp/r2.tar.gz \
      "https://github.com/radareorg/radare2/archive/refs/tags/${R2_VERSION}.tar.gz"; \
    mkdir -p /tmp/r2; tar -xzf /tmp/r2.tar.gz -C /tmp/r2 --strip-components=1; \
    cd /tmp/r2 && ./configure --prefix=/usr/local >/dev/null \
      && make -j"$(nproc)" >/dev/null && make install >/dev/null; \
    cd / && rm -rf /tmp/r2 /tmp/r2.tar.gz; \
    ldconfig; \
    r2 -v | head -1 | grep -q "radare2 ${R2_VERSION}"

# Temurin JDK 25 for Ghidra; the distro only ships 17.
RUN set -eux; \
    curl -fsSL -o /tmp/jdk.tar.gz \
      "https://api.adoptium.net/v3/binary/latest/${JDK_VERSION}/ga/linux/x64/jdk/hotspot/normal/eclipse"; \
    mkdir -p /opt/jdk; tar -xzf /tmp/jdk.tar.gz -C /opt/jdk --strip-components=1; \
    rm /tmp/jdk.tar.gz; \
    /opt/jdk/bin/java -version 2>&1 | grep -q "version \"${JDK_VERSION}"

# jadx: APK/DEX decompiler.
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


# searchsploit: the local exploit-db index, so a version banner can be matched
# against known exploits without a network round trip.
ARG EXPLOITDB_COMMIT=main
RUN set -eux; \
    git init -q /opt/exploitdb; \
    cd /opt/exploitdb; \
    git remote add origin https://gitlab.com/exploit-database/exploitdb; \
    git fetch -q --depth 1 origin "$EXPLOITDB_COMMIT"; \
    git checkout -q --detach FETCH_HEAD; \
    rm -rf /opt/exploitdb/.git; \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit; \
    searchsploit --version >/dev/null 2>&1 || true

# Gaps observed in real engagements (RedEye/TakeOff): the ssh client and bc
# were absent mid-run (exit 127), and NetExec's pinned certipy fork installs
# as a library with no console script, so `certipy` did not resolve. Kept in
# its own final layer so the heavy layers above stay cacheable.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssh-client bc; \
    rm -rf /var/lib/apt/lists/*; \
    printf '#!/bin/sh\nexec python3 -c "from certipy.entry import main; main()" "$@"\n' > /usr/local/bin/certipy; \
    chmod 0755 /usr/local/bin/certipy; \
    for t in ssh ssh-keygen bc certipy; do \
      command -v "$t" >/dev/null || { echo "missing $t"; exit 1; }; \
    done; \
    ssh -V 2>&1 | grep -qi openssh; \
    echo '2+3' | bc | grep -q 5; \
    certipy --help 2>&1 | grep -qi certipy
COPY m1nervac0nsole/dist/${TARGETARCH}/m1nervac0nsole /opt/m1nervac0nsole/m1nervac0nsole
COPY m1nervac0nsole/skills/ /opt/m1nervac0nsole/skills/
COPY deployment/guest-start.py deployment/guest-export.py /opt/agentlab/
RUN chmod 0755 /opt/m1nervac0nsole/m1nervac0nsole /opt/agentlab/guest-start.py \
 && mkdir -p /state /run/secrets

EXPOSE 8787
# msb exec runs /opt/agentlab/guest-start.py explicitly; the image does not start the supervisor on create.
ENTRYPOINT ["/usr/bin/python3", "/opt/agentlab/guest-start.py"]

#!/usr/bin/python3
"""AgentLab guest supervisor (stdlib only; runs as guest root via `msb exec`).

Start order: lock -> PostgreSQL (/state/postgres, loopback TCP + /run/postgresql socket)
-> artex DB role/database -> tcpdump (must report "listening on") -> ARTEX under strace.
Stop order on SIGTERM/SIGINT or ARTEX exit: ARTEX group -> tcpdump (SIGINT, flushes pcap)
-> PostgreSQL (pg_ctl -m fast).

Exit: ARTEX's exit code (128+signal if killed), 1 on any failure, 3 if another supervisor holds the lock.
Outputs: /state/runtime/{artex,jwt.key,status.json,secrets/artex-db.dsn,logs/...}
         /state/captures/<session-id>/{manifest.json,pcap/,strace/,logs/}
"""
import datetime as dt
import fcntl
import glob
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import signal
import subprocess
import sys
import time
import traceback
import urllib.parse

STATE = "/state"
RUNTIME = f"{STATE}/runtime"
LOCK_PATH = f"{RUNTIME}/supervisor.lock"
STATUS_PATH = f"{RUNTIME}/status.json"
SUPERVISOR_PID = f"{STATE}/supervisor.pid"
CURRENT_CAPTURE = f"{STATE}/current-capture.json"
DSN_PATH = f"{RUNTIME}/secrets/artex-db.dsn"
PGDATA = f"{STATE}/postgres"
PG_LOGDIR = f"{RUNTIME}/logs/postgres"
PG_LOG = f"{PG_LOGDIR}/postgres.log"
PG_SOCKDIR = "/run/postgresql"
PG_PORT = 5432
PG_OPTS = f"-c listen_addresses=127.0.0.1 -c port={PG_PORT} -c unix_socket_directories={PG_SOCKDIR}"
PG_HBA = """# managed by guest-start.py; rewritten on every start
local   all   all                 trust
host    all   all   127.0.0.1/32  scram-sha-256
"""
ARTEX_DATA = f"{STATE}/artex"
CAPTURES = f"{STATE}/captures"
ADMIN_SECRET = "/run/secrets/agentlab-admin"
IMAGE_BIN = "/opt/artex/artex"
SKILLS_DIR = "/opt/artex/skills"
BROWSERS_DIR = "/opt/ms-playwright"
# Guest-local capture proxy; not the host native provider proxy, which also listens on 8788.
ARTEX_ARGS = ["-addr", ":8787", "-proxy", "127.0.0.1:8788", "-data", ARTEX_DATA]
STRACE_ARGS = ["-ff", "-ttt", "-T", "-yy", "-s256", "-e", "trace=process,file,network"]
SEGMENT_MB = 128   # tcpdump -C counts millions of bytes
MAX_SEGMENTS = 32  # tcpdump -W ring size
# Optional OpenVPN profile, streamed in by `lab start --vpn <file>` before the
# supervisor launches. Absent means no VPN, which is the default.
VPN_PROFILE = "/run/secrets/openvpn-profile.ovpn"
VPN_LOG = f"{RUNTIME}/logs/openvpn.log"
VPN_TIMEOUT = 90  # seconds to reach an address on the tunnel interface
# Outbound HTTP proxy. Every tool that honours proxy environment variables is
# routed through it, so the identity the target sees is the engagement's, not the
# tool's. Raw TCP (SMB, SSH, port scans) bypasses it by design.
EGRESS_ADDR = "127.0.0.1:8888"
EGRESS_DIR = f"{RUNTIME}/egress"
EGRESS_CA = f"{EGRESS_DIR}/ca.pem"
EGRESS_LOG = f"{RUNTIME}/logs/egress.log"
EGRESS_TIMEOUT = 20
# The operator's hard rule for shared labs: never exceed 100 requests a minute
# against one target. Enforced per target so a backlog does not make each box
# wait behind the others.
EGRESS_RPM = 100
CAPTURE_LIMITS = {
    "tool": "tcpdump",
    "interface": "any",
    "snaplen": "-s0 (full packets)",
    "flush": "-U (per packet)",
    "rotation": f"-C {SEGMENT_MB} (~{SEGMENT_MB} million bytes per segment) -W {MAX_SEGMENTS}",
    "max_segments": MAX_SEGMENTS,
    "approx_max_bytes": SEGMENT_MB * 1_000_000 * MAX_SEGMENTS,
    "overflow": "ring: after max_segments the oldest segment is overwritten; wrap_suspected=true when all slots are in use",
    "privileges": "-Z root (no privilege drop; output directory is root-only)",
    "not_captured": "HTTPS/TLS payloads are ciphertext; no key material is captured",
    "tamper": "guest root can modify or delete captures and this manifest",
    "native_transport": "Provider sockets run in the host native provider proxy; guest PCAP captures the host API and task traffic. Host provider-proxy network syscalls are exported separately.",
}
START_TIMEOUT = 20
APP_STOP_TIMEOUT = 30
TCPDUMP_STOP_TIMEOUT = 20
PG_TIMEOUT = 60

STOP = {"signal": None}


class Fatal(Exception):
    pass


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def log(msg):
    print(f"[guest-start {now_iso()}] {msg}", flush=True)


def write_file(path, data, mode=0o644):
    if isinstance(data, str):
        data = data.encode()
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def chown_postgres(path):
    pw = pwd.getpwnam("postgres")
    os.chown(path, pw.pw_uid, pw.pw_gid)


def as_postgres(argv):
    return ["runuser", "-u", "postgres", "--", *argv]


def run(cmd, what, input_=None, redact=()):
    r = subprocess.run(cmd, input=input_, capture_output=True)
    if r.returncode != 0:
        text = (r.stdout + r.stderr).decode(errors="replace")
        for s in redact:
            text = text.replace(s, "***")
        raise Fatal(f"{what} failed (rc={r.returncode}): {text.strip()[-1500:]}")
    return r


def proc_info(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
        with open(f"/proc/{pid}/stat") as f:
            starttime = int(f.read().rsplit(")", 1)[1].split()[19])
    except OSError:
        return {"pid": pid, "alive": False}
    return {"pid": pid, "cmdline": cmdline, "starttime_ticks": starttime}


def signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False


def wait_group_gone(pgid, timeout):
    deadline = time.monotonic() + timeout
    while signal_group(pgid, 0):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.2)
    return True


def exit_code(rc):
    return 128 - rc if rc < 0 else rc


def on_signal(signum, _frame):
    STOP["signal"] = signal.Signals(signum).name


def acquire_lock():
    os.makedirs(RUNTIME, exist_ok=True)
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        log(f"another guest supervisor holds {LOCK_PATH}; refusing to start a duplicate")
        sys.exit(3)
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())
    return fd  # kept open by the caller for the process lifetime


def prepare_dirs():
    pw = pwd.getpwnam("postgres")
    for d in (RUNTIME, f"{RUNTIME}/secrets", PG_LOGDIR, ARTEX_DATA, CAPTURES, PG_SOCKDIR, PGDATA):
        os.makedirs(d, exist_ok=True)
    for parent in (STATE, RUNTIME, f"{RUNTIME}/logs"):
        os.chmod(parent, 0o711)  # PostgreSQL needs traversal; host AgentLab remains private.
    os.chmod(PG_LOGDIR, 0o700)
    os.chmod(f"{RUNTIME}/secrets", 0o700)
    os.chmod(CAPTURES, 0o700)
    for d in (PG_LOGDIR, PG_SOCKDIR, PGDATA):
        os.chown(d, pw.pw_uid, pw.pw_gid)
    os.chmod(PG_SOCKDIR, 0o775)
    os.chmod(PGDATA, 0o700)


class Session:
    def __init__(self):
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
        self.dir = os.path.join(CAPTURES, self.id)
        self.logs = os.path.join(self.dir, "logs")
        self.pcap = os.path.join(self.dir, "pcap")
        self.strace = os.path.join(self.dir, "strace")
        for d in (self.dir, self.logs, self.pcap, self.strace):
            os.makedirs(d, mode=0o700, exist_ok=True)
        self.m = {
            "schema": "agentlab.capture-session/1",
            "session_id": self.id,
            "state": "starting",
            "started_at": now_iso(),
            "ended_at": None,
            "exit_code": None,
            "supervisor": proc_info(os.getpid()),
            "postgres": {"status": "not_started"},
            "capture": {"status": "not_started", "limits": CAPTURE_LIMITS},
            "artex": {"status": "not_started", "strace_args": STRACE_ARGS,
                      "strace_notes": "process/file/network syscalls; decoded string arguments limited to 256 bytes"},
            "errors": [],
        }
        self.save()

    def save(self):
        self.m["updated_at"] = now_iso()
        write_file(os.path.join(self.dir, "manifest.json"),
                   json.dumps(self.m, indent=2, sort_keys=True) + "\n", 0o600)
        pids = {"supervisor": os.getpid(), "postgres": self.m["postgres"].get("pid"),
                "tcpdump": self.m["capture"].get("pid"), "artex_strace": self.m["artex"].get("strace_pid")}
        write_file(STATUS_PATH, json.dumps({"session_id": self.id, "state": self.m["state"],
                                            "updated_at": self.m["updated_at"], "pids": pids}, indent=2) + "\n")

    def set_state(self, state):
        self.m["state"] = state
        self.save()

    def error(self, msg):
        self.m["errors"].append({"at": now_iso(), "message": msg})
        self.m["state"] = "failed"
        if not self.m.get("exit_code"):
            self.m["exit_code"] = 1
        # Diagnostics must never prevent process cleanup or hide its failure.
        for label, action in (("log", lambda: log(f"ERROR {msg}")), ("manifest", self.save)):
            try:
                action()
            except Exception as error:
                self.m["errors"].append({"at": now_iso(), "message": f"{label} failed: {error}"})

    def sample_resources(self):
        with open("/proc/stat") as stream:
            cpu_ticks = [int(value) for value in stream.readline().split()[1:]]
        with open("/proc/meminfo") as stream:
            memory_kib = {parts[0].rstrip(":"): int(parts[1]) for line in stream
                          if (parts := line.split())[0] in ("MemTotal:", "MemAvailable:", "MemFree:", "Cached:")}
        with open("/proc/net/dev") as stream:
            network = {}
            for line in stream:
                if ":" in line:
                    interface, counters = line.split(":", 1)
                    values = counters.split()
                    network[interface.strip()] = {"rx_bytes": int(values[0]), "rx_packets": int(values[1]),
                                                  "tx_bytes": int(values[8]), "tx_packets": int(values[9])}
        with open(os.path.join(self.dir, "resources.jsonl"), "a") as stream:
            stream.write(json.dumps({"timestamp": now_iso(), "monotonic_ns": time.monotonic_ns(),
                                     "cpu_ticks": cpu_ticks, "memory_kib": memory_kib, "network": network}) + "\n")


# ---------- PostgreSQL ----------

def pg_bindir():
    found = sorted(glob.glob("/usr/lib/postgresql/*/bin/pg_ctl"))
    if not found:
        raise Fatal("no PostgreSQL server binaries under /usr/lib/postgresql/*/bin")
    return os.path.dirname(found[-1])


def pg_init(bindir):
    if os.path.exists(os.path.join(PGDATA, "PG_VERSION")):
        return
    if os.listdir(PGDATA):
        raise Fatal(f"{PGDATA} is not empty and has no PG_VERSION; refusing to initdb over it")
    log(f"initdb {PGDATA}")
    run(as_postgres([f"{bindir}/initdb", "-D", PGDATA, "-U", "postgres", "--auth-local=trust",
                     "--auth-host=scram-sha-256", "--encoding=UTF8", "--locale=C.UTF-8"]), "initdb")


def pg_write_hba():
    path = os.path.join(PGDATA, "pg_hba.conf")
    write_file(path, PG_HBA, 0o600)
    chown_postgres(path)


def pg_start(sess, bindir):
    ctl = f"{bindir}/pg_ctl"
    st = subprocess.run(as_postgres([ctl, "-D", PGDATA, "status"]), capture_output=True).returncode
    if st == 0:
        raise Fatal(f"PostgreSQL already running on {PGDATA}; refusing to start a second server")
    if st != 3:
        raise Fatal(f"pg_ctl status returned {st} for {PGDATA}")
    pid_file = os.path.join(PGDATA, "postmaster.pid")
    if os.path.exists(pid_file):
        os.remove(pid_file)  # stale: pg_ctl status reported no live server
    log("starting PostgreSQL on 127.0.0.1:5432 and " + PG_SOCKDIR)
    sess.m["postgres"].update(status="starting", bindir=bindir)
    run(as_postgres([ctl, "-D", PGDATA, "-l", PG_LOG, "-o", PG_OPTS, "-w", "-t", str(PG_TIMEOUT), "start"]),
        "pg_ctl start")
    with open(pid_file) as f:
        return int(f.readline())


def pg_stop(bindir):
    r = subprocess.run(as_postgres([f"{bindir}/pg_ctl", "-D", PGDATA, "-m", "fast", "-w",
                                    "-t", str(PG_TIMEOUT), "stop"]), capture_output=True)
    return r.returncode, (r.stdout + r.stderr).decode(errors="replace").strip()[-1000:]


def pg_provision(bindir):
    pw = None
    if os.path.exists(DSN_PATH):
        with open(DSN_PATH) as f:
            pw = urllib.parse.urlsplit(f.read().strip()).password
    if not pw or not re.fullmatch(r"[A-Za-z0-9_-]+", pw):
        pw = secrets.token_urlsafe(32)  # urlsafe alphabet: no quoting issues in the psql script
    # Password travels on psql stdin only (never argv); ALTER runs every start so the DSN file stays authoritative.
    script = (
        "\\set ON_ERROR_STOP 1\n"
        f"\\set pw '{pw}'\n"
        "SELECT format('CREATE ROLE artex LOGIN PASSWORD %L', :'pw') "
        "WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'artex')\\gexec\n"
        "SELECT format('ALTER ROLE artex LOGIN NOSUPERUSER PASSWORD %L', :'pw')\\gexec\n"
        "SELECT 'CREATE DATABASE artex OWNER artex' "
        "WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'artex')\\gexec\n"
    )
    run(as_postgres([f"{bindir}/psql", "-X", "-q", "-h", PG_SOCKDIR, "-p", str(PG_PORT),
                     "-U", "postgres", "-d", "postgres", "-f", "-"]),
        "artex role/database provisioning", input_=script.encode(), redact=(pw,))
    dsn = f"postgres://artex:{pw}@127.0.0.1:{PG_PORT}/artex?sslmode=disable"
    write_file(DSN_PATH, dsn + "\n", 0o600)
    return dsn


# ---------- ARTEX / inputs ----------

def admin_password():
    try:
        with open(ADMIN_SECRET, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        log(f"{ADMIN_SECRET} not mounted: ARTEX_ADMIN_PASSWORD not set (use the setup-token flow)")
        return None
    pw = raw.rstrip(b"\r\n").decode()
    if not pw:
        raise Fatal(f"{ADMIN_SECRET} is empty")
    return pw


def app_env(dsn, admin_pw):
    # Explicit allowlist: no model/provider variables and no inherited supervisor environment.
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "ARTEX_SELFUPDATE_SMOKE": "1",
        "ARTEX_PG_DSN": dsn,
        "ARTEX_SKILL_DIR": SKILLS_DIR,
        "PLAYWRIGHT_BROWSERS_PATH": BROWSERS_DIR,
        "ARTEX_NATIVE_PROXY_URL": "http://host.microsandbox.internal:8788",
        "ARTEX_NATIVE_PROXY_TOKEN_FILE": "/run/secrets/agentlab-native-proxy",
    }
    # Route target-bound HTTP through the identity proxy. The host native proxy
    # is excluded from it, or model calls would be rewritten as target traffic.
    proxy = f"http://{EGRESS_ADDR}"
    env.update({
        "http_proxy": proxy, "https_proxy": proxy,
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
        "no_proxy": "localhost,127.0.0.1,::1,host.microsandbox.internal",
        "NO_PROXY": "localhost,127.0.0.1,::1,host.microsandbox.internal",
        "SSL_CERT_FILE": EGRESS_CA,
        "CURL_CA_BUNDLE": EGRESS_CA,
        "REQUESTS_CA_BUNDLE": EGRESS_CA,
        "NODE_EXTRA_CA_CERTS": EGRESS_CA,
    })
    if admin_pw is not None:
        env["ARTEX_ADMIN_PASSWORD"] = admin_pw
    return env


def install_binary():
    if not os.path.exists(IMAGE_BIN):
        raise Fatal(f"{IMAGE_BIN} missing from image")
    dst = f"{RUNTIME}/artex"
    shutil.copyfile(IMAGE_BIN, dst + ".new")
    os.chmod(dst + ".new", 0o755)
    os.replace(dst + ".new", dst)  # jwt.key is generated beside this binary (config.BaseDir) and persists in RUNTIME
    with open(dst, "rb") as f:
        return dst, hashlib.file_digest(f, "sha256").hexdigest()


# ---------- capture ----------

STAT_KEYS = {"packets captured": "captured", "packets received by filter": "received_by_filter",
             "packets dropped by kernel": "dropped_by_kernel"}


def parse_stats(text):
    stats = {}
    for line in text.splitlines():
        for needle, key in STAT_KEYS.items():
            m = re.match(r"\s*(\d+) " + re.escape(needle), line)
            if m:
                stats[key] = int(m.group(1))
    return stats


def list_segments(d):
    segs = []
    for path in sorted(glob.glob(os.path.join(d, "capture.pcap*")), key=os.path.getmtime):
        st = os.stat(path)
        segs.append({"name": os.path.basename(path), "bytes": st.st_size,
                     "mtime": dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(timespec="seconds")})
    return segs


def start_egress(sess, binary):
    """Start the outbound proxy that presents one browser identity to targets.

    It runs as its own process so a proxy crash cannot take the backend with it,
    and so the supervisor can report it the way it reports the tunnel.
    """
    os.makedirs(os.path.dirname(EGRESS_LOG), exist_ok=True)
    cmd = [binary, "egress-proxy", "-addr", EGRESS_ADDR, "-dir", EGRESS_DIR,
           "-rpm", str(EGRESS_RPM)]
    with open(EGRESS_LOG, "ab") as logf:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,
                             start_new_session=True)
    sess.m["egress"] = {"status": "starting", "pid": p.pid, "addr": EGRESS_ADDR,
                        "dir": EGRESS_DIR, "ca": EGRESS_CA, "log": EGRESS_LOG,
                        "started_at": now_iso()}
    sess.save()
    host, port = EGRESS_ADDR.rsplit(":", 1)
    deadline = time.monotonic() + EGRESS_TIMEOUT
    while True:
        if p.poll() is not None:
            raise Fatal(f"egress proxy exited during start (rc={p.returncode}); see {EGRESS_LOG}")
        try:
            with socket.create_connection((host, int(port)), timeout=1):
                break
        except OSError:
            pass
        if time.monotonic() > deadline:
            raise Fatal(f"egress proxy did not listen on {EGRESS_ADDR} within {EGRESS_TIMEOUT}s")
        time.sleep(0.2)
    if not os.path.exists(EGRESS_CA):
        raise Fatal(f"egress proxy did not write a CA to {EGRESS_CA}")
    sess.m["egress"].update(status="running", process=proc_info(p.pid),
                            ca_sha256=hashlib.sha256(open(EGRESS_CA, "rb").read()).hexdigest())
    sess.save()
    log(f"egress proxy up on {EGRESS_ADDR}")
    return p

def stop_egress(sess, p):
    if p is None:
        return
    try:
        p.terminate()
        p.wait(timeout=10)
    except Exception as error:
        sess.error(f"egress proxy did not stop cleanly: {error}")
        try:
            p.kill()
        except Exception:
            pass

def start_vpn(sess):
    """Bring up the OpenVPN tunnel an operator supplied, and prove it carries traffic.

    The profile is streamed into VPN_PROFILE by `lab start --vpn`; without it this
    returns None and nothing changes. Bringing the tunnel up before tcpdump means
    the capture sees the encrypted egress on the real interface, which is the point:
    an engagement's traffic must be attributable and the pcap must show what left.
    """
    if not os.path.exists(VPN_PROFILE):
        return None
    openvpn = shutil.which("openvpn")
    if openvpn is None:
        raise Fatal("an OpenVPN profile was supplied but openvpn is not installed")
    os.makedirs(os.path.dirname(VPN_LOG), exist_ok=True)
    # --auth-nocache keeps credentials out of the process list; --config-file is
    # explicit so a stray /etc/openvpn default cannot be picked up instead.
    cmd = [openvpn, "--config", VPN_PROFILE, "--auth-nocache", "--log", VPN_LOG]
    with open(VPN_LOG, "ab") as logf:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf, start_new_session=True)
    with open(VPN_PROFILE, "rb") as profile:
        profile_digest = hashlib.sha256(profile.read()).hexdigest()
    sess.m["vpn"] = {"status": "starting", "pid": p.pid, "argv": cmd[:2] + ["<profile>"],
                     "profile_sha256": profile_digest,
                     "log": VPN_LOG, "started_at": now_iso()}
    sess.save()
    try:
        deadline = time.monotonic() + VPN_TIMEOUT
        address = ""
        while True:
            if p.poll() is not None:
                raise Fatal(f"openvpn exited during start (rc={p.returncode}); see {VPN_LOG}")
            address = vpn_address()
            if address:
                break
            if time.monotonic() > deadline:
                raise Fatal(f"openvpn did not bring up a tunnel address within {VPN_TIMEOUT}s; see {VPN_LOG}")
            time.sleep(0.5)
        sess.m["vpn"].update(status="running", address=address, interface=vpn_interface(address))
        sess.save()
        log(f"openvpn tunnel up: {address}")
    except BaseException:
        try:
            stop_vpn(sess, p)
        except Exception as error:
            sess.error(f"openvpn startup cleanup failed: {error}")
        raise
    return p

def vpn_interface(address):
    """Name of the interface holding the tunnel address, or '' when it is not up."""
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[3].split("/")[0] == address:
            return parts[1]
    return ""

def vpn_address():
    """The first non-loopback IPv4 on a tun/tap interface, or '' if none yet."""
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[1].startswith(("tun", "tap")):
            return parts[3].split("/")[0]
    return ""

def stop_vpn(sess, p):
    vpn = sess.m.get("vpn") or {}
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            signal_group(p.pid, signal.SIGKILL)
            p.wait(timeout=5)
    vpn.update(status="stopped", stopped_at=now_iso(), exit_code=p.returncode)
    sess.m["vpn"] = vpn
    sess.save()

def start_tcpdump(sess):
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        raise Fatal("tcpdump not installed")
    pcap = os.path.join(sess.pcap, "capture.pcap")
    err_path = os.path.join(sess.logs, "tcpdump.stderr.log")
    cmd = [tcpdump, "-i", "any", "-s0", "-U", "-Z", "root", "-C", str(SEGMENT_MB),
           "-W", str(MAX_SEGMENTS), "-w", pcap]
    with open(err_path, "wb") as errf:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=errf, stderr=errf, start_new_session=True)
    try:
        sess.m["capture"].update(status="starting", pid=p.pid, process=proc_info(p.pid), argv=cmd,
                                 dir=sess.pcap, stderr_log=err_path, started_at=now_iso())
        sess.save()
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            if p.poll() is not None:
                raise Fatal(f"tcpdump exited during start (rc={p.returncode}); see {err_path}")
            with open(err_path, "rb") as f:
                if b"listening on" in f.read():
                    break
            if time.monotonic() > deadline:
                p.kill()
                p.wait()
                raise Fatal(f"tcpdump did not report 'listening on' within {START_TIMEOUT}s; see {err_path}")
            time.sleep(0.2)
        sess.m["capture"]["status"] = "running"
        sess.save()
    except BaseException:
        try:
            stop_tcpdump(sess, p)
        except Exception as error:
            sess.error(f"tcpdump startup cleanup failed: {error}")
        raise
    return p


def stop_tcpdump(sess, p):
    cap = sess.m["capture"]
    if p.poll() is None:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(TCPDUMP_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            sess.error(f"tcpdump ignored SIGINT for {TCPDUMP_STOP_TIMEOUT}s; killed, last segment may be incomplete")
    cap["exit_code"] = p.returncode
    cap["stopped_at"] = now_iso()
    cap["status"] = "stopped" if p.returncode == 0 else "failed"
    with open(cap["stderr_log"], "rb") as f:
        cap["stats"] = parse_stats(f.read().decode(errors="replace"))
    cap["segments"] = list_segments(sess.pcap)
    cap["wrap_suspected"] = len(cap["segments"]) >= MAX_SEGMENTS
    if p.returncode != 0:
        sess.error(f"tcpdump exit code {p.returncode}")


# ---------- ARTEX ----------

def start_app(sess, binary, env):
    strace = shutil.which("strace")
    if strace is None:
        raise Fatal("strace not installed")
    out_path = os.path.join(sess.logs, "artex.stdout.log")
    err_path = os.path.join(sess.logs, "artex.stderr.log")
    cmd = [strace, *STRACE_ARGS, "-o", os.path.join(sess.strace, "strace"), binary, *ARTEX_ARGS]
    with open(out_path, "ab") as out, open(err_path, "ab") as err:
        p = subprocess.Popen(cmd, cwd=RUNTIME, env=env, stdin=subprocess.DEVNULL,
                             stdout=out, stderr=err, start_new_session=True)
    try:
        sess.m["artex"].update(status="running", started_at=now_iso(), strace_pid=p.pid,
                               strace_process=proc_info(p.pid), argv=cmd, binary=binary,
                               sha256=sess.m["artex"].get("sha256"), stdout_log=out_path, stderr_log=err_path,
                               env_keys=sorted(env), skills_dir=SKILLS_DIR, data_dir=ARTEX_DATA)
        sess.save()
    except BaseException:
        try:
            stop_app(sess, p)
        except Exception as error:
            sess.error(f"ARTEX startup cleanup failed: {error}")
        raise
    return p


def stop_app(sess, p):
    pgid = p.pid  # start_new_session: strace is the group leader; ARTEX runs in its group
    if p.poll() is None:
        signal_group(pgid, signal.SIGTERM)
        try:
            p.wait(APP_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            sess.error(f"ARTEX did not exit within {APP_STOP_TIMEOUT}s of SIGTERM; SIGKILL to group {pgid}")
            signal_group(pgid, signal.SIGKILL)
            p.wait()
    if signal_group(pgid, 0):  # members outlived the leader (e.g. browsers spawned by ARTEX)
        signal_group(pgid, signal.SIGTERM)
        if not wait_group_gone(pgid, APP_STOP_TIMEOUT):
            sess.error(f"process group {pgid} still alive after SIGTERM; SIGKILL")
            signal_group(pgid, signal.SIGKILL)
    traced = []
    for path in glob.glob(os.path.join(sess.strace, "strace.*")):
        suffix = path.rsplit(".", 1)[1]
        if suffix.isdigit():
            traced.append(int(suffix))
    sess.m["artex"].update(status="stopped" if p.returncode == 0 else "exited", exit_code=p.returncode,
                           exit_code_normalized=exit_code(p.returncode), ended_at=now_iso(),
                           pids=sorted(traced))


# ---------- lifecycle ----------

def shutdown(sess, app, tcpd, bindir, vpn=None, egress=None):
    try:
        sess.set_state("stopping")
    except Exception as error:
        sess.error(f"could not persist stopping state: {error}")
    for name, process, stop in (("artex", app, stop_app), ("capture", tcpd, stop_tcpdump),
                                ("vpn", vpn, stop_vpn), ("egress", egress, stop_egress)):
        if process is not None:
            try:
                stop(sess, process)
            except Exception as error:
                if name in sess.m:
                    sess.m[name]["status"] = "failed"
                sess.error(f"{name} cleanup failed: {error}")
    if bindir is not None:
        try:
            rc, out = pg_stop(bindir)
            sess.m["postgres"].update(status="stopped" if rc == 0 else "failed",
                                      stop={"rc": rc, "output": out, "at": now_iso()})
            if rc != 0:
                sess.error(f"pg_ctl stop -m fast failed rc={rc}: {out}")
        except Exception as error:
            sess.m["postgres"]["status"] = "failed"
            sess.error(f"PostgreSQL cleanup failed: {error}")
    try:
        sess.save()
    except Exception as error:
        sess.error(f"could not persist cleanup state: {error}")


def main():
    global_lock = acquire_lock()  # noqa: F841 - held for process lifetime
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    prepare_dirs()
    sess = Session()
    bindir = None
    tcpd = None
    app = None
    vpn = None
    egress = None
    rc = 0
    try:
        log(f"session {sess.id} -> {sess.dir}")
        write_file(SUPERVISOR_PID, f"{os.getpid()}\n")
        write_file(CURRENT_CAPTURE, json.dumps({"path": str(sess.dir), "pid": os.getpid()}) + "\n")
        bindir = pg_bindir()
        pg_init(bindir)
        pg_write_hba()
        pg_pid = pg_start(sess, bindir)
        sess.m["postgres"].update(status="running", pid=pg_pid, process=proc_info(pg_pid), bindir=bindir,
                                  listen="127.0.0.1:%d" % PG_PORT, socket=PG_SOCKDIR, log=PG_LOG,
                                  auth={"local": "trust", "host": "scram-sha-256"})
        sess.save()
        dsn = pg_provision(bindir)
        binary, digest = install_binary()
        sess.m["artex"]["sha256"] = digest
        env = app_env(dsn, admin_password())
        vpn = start_vpn(sess)
        egress = start_egress(sess, binary)
        tcpd = start_tcpdump(sess)
        if STOP["signal"] is None:
            app = start_app(sess, binary, env)
            sess.set_state("running")
        last_sample = 0.0
        while app is not None and app.poll() is None and STOP["signal"] is None:
            if tcpd.poll() is not None:
                raise Fatal(f"tcpdump exited while ARTEX was running (rc={tcpd.returncode}); ARTEX stopped to avoid uncaptured runs")
            # Kill switch: a dropped tunnel must stop the engagement, not silently
            # resume egress over the host's own address.
            if egress.poll() is not None:
                raise Fatal(f"egress proxy exited while ARTEX was running (rc={egress.returncode}); ARTEX stopped so no request leaves with the wrong identity")
            if vpn is not None and vpn.poll() is not None:
                raise Fatal(f"openvpn exited while ARTEX was running (rc={vpn.returncode}); ARTEX stopped to avoid traffic leaving outside the tunnel")
            if time.monotonic() - last_sample >= 1:
                sess.sample_resources()
                last_sample = time.monotonic()
            time.sleep(0.5)
        if STOP["signal"] is not None:
            log(f"received {STOP['signal']}; stopping")
    except Exception as e:  # noqa: BLE001 - every failure must land in the manifest
        rc = 1
        msg = str(e) if isinstance(e, Fatal) else "unexpected: " + traceback.format_exc()
        sess.error(msg)
        if sess.m["capture"]["status"] == "starting":
            sess.m["capture"]["status"] = "failed"
    finally:
        owned_pg = bindir if sess.m["postgres"]["status"] in ("starting", "running") else None
        shutdown(sess, app, tcpd, owned_pg, vpn, egress)
        try:
            with open(SUPERVISOR_PID) as stream:
                owned_pid = stream.read().strip() == str(os.getpid())
            if owned_pid:
                os.unlink(SUPERVISOR_PID)
        except FileNotFoundError:
            pass
        except Exception as error:
            sess.error(f"could not remove owned supervisor PID: {error}")
    if app is not None and rc == 0 and app.returncode is not None:
        rc = exit_code(app.returncode)
    if rc == 0 and sess.m["errors"]:
        rc = 1
    sess.m["exit_code"] = rc
    sess.m["ended_at"] = now_iso()
    try:
        sess.set_state("failed" if rc else "stopped")
    except Exception as error:
        sess.error(f"could not persist final state: {error}")
    try:
        log(f"session {sess.id} finished rc={sess.m['exit_code']}")
    except Exception as error:
        sess.error(f"could not log final state: {error}")
    if rc == 0 and sess.m["errors"]:
        rc = 1
    sess.m["exit_code"] = rc
    return rc


if __name__ == "__main__":
    sys.exit(main())

---
name: privesc
description: "Invoke this skill when a task holds code execution or file access on a Linux or Windows host inside an authorized scope and needs to determine whether that access can be elevated, or when auditing a host's escalation surface without exploiting it. Covers enumeration order, GTFOBins and LOLBAS lookups for sudo/SUID/capability/Windows-binary abuse, credential and misconfiguration discovery, and the proof standard for an escalation finding."
---

# Privilege Escalation

Under an **authorized** engagement only. Escalation is the point where a low-impact finding (an RCE, a file read, a shell as a service account) becomes the whole engagement: proving you can become root or SYSTEM is a different finding from proving you can run a command, and the two are reported separately. The standing finding quality gates and the adversarial gate in your system prompt apply throughout.

## Before you enumerate

1. **Confirm the boundary.** Escalating on a host is inside scope only if the program's scope covers that host's privilege model. Many programs scope "the web application" and not "the server"; a root shell on shared infrastructure can breach the program's impact budget even when the initial bug was in scope. Check the policy text, not your intuition.
2. **Record the starting privilege** exactly: user id, groups, sudo rights, capabilities, whether the shell is restricted. An escalation claim without a stated starting point is unfalsifiable.
3. **Never escalate to prove impact when a lesser proof suffices.** A readable `/etc/shadow` line is proof of the capability; cracking it or logging in as root is not required and usually breaches scope.

## Linux: enumeration order

Work from cheapest and most decisive to broadest. Stop at the first privilege boundary you can prove; do not run the full sweep to look thorough.

| Step | What to check | Why it is decisive |
|---|---|---|
| 1 | `id`, `sudo -n -l`, `/etc/sudoers` readable | An explicit NOPASSWD entry is the shortest path and needs no exploitation |
| 2 | SUID/SGID inventory: `find / -perm -4000 -o -perm -2000 2>/dev/null` | A SUID binary not in the distro's default set is the classic escalation |
| 3 | File capabilities: `getcap -r / 2>/dev/null` | `cap_setuid`, `cap_dac_read_search`, `cap_sys_admin` on a user-writable binary are equivalent to root |
| 4 | Cron and timers: `/etc/cron*`, `systemctl list-timers`, writable scripts a root job runs | Writable-by-you + executed-by-root is escalation with no memory corruption |
| 5 | Writable service units, PATH entries, `LD_PRELOAD`/`LD_LIBRARY_PATH` inheritance | A root process loading your file is escalation |
| 6 | Group membership: `docker`, `lxd`, `disk`, `adm`, `shadow`, `sudo` | Mounting a disk image or joining a privileged group is a documented root path |
| 7 | Readable credentials: config files, `.env`, history, SSH keys, cloud metadata, database credentials | Reuse across a trust boundary is escalation and frequently the real finding |
| 8 | Kernel and package versions against known local-root CVEs | Last resort: noisy, may crash the host, and out of scope on most programs |

For the broad sweep, run the vendored `scripts/linpeas.sh` (PEASS-ng, pinned checksum in `reference/README.md`). Treat its output as a **lead list, not evidence** — it flags anything unusual, including many false positives. Every line it highlights must be confirmed by hand before it becomes a finding.

## GTFOBins lookups (Linux)

`reference/gtfobins.json` indexes 458 executables by escape class. Query it before reasoning from memory:

```python
import json
g = json.load(open("reference/gtfobins.json"))
g["find"]["functions"]          # escape classes this binary supports
g["find"]["functions"]["shell"]["contexts"]   # sudo / suid / unprivileged / capabilities
g["find"]["functions"]["shell"]["example"]    # one working invocation
```

Index vocabulary: `shell`, `file-read`, `file-write`, `command`, `reverse-shell`, `bind-shell`, `upload`, `download`, `library-load`, `inherit`, `privilege-escalation`; contexts are `sudo`, `suid`, `unprivileged`, `capabilities`.

The lookup only answers "does this binary escape?" — the finding needs the specific one in front of you. A SUID `find` is only an escalation if that binary is actually SUID on this host; confirm with `ls -l` before claiming it. Contexts are not interchangeable: an escape that works under `sudo` says nothing about the same binary under SUID, because SUID drops the environment while `sudo` may preserve it.

## Windows: enumeration order

| Step | What to check |
|---|---|
| 1 | `whoami /priv`, `whoami /groups` — SeImpersonate, SeAssignPrimaryToken, SeBackup, SeTakeOwnership, SeDebug |
| 2 | Service binary and config permissions: unquoted paths, writable directories, writable `ImagePath` |
| 3 | Scheduled tasks running as SYSTEM with a writable action |
| 4 | AlwaysInstallElevated, AutoLogon credentials in the registry, unattended install files |
| 5 | Writable service binaries or DLL search-order directories |
| 6 | Credentials in memory-adjacent stores the account can read, and in configuration files |

`reference/lolbas.json` indexes 248 signed Windows binaries that can execute, download, dump or bypass. Query by category:

```python
import json
l = json.load(open("reference/lolbas.json"))
[x for x, v in l.items() if "UAC Bypass" in v["categories"]]
l["certutil.exe"]["example"]
```

Categories present: `Execute`, `Download`, `AWL Bypass`, `ADS`, `Dump`, `Copy`, `UAC Bypass`, `Upload`, `Tamper`, `Credentials`, `Compile`, `Reconnaissance`.

The LOLBAS value here is **not** exploitation — it is that these binaries are signed and already present, so a technique using them survives application allowlisting and produces different telemetry than a dropped payload. That matters for an adversary-emulation task (`edr-bypass-re`) and for explaining why a control did or did not catch the technique.

## Gates for an escalation finding

A finding must show all four. Anything less is a hardening note.

1. **Starting privilege stated**: the exact user, groups, and rights before the step.
2. **The specific misconfiguration**, cited by path and permissions, not by class. "SUID binary present" is not a finding; "`/usr/local/bin/backup` is SUID root, world-writable, and its `tar` invocation resolves through `$PATH`" is.
3. **Executed end to end** against a real host, showing the elevated identity (`id`, `whoami /priv`) afterwards. A GTFOBins example that would work is not a proof that it works here.
4. **Measured impact with its denominator**: what the elevated identity reaches that the starting identity did not — how many hosts, which data, which trust boundary.

If you cannot execute (the host is production and out of the impact budget), say so explicitly, label the finding potential, and give the static chain with file:line and permissions. Do not upgrade a static chain to confirmed.

## Anti-patterns that produce false findings

- **Assuming the distro's default SUID set is benign.** Compare against the baseline for that distribution; an extra entry is the finding.
- **Treating a writable file as exploitable without an executing root process.** Writable is a prerequisite; the root job that runs it is the finding. Confirm the job exists and runs.
- **Citing a CVE by version match alone.** A version string in a banner is not proof of the vulnerable build; verify the actual package version and, where cheap, the vulnerable code path.
- **Reporting the same misconfiguration per-binary.** One writable directory that root loads from is one finding, however many binaries live in it.
- **Escalating past the scope boundary to "prove" impact.** The escalation itself is often the out-of-scope act.

## Data provenance

`reference/gtfobins.json` and `reference/lolbas.json` are generated from GTFOBins (GPL-3.0) and LOLBAS (MIT) by `scripts/build-indexes.py`; `scripts/linpeas.sh` is the PEASS-ng release artifact (NOASSERTION — the upstream project publishes under a non-standard licence, reviewed before vendoring). Checksums and regeneration steps are in `reference/README.md`. These are reference data, not code this project maintains: refresh them deliberately, and re-read the diff before committing.

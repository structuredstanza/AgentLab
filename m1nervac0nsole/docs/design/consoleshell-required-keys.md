<!-- Design record (2026-11-10). Shipped. -->

Required en.json changes for the shell (parent owns the file).

Add under "nav.group" (new keys, translated group labels):
  "operations": "Operations",
  "evidence": "Evidence",
  "intelligence": "Intelligence",
  "configuration": "Configuration"

Change value under "nav.item":
  "dashboard": "Overview"      // was "Dashboard"; the sidebar/palette group is Operations

Optional but keeps old keys meaningful: "nav.group.function" and "nav.group.system"
are no longer referenced by the shell and can be removed once nothing else uses them.

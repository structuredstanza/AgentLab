---
name: api-recon
description: Use this skill when collecting website API endpoints.
---

# API Recon (Frontend Interface Reconnaissance)

Within **authorized** scope, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI feature trigger points** (tabs, dialogs, table actions, etc.).

---

## Scope and Prohibitions (Agents Must Read · Violations Are Out of Scope)

This skill **covers only API / parameter-surface reconnaissance**; it is not a vulnerability-hunting or exploitation phase.

### Task Boundaries

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege escalation/brute force/fuzz for vulnerabilities, packet tampering, destructive operations |
| **Authentication** | Hooks + stub/mock to bypass the **client-side** login gate | Asking the user for or guessing usernames/passwords; attempting real login-form submission |
| **Runtime** | Hook interfaces without credentials; use mock responses so the SPA enters the post-login shell | Flows that depend on a real backend session to proceed |

### Credential-Free Dynamic Analysis (Phase 3 Default)

1. Through `preload.js` / `runtime_harvest.js`, **intercept and stub** bootstrap interfaces such as login, permissions, and menus;
2. Return mock bodies with **correct structure, a successful business code, and possibly empty data** for business query interfaces;
3. Let the frontend still render post-login pages in an environment without a backend or with 401 responses, so that more XHR/fetch/WebSocket requests are triggered;
4. **Empty data, blank tables, and placeholder UI are all expected**; do not switch to real login or vulnerability testing because of them.

**In short**: use mocks to keep frontend routes and component mounting going, **record only outbound requests**; what the backend returns does not matter. What matters is which interfaces the frontend **still sends requests to**.

### Hard Workflow Prohibitions

| Prohibited | Alternative |
|---|---|
| Before Phase 1 completes, grep/curl/Read the main entry `index-*.js` to extract API paths | Run `OUTDIR/harvest_static.py` |
| Hand-write substitute harvest scripts such as `extract_apis.py` | Modify `OUTDIR/harvest_static.py` and rerun |
| Same grep/command fails ≥2 times and is repeated | Change strategy: read tool_logs, modify harvest, consult reference |
| Real usernames/passwords, OTP, OAuth, or other authentication | stub/mock (see above) |
| Skip gates A/B and run the original `scripts/` directly | Copy to OUTDIR and adapt to the target |
| Skip stubbing in pursuit of "real data" to perform privilege-escalation/injection tests | Record only outbound requests; this is the recon boundary |
| Irreversible actions such as deletion, exporting sensitive data, bulk writes | Same applies to coverage clicks |
| Claim all pages and interfaces are discovered without completing runtime + dynamic enumeration | See "Definition of Done" or note the limitation |
| Claim full parameter knowledge without completing the parameter trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Infer required/optional status from a single runtime sample | Multi-sample diff, or validation rules / error-based inference |

---

## Two-Layer Model + Run Modes

| Layer | Output | Limits |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, draft routes, candidate fields at packaging points | No HTTP methods; parameters require Phase 1b; misses runtime-concatenated URLs |
| **Runtime** (live session) | Methods + body + response + dynamic URLs + WS/SSE; multi-sample diff to fill in parameters | Pages must actually render before requests are sent; a single sample is insufficient to determine required/optional |

| Run mode | Engine | Use |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Clicking tabs/dialogs/tables, deeper feature coverage |
| **both** | depth first, then coverage | Most complete, longest runtime |

**Parameter methodology** (no generic script): find paths with harvest/regex; find parameters with **anchor-window expansion + UI binding chain + multi-sample diff + error-based inference** (grep recipes in section J of [reference.md](reference.md)).

---

## Definition of Done

Recon may be declared complete only when all of the following are met:

- [ ] **Static**: Phase 1 harvest produces `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: at least one of depth or coverage; coverage/both require **effective hooks + a dynamic enumeration loop**
- [ ] **Shell loaded**: visiting business paths does not land on `/login` (watch for hash routing)
- [ ] **Parameters**: coverage/both complete the parameter trigger matrix + `param_samples.json`; Phase 5 merges into `params_merged.json`
- [ ] **Depth** (if module pages are blank): restore the Phase 4 permission tree and rerun until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: Phase 5 outputs complete (see Phase 5 output table); `insert_assets` writes service and endpoint assets

---

## Scripts and Gates

`scripts/` contains reference templates only; **do not** run the originals directly and treat their output as final results.

**Rule**: read first → adapt to the target → write to `OUTDIR` (e.g. `recon/`) → record in `CHANGES.md`; if it does not match, rewrite following the methodology and borrow only the structure.

| Gate | When | Reference script → OUTDIR copy | Common required changes |
|---|---|---|---|
| **A (static)** | After Phase 0, **before the first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | **Default regexes work as-is on most sites**; only change the endpoint regex, webpack/Vite `publicPath`, or MPA exclude/cookie when the manifest or dialect does not match |
| **B (runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralized success values, stubs, login regex, API prefix, hash/history |

**Required SPA order** (not interchangeable; Phase numbering takes precedence over "explore first, then script"):

| Step | Required | Prohibited |
|---|---|---|
| After Phase 0 | Next Bash command = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy script → make small changes as needed → **run immediately** | Manually extract APIs before deciding whether to harvest |
| Before Phase 1 completes | Validate output with `wc -l`; on 404, modify harvest and retry | Hand-write extract scripts; repeatedly grep URLs that were not downloaded |
| From Phase 1b onward | grep only `OUTDIR/js/*.js` | Use the main bundle instead of harvest |

- ✅ Copy `harvest_static.py` → (optional) adjust regex → **run immediately**
- ❌ curl the main bundle → grep repeatedly → write a temporary extractor → harvest only at the end
- **MPA**: next Bash command after Phase 0 = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and Output Constraints

| Constraint | Description |
|---|---|
| Large files | **Do not** Read/grep `index-*.js` files >100KB into context; batch-process with OUTDIR scripts |
| grep output | Must use `\| head -20` or `-m 5`; keep only path summaries in the conversation, do not paste bundle fragments |
| Validation | Use `wc -l` and `ls \| wc -l`; do not Read whole directories |
| Initial regex probe | Optional, at most once, only on small chunks ≤50KB or HTML; formal static results come from harvest |
| Reference | Recipes/templates/troubleshooting are in [reference.md](reference.md); do not repeat the full text inline |

---

## Execution Roadmap

```
Phase 0 classification + OUTDIR
  → Gate A → Phase 1 harvest (★ run immediately ★)
  → Phase 1b parameter reverse engineering
  → Phase 2 three authentication gates → config.json
  → Gate B → Phase 3 runtime + parameter matrix
  → Phase 4 permission tree (if needed) → rerun Phase 3
  → Phase 5 merge report + insert_assets: bulk-insert all discovered service and endpoint API assets; never omit any discovered asset during insertion
```

Check off in order; **do not enter the next Phase until the previous item is complete**.

1. [ ] **Phase 0**: initial SPA/MPA assessment; create `OUTDIR` → [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: copy script → **immediately** harvest → validate with `wc -l` → [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: anchor-window expansion + binding layer → `param_candidates.json` → [Phase 1b](#phase-1b--parameter-reverse-engineering)
4. [ ] **Phase 2**: three authentication gates → `config.json` → [Phase 2](#phase-2--three-authentication-gates)
5. [ ] **Gate B**: adjust runtime scripts → [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm shell loaded; parameter trigger matrix → `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree → patch stubs → rerun Phase 3 → [Phase 4](#phase-4--permission-tree-restoration)
8. [ ] **Phase 5**: merge outputs + report + `insert_assets` → [Phase 5](#phase-5--merge-and-report)

---

## Phase 0 — Classification

Fetch the entry HTML and **create `OUTDIR`** (do not modify `scripts/` inside the skill):

- **SPA**: empty shell + `<div id=app>` + chunks → Phase 1–5
- **MPA**: SSR + `<form>`, no endpoint bundle → after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt`, and `api_inline.txt`. If an SPA yields roughly zero forms, switch to Phase 1.

---

## Phase 1 — Static

Follow [Scripts and Gates](#scripts-and-gates) · [Tool and Output Constraints](#tool-and-output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

Harvest: parse HTML scripts → webpack/Vite manifest → download all lazy chunks → produce `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- Chunk count vs manifest: on 404, modify harvest and retry; do not manually curl chunks one by one
- If `api_static.txt` is too small → loosen the endpoint regex in OUTDIR and rerun (see reference)

### Phase 1b — Parameter Reverse Engineering

Paths come from Phase 1; parameter fields must be investigated separately. See [Tool and Output Constraints](#tool-and-output-constraints) for grep rules.

**Completion criteria**: for key interfaces, be able to answer: field names, transport location, type inference, whether required, sample values, and confidence.

#### 1b.0 — Transport Shapes

| Form | Where parameters are | Static inspection priority |
|---|---|---|
| REST JSON | body + query | Beside path anchors: `(params\|data\|body)\s*:\s*\{` |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameter | `/user/:id` | Route table + `useParams` / `$route.params` |
| Encryption/signing | Wrapped in `sign`/`data` | Hook-encryption function inputs (reference section D) |

Output: annotate each interface with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — Anchor-Window Expansion

Use a known path as an anchor and widen the window to locate the request-assembly object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clues |
|---|---|
| axios instance | `data` / `params` |
| Unified request wrapper | Interceptors inject global fields |
| OpenAPI client | Generated method signatures |
| React Query / SWR | Hook's second argument |
| Vue composable | Composable input parameters |

Type remnants: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

→ `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — Binding Layer

```
Form field → onFinish/handleSubmit → transform → API payload
```

| Binding source | Technique |
|---|---|
| Form submit | Follow submit → transform → API |
| Table search | `getFieldsValue()` → `params` |
| Route | `:id` / `?tab=` |
| Interceptor | Global `tenantId`, pagination, sign |
| Enum select | `options` → API enum values |

From the DevTools call stack, trace upward from `fetch`/`XHR.send` to the request-assembly function.

#### 1b.3 — Three Request-Assembly Questions (≠ Phase 2 Authentication Gates)

| Question | What to determine |
|---|---|
| **Assembly** | Where the payload is built, traces of transforms |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

The interceptor gate (Phase 2) also reads globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 — Connecting to Phase 3

Candidate fields come from the static/binding layers; **required/optional/conditional dependencies** must be determined via the Phase 3 parameter matrix + diff + Phase 5 error inference.

---

## Phase 2 — Three Authentication Gates

Grep in `OUTDIR/js/` (with `head`) and write results to `config.json` (recipes in reference):

| Gate | Question | Keywords |
|---|---|---|
| **Rendering gate** | How is logged-in state determined? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers a redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Do not treat localStorage key names as credentials; confirm them from the chunk/request chain.

**Exit = Gate B**: record conclusions in `config.json` and adapt `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b — API Observation (Optional)

Use `preload.js` in OUTDIR to confirm session key names, Authorization, and nested API URLs:

| Configuration | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | Header observation |
| `extractUrlsFromResponse: true` | Nested APIs within responses |
| `observe.storageReads/cookieReads: true` | Backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

Each coverage round exports: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — Runtime

Gate B must be passed; follow [Scope and Prohibitions](#scope-and-prohibitions-agents-must-read--violations-are-out-of-scope) · the credential-free mock strategy.

`config.json` setting: `"runtimeMode": "depth" | "coverage" | "both"` (template in reference).

### Hooks and Stubs (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 exact | auth/permission/bootstrap stubs | Pass first-screen authentication |
| L2 negative correction | All JSON responses | Convert not-logged-in codes → success |
| L3 fallback | `/api` etc. not matched by L1 | Empty success body to keep the UI populated |

- **depth**: fake auth + `forward` to rewrite business codes + `stubs`; traverse `routes` (hash/history); produce `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or Userscript)

Verify: `window.__API_RECON_PRELOAD__` exists; business paths do not redirect to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — Coverage Dynamic Enumeration (Required)

1. Main navigation/sidebar: click each item and wait 1–3s for network activity
2. Tabs: `role=tab`, `.ant-tabs-tab`
3. Tables: view/edit/details on the first row
4. Toolbars: export, filter, create (**avoid irreversible deletion**)
5. On entering each module: merge APIs/routes
6. SPA: for paths in `routes.txt` that are not covered, use controlled `pushState` (prohibited for MPA)

**Parameter trigger matrix** (required): for each module, record each operation type once and **diff multiple samples**:

| Operation | Parameters typically added |
|---|---|
| Initial list view | Pagination + default filters |
| Click search | keyword, filter |
| Advanced filter | More optional parameters |
| Create/edit | Full entity |
| Bulk/export/sort | `ids[]`, `exportType`, `sortField` |

**Under stubs, outbound body/headers remain real**; trust the requests. Record to `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: run 3a depth first, then 3b coverage

---

## Phase 4 — Permission Tree Restoration

**Trigger**: module pages are blank / each route only loads bootstrap (e.g. locale) → content gate not passed.

| Symptom | Meaning |
|---|---|
| Shell loads successfully | Rendering + interceptor gates passed |
| Missing sidebar items / blank after clicking | Stub shape or permission codes incomplete |
| Same and very few APIs on every route | `v-if permission` check not passed |
| `routes.txt` far fewer than in the bundle | Must be completed from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) → `getResultTree` → `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Stub checks: outer `response_code` matches the interceptor gate; flat codes align with the tree; `routes` covers all links in `route_map`.

After updating `config.json`, **rerun Phase 3**. For large SPAs, tune `waitUntil`, `routeTimeout`, and `perRouteMs` (see reference sections A3/I).

---

## Phase 5 — Merge and Report

### Output Table

| File | Phase | Contents |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | Static bundles and paths |
| `param_candidates.json` | 1b | Static parameter field candidates |
| `config.json` | 2 | Three gates + runtime configuration |
| `runtime_api.json` | 3a | Detailed depth recording (incl. WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | Multi-sample data, click logs, details |
| `route_map.json`, etc. | 4 | Permission-tree intermediate files (if run) |
| `params_merged.json` | 5 | Merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | Routes, APIs, params, feature points, limitations |
| **insert_assets** | 5 | Write all service and endpoint assets to the asset library |

### 5b — Parameter Merging

Diff `param_samples.json`; **there is no generic merge script**. See reference J7 for confidence rules (high/medium/low/pending trigger).

### 5c — Error-Based Inference

Within the authorized scope, incomplete requests may be sent to read 400 responses (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Pay attention to `data` wrappers, `variables`, and `bizData` before encryption.

The report must state: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary relative to the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

For more fields and grep recipes, see [reference.md](reference.md).

---

## General Notes

- **Framework-agnostic**: webpack/Vite/Angular lazy loading uses the same approach
- **Transport**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetches can be recorded; RSC/Server Actions cannot be fully enumerated
- **Blind spots**: JSVMP, WASM, strong HMAC/mTLS validation → rely on static analysis and document limitations
- **Parameter blind spots**: conditional linkage, hidden params, WASM request assembly → mark as "pending trigger" / "unreachable"
- **Static analysis is the safety net**: when runtime is blocked, static analysis can still enumerate endpoints

---

## Additional Resources

- Grep recipes, `config.json` template, troubleshooting, hooks, parameter reverse engineering (section J), site_map template: **[reference.md](reference.md)**
- Reference script paths: see the [Scripts and Gates](#scripts-and-gates) table

# api-recon — Reference Manual

Grep recipes, `config.json` templates, and troubleshooting. All greps run against the `js/` directory. For single-line bundles, first try `js-beautify` or `sed 's/}/}\n/g'`; a raw grep with context windows usually suffices.

## Script Notes

All files in `scripts/` are **reference templates** and must be adjusted to the target site before execution. Typical change points:

| Script | Common adjustments |
|---|---|
| `harvest_static.py` | endpoint regex, webpack/Vite manifest parsing, micro-frontend publicPath, retry/concurrency |
| `runtime_harvest.js` | neutralize field names and success value, stub match rules and body structure, route sources, WS recording, `waitUntil`/`routeTimeout`/`proxy` |
| `preload.js` | `loginPathRe`, L1 stubs, `neutralize.fields`, `apiPattern`, whether L3 is enabled, `recordDetail`, `observe.*`, `neutralizeVueRouter` |
| `spider_mpa.py` | `--exclude` for destructive links, cookies, depth/max, same-domain filtering |
| `extract_route_map.py` | `routeMap` / `routeLink` regex, KEY naming patterns |
| `build_perm_tree.py` | `userRouteAuth` parsing, `ROOTS`/`PREFIX_PARENT` hierarchy heuristics, outer stub field names |
| `config.json` | single entry point for all site-specific parameters above |

Store adjusted files in the task working directory (e.g. `recon/`), and note in the report the specific changes relative to the reference scripts.

---

## A. Three Reverse-Engineering Gates

### A1. Render Gate — "How do we tell we are logged in?"

```bash
grep -rhoaE '.{0,40}(isLogin|isAuthenticated|loggedIn|hasLogin|requireAuth)\b.{0,80}' js | head
grep -rhoaE 'function (getUser|getToken|getAuth)[0-9]?\([^)]*\)\{.{0,200}' js | head
grep -rhoaE '(localStorage|sessionStorage)\.getItem\("[^"]+"\)' js | sort -u
grep -rhoaE '(Cookies?|cookie)\.(get|load)\("[^"]+"\)' js | sort -u
grep -rhoaE '\batob\(|JSON\.parse\(|jwt|decode' js | head
```

Trace the chain `isLogin = f(getUser())` → `getUser = decode(storage.read(KEY))`, and determine the **storage key**, the **container** (Cookie vs localStorage), and the **encoding**:

| Encoding | How to forge in config |
|---|---|
| Plain string / `"1"` / token | `"value": "anything-truthy"` |
| `JSON.parse(x)` | `"value": "json:{\"id\":1,\"username\":\"admin\"}"` |
| `JSON.parse(atob(x))` | `"value": "b64json:{\"id\":1,\"username\":\"admin\"}"` |
| JWT | Unsigned / `alg:none` JWT, or a key signature from the bundle |
| Encrypted (SM2/AES/RSA) | Find hard-coded keys; if the render gate only needs a decodable blob, forge it; otherwise fall back to static analysis |

→ write into `cookies` / `localStorage`.

### A2. Interceptor Gate — "What triggers a redirect to /login?"

```bash
grep -rhoaE '.{0,60}(interceptors\.response|axios|request\.use).{0,120}' js | head
grep -rhoaE '.{0,40}(response_code|errcode|errno|\bcode\b|\bret\b|\bstatus\b)\s*[=!]==?\s*[\-0-9]{1,4}.{0,60}' js | head -20
grep -rhoaP '.{0,40}(\x{672a}\x{767b}\x{5f55}|\x{8bf7}\x{91cd}\x{65b0}\x{767b}\x{5f55}|\x{767b}\x{5f55}\x{5df2}\x{8fc7}\x{671f}|unauthorized|\x{767b}\x{5f55}\x{5931}\x{6548}|\x{6388}\x{6743}|token.{0,10}invalid).{0,40}' js | head
grep -rhoaE '.{0,30}(location\.href|router\.(push|replace)|navigate)\([^)]*login[^)]*\)' js | head
```

Determine the **field name**, the **success value** (usually `0` or `200`), and the **failure value that triggers the redirect**. Verify with a junk session:

```bash
curl -sk -X POST -H 'Cookie: <fakekey>=junk' https://target/api/<protected> -d '{}' -H 'Content-Type: application/json'
```

→ write into `neutralize.fields` + `neutralize.success`.

### A3. Content Gate — "Where do menus/permissions come from?"

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl|resource|nav)[^"]*"' js | sort -u
grep -rhoaE '.{0,30}(menus|permissions|menuList|routeList|authList|role_permissions)\b.{0,120}' js | head
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|hasPermission|checkAuth' js | head
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head
```

**Two layers of data** (common in enterprise back-offices):

| API | Typical payload | Consumer |
|---|---|---|
| `.../role_permissions` | `{ permissions: string[], role_type }` | Route guards, button-level ACL |
| `.../permissions/all` | `tree[{ code, position, children }]` | Sidebar menu rendering |
| `userRouteAuth` in bundle | `{ CODE: { url, name? } }` | code → frontend path |
| `routeMap` in bundle | `{ KEY: { name, link } }` | Alias resolution (webpack `o.DASHBOARD`) |

Confirm by reading the consumer code: how `getResultTree(tree, permissions)` filters, and which field `v-if` / `hasAuth(code)` checks.

**Manual forge** (small sites): build a permissive payload → `stubs`.

**Full permission-tree reconstruction** (large sites where the sidebar/submodules stay blank): see **Section I**.

---

## B. config.json Template

```json
{
  "baseUrl": "https://target/",
  "runtimeMode": "both",
  "chromium": "/usr/bin/chromium",

  "cookies": [
    { "name": "auth", "value": "b64json:{\"id\":1,\"username\":\"admin\",\"role\":\"admin\",\"func\":{},\"permissions\":[\"*\"]}" }
  ],
  "localStorage": { "token": "faketoken", "isLogin": "1" },

  "neutralize": {
    "fields": ["response_code", "code", "errno", "ret", "status"],
    "success": 0,
    "flags": { "success": true, "message": "ok" }
  },
  "forward": true,
  "loginUrlPattern": "/login",
  "apiPattern": "/api/|/rest/|/graphql",

  "mockTier": "L1+L2",
  "recordDetail": true,
  "observe": {
    "storageReads": false,
    "cookieReads": false,
    "xhrHeaders": true
  },
  "neutralizeVueRouter": true,
  "stubs": [
    {
      "match": "permissions/all|/menu|role_permissions",
      "body": {
        "response_code": 0, "code": 0,
        "data": {
          "permissions": ["*"],
          "menus": [
            { "name": "dashboard", "path": "/dashboard", "show": true, "children": [] },
            { "name": "alert", "path": "/alert", "show": true, "children": [] }
          ]
        }
      }
    }
  ],

  "explore": {
    "clickTabs": true,
    "clickTables": true,
    "pushStateFallback": true,
    "maxMenuItems": 50
  },

  "routes": ["/dashboard", "/alert", "/asset", "/device", "/report", "/config", "/system"],
  "waitMs": 1500, "perRouteMs": 900, "headless": true,
  "waitUntil": "domcontentloaded",
  "routeTimeout": 12000,
  "proxy": "",

  "captureResponses": true, "recordWs": true, "respMax": 600
}
```

Field reference:
- `runtimeMode`: `depth` (Puppeteer), `coverage` (browser MCP), `both`
- `cookies[].value` prefixes: `b64json:` → base64(JSON); `json:` → raw JSON; no prefix → literal
- `forward: true` forwards real requests and rewrites code fields; `false` stubs fully offline
- `mockTier`: preload layers enabled in coverage mode, e.g. `L1+L2`, `L1+L2+L3`
- `routes` comes from `routes.txt`; after forging the menu, the harness appends `<a href>` automatically
- `captureResponses` / `recordWs` only take effect in depth mode
- `waitUntil`: use `domcontentloaded` for large SPAs to avoid `networkidle2` hangs
- `routeTimeout`: per-route `page.goto` timeout (milliseconds)
- `proxy`: Puppeteer `--proxy-server`; you can also set `HTTP_PROXY` / `HTTPS_PROXY`

### B1. Dual-Stub Template (role_permissions + permissions/all)

```json
"stubs": [
  {
    "match": "role_permissions",
    "body": {
      "response_code": 0,
      "data": {
        "permissions": ["MONITOR", "MONITOR_ALERT", "THREAT", "ASSETS_RISK"],
        "role_type": "SUPER_ADMIN"
      }
    }
  },
  {
    "match": "permissions/all",
    "body": {
      "response_code": 0,
      "data": [
        {
          "code": "MONITOR",
          "position": 1,
          "children": [
            { "code": "MONITOR_ALERT", "position": 1, "children": [] }
          ]
        }
      ]
    }
  }
]
```

The outer field names (`response_code` / `code` / `data`) must match the A2 interceptor gate; `permissions` must cover every leaf code in the tree.

---

## C. Coverage Mode: preload Configuration

Edit the `CONFIG` object at the top of `scripts/preload.js`, or replace it before injecting via CDP:

```javascript
const CONFIG = {
  loginPathRe: /\/(login|signin)(\/|$|\?)/i,
  mockTier: 'L1+L2',
  forward: true,
  recordDetail: true,
  extractUrlsFromResponse: true,
  neutralizeVueRouter: true,
  observe: { storageReads: false, cookieReads: false, xhrHeaders: true },
  neutralize: { fields: ['response_code', 'code'], success: 0 },
  stubs: [ /* same as config.json stubs */ ],
  apiPattern: /\/(api|apis|v\d+|dev|internal|graphql)\//i,
};
```

Verify: `window.__API_RECON_PRELOAD__ === true` and the pathname is stable.

Export the recorded results:

```javascript
JSON.stringify({
  apis: [...window.__API_RECON_LOG__],
  detail: window.__API_RECON_DETAIL__,
  routes: [...(window.__API_RECON_ROUTES__ || [])],
  observe: window.__API_RECON_OBSERVE__,
}, null, 2)
```

---

## D. preload / runtime Hook Capabilities

Browser hook capabilities built into preload (coverage) and runtime_harvest (depth), and their coverage:

| Hook capability | Value for API discovery | Coverage |
|---|---|---|
| Hook fetch / XHR.open | Record request URL/method | ✅ `recordDetail` + `__API_RECON_LOG__` |
| Hook XHR.setRequestHeader | Discover headers such as Authorization | ✅ `observe.xhrHeaders` |
| Hook localStorage/cookie reads | Confirm session key names | ⚠️ Optional `observe.storageReads/cookieReads` |
| Vue route retrieval | Complete frontendRoutes | ✅ `__API_RECON_ROUTES__` (loaded routes) |
| Vue route guard neutralization / login-redirect blocking | Unlock module-triggered APIs | ✅ `neutralizeVueRouter` + native redirect neutralization |
| React route retrieval | Supplement routes | ⚠️ Static + click; no dedicated hook |
| Page-navigation blocking (login path) | Keep the page for analysis | ⚠️ Blocks only login paths, so business navigation is not disrupted |
| Hook crypto libraries (CryptoJS/SM, etc.) | Encrypted params → plaintext API body | ❌ Must hook the encryption function's arguments manually; record conclusions in config |
| Anti-debugging bypass | Otherwise runtime cannot record APIs | ❌ Must handle manually; static analysis still works |

---

## E. Endpoint Extraction Regex (When Static Results Are Sparse)

Loosen `extract_endpoints` in `harvest_static.py`, or do it manually:

```bash
grep -rhoaE '"/[a-z][A-Za-z0-9_/\-]{3,}"' js | sort -u
grep -rhoaE '/api/[a-zA-Z0-9_./-]+' js | sort -u
```

---

## F. Troubleshooting

| Symptom | Cause → remedy |
|---|---|
| Few static APIs | Endpoint dialect mismatch → loosen the regex (Section D) |
| Chunk count ≪ manifest | CSS-only or undeployed chunks; 404s were already retried |
| Runtime still shows the login page | Rendering gate error → recheck A1: key name, container, encoding, domain |
| Shell loads but modules are blank | Content gate → forge the menu (A3); `routes` paths may be wrong |
| Only bootstrap/locale per route | Permission codes incomplete → Section I permission-tree reconstruction; check the `role_permissions` + `permissions/all` dual stubs |
| Sidebar items present but subpages blank | Tree missing intermediate nodes, or codes do not match `userRouteAuth` |
| Every API redirects to login | Interceptor gate → confirm `neutralize`; nested fields may require extending the walk logic |
| Zero WS frames | Must subscribe after user interaction; increase `perRouteMs` |
| Empty response bodies | Real responses only with `forward: true` |
| Chromium missing | Install chromium or set `config.chromium` / `CHROMIUM` |
| Still redirected to login despite many mocks | Hook applied too late or missing `location.href` setter → use document-start + preload |
| Lists entirely empty | Empty L3 arrays are normal; keep clicking tabs/settings/details |
| Redux action mistaken for a route | Filter out internal paths containing get/set/change/clear/toggle/upload |
| Vue still redirects to login | Preload not at document-start → change injection timing; or manually clear guards when `neutralizeVueRouter: false` |
| URL in response but not in log | Enable `extractUrlsFromResponse`; or extract manually from `__API_RECON_DETAIL__` |
| Authorization header name unknown | Enable `observe.xhrHeaders` or check request headers in DevTools |
| Runtime extremely slow / timing out | Switch to `waitUntil: domcontentloaded`; lower `routeTimeout`; avoid `networkidle2` |
| Proxy connection failure | Check `proxy` / environment variables; Puppeteer and curl must use the same proxy port |

---

## G. Hardened Targets

When the server progressively validates the session (unforgeable signed cookies, server-rendered menus that cannot be stubbed), the runtime stalls at the shell. Expected behavior:

- **Static analysis is sufficient for endpoint enumeration** — module paths are in the code
- If authorized, run the same harness with a **real session**: `forward: true`, no neutralization needed, capturing real methods/params/responses

---

## H. Single-Task Checklist

1. Confirm the authorized scope
2. **Read** `scripts/harvest_static.py` → adapt it to the target → run → review `api_static.txt` and `routes.txt`
3. **Phase 1b**: expand around path anchors + binding layers → `param_candidates.json` (Section J)
4. Reverse-engineer A1/A2/A3 → write the site-specific `config.json`
5. **Read and adapt** `runtime_harvest.js` / `preload.js` before running
6. `runtimeMode=depth`: `npm install` → run the adapted harvest script
7. `runtimeMode=coverage/both`: inject the adapted preload at document-start → dynamic enumeration via browser MCP + **parameter trigger matrix**
8. If modules do not render → **Section I permission-tree reconstruction** → patch stubs → rerun
9. Multi-sample parameter diff + back-inference from errors → `params_merged.json`
10. Merge → `site_map.json` + `api_merged.txt`; honestly document coverage, gaps, and script change points

---

## I. Permission-Tree Reconstruction (Phase 4 Deepening)

Use this when a simple forged `menus: [{ path, show: true }]` is ineffective and submodules still fail to mount.

### I1. Locate the Auth Module

```bash
grep -l 'userRouteAuth' js/*.js
grep -l 'routeMap\|routeLink' js/*.js
grep -rhoaE 'getResultTree|role_permissions|permissions/all' js | head
```

Record the **permission API path**, **response field names**, and **consumer chunk filename**.

### I2. Extract routeMap

```bash
python3 scripts/extract_route_map.py recon/js recon/
# Produces recon/route_map.json
```

If `[!] no routeMap pattern found`, loosen the regex in `extract_route_map.py` or grep manually:

```bash
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head -20
```

### I3. Build the Permission Tree + Stub

```bash
python3 scripts/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Script logic:
1. Parse `userRouteAuth={MONITOR:{url:...},...}` (including the webpack alias `He=o.DASHBOARD`)
2. Resolve aliases to real paths using `route_map.json`
3. Infer parents from code prefixes (`MONITOR_ALERT` → `MONITOR`)
4. Output `permissions_tree.json`, `permissions_all_stub.json`, and `role_permissions_stub.json`
5. With `--config`, automatically write `stubs` into `config.json` and extend `routes`

**Adapt to the target** (at the top of the script):
- `DEFAULT_ROOTS`: list of top-level module codes
- `DEFAULT_PREFIX_PARENT`: `PREFIX_` → parent mapping
- `DEFAULT_EXTRA_PARENT`: orphan nodes whose relation is not prefix-based

### I4. Verify Stub Consistency

```bash
# The permissions count should be approximately the number of userRouteAuth entries
wc -l recon/perm_codes_all.txt
# routes should cover all link values in route_map
python3 -c "import json; m=json.load(open('recon/route_map.json')); r=set(json.load(open('recon/config.json'))['routes']); print('missing', [v['link'] for v in m.values() if v['link'] not in r])"
```

### I5. Rerun Runtime and Compare

```bash
node recon/runtime_harvest.js recon/config.json
# Compare entry counts in runtime_api.json before and after forging; check whether module APIs appear for /attack, /asset, etc.
```

| Before forging | After forging (success) |
|---|---|
| Same 3–5 bootstrap calls on every route | Different routes trigger different module APIs |
| Only `/api/locale/language` | Module endpoints such as `/api/web/...` appear |
| Only a few routes in `routes.txt` | `routes` contains 80–110+ entries from route_map |

### I6. If It Still Fails

- **Coverage mode**: click sidebar items and tabs; permission gating may only request data after interaction
- **Stub fields**: compare the real API (curl + real session) with the stub's nesting
- **Additional guards**: grep for button-level checks such as `hasPermission|checkRole|func.`, and extend `role_permissions.permissions`
- **Static fallback**: module API paths remain in `api_static.txt`; runtime only supplements METHOD/body. Keep parameters in `param_candidates.json` + recorded samples

---

## J. Parameter Reverse Engineering (Phases 1b / 5b / 5c)

**Methodology, not a generic script.** Find paths with regex; find parameters by expanding around anchors + UI binding chains + multi-sample diffs + inference from errors.

### J1. Expand Around Anchors — Find the Payload Object from a Path

```bash
# Use paths known from Phase 1 as anchors
grep -n '"/api/user/list"' js/*.js
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' js | head
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' js | head
grep -rhoaE '(get|post|put|delete|patch)\([^,]+,\s*\{' js | head
```

### J2. Wrappers and Transport Formats

```bash
# axios / unified request wrapper
grep -rhoaE '(axios|request)\.(get|post|put|delete|patch)\(' js | head
grep -rhoaE 'interceptors\.(request|response)' js | head

# GraphQL
grep -rhoaE '(query|mutation)\s+\w+|gql`|graphql\(' js | head
grep -rhoaE '\$[a-zA-Z_]+\s*:\s*(Int|String|Boolean|\[)' js | head

# FormData / multipart
grep -rhoaE 'FormData|\.append\(' js | head

# Path parameters
grep -rhoaE 'path:\s*"/[^"]*:[^"]+"' js | head
grep -rhoaE 'useParams|route\.params|\$route\.params' js | head
```

### J3. Validation Gate — Required / Format / Enum

```bash
grep -rhoaE '(required|message|pattern|enum|validator)\s*:' js | head
grep -rhoaE 'yup\.|zod\.|async-validator|Form\.Item|a-form-item|el-form-item' js | head
grep -rhoaE 'rules\s*:\s*\[|name:\s*["\'][a-zA-Z_]+["\']' js | head
grep -rhoaE 'label.*value|options\s*:\s*\[' js | head
```

### J4. Binding Layer — Form → API

```bash
grep -rhoaE 'onFinish|handleSubmit|getFieldsValue|validateFields' js | head
grep -rhoaE '(pick|omit|transform|dayjs|moment)\(' js | head
```

Runtime fallback: in DevTools → Network → select the request → **Initiator** (call stack), then trace upward from `fetch`/`send` to the function that assembles the payload.

### J5. Encrypted Parameters

```bash
grep -rhoaE 'encrypt|decrypt|sign|CryptoJS|sm2|sm3|sm4|RSA|AES' js | head
```

**Do not guess fields from ciphertext** — Hook the encryption function's **arguments** and record the plaintext payload before encryption; record conclusions in `config.json` / `param_candidates.json`.

### J6. Parameter Trigger Matrix (required in Phase 3)

For each module, record each operation once and diff the request body/query:

| Operation | Focus |
|---|---|
| Initial list load | Default pagination values |
| Search | keyword, filters |
| Advanced filter | optional fields |
| Create/edit | full entity |
| Batch/export | `ids[]`, `exportType` |
| Sort/paginate | `sortField`, `order` |

Produce `param_samples.json`: `[{ "path", "method", "action": "search", "body", "query", "headers" }]`

### J7. Confidence Rules

| Confidence | Condition |
|---|---|
| **High** | Static callsite + runtime ≥2 consistent samples |
| **Medium** | Static only, or only 1 runtime observation |
| **Low** | Inferred from responses/errors, not re-verified |
| **Pending trigger** | Field known statically; UI/permissions have not reached it |

### J8. Quick Recipes by Scenario

| Scenario | Sequence |
|---|---|
| REST list page | J1 payload object → J6 four-way diff → J3 rules |
| Create/edit form | J3 Form name → J4 submit chain → runtime submit + deliberately leave a field empty to observe the 400 |
| GraphQL | J2 variables declarations → record variables for each operation at runtime |
| Encrypted body | J5 Hook arguments → fields before encryption are the real params |

### J9. Mapping to api-recon Phases

| api-recon | Parameter recon |
|---|---|
| Phase 1 static | J1 expand around anchors |
| Phase 2 A2 interceptor | Globally injected fields (tenantId, sign) |
| Phase 3 runtime | J6 trigger matrix + `param_samples.json` |
| Phase 4 permission tree | Forms differ across modules → fields are triggered only when permissions allow |
| Phase 5 merge | `params_merged.json` + confidence; do not infer required fields from a single sample |

### J10. Troubleshooting

| Symptom | Remedy |
|---|---|
| Field exists statically but never appears at runtime | Mark "awaiting trigger"; expand the permission tree / click advanced filters / cycle through each option of linked selects |
| Same path with different body shapes | Normal — record each by `action`; do not force a merged schema |
| Stub response is fake but you want the params | **Inspect the outbound request** body/headers; do not infer from the stub response |
| 400 reports a nested field | Check the outer wrapper: `data` / `bizData` / `variables` |
| GraphQL shows only operation names | Expand the `variables` JSON; statically search for `$var: Type` |

---

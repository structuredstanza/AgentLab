-- ARTEX PostgreSQL schema (single source of truth)
-- Idempotent: safe to re-run (IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS).

-- =====================================================================
-- 0. Common: updated_at trigger
-- =====================================================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

-- Safe text→inet conversion: invalid values return NULL instead of raising 22P02. assets.ip is free text
-- (the Agent / asset API may write hostnames into it), so a bare a.ip::inet cast would let a single bad row break the whole
-- enterprise ownership recalculation statement. Callers use try_inet(...) IS NULL to find these rows and raise alerts.
-- pg_input_is_valid is not used because it requires PG16+, and this must stay compatible with older existing databases.
CREATE OR REPLACE FUNCTION try_inet(value text) RETURNS inet AS $$
BEGIN
    RETURN value::inet;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- =====================================================================
-- A. Asset layer: companies / assets / company_scope
-- =====================================================================

CREATE TABLE IF NOT EXISTS companies (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    nkey       TEXT NOT NULL UNIQUE,
    logo       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_companies_nkey ON companies(nkey);
DROP TRIGGER IF EXISTS trg_companies_upd ON companies;
CREATE TRIGGER trg_companies_upd BEFORE UPDATE ON companies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS assets (
    id              BIGSERIAL PRIMARY KEY,
    type            TEXT NOT NULL CHECK (type IN (
                        'root_domain','ip','subdomain','app','service','endpoint'
                    )),
    company_id      BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    -- explicit: caller/user selected the company; scope: derived from company_scope.
    -- Existing installations are conservatively migrated as explicit so a scope
    -- rebuild can never erase a historical manual association.
    company_source  TEXT NOT NULL DEFAULT 'explicit'
                    CHECK (company_source IN ('explicit','scope')),
    task_ids        BIGINT[] NOT NULL DEFAULT '{}',
    domain          TEXT,
    root_domain     TEXT,
    ip              TEXT,
    c_segment       CIDR,
    port            INTEGER CHECK (port BETWEEN 1 AND 65535),
    icp             TEXT,
    bound_domains   TEXT[]  NOT NULL DEFAULT '{}',
    open_ports      JSONB[] NOT NULL DEFAULT '{}',
    record_type     TEXT,
    record_value    TEXT[],
    bundle_id       TEXT,
    app_name        TEXT,
    category        TEXT,
    app_description TEXT,
    app_icp         TEXT,
    url             TEXT,
    service_type    TEXT CHECK (service_type IN ('http','other')),
    service_name    TEXT,
    favicon_mmh3    TEXT,
    status_code     INTEGER,
    content_length  BIGINT,
    page_title      TEXT,
    technologies    TEXT[]  NOT NULL DEFAULT '{}',
    auth            JSONB[] NOT NULL DEFAULT '{}',
    method          TEXT,
    params          JSONB[] NOT NULL DEFAULT '{}',
    extra           JSONB   NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_root_domain  ON assets(domain) WHERE type = 'root_domain';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_ip           ON assets(ip)     WHERE type = 'ip';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_subdomain    ON assets(domain, COALESCE(record_type,'')) WHERE type = 'subdomain';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_app_bundle   ON assets(bundle_id) WHERE type = 'app' AND bundle_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_app_name     ON assets(app_name)  WHERE type = 'app' AND bundle_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_service_http ON assets(url) WHERE type = 'service' AND service_type = 'http';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_service_other
    ON assets(COALESCE(domain,''), COALESCE(ip,''), port, service_name) WHERE type = 'service' AND service_type = 'other';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_endpoint     ON assets(url, method) WHERE type = 'endpoint';
CREATE INDEX IF NOT EXISTS idx_av2_company      ON assets(company_id)       WHERE company_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_company_type ON assets(company_id, type) WHERE company_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_task_ids     ON assets USING GIN(task_ids);
CREATE INDEX IF NOT EXISTS idx_av2_domain       ON assets(domain)      WHERE domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_root_domain  ON assets(root_domain) WHERE root_domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_ip           ON assets(ip)          WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_c_segment    ON assets USING GIST(c_segment inet_ops) WHERE c_segment IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_technologies ON assets USING GIN(technologies) WHERE type = 'service';
CREATE INDEX IF NOT EXISTS idx_av2_bound_domains ON assets USING GIN(bound_domains) WHERE type = 'ip';
CREATE INDEX IF NOT EXISTS idx_av2_open_ports   ON assets USING GIN(open_ports)    WHERE type = 'ip';
CREATE INDEX IF NOT EXISTS idx_av2_last_seen    ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_av2_type_seen    ON assets(type, last_seen DESC);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS company_source TEXT;
UPDATE assets SET company_source = 'explicit' WHERE company_source IS NULL;
ALTER TABLE assets ALTER COLUMN company_source SET DEFAULT 'explicit';
ALTER TABLE assets ALTER COLUMN company_source SET NOT NULL;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_company_source_check;
ALTER TABLE assets ADD CONSTRAINT assets_company_source_check
    CHECK (company_source IN ('explicit','scope'));
-- Liveness: when a direct (proxy-free) probe last found this host unreachable.
-- last_seen records contact; this records the absence that ends an engagement
-- rather than looping on it. Cleared on the next successful contact.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_unreachable_at TIMESTAMPTZ;
DROP TRIGGER IF EXISTS trg_av2_upd ON assets;
CREATE TRIGGER trg_av2_upd BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS company_scope (
    id         BIGSERIAL PRIMARY KEY,
    company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('domain','ip','cidr','icp','keyword')),
    domain     TEXT,
    net        CIDR,
    value      TEXT,
    raw        TEXT NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_sv2_domain UNIQUE (company_id, domain),
    CONSTRAINT uq_sv2_net    UNIQUE (company_id, net),
    CONSTRAINT ck_company_scope_payload CHECK (
        (kind = 'domain' AND domain IS NOT NULL AND net IS NULL AND value IS NULL)
        OR (kind IN ('ip','cidr') AND domain IS NULL AND net IS NOT NULL AND value IS NULL)
        OR (kind IN ('icp','keyword') AND domain IS NULL AND net IS NULL AND value IS NOT NULL)
    )
);
-- Existing installations need the new text payload and expanded kind check.
ALTER TABLE company_scope ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE company_scope DROP CONSTRAINT IF EXISTS company_scope_kind_check;
ALTER TABLE company_scope ADD CONSTRAINT company_scope_kind_check
    CHECK (kind IN ('domain','ip','cidr','icp','keyword'));
ALTER TABLE company_scope DROP CONSTRAINT IF EXISTS ck_company_scope_payload;
ALTER TABLE company_scope ADD CONSTRAINT ck_company_scope_payload CHECK (
    (kind = 'domain' AND domain IS NOT NULL AND net IS NULL AND value IS NULL)
    OR (kind IN ('ip','cidr') AND domain IS NULL AND net IS NOT NULL AND value IS NULL)
    OR (kind IN ('icp','keyword') AND domain IS NULL AND net IS NULL AND value IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_sv2_domain  ON company_scope(domain)   WHERE kind = 'domain';
CREATE INDEX IF NOT EXISTS idx_sv2_net     ON company_scope USING GIST(net inet_ops) WHERE kind IN ('ip','cidr');
CREATE UNIQUE INDEX IF NOT EXISTS uq_sv2_value ON company_scope(company_id, kind, value) WHERE kind IN ('icp','keyword');
CREATE INDEX IF NOT EXISTS idx_sv2_icp ON company_scope(value) WHERE kind = 'icp';
CREATE INDEX IF NOT EXISTS idx_sv2_company ON company_scope(company_id);

-- =====================================================================
-- B. Reasoning exploration layer
-- =====================================================================
CREATE TABLE IF NOT EXISTS explorations (
    id          BIGSERIAL PRIMARY KEY,
    description TEXT,
    goal        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','achieved','failed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- cold-digest (§2.3): per-task planner round counter — bumped once each time the
-- planner wakes and processes a round. Drives the ≥R cold-node debounce (measured in
-- this exploration's own rounds, not global node ids or wall-clock).
ALTER TABLE explorations ADD COLUMN IF NOT EXISTS round_no BIGINT NOT NULL DEFAULT 0;
DROP TRIGGER IF EXISTS trg_exp_upd ON explorations;
CREATE TRIGGER trg_exp_upd BEFORE UPDATE ON explorations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploration_nodes (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}',
    priority       INT  NOT NULL DEFAULT 0,
    state          TEXT NOT NULL DEFAULT 'open',
    origin         TEXT,
    owner          TEXT,
    blocked_reason TEXT,
    delete_reason  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ,
    CONSTRAINT ck_node_kind CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest')),
    CONSTRAINT ck_node_state CHECK (
        (kind='begin'   AND state IN ('open')) OR
        (kind='intent'  AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
        (kind='goal'    AND state IN ('open','met','abandoned')) OR
        (kind='fact'    AND state IN ('confirmed','dismissed','origin')) OR
        (kind='finding' AND state IN ('confirmed','dismissed')) OR
        (kind='hint'    AND state IN ('active','consumed')) OR
        (kind='digest'  AND state IN ('active','superseded'))
    )
);
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS blocked_reason TEXT;
-- Intent soft delete: when state='deleted', delete_reason records the deletion reason entered by the user.
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS delete_reason TEXT;
-- cold-digest (§2.3/§5.3): content_version bumps on any change that could alter a
-- digest body (summary/state/confidence); cold_since_round stamps the planner round
-- a node most recently went from "has a live downstream branch" to none (NULL = hot).
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS content_version  INT    NOT NULL DEFAULT 0;
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS cold_since_round BIGINT;
-- ck_node_kind: existing installs predate the 'digest' kind — recreate to allow it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='exploration_nodes'::regclass
          AND conname='ck_node_kind'
          AND pg_get_constraintdef(oid) NOT LIKE '%digest%'
    ) THEN
        ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_kind;
        ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_kind
            CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest'));
    END IF;
END $$;
-- ck_node_state: recreate when it lacks the 'paused' (older), 'superseded' (digest rev),
-- or 'deleted' (intent soft-delete rev) branches.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='exploration_nodes'::regclass
          AND conname='ck_node_state'
          AND (pg_get_constraintdef(oid) NOT LIKE '%paused%'
               OR pg_get_constraintdef(oid) NOT LIKE '%superseded%'
               OR pg_get_constraintdef(oid) NOT LIKE '%deleted%')
    ) THEN
        ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_state;
        ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_state CHECK (
            (kind='begin'   AND state IN ('open')) OR
            (kind='intent'  AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
            (kind='goal'    AND state IN ('open','met','abandoned')) OR
            (kind='fact'    AND state IN ('confirmed','dismissed','origin')) OR
            (kind='finding' AND state IN ('confirmed','dismissed')) OR
            (kind='hint'    AND state IN ('active','consumed')) OR
            (kind='digest'  AND state IN ('active','superseded'))
        );
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_expnodes_part     ON exploration_nodes(exploration_id, kind);
CREATE INDEX IF NOT EXISTS idx_expnodes_frontier ON exploration_nodes(exploration_id, priority DESC)
    WHERE kind='intent' AND state='open';
DROP TRIGGER IF EXISTS trg_expnodes_upd ON exploration_nodes;
CREATE TRIGGER trg_expnodes_upd BEFORE UPDATE ON exploration_nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploration_edges (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    src_id         BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    dst_id         BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    rel            TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, src_id, rel, dst_id),
    CONSTRAINT ck_edge_noself CHECK (src_id <> dst_id),
    CONSTRAINT ck_edge_rel CHECK (rel IN ('spawns','derived_from','yields','proves','covers'))
);
CREATE INDEX IF NOT EXISTS idx_expedges_src ON exploration_edges(src_id, rel);
CREATE INDEX IF NOT EXISTS idx_expedges_dst ON exploration_edges(dst_id, rel);
-- cold-digest (§1): the 'covers' relation (digest→member) postdates shipped installs,
-- whose rel CHECK is an inline auto-named constraint. Find and recreate it as ck_edge_rel.
DO $$
DECLARE cname text;
BEGIN
    SELECT conname INTO cname FROM pg_constraint
     WHERE conrelid='exploration_edges'::regclass AND contype='c'
       AND pg_get_constraintdef(oid) LIKE '%rel%'
       AND pg_get_constraintdef(oid) NOT LIKE '%covers%';
    IF cname IS NOT NULL THEN
        EXECUTE 'ALTER TABLE exploration_edges DROP CONSTRAINT '||quote_ident(cname);
        ALTER TABLE exploration_edges ADD CONSTRAINT ck_edge_rel
            CHECK (rel IN ('spawns','derived_from','yields','proves','covers'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS exploration_anchors (
    node_id   BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    asset_id  BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_anchor_asset ON exploration_anchors(asset_id);

-- task_constraints: operator-authored operation constraints (allow/deny) for a task.
-- Extracted by the goals decomposer at round 0 (from goal/description), editable at
-- runtime by the main agent + overview "constraint management". Injected into the planner/worker system
-- prompt each round (config-gated) to keep exploration within the operator's boundary.
CREATE TABLE IF NOT EXISTS task_constraints (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('allow','deny')),
    text           TEXT NOT NULL,
    origin         TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_constraints_exp ON task_constraints(exploration_id);

CREATE TABLE IF NOT EXISTS activity (
    id                 BIGSERIAL PRIMARY KEY,
    exploration_id     BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    node_id            BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    metadata           JSONB NOT NULL DEFAULT '{}',
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE activity ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
-- main_seg segments the main-agent session into resettable conversations: a new
-- main session bumps the segment so its transcript + activity start clean while the
-- task's graph/assets/goal are untouched. NULL == legacy rows == segment 0 (the
-- original session). Only worker='mainagent' rows carry it.
ALTER TABLE activity ADD COLUMN IF NOT EXISTS main_seg INTEGER;
CREATE INDEX IF NOT EXISTS idx_act_node  ON activity(exploration_id, node_id, id);
CREATE INDEX IF NOT EXISTS idx_act_since ON activity(exploration_id, id);
CREATE INDEX IF NOT EXISTS idx_act_tool_call ON activity(exploration_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');
-- Main/Plan history pages filter by worker (both carry NULL node_id, so idx_act_node
-- can't distinguish them); this covers reverse pagination of those sessions.
CREATE INDEX IF NOT EXISTS idx_act_worker ON activity(exploration_id, worker, id);
-- Main-session pages filter by segment on top of worker='mainagent'; this partial
-- index covers reverse pagination within one segment.
CREATE INDEX IF NOT EXISTS idx_act_main_seg ON activity(exploration_id, main_seg, id)
    WHERE worker='mainagent';
-- Task-list polls aggregate result usage and find the latest event repeatedly.
-- Cover the token columns for index-only aggregation and the timestamp order for
-- per-exploration latest-activity lookups.
CREATE INDEX IF NOT EXISTS idx_act_result_usage ON activity(exploration_id)
    INCLUDE (input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
    WHERE kind='result';
CREATE INDEX IF NOT EXISTS idx_act_latest ON activity(exploration_id, created_at DESC);

-- main_sessions records the resettable main-agent conversation segments of a task.
-- Segment 0 (the original session) is implicit and never stored; this table holds
-- only the extra segments created by "New Session" (seq >= 1). The current segment is
-- MAX(seq) or 0. Each segment gets its own transcript file + activity slice; the
-- task's exploration graph/assets/goal are shared and never reset.
CREATE TABLE IF NOT EXISTS main_sessions (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    seq            INTEGER NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, seq)
);

-- =====================================================================
-- C. LLM profiles
-- =====================================================================
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS llm_profiles (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    format           TEXT NOT NULL CHECK (format IN ('openai','anthropic','openai-responses','antigravity','ollama')),
    auth_method      TEXT NOT NULL DEFAULT 'api_key' CHECK (auth_method IN ('api_key','claude_code','codex','antigravity','custom')),
    base_url         TEXT,
    proxy            TEXT,
    model            TEXT NOT NULL,
    api_key          TEXT,
    api_key_hint     TEXT,
    rate_per_second  DOUBLE PRECISION NOT NULL DEFAULT 0,
    rate_per_minute  DOUBLE PRECISION NOT NULL DEFAULT 0,
    context_window_k INTEGER NOT NULL DEFAULT 0,
    -- Split the thinking parameter into two independent fields: thinking_type = thinking switch (''/disabled/enabled/adaptive),
    -- reasoning_effort = thinking intensity (''/low/medium/high/xhigh/max), with no coupling between them.
    reasoning_effort TEXT NOT NULL DEFAULT '',
    thinking_type    TEXT NOT NULL DEFAULT '',
    is_default       BOOLEAN NOT NULL DEFAULT false,
    -- Rotation (failover) parameters; see docs/LLM\u8f6e\u8be2\u8bbe\u8ba1.md:
    --   priority     Rank order; the higher the value, the earlier it is selected. The activated configuration (is_default) always comes first in the chain, regardless of this value.
    --   pool_exclude true=not used as a failover target (can still be explicitly bound to an agent/task for use).
    priority         INTEGER NOT NULL DEFAULT 0,
    pool_exclude     BOOLEAN NOT NULL DEFAULT false,
    -- streaming=true (default) uses streaming SSE; false uses true non-streaming (stream:false, a single JSON response).
    streaming        BOOLEAN NOT NULL DEFAULT true,
    -- Output token limit for a single reply. 0 = the field is not sent, and the server-side default applies, preserving the existing behavior.
    -- This is a different thing from context_window_k (the total model capacity, used locally only for the compression threshold): this value is sent with the request.
    max_tokens       INTEGER NOT NULL DEFAULT 0,
    -- Which request field name is used for the output limit; only applies when format='openai':
    --   ''                      = max_tokens (default, compatible with most gateways)
    --   'max_completion_tokens' = new field; OpenAI reasoning models (o-series/GPT-5) only recognize this one,
    -- Sending max_tokens will be rejected with unsupported_parameter.
    -- anthropic (max_tokens is required) and openai-responses (max_output_tokens) use their own field names and are not affected by this value.
    max_tokens_field TEXT NOT NULL DEFAULT '',
    -- Custom session header: when non-empty, every request carries an HTTP header with this name, and the header value is the current running session id
    -- (chat session / worker intent). Used by some gateways that do prompt caching or sticky routing keyed on a session-id header. ''= do not send.
    session_header_key TEXT NOT NULL DEFAULT '',
    -- Retry override: count 0 = use the global default / -1 = disable / >0 = use this value; interval 0 = use the default exponential backoff / >0 = fixed milliseconds.
    -- The three groups correspond to connection-establishment retries, empty-response retries, and same-provider safety-window retries; see the comment at the ALTER below for details.
    retry_connect_attempts    INTEGER NOT NULL DEFAULT 0,
    retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0,
    retry_empty_attempts      INTEGER NOT NULL DEFAULT 0,
    retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0,
    retry_stream_attempts     INTEGER NOT NULL DEFAULT 0,
    retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0,
    refusal_fallback JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth_grants (
    profile_id   BIGINT PRIMARY KEY REFERENCES llm_profiles(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL DEFAULT '',
    expiry       TIMESTAMPTZ NOT NULL,
    account_id   TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT '',
    org_id       TEXT NOT NULL DEFAULT '',
    org_name     TEXT NOT NULL DEFAULT '',
    project_id   TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_one_default ON llm_profiles(is_default) WHERE is_default;
DROP TRIGGER IF EXISTS trg_llm_upd ON llm_profiles;
CREATE TRIGGER trg_llm_upd BEFORE UPDATE ON llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- Round-robin position / exclusion flag; backfills old databases. Default 0 / false = all configurations participate in round-robin.
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS priority     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS pool_exclude BOOLEAN NOT NULL DEFAULT false;
-- Streaming toggle; backfills old databases. Default true = keep the existing streaming behavior, so old configurations upgrade transparently.
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS streaming    BOOLEAN NOT NULL DEFAULT true;
-- Relax the format constraint to accommodate openai-responses (OpenAI Responses API); backfill the legacy database.
-- Executed on every startup, idempotent: first drop the old CHECK, then create the new CHECK that includes all three values.
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_format_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_format_check
    CHECK (format IN ('openai','anthropic','openai-responses','antigravity','ollama'));
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'api_key';
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_auth_method_check;
ALTER TABLE llm_profiles ADD CONSTRAINT llm_profiles_auth_method_check
    CHECK (auth_method IN ('api_key','claude_code','codex','antigravity','custom'));

-- Output token cap and its field name; backfill the legacy database. Default 0 / '' = do not send the cap, keep the max_tokens field name,
-- Legacy configuration behavior remains completely unchanged.
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens_field TEXT    NOT NULL DEFAULT '';
-- Same as format: drop first, then create, to ensure idempotence on every startup.
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_field_check;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_input_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_output_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_cache_read_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_cache_write_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_field_check
    CHECK (max_tokens_field IN ('','max_completion_tokens'));
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_check
    CHECK (max_tokens >= 0);
-- Custom session header name; backfill the legacy database. Default '' = not sent, legacy configuration behavior unchanged.
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS session_header_key TEXT NOT NULL DEFAULT '';

-- Per-profile retry overrides (see docs/LLM\u91cd\u8bd5\u8bbe\u8ba1.md). Each of the three groups has an "attempt count + fixed interval" pair,
-- Unified semantics: count 0 = inherit the global default, -1 = disable retries at this layer, >0 = use this value; interval 0 = inherit this layer's
-- Default to exponential backoff; >0 = use this fixed number of milliseconds instead. All defaults are 0, so existing databases/configs keep their behavior unchanged.
--   connect = connection-establishment retry (SDK doStream: connection reset/timeout/429/5xx, before the stream starts)
--   empty   = empty-response retry (SDK: completed but without any content block; openai format only)
--   stream  = retry within the same provider's safe window (in this project's task_llm: replay of a stream that drops before any output has been delivered)
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_attempts    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_attempts      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_attempts     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0;
-- Same format: delete first, then create, so every startup is idempotent. Minimum retry count is -1 (disabled); interval must not be negative.
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_retry_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_retry_check CHECK (
    retry_connect_attempts >= -1 AND retry_empty_attempts >= -1 AND retry_stream_attempts >= -1
    AND retry_connect_interval_ms >= 0 AND retry_empty_interval_ms >= 0 AND retry_stream_interval_ms >= 0);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS refusal_fallback JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Thinking toggle field thinking_type, split in one pass from the old single reasoning_effort semantics.
-- schema.sql runs on every startup, so the migration must run only once: backfill only when the column does not yet exist,
-- otherwise every startup would overwrite combinations the user later set manually. Old reasoning_effort semantics:
--   'off'                    → explicitly off  → thinking_type='disabled', strength cleared
--   'low/medium/high/max'    → on + strength   → thinking_type='enabled', strength kept
--   ''                       → not sent        → both empty (default)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'llm_profiles' AND column_name = 'thinking_type'
    ) THEN
        ALTER TABLE llm_profiles ADD COLUMN thinking_type TEXT NOT NULL DEFAULT '';
        UPDATE llm_profiles SET thinking_type = 'enabled'
            WHERE reasoning_effort IN ('low','medium','high','max');
        UPDATE llm_profiles SET thinking_type = 'disabled', reasoning_effort = ''
            WHERE reasoning_effort = 'off';
    END IF;
END $$;

-- LLM round-robin circuit-breaker state: after a config fails consecutively (insufficient balance / invalid key / rate limit), it enters a cooldown; during the cooldown
-- round-robin polling skips it directly. The in-memory state is authoritative; persisting here only keeps the cooldown window from being lost across restarts. On load, only rows that have not yet
-- expired are fetched (open_until > now). Expired rows naturally return to "normal" and wait for the next call to perform a half-open probe.
CREATE TABLE IF NOT EXISTS llm_profile_health (
    profile_id  BIGINT PRIMARY KEY REFERENCES llm_profiles(id) ON DELETE CASCADE,
    fails       INTEGER NOT NULL DEFAULT 0,  -- current consecutive failure count (reset to zero on success)
    trips       INTEGER NOT NULL DEFAULT 0,  -- cumulative number of circuit-breaker trips, used for exponential backoff of the cooldown time
    open_until  TIMESTAMPTZ,                 -- Cooldown deadline; NULL/expired = not tripped
    last_error  TEXT NOT NULL DEFAULT '',
    last_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
-- D. Task layer
-- =====================================================================
-- Global task categories are intentionally independent from task templates.
-- Deleting a category only moves its tasks back to the uncategorized bucket.
CREATE TABLE IF NOT EXISTS task_categories (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    nkey       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_categories_name ON task_categories(name, id);
DROP TRIGGER IF EXISTS trg_task_categories_upd ON task_categories;
CREATE TRIGGER trg_task_categories_upd BEFORE UPDATE ON task_categories
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS tasks (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT NOT NULL DEFAULT '',
    category_id    BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    description    TEXT NOT NULL,
    goal           TEXT NOT NULL,
    exploration_id BIGINT NOT NULL UNIQUE
                     REFERENCES explorations(id) ON DELETE RESTRICT,
    status         TEXT NOT NULL DEFAULT 'created'
                     CHECK (status IN ('created','running','paused','needs_operator','done','failed','timeout')),
    paused         BOOLEAN NOT NULL DEFAULT false,
    queued         BOOLEAN NOT NULL DEFAULT false,
    queued_at      TIMESTAMPTZ,
    queue_mode     TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    active_llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    llm_chain_revision BIGINT NOT NULL DEFAULT 0,
    company_id     BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    parent_ref     TEXT,
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300,
    plan_quiet_mode BOOLEAN NOT NULL DEFAULT true,
    llm_rotate     BOOLEAN NOT NULL DEFAULT false,
    coverage_enabled BOOLEAN NOT NULL DEFAULT true,
    pinned_at      TIMESTAMPTZ,
    first_run_at   TIMESTAMPTZ,
    deadline_at    TIMESTAMPTZ,
    archived_at    TIMESTAMPTZ,
    deleted_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tasks_alive  ON tasks(created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)          WHERE deleted_at IS NULL;
-- needs_operator: the planner stopped because the engagement cannot continue
-- without a human (an absent target, a missing credential, a blocked path).
-- It is not terminal: resuming returns the task to 'running'.
ALTER TABLE tasks DROP CONSTRAINT IF EXISTS tasks_status_check;
ALTER TABLE tasks ADD CONSTRAINT tasks_status_check
    CHECK (status IN ('created','running','paused','needs_operator','done','failed','timeout'));
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS blocked_reason TEXT NOT NULL DEFAULT '';
DROP TRIGGER IF EXISTS trg_tasks_upd ON tasks;
CREATE TRIGGER trg_tasks_upd BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- Planner heartbeat trigger interval (seconds); backfill for legacy DBs. Default 300s (5min). See docs/planner-trigger-impl-plan.md
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS plan_quiet_mode BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS llm_rotate BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS paused_at TIMESTAMPTZ;
-- Suspended state for concurrency limit; backfill for legacy DBs. true = queued due to concurrency cap, automatically started when a slot becomes available.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queued BOOLEAN NOT NULL DEFAULT false;
-- Asset coverage feature switch; backfill for legacy DBs. true (default) = compute/display test coverage, automatically accumulate test scope,
-- expose add_task_scope/list_untested_assets to the agent; false = all disabled (see task_scope.go).
-- Existing tasks default to true to preserve original behavior; company associations (task_scope kind=company) are not affected by this switch.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS coverage_enabled BOOLEAN NOT NULL DEFAULT true;
-- queued_at makes admission FIFO reflect the actual enqueue order rather than the
-- task creation order. queue_mode distinguishes first bootstrap from resuming an
-- exploration that already owns goals/history.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queue_mode TEXT NOT NULL DEFAULT '';
-- Optional task name; backfill for legacy DBs. Empty string = unnamed, frontend falls back to description when displaying.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS active_llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS llm_chain_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks(category_id, created_at DESC)
    WHERE deleted_at IS NULL AND category_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_pinned ON tasks(pinned_at DESC)
    WHERE deleted_at IS NULL AND pinned_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_archived ON tasks(archived_at DESC)
    WHERE archived_at IS NOT NULL;

-- Cold task archives retain only compact metadata in PostgreSQL. The complete
-- task payload lives in a versioned .tar.zst package under data/archives/tasks.
-- task_id stays unique so an operation can be retried safely after a restart.
CREATE TABLE IF NOT EXISTS task_archives (
    id                         BIGSERIAL PRIMARY KEY,
    task_id                    BIGINT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
    state                      TEXT NOT NULL DEFAULT 'archive_queued' CHECK (state IN (
                                   'archive_queued','archiving','archive_failed','ready',
                                   'restore_queued','restoring','restore_failed',
                                   'delete_queued','deleting','delete_failed'
                               )),
    phase                      TEXT NOT NULL DEFAULT 'queued',
    progress                   INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    error                      TEXT NOT NULL DEFAULT '',
    warnings                   JSONB NOT NULL DEFAULT '[]',
    format_version             INTEGER NOT NULL DEFAULT 2,
    archive_path               TEXT NOT NULL DEFAULT '',
    sha256                     TEXT NOT NULL DEFAULT '',
    original_size              BIGINT NOT NULL DEFAULT 0,
    compressed_size            BIGINT NOT NULL DEFAULT 0,
    task_name                  TEXT NOT NULL DEFAULT '',
    task_description           TEXT NOT NULL DEFAULT '',
    task_goal                  TEXT NOT NULL DEFAULT '',
    original_status            TEXT NOT NULL DEFAULT '',
    category_id_snapshot       BIGINT,
    category_name_snapshot     TEXT NOT NULL DEFAULT '',
    source_task_ids            BIGINT[] NOT NULL DEFAULT '{}',
    remaining_timeout_seconds  BIGINT NOT NULL DEFAULT 0,
    data_counts                JSONB NOT NULL DEFAULT '{}',
    aggregate_stats            JSONB NOT NULL DEFAULT '{}',
    archived_at                TIMESTAMPTZ,
    requested_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE task_archives ALTER COLUMN format_version SET DEFAULT 2;
CREATE INDEX IF NOT EXISTS idx_task_archives_state ON task_archives(state, requested_at, id);
CREATE INDEX IF NOT EXISTS idx_task_archives_archived ON task_archives(archived_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_task_archives_sources ON task_archives USING GIN(source_task_ids);
DROP TRIGGER IF EXISTS trg_task_archives_upd ON task_archives;
CREATE TRIGGER trg_task_archives_upd BEFORE UPDATE ON task_archives
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reusable task description/goal presets. nkey is the normalized, case-insensitive
-- identity used to reject visually equivalent duplicate names.
CREATE TABLE IF NOT EXISTS task_templates (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    nkey        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    goal        TEXT NOT NULL,
    -- Preset task categories; set to NULL when a category is deleted (consistent with tasks.category_id, does not block deletion).
    category_id     BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    -- Preset task-level intercept/allow rule snapshot (array of AssetInterceptRuleInput); applied to the new task when a template is applied.
    intercept_rules JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Backfill for existing databases (already released; columns added with IF NOT EXISTS).
ALTER TABLE task_templates ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL;
ALTER TABLE task_templates ADD COLUMN IF NOT EXISTS intercept_rules JSONB NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS idx_task_templates_updated ON task_templates(updated_at DESC, id DESC);
DROP TRIGGER IF EXISTS trg_task_templates_upd ON task_templates;
CREATE TRIGGER trg_task_templates_upd BEFORE UPDATE ON task_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Direct, read-only task context inheritance. Relations are intentionally not
-- recursive: a task sees only the source tasks explicitly chosen at creation.
CREATE TABLE IF NOT EXISTS task_relations (
    task_id        BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    source_task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, source_task_id),
    CONSTRAINT ck_task_relation_not_self CHECK (task_id <> source_task_id)
);
CREATE INDEX IF NOT EXISTS idx_task_relations_source ON task_relations(source_task_id);

-- Task/asset provenance supplements the legacy assets.task_ids association. The
-- array remains the compatibility source for existing query and cleanup paths;
-- this relation records how each association was obtained for operator review.
CREATE TABLE IF NOT EXISTS task_asset_links (
    task_id        BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    asset_id       BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source         TEXT NOT NULL DEFAULT 'system',
    source_summary TEXT NOT NULL DEFAULT '',
    source_node_id BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_task_asset_links_asset ON task_asset_links(asset_id, task_id);
CREATE INDEX IF NOT EXISTS idx_task_asset_links_node ON task_asset_links(source_node_id)
    WHERE source_node_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_asset_links_upd ON task_asset_links;
CREATE TRIGGER trg_task_asset_links_upd BEFORE UPDATE ON task_asset_links
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Keep provenance rows synchronized when existing asset upsert paths append or
-- remove task ids. Detailed callers overwrite the generic source after upsert.
CREATE OR REPLACE FUNCTION sync_task_asset_links() RETURNS trigger AS $$
BEGIN
    INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
    SELECT task.id, NEW.id, 'system', 'Auto-linked during task execution'
    FROM unnest(NEW.task_ids) AS requested(task_id)
    JOIN tasks task ON task.id=requested.task_id AND task.deleted_at IS NULL
    ON CONFLICT (task_id, asset_id) DO NOTHING;

    DELETE FROM task_asset_links link
    WHERE link.asset_id=NEW.id
      AND NOT (link.task_id=ANY(NEW.task_ids));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_assets_task_links ON assets;
CREATE TRIGGER trg_assets_task_links AFTER INSERT OR UPDATE OF task_ids ON assets
    FOR EACH ROW EXECUTE FUNCTION sync_task_asset_links();

-- Existing installations receive an auditable legacy source without rewriting
-- task_ids. Ignore stale array ids that no longer resolve to a live task.
INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
SELECT task.id, asset.id, 'legacy', 'Migrated from legacy task-asset links'
FROM assets asset
CROSS JOIN LATERAL unnest(asset.task_ids) AS requested(task_id)
JOIN tasks task ON task.id=requested.task_id AND task.deleted_at IS NULL
ON CONFLICT (task_id, asset_id) DO NOTHING;

-- Ordered task-level LLM failover chain. A quota-exhausted entry is skipped
-- until the user saves/resets the chain, which clears all failure state.
CREATE TABLE IF NOT EXISTS task_llm_profiles (
    task_id          BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    profile_id       BIGINT NOT NULL REFERENCES llm_profiles(id) ON DELETE CASCADE,
    position         INTEGER NOT NULL CHECK (position >= 0),
    status           TEXT NOT NULL DEFAULT 'ready'
                       CHECK (status IN ('ready','quota_exhausted','refused')),
    last_error       TEXT,
    exhausted_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, profile_id),
    UNIQUE (task_id, position)
);
-- CREATE TABLE IF NOT EXISTS does not rewrite an existing CHECK, so old databases are widened here.
ALTER TABLE task_llm_profiles DROP CONSTRAINT IF EXISTS task_llm_profiles_status_check;
ALTER TABLE task_llm_profiles ADD CONSTRAINT task_llm_profiles_status_check CHECK (status IN ('ready','quota_exhausted','refused'));
CREATE INDEX IF NOT EXISTS idx_task_llm_profiles_order ON task_llm_profiles(task_id, position);
CREATE INDEX IF NOT EXISTS idx_task_llm_profiles_profile ON task_llm_profiles(profile_id, task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_llm_profile ON tasks(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_active_llm_profile ON tasks(active_llm_profile_id) WHERE active_llm_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_llm_profiles_upd ON task_llm_profiles;
CREATE TRIGGER trg_task_llm_profiles_upd BEFORE UPDATE ON task_llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One-time-compatible backfill: old pinned tasks become one-entry chains. A user
-- can still clear the chain later because the update path also clears the legacy
-- llm_profile_id column, preventing this block from re-adding it on restart.
INSERT INTO task_llm_profiles(task_id, profile_id, position)
SELECT t.id, t.llm_profile_id, 0
FROM tasks t
WHERE t.llm_profile_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM task_llm_profiles x WHERE x.task_id=t.id)
ON CONFLICT DO NOTHING;
UPDATE tasks t
SET active_llm_profile_id = t.llm_profile_id
WHERE t.active_llm_profile_id IS NULL
  AND t.llm_profile_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM task_llm_profiles x WHERE x.task_id=t.id AND x.profile_id=t.llm_profile_id);

-- Task test scope (denominator for asset coverage + authorization boundary).
--   Auto-populated (source='auto'): conservative scope added for asset types explicitly inserted per worker at the top level of insertAssets:
--     (root_domain→root_domain, subdomain/service/endpoint→subdomain(host), ip→ip);
-- Assets derived through side-effect are not in scope (the hook is at the top level of the handler, while the derivation happens inside the db layer).
--   agent fills in (source='agent'): add_task_scope adds company/root_domain/subdomain/ip.
-- Coverage = share of the assets (denominator) matching active rows that are anchored by a fact node (numerator).
-- effect: include (default) or exclude. An exclude row is enforced by the tool
-- guard: a call naming that asset is refused before it runs. Added after the
-- original table so existing rows keep their meaning as includes.
CREATE TABLE IF NOT EXISTS task_scope (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword')),
    company_id  BIGINT REFERENCES companies(id) ON DELETE CASCADE,  -- kind='company'
    domain      TEXT,          -- root_domain / subdomain
    net         CIDR,          -- ip / cidr
    value       TEXT,          -- icp / keyword
    source      TEXT NOT NULL DEFAULT 'auto' CHECK (source IN ('auto','agent','manual')),
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Legacy DB upgrade: extend the task scope so that it matches the single-text-box recognition capability of the enterprise scope.
ALTER TABLE task_scope ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE task_scope DROP CONSTRAINT IF EXISTS task_scope_kind_check;
ALTER TABLE task_scope ADD CONSTRAINT task_scope_kind_check
    CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword'));
-- The effect column: 'include' (the default) or 'exclude'. An exclusion is the
-- only value the tool guard enforces. Declared here, before the dedup index
-- below, because that index is keyed on it.
ALTER TABLE task_scope ADD COLUMN IF NOT EXISTS effect TEXT NOT NULL DEFAULT 'include';
ALTER TABLE task_scope DROP CONSTRAINT IF EXISTS task_scope_effect_check;
ALTER TABLE task_scope ADD CONSTRAINT task_scope_effect_check CHECK (effect IN ('include','exclude'));
-- Deduplication: the same scope entry for the same task is stored only once (auto-fill batch inserts rely on this for idempotency).
--
-- effect is part of the key on purpose. Without it, excluding a host that
-- auto-scope had already recorded as an include hit the include row, was
-- dropped by ON CONFLICT DO NOTHING, and the operator's exclusion vanished:
-- the API reported success and the guard never fired. With effect in the key
-- both rows coexist and the checker's "an exclusion always wins" rule decides.
DROP INDEX IF EXISTS uq_task_scope;
DROP INDEX IF EXISTS uq_task_scope_v2;
CREATE UNIQUE INDEX IF NOT EXISTS uq_task_scope_v3 ON task_scope(
    task_id, kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(company_id,0), COALESCE(value,''), effect);
CREATE INDEX IF NOT EXISTS idx_ts_domain  ON task_scope(domain) WHERE kind IN ('root_domain','subdomain');
CREATE INDEX IF NOT EXISTS idx_ts_net     ON task_scope USING GIST(net inet_ops) WHERE kind IN ('ip','cidr');
CREATE INDEX IF NOT EXISTS idx_ts_company ON task_scope(company_id) WHERE kind = 'company';

-- =====================================================================
-- E. Agents / Prompt Templates / Variable Catalog
-- =====================================================================
CREATE TABLE IF NOT EXISTS agents (
    id                BIGSERIAL PRIMARY KEY,
    key               TEXT NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    name              TEXT NOT NULL,
    description       TEXT,
    role              TEXT NOT NULL,
    builtin           BOOLEAN NOT NULL DEFAULT true,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    llm_profile_id    BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    current_prompt_id BIGINT,
    max_turns         INTEGER NOT NULL DEFAULT 0,
    run_seconds       INTEGER NOT NULL DEFAULT 1200,
    web_search        BOOLEAN NOT NULL DEFAULT false,
    interactive_shell BOOLEAN NOT NULL DEFAULT false,
    wrapup_prompt     TEXT NOT NULL DEFAULT '',
    wrapup_max_turns  INTEGER NOT NULL DEFAULT 0,
    task_timeout_wrapup_prompt    TEXT NOT NULL DEFAULT '',
    task_timeout_wrapup_max_turns INTEGER NOT NULL DEFAULT 0,
    trigger_run_mode     TEXT    NOT NULL DEFAULT 'serial'  CHECK (trigger_run_mode IN ('serial','parallel')),
    trigger_merge_mode   TEXT    NOT NULL DEFAULT 'all' CHECK (trigger_merge_mode IN ('by_task','all','none')),
    trigger_max_parallel INTEGER NOT NULL DEFAULT 5,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agents_role_ck CHECK (role IN ('goals','main','planner','worker','assistant'))
);
-- Column-add migration (already released; upgrades older databases by adding the columns; fresh databases already include them in CREATE). The migration carries no CHECK: existing data in old databases is safe, and the backend write allowlist serves as the fallback.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_run_mode     TEXT    NOT NULL DEFAULT 'serial';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_merge_mode   TEXT    NOT NULL DEFAULT 'all';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_max_parallel INTEGER NOT NULL DEFAULT 5;
-- per-agent LLM binding (agent-level default model): the column has been in the CREATE above since the initial version; this ALTER is only a fallback for very old databases (idempotent).
ALTER TABLE agents ADD COLUMN IF NOT EXISTS llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;
-- run_seconds, the wall-clock default for a single run, changed from 600 to 1200: this only changes the column default (affecting newly inserted rows going forward) and does not touch existing rows in old databases.
ALTER TABLE agents ALTER COLUMN run_seconds SET DEFAULT 1200;
CREATE INDEX IF NOT EXISTS idx_agents_llm_profile ON agents(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_agents_upd ON agents;
CREATE TRIGGER trg_agents_upd BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS agent_prompts (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version       INT NOT NULL,
    template_text TEXT NOT NULL,
    note          TEXT,
    updated_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, version)
);
-- Circular foreign key: agents.current_prompt_id → agent_prompts.id (must be added after both tables are created).
DO $$ BEGIN
    ALTER TABLE agents ADD CONSTRAINT fk_agents_curprompt
        FOREIGN KEY (current_prompt_id) REFERENCES agent_prompts(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS agent_prompt_vars (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    var_name    TEXT NOT NULL,
    description TEXT,
    example     TEXT,
    source      TEXT NOT NULL CHECK (source IN ('exploration','runtime','distilled')),
    UNIQUE (agent_id, var_name)
);

-- =====================================================================
-- F. MCP service
-- =====================================================================
CREATE TABLE IF NOT EXISTS mcp_servers (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    transport   TEXT NOT NULL CHECK (transport IN ('stdio','http','sse')),
    command     TEXT,
    args        JSONB NOT NULL DEFAULT '[]',
    env         JSONB NOT NULL DEFAULT '{}',
    url         TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    insecure    BOOLEAN NOT NULL DEFAULT false,  -- http: skip TLS certificate verification (self-signed certificate scenario, issue #108)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Allow legacy MCP SSE servers on databases created before SSE support.
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_transport_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_transport_check
    CHECK (transport IN ('stdio','http','sse'));
-- Backfill missing columns in an older database (schema.sql is Exec'd on every startup).
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS insecure BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS timeout_seconds INT NOT NULL DEFAULT 120;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS last_connect_at TIMESTAMPTZ;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS last_connect_ok BOOLEAN;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS last_connect_err TEXT;
DROP TRIGGER IF EXISTS trg_mcp_upd ON mcp_servers;
CREATE TRIGGER trg_mcp_upd BEFORE UPDATE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Default data source placeholder: ScopeSentry asset sync MCP (address and auth left blank, not enabled).
-- Lets the "Asset Sync" page detect whether the data source is configured; the user enables it after filling in url and X-API-Key on the page.
-- Insert only when missing; never overwrite a server the user has already configured or enabled (schema.sql is Exec'd on every startup).
INSERT INTO mcp_servers (name, transport, url, env, enabled)
VALUES ('ScopeSentry', 'http', NULL, '{"X-API-Key":""}', false)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS mcp_tools_cache (
    id            BIGSERIAL PRIMARY KEY,
    server_id     BIGINT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    tool_name     TEXT NOT NULL,
    description   TEXT,
    schema        JSONB,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, tool_name)
);

-- =====================================================================
-- G. Visibility: agent × mcp / skill
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_visibility (
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_kind TEXT   NOT NULL CHECK (resource_kind IN ('mcp')),
    resource_id   BIGINT NOT NULL,
    mcp_tool_name TEXT   NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, resource_kind, resource_id, mcp_tool_name)
);
CREATE INDEX IF NOT EXISTS idx_vis_resource ON agent_visibility(resource_kind, resource_id);

CREATE TABLE IF NOT EXISTS agent_skill_visibility (
    agent_id   BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    skill_name TEXT   NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, skill_name)
);
CREATE INDEX IF NOT EXISTS idx_askv_skill ON agent_skill_visibility(skill_name);

-- Skill invocation ledger (see db/skill_usage.go). One row per Skill() call; records dimensions only, never the body text.
-- Intentionally no foreign key: statistics must survive task/session deletion (same reasoning as llm_usage), and a skill is itself just a
-- A directory name on the filesystem with no corresponding table.
CREATE TABLE IF NOT EXISTS skill_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    skill          TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT,
    args_len       INTEGER NOT NULL DEFAULT 0,
    -- false = the model named a skill that does not exist (miss). Rows like this are also kept: they reflect "wanted to use but none available"
    -- The gap is the basis for supplementing the skill.
    found          BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_skill_usage_skill ON skill_usage(skill, ts DESC);
CREATE INDEX IF NOT EXISTS idx_skill_usage_task  ON skill_usage(task_id);

-- Tool usage ledger (see db/tool_usage.go). One row per actual CoreTool.Call, recording only the attribution dimensions,
-- and not the tool arguments or return content. Intentionally no foreign key: statistics are retained after a task, session, or custom tool is deleted.
CREATE TABLE IF NOT EXISTS tool_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    tool_key       TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_usage_tool ON tool_usage(tool_key, ts DESC);
CREATE INDEX IF NOT EXISTS idx_tool_usage_task ON tool_usage(task_id);

-- =====================================================================
-- H. Built-in tool catalog
-- =====================================================================
CREATE TABLE IF NOT EXISTS tools (
    key         TEXT PRIMARY KEY,
    system      BOOLEAN NOT NULL DEFAULT true,
    description TEXT    NOT NULL DEFAULT '',
    schema      JSONB   NOT NULL DEFAULT '{}',
    agents      JSONB   NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT    NOT NULL DEFAULT 'builtin',
    exec        JSONB   NOT NULL DEFAULT '{}',
    deferred    BOOLEAN NOT NULL DEFAULT false,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- What SeedTool last wrote from code. SeedTool overwrites description/schema only
-- while the live value still equals its baseline, so a code change reaches an
-- existing row without ever discarding an operator edit. NULL means operator-owned:
-- the row was edited, or predates this tracking, and is never overwritten.
ALTER TABLE tools ADD COLUMN IF NOT EXISTS seeded_description TEXT;
ALTER TABLE tools ADD COLUMN IF NOT EXISTS seeded_schema JSONB;
DROP TRIGGER IF EXISTS trg_tools_upd ON tools;
CREATE TRIGGER trg_tools_upd BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- I. Sessions (chat page)
-- =====================================================================
CREATE TABLE IF NOT EXISTS conversations (
    id             BIGSERIAL PRIMARY KEY,
    agent_key      TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    pinned_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_conversations_llm_profile ON conversations(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_conversations_pinned ON conversations(pinned_at DESC) WHERE pinned_at IS NOT NULL;
DROP TRIGGER IF EXISTS trg_conversations_upd ON conversations;
CREATE TRIGGER trg_conversations_upd BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS conversation_activities (
    id                 BIGSERIAL PRIMARY KEY,
    conversation_id    BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conv_act ON conversation_activities(conversation_id, id);
CREATE INDEX IF NOT EXISTS idx_conv_act_tool_call ON conversation_activities(conversation_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');

-- =====================================================================
-- J. Agent trigger
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_triggers (
    id                          BIGSERIAL PRIMARY KEY,
    agent_key                   TEXT NOT NULL,
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    interval_sec                INTEGER NOT NULL DEFAULT 0,
    on_finding                  BOOLEAN NOT NULL DEFAULT false,
    on_goal_met                 BOOLEAN NOT NULL DEFAULT false,
    on_task_timeout             BOOLEAN NOT NULL DEFAULT false,
    on_tool_call                BOOLEAN NOT NULL DEFAULT false,
    on_task_create              BOOLEAN NOT NULL DEFAULT false,
    interval_message            TEXT NOT NULL DEFAULT '',
    finding_message             TEXT NOT NULL DEFAULT '',
    goal_message                TEXT NOT NULL DEFAULT '',
    task_timeout_message        TEXT NOT NULL DEFAULT '',
    tool_call_message           TEXT NOT NULL DEFAULT '',
    task_create_message         TEXT NOT NULL DEFAULT '',
    tool_names                  TEXT NOT NULL DEFAULT '',
    last_fire                   TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_triggers_agent ON agent_triggers(agent_key);
-- Add-column migration (already released; upgrades existing databases by adding missing columns. New databases already include these columns in CREATE, so ALTER is a no-op). Idempotent; safe to re-run on every startup.
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_tool_call        BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS tool_call_message   TEXT    NOT NULL DEFAULT '';
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS tool_names          TEXT    NOT NULL DEFAULT '';
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_task_create      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS task_create_message TEXT    NOT NULL DEFAULT '';
DROP TRIGGER IF EXISTS trg_agent_triggers_upd ON agent_triggers;
CREATE TRIGGER trg_agent_triggers_upd BEFORE UPDATE ON agent_triggers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS scheduler_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- =====================================================================
-- K. Interception rules
-- =====================================================================
CREATE TABLE IF NOT EXISTS intercept_rules (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    priority        INTEGER NOT NULL DEFAULT 0,
    match_target    TEXT NOT NULL CHECK (match_target IN ('tool_name', 'tool_input')),
    match_type      TEXT NOT NULL CHECK (match_type IN ('string', 'regex')),
    pattern         TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask')),
    message         TEXT NOT NULL DEFAULT '',
    timeout_enabled BOOLEAN NOT NULL DEFAULT true,
    timeout_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_action  TEXT    NOT NULL DEFAULT 'deny',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
DROP TRIGGER IF EXISTS trg_intercept_rules_upd ON intercept_rules;
CREATE TRIGGER trg_intercept_rules_upd BEFORE UPDATE ON intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS intercept_pending (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         BIGINT REFERENCES intercept_rules(id) ON DELETE SET NULL,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id         TEXT,
    agent_name      TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL,
    tool_input      JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'allowed', 'denied', 'timeout')),
    -- Decision reason: the rule's message on a rule match; a brief reason from the model for an LLM fallback decision (prefixed with [Model]).
    reason          TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_status ON intercept_pending(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_task   ON intercept_pending(task_id, created_at DESC);
-- Backfill for existing databases: reason column (already released; adding the column must use IF NOT EXISTS).
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
-- Detail payloads are lazy-loaded; NULL preserves the meaning of legacy history.
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS audit JSONB;
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS decision_source TEXT NOT NULL DEFAULT '';
UPDATE intercept_pending SET decision_source=CASE WHEN rule_id IS NOT NULL THEN 'rule'
 WHEN reason LIKE U&'[\6A21\578B]%' THEN 'model' ELSE 'unknown' END WHERE decision_source='';

-- =====================================================================
-- L. Vulnerability finding persistence
-- =====================================================================
CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    node_id     BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    vulnclass   TEXT NOT NULL DEFAULT '',
    -- Vulnerability name (readable title); when empty, the frontend falls back to displaying vulnclass. severity accepts the values:
    -- critical (severe) / high (high) / medium (medium) / low (low) (no CHECK added; consistent with status, validated by server whitelist).
    name        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    worker      TEXT NOT NULL DEFAULT '',
    asset_ids   JSONB NOT NULL DEFAULT '[]',
    -- Disposition status: pending (awaiting handling) / in_progress (being handled) / confirmed (confirmed) / resolved (handled) / fixed (remediated) /
    -- false_positive (false positive) / ignored (ignored) / duplicate (duplicate) / risk_accepted (risk accepted).
    -- Values are not constrained with CHECK: older databases get their columns added via the ALTER below, and a CHECK cannot be backfilled, so validation is handled uniformly by an allowlist on the server side.
    status      TEXT NOT NULL DEFAULT 'pending',
    -- Detailed vulnerability report (Markdown); empty by default, read and displayed only on the detail page, and not included in the list API to avoid payload bloat.
    report      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS name   TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS report TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_time ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, created_at DESC);
-- The "by asset" view looks up findings via asset_ids @> '[<id>]'; without this GIN index it becomes a full table scan.
CREATE INDEX IF NOT EXISTS idx_findings_asset_ids ON findings USING GIN(asset_ids jsonb_path_ops);

-- Manual retests belong to a separate session; their conclusions are stored separately from the original vulnerability's disposition status.
CREATE TABLE IF NOT EXISTS finding_retests (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    conversation_id BIGINT UNIQUE REFERENCES conversations(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','stopped')),
    verdict TEXT NOT NULL DEFAULT '' CHECK (verdict IN ('','reproduced','fixed','inconclusive')),
    notes TEXT NOT NULL DEFAULT '',
    snapshot JSONB NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_finding_retests_history ON finding_retests(finding_id, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_retests_active ON finding_retests(finding_id)
    WHERE status IN ('pending','running');

-- Deleting a session keeps its retest records, while also releasing any retest occupancy that has not yet finished.
CREATE OR REPLACE FUNCTION stop_deleted_conversation_retest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE finding_retests SET status='stopped', error='retest conversation was deleted', finished_at=now()
    WHERE conversation_id=OLD.id AND status IN ('pending','running');
    RETURN OLD;
END;
$$;
DROP TRIGGER IF EXISTS trg_conversation_retest_delete ON conversations;
CREATE TRIGGER trg_conversation_retest_delete BEFORE DELETE ON conversations
    FOR EACH ROW EXECUTE FUNCTION stop_deleted_conversation_retest();

-- Evidence above InlineEvidenceLimit is content-addressed under the evidence
-- directory and referenced here, so a list query does not carry megabytes of
-- request bodies it never reads. Empty means the evidence is inline in the
-- `evidence` column, which stays the source for small findings.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_path TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS report_evidence_version BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS traffic_evidence_snapshots (
    id TEXT PRIMARY KEY,
    source_traffic_id TEXT NOT NULL,
    captured_at BIGINT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    req_head TEXT NOT NULL,
    resp_head TEXT NOT NULL,
    req_hash TEXT NOT NULL,
    resp_hash TEXT NOT NULL,
    req_len BIGINT NOT NULL,
    resp_len BIGINT NOT NULL,
    unreferenced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_traffic_bindings (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES traffic_evidence_snapshots(id),
    role TEXT NOT NULL DEFAULT 'supporting',
    note TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(finding_id, snapshot_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_order ON finding_traffic_bindings(finding_id, position, id);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_snapshot ON finding_traffic_bindings(snapshot_id);

-- =====================================================================
-- M. Backend log persistence
-- =====================================================================
CREATE TABLE IF NOT EXISTS server_logs (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    level      TEXT NOT NULL DEFAULT 'info',
    tag        TEXT NOT NULL DEFAULT '',
    text       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_server_logs_id ON server_logs(id DESC);

-- Independent /btw history and the latest provider-ready main checkpoint.
CREATE TABLE IF NOT EXISTS side_question_sessions (
    session_key TEXT PRIMARY KEY,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
    exploration_id BIGINT REFERENCES explorations(id) ON DELETE CASCADE,
    intent_id BIGINT REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    run_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0,
    CHECK ((conversation_id IS NOT NULL AND task_id IS NULL AND exploration_id IS NULL AND intent_id IS NULL)
        OR (conversation_id IS NULL AND task_id IS NOT NULL AND exploration_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_side_sessions_conv ON side_question_sessions(conversation_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_task ON side_question_sessions(task_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_exp ON side_question_sessions(exploration_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_intent ON side_question_sessions(intent_id);

CREATE TABLE IF NOT EXISTS side_question_requests (
    id TEXT PRIMARY KEY,
    ordinal BIGSERIAL UNIQUE,
    session_key TEXT NOT NULL REFERENCES side_question_sessions(session_key) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    client_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed','cancelled','interrupted')),
    error TEXT NOT NULL DEFAULT '',
    model JSONB NOT NULL,
    snapshot_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sequence BIGINT NOT NULL DEFAULT 0,
    usage JSONB NOT NULL DEFAULT '{}',
    UNIQUE(session_key,generation,client_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_side_request_running ON side_question_requests(session_key) WHERE status='running';
CREATE INDEX IF NOT EXISTS idx_side_requests_history ON side_question_requests(session_key,ordinal DESC);

-- Additive v3 archive fields; old archives restore these as empty objects.
ALTER TABLE side_question_sessions ADD COLUMN IF NOT EXISTS memory JSONB NOT NULL DEFAULT '{}';
ALTER TABLE side_question_requests ADD COLUMN IF NOT EXISTS context_info JSONB NOT NULL DEFAULT '{}';

-- =====================================================================
-- Asset interception rules (global blocklist)
-- Independent of §K command interception (intercept_rules): intercept_rules match tool names/input argument text,
-- This table matches the "target asset": exact or fuzzy domain, IP, and URL values, as well as CIDR network ranges.
-- Stores rules only; the actual matching/interception logic is implemented elsewhere.
-- Seven kinds of kind:
--   exact_domain / exact_ip / exact_url  —— exact match
--   fuzzy_domain / fuzzy_ip / fuzzy_url  —— fuzzy match
--   cidr                                 —— CIDR network range
-- =====================================================================
CREATE TABLE IF NOT EXISTS asset_intercept_rules (
    id          BIGSERIAL PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'exact_domain', 'exact_ip', 'exact_url',
                    'fuzzy_domain', 'fuzzy_ip', 'fuzzy_url',
                    'cidr')),
    pattern     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    builtin     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_intercept_enabled ON asset_intercept_rules(enabled);
DROP TRIGGER IF EXISTS trg_asset_intercept_rules_upd ON asset_intercept_rules;
CREATE TRIGGER trg_asset_intercept_rules_upd BEFORE UPDATE ON asset_intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- Task-level asset intercept/allow rules
-- Same structure as the global asset_intercept_rules (kind/pattern/note/enabled), but keyed by task_id
-- Linked to tasks and cascade-deleted with them; entered when the task is created and editable in the task details.
-- action: 'block' = intercept (testing forbidden)  'allow' = allow (whitelist).
-- Evaluation: first match against intercept rules (global ∪ task-level block); if matched, testing is forbidden. If not matched and the task has
-- When enabled allow rules exist, a test is permitted only if it matches at least one allow rule; otherwise it is "not allowed to test".
-- =====================================================================
CREATE TABLE IF NOT EXISTS task_intercept_rules (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    action      TEXT NOT NULL DEFAULT 'block' CHECK (action IN ('block','allow')),
    kind        TEXT NOT NULL CHECK (kind IN (
                    'exact_domain', 'exact_ip', 'exact_url',
                    'fuzzy_domain', 'fuzzy_ip', 'fuzzy_url',
                    'cidr')),
    pattern     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_task_intercept_task ON task_intercept_rules(task_id);
-- Per-task test accounts (#3): user-declared (e.g. a program-provided alias
-- account) or agent-registered and recorded so they are not forgotten. Passwords
-- are local-only, same trust domain as captured traffic evidence; the UI masks
-- them by default.
CREATE TABLE IF NOT EXISTS task_credentials (
    id         BIGSERIAL PRIMARY KEY,
    task_id    BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user','agent')),
    note       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, domain, username)
);
-- Upgrading an old database (table created earlier in this session, without an action column): add the column (with IF NOT EXISTS).
ALTER TABLE task_intercept_rules ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'block';
DROP TRIGGER IF EXISTS trg_task_intercept_rules_upd ON task_intercept_rules;
CREATE TRIGGER trg_task_intercept_rules_upd BEFORE UPDATE ON task_intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- M. Vulnerability IM push
--
-- The three tables are deliberately separate, mainly for the sake of blast radius: the transaction that writes the finding (RecordFindingTx, 
-- (holding the task row lock) only a single blind INSERT is permitted; it must not read the channel table or run the user's filter rules. Otherwise
-- a misconfigured webhook filter condition could pollute or abort the transaction, so the finding could not be stored.
--
--   notification_channels   channel instance configuration (mutable, contains credentials, managed via UI)
--   notification_events     event facts (blind-inserted within the finding-write transaction, includes rendered snapshot)
--   notification_deliveries delivery tasks (produced by fan-out outside the transaction, carry status/retry/batch)
-- =====================================================================

-- Channel instances: multiple instances may be configured for the same kind (e.g., an "emergency group" and a "daily group", each a DingTalk bot).
-- The values of kind are validated by a whitelist on the server side, with no CHECK constraint: same as findings.status,
-- Adding a new channel later should not require a schema change.
CREATE TABLE IF NOT EXISTS notification_channels (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    -- dingtalk DingTalk / feishu Feishu / wecom WeCom / webhook generic / telegram / email
    kind         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    -- Credentials (stored in plaintext; the UI shows them masked. See maskChannelSecrets on the server side). The six channel types differ greatly in their fields,
    -- Use a unified JSONB column with strict validation on the Go side according to kind, to avoid adding a pile of NULL columns for each channel:
    --   dingtalk {webhook,secret}
    --   feishu   {webhook,secret}
    --   wecom    {webhook}
    --   webhook  {url,method,content_type,headers{},body_template}
    --   telegram {bot_token,chat_id,base_url}
    --   email    {host,port,username,password,from,to[],tls}
    config       JSONB NOT NULL DEFAULT '{}',
    -- Push timing: realtime sends immediately on match; digest queues into a batch and is summarized into a single message per global period.
    mode         TEXT NOT NULL DEFAULT 'realtime',
    -- Filter conditions. All fields are optional (default = no filtering):
    --   min_severity       ''|low|medium|high|critical
    --   task_ids/asset_ids: an empty array means no restriction; if non-empty, the intersection must be non-empty
    --   vulnclass_include/exclude: arrays of keywords (case-insensitive substring match); an empty include means include everything
    --   on_status_change   bool, only meaningful in realtime mode
    filter       JSONB NOT NULL DEFAULT '{}',
    -- Maximum number of deliveries per minute; 0 = no rate limit. Default 20, aligned with the official hard limits of DingTalk/WeCom.
    -- When the limit is exceeded, no message is dropped; delivery is only deferred to the next tick.
    rate_per_min INTEGER NOT NULL DEFAULT 20,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS trg_notification_channels_upd ON notification_channels;
CREATE TRIGGER trg_notification_channels_upd BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Event facts. Written in the same transaction as RecordFindingTx / the status-change transaction, which guarantees that "the finding is persisted"
-- is atomically consistent with "the push task exists" -- there is no window where the commit succeeds but the message is never enqueued and is lost permanently.
-- snapshot is deliberately redundant: findings may later be renamed, have their severity changed, or change status, while the push content should reflect the state "at the time of the event",
-- and fan-out and rendering do not need to look back up the findings/tasks/assets tables.
-- Deleting a finding does not cascade-delete its events, consistent with the semantics of the findings table, where events remain independently retained after task deletion.
CREATE TABLE IF NOT EXISTS notification_events (
    id         BIGSERIAL PRIMARY KEY,
    -- finding_created | finding_status_changed
    kind       TEXT NOT NULL,
    finding_id BIGINT NOT NULL,
    snapshot   JSONB NOT NULL,
    -- fan-out idempotency flag: the dispatcher picks up unprocessed events by this column, and sets it to true once handled.
    -- Use a column instead of deleting the row, so that delivery history can be traced back to the event.
    fanned_out BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_events_pending
    ON notification_events(id) WHERE NOT fanned_out;

-- Delivery task: one event × one enabled channel = one row. Fan-out runs outside the transaction, so channels
-- enabled later do not backfill history (consistent with the agent_triggers semantics of "a trigger enabled late does not backfill history",
-- to avoid flooding with a backlog of history when a channel is enabled).
-- channel_id cascade delete: once the channel config is gone, its delivery history is meaningless.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id          BIGSERIAL PRIMARY KEY,
    event_id    BIGINT NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
    channel_id  BIGINT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    -- pending: waiting to be sent / sent: delivered / failed: retries exhausted (can be resent manually) / skipped: channel disabled or batch cancelled
    -- pending: waiting to be sent / sending: claimed by a dispatcher (lease not yet expired) / sent: delivered /
    -- failed: retries exhausted or permanent failure (can be resent manually); skipped: channel disabled. No CHECK constraint on the values,
    -- Same as findings.status, validated by a whitelist on the server side.
    state       TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    -- Doubles as both the "next claimable time" and the "lease expiry time": when a row is claimed, pushing this value into the future forms the lease,
    -- so "lease not yet expired" and "retry time not yet reached" share the same condition expression, and no separate
    -- lease_until column is needed. A sending row left behind by a process crash will be reclaimed in the next round once its lease expires.
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error  TEXT NOT NULL DEFAULT '',
    -- Shared across the same batch in digest mode; always NULL in realtime mode. After the whole batch is rendered into a single message, it is set to sent together.
    batch_id    BIGINT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_due
    ON notification_deliveries(next_attempt_at) WHERE state='pending';
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_history
    ON notification_deliveries(id DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_batch
    ON notification_deliveries(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel
    ON notification_deliveries(channel_id, id DESC);

-- Cost ledger (#70): optional per-profile pricing, EUR per 1M tokens. NULL/0 = unset;
-- usage aggregations compute cost only when at least one price is set.
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_input_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_output_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_cache_read_per_m NUMERIC(12,6);
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS price_cache_write_per_m NUMERIC(12,6);

-- =====================================================================
-- RSI lesson library (shadow mode)
-- Deterministic, evidence-gated lessons extracted from closed tasks. A
-- lesson exists only when it has a cue, an action, and at least one
-- evidence row; support is the number of distinct evidence sources, so
-- re-running extraction is idempotent. Pattern from harness2 (Google
-- Research, Apache-2.0, arXiv 2610.14224): no lesson without evidence.
-- =====================================================================
CREATE TABLE IF NOT EXISTS rsi_lessons (
    id          BIGSERIAL PRIMARY KEY,
    dedupe_key  TEXT NOT NULL UNIQUE,
    -- positive = a confirmed outcome worth reusing; negative = do not repeat;
    -- caution = recheck before reporting (version or retest sensitive).
    kind        TEXT NOT NULL CHECK (kind IN ('positive','negative','caution')),
    cue         TEXT NOT NULL,
    action      TEXT NOT NULL,
    category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    company_id  BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    status      TEXT NOT NULL DEFAULT 'candidate'
                CHECK (status IN ('candidate','adopted','retired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rsi_lessons_scope ON rsi_lessons(company_id, category_id, status);
CREATE INDEX IF NOT EXISTS idx_rsi_lessons_kind  ON rsi_lessons(kind, updated_at DESC);

-- One row per (lesson, source). The primary key makes extraction idempotent:
-- a second run for the same task adds nothing and cannot inflate support.
CREATE TABLE IF NOT EXISTS rsi_lesson_evidence (
    lesson_id   BIGINT NOT NULL REFERENCES rsi_lessons(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    source_id   BIGINT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (lesson_id, source_kind, source_id)
);

-- What was shown to which task, and in which mode (shadow = logged but not
-- injected; inject = appended to the planner/worker system prompt).
CREATE TABLE IF NOT EXISTS rsi_lesson_usage (
    lesson_id BIGINT NOT NULL REFERENCES rsi_lessons(id) ON DELETE CASCADE,
    task_id   BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    mode      TEXT NOT NULL CHECK (mode IN ('shadow','inject')),
    shown_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (lesson_id, task_id, mode)
);

-- =====================================================================
-- Knowledge base (KB) and reflection pool
-- Durable operational memory: reusable technique/tool/opsec knowledge plus
-- per-task reflections about what worked, what was noisy, and what to look
-- for next. Visibility is the security boundary: a candidate entry never
-- leaves the task it was learned in, and a task-scoped entry can only reach
-- company/global scope through an explicit owner promotion that re-scrubs
-- the origin task's identifiers.
-- =====================================================================
-- A generated column's expression must be IMMUTABLE, and array_to_string is
-- only STABLE (its array_out arm). For a fixed delimiter the result depends on
-- the array alone, so this thin wrapper declares what is already true.
CREATE OR REPLACE FUNCTION knowledge_tags_text(tags text[]) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT array_to_string(tags, ' ') $$;

CREATE TABLE IF NOT EXISTS knowledge_entries (
    id             BIGSERIAL PRIMARY KEY,
    scope          TEXT NOT NULL CHECK (scope IN ('global','environment','company','task')),
    company_id     BIGINT REFERENCES companies(id) ON DELETE CASCADE,
    task_id        BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
    CONSTRAINT ck_knowledge_scope CHECK (
        (scope='global'      AND company_id IS NULL AND task_id IS NULL) OR
        (scope='environment' AND company_id IS NULL AND task_id IS NULL) OR
        (scope='company'     AND company_id IS NOT NULL AND task_id IS NULL) OR
        (scope='task'        AND task_id IS NOT NULL)
    ),
    -- lead = a route that was reasoned out but never executed. Kept apart from
    -- playbook so an unproven chain can never be read as a proven one.
    kind           TEXT NOT NULL CHECK (kind IN ('technique','tool','opsec','indicator','playbook','lead','note')),
    title          TEXT NOT NULL,
    body           TEXT NOT NULL,
    tags           TEXT[] NOT NULL DEFAULT '{}',
    -- candidate = agent-written, task-private; adopted = owner-approved, may
    -- cross engagement boundaries; retired = kept for audit, never injected.
    status         TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate','adopted','retired')),
    source         TEXT NOT NULL CHECK (source IN ('operator','agent','reflection')),
    -- Task the entry was learned in. Deliberately no FK: promotion must still
    -- know the origin scope when the task row is gone.
    origin_task_id BIGINT,
    tsv            TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('english', title), 'A')
     || setweight(to_tsvector('english', knowledge_tags_text(tags)), 'B')
     || setweight(to_tsvector('english', body), 'C')
    ) STORED,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_knowledge_tsv   ON knowledge_entries USING GIN(tsv);
CREATE INDEX IF NOT EXISTS idx_knowledge_scope ON knowledge_entries(scope, status);
CREATE INDEX IF NOT EXISTS idx_knowledge_task  ON knowledge_entries(task_id);
-- Deduplication inside one task: the same title written twice is one entry.
CREATE UNIQUE INDEX IF NOT EXISTS uq_knowledge_task_title
    ON knowledge_entries(task_id, lower(title)) WHERE scope='task';
-- The knowledge tsvector used the 'simple' configuration, which does not stem:
-- 'reachability' never matched 'reachable' and 'proxies' never matched 'proxy',
-- the vocabulary this memory is written in. Rebuild the generated column once,
-- and only while its stored expression still names 'simple' - a rebuild rewrites
-- the table and gives the column a new attnum, so schema.sql (Exec'd on every
-- start) must not do it again. Dropping the column drops idx_knowledge_tsv.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute a
        JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE a.attrelid = 'knowledge_entries'::regclass
          AND a.attname = 'tsv'
          AND a.attgenerated = 's'
          AND pg_get_expr(ad.adbin, ad.adrelid) LIKE '%''simple''%'
    ) THEN
        ALTER TABLE knowledge_entries DROP COLUMN tsv;
        ALTER TABLE knowledge_entries ADD COLUMN tsv TSVECTOR GENERATED ALWAYS AS (
            setweight(to_tsvector('english', title), 'A')
         || setweight(to_tsvector('english', knowledge_tags_text(tags)), 'B')
         || setweight(to_tsvector('english', body), 'C')
        ) STORED;
        CREATE INDEX idx_knowledge_tsv ON knowledge_entries USING GIN(tsv);
    END IF;
END $$;
-- Existing databases: widen the scope and kind sets in place.
ALTER TABLE knowledge_entries DROP CONSTRAINT IF EXISTS knowledge_entries_scope_check;
ALTER TABLE knowledge_entries ADD CONSTRAINT knowledge_entries_scope_check
    CHECK (scope IN ('global','environment','company','task'));
ALTER TABLE knowledge_entries DROP CONSTRAINT IF EXISTS ck_knowledge_scope;
ALTER TABLE knowledge_entries ADD CONSTRAINT ck_knowledge_scope CHECK (
    (scope='global'      AND company_id IS NULL AND task_id IS NULL) OR
    (scope='environment' AND company_id IS NULL AND task_id IS NULL) OR
    (scope='company'     AND company_id IS NOT NULL AND task_id IS NULL) OR
    (scope='task'        AND task_id IS NOT NULL)
);
ALTER TABLE knowledge_entries DROP CONSTRAINT IF EXISTS knowledge_entries_kind_check;
ALTER TABLE knowledge_entries ADD CONSTRAINT knowledge_entries_kind_check
    CHECK (kind IN ('technique','tool','opsec','indicator','playbook','lead','note'));

CREATE TABLE IF NOT EXISTS task_reflections (
    id         BIGSERIAL PRIMARY KEY,
    task_id    BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    intent_id  BIGINT,
    kind       TEXT NOT NULL CHECK (kind IN ('opsec','noise','lookfor','learning','mistake')),
    source     TEXT NOT NULL CHECK (source IN ('engine','worker','planner')),
    dedupe_key TEXT NOT NULL,
    summary    TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    signal     JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_reflections_task ON task_reflections(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reflections_kind ON task_reflections(task_id, kind);

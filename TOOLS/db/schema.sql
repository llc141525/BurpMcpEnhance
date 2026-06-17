-- Full schema — includes all migrations 001-009.
-- New DBs created via init_db() use this file directly.
-- init_db() marks all migrations as already applied.

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    domain TEXT,
    ip TEXT,
    tech_stack TEXT,
    requires_auth INTEGER DEFAULT 0,
    auth_status TEXT DEFAULT 'not_logged_in',
    discovered_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS scan_state (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    seed_url TEXT,
    phase TEXT DEFAULT 'init',
    started_at TEXT,
    spider_ended_at TEXT,
    reviewed_at TEXT,
    max_depth INTEGER DEFAULT 3,
    max_pages INTEGER DEFAULT 200,
    total_pages INTEGER DEFAULT 0,
    total_js INTEGER DEFAULT 0,
    total_apis INTEGER DEFAULT 0,
    total_forms INTEGER DEFAULT 0,
    total_suspicious INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    call_count INTEGER DEFAULT 0,
    cdp_url TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    depth INTEGER DEFAULT 0,
    status TEXT DEFAULT 'queued',
    title TEXT,
    links_found INTEGER DEFAULT 0,
    forms_json TEXT,
    js_files_json TEXT,
    api_calls_json TEXT,
    suspicious_params_json TEXT,
    crawled_at TEXT,
    source TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    page_url TEXT,
    analyzed INTEGER DEFAULT 0,
    discovered_apis_json TEXT,
    hardcoded_secrets_json TEXT,
    internal_routes_json TEXT,
    debug_switches_json TEXT,
    analyzed_at TEXT
);

CREATE TABLE IF NOT EXISTS suspicious_points (
    id TEXT PRIMARY KEY,
    page_url TEXT,
    url TEXT,
    param TEXT,
    method TEXT DEFAULT 'GET',
    test_type TEXT,
    evidence TEXT,
    source TEXT,
    reasoning TEXT,
    risk TEXT DEFAULT 'Medium',
    test_status TEXT DEFAULT 'untested',
    burp_request_id INTEGER,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT,
    endpoint_fingerprint TEXT,
    response_summary TEXT,
    risk_score INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suspicious_points_auth_fingerprint
    ON suspicious_points(source, endpoint_fingerprint, test_type)
    WHERE endpoint_fingerprint IS NOT NULL;

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    sp_id TEXT,
    target_id INTEGER REFERENCES targets(id),
    type TEXT,
    url TEXT,
    param TEXT,
    method TEXT,
    payload TEXT,
    evidence TEXT,
    risk TEXT,
    cvss TEXT,
    remediation TEXT,
    confirmed_at TEXT,
    burp_request_id INTEGER,
    review_status TEXT DEFAULT NULL,
    review_notes TEXT,
    reported_platforms TEXT DEFAULT '',
    report_file TEXT,
    audit_status TEXT DEFAULT 'pending',
    audit_notes TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS auth_credentials (
    id INTEGER PRIMARY KEY,
    account_label TEXT,
    username TEXT,
    password TEXT,
    login_url TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS auth_flow_steps (
    id INTEGER PRIMARY KEY,
    step_index INTEGER,
    action_type TEXT,
    url TEXT,
    selector_uid TEXT,
    value TEXT,
    wait_ms INTEGER,
    description TEXT
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY,
    token_type TEXT,
    token_name TEXT,
    token_value TEXT,
    domain TEXT,
    path TEXT DEFAULT '/',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    role TEXT DEFAULT 'primary',
    expires_at TEXT,
    last_checked_at TEXT,
    cookie_source TEXT DEFAULT 'manual',
    username TEXT DEFAULT NULL,
    password TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS hunt_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    query_string TEXT,
    body TEXT,
    content_type TEXT,
    burp_history_id INTEGER,
    endpoint_type TEXT,
    business_intent TEXT,
    risk_hint TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'queued' CHECK(status IN ('queued','in_progress','tested','confirmed','error')),
    tested_types_json TEXT DEFAULT '[]',
    finding_ids TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    tested_at TEXT,
    notes TEXT,
    source TEXT DEFAULT 'auto' CHECK(source IN ('auto','manual_replay','auth_explore')),
    flow_id TEXT,
    UNIQUE(method, url, query_string)
);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_status ON hunt_queue(status);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_target ON hunt_queue(target_id);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_source ON hunt_queue(source);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_role_name_domain
    ON auth_sessions(role, token_name, domain);

CREATE TABLE IF NOT EXISTS auth_storage_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT DEFAULT 'primary',
    storage_type TEXT NOT NULL,
    origin TEXT NOT NULL,
    token_name TEXT NOT NULL,
    token_value TEXT NOT NULL,
    token_kind TEXT DEFAULT 'storage',
    is_active INTEGER DEFAULT 1,
    first_seen_at TEXT DEFAULT (datetime('now','localtime')),
    last_seen_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT,
    source TEXT DEFAULT 'cdp_capture',
    UNIQUE(role, storage_type, origin, token_name)
);

CREATE TABLE IF NOT EXISTS plugins (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    type              TEXT NOT NULL CHECK(type IN (
                          'nuclei_template','python_script','tool_binary','config'
                      )),
    trigger_stack     TEXT,
    covers_vuln_types TEXT,
    file_path         TEXT,
    install_cmd       TEXT,
    source            TEXT DEFAULT 'mapping'
                          CHECK(source IN ('mapping','ai_generated')),
    active            INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now','localtime')),
    last_used_at      TEXT
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now', 'localtime')),
    description TEXT
);

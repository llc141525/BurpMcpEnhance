-- SRC 漏洞挖掘系统数据库 Schema
-- 适用于 sqlite3, PRAGMA journal_mode=WAL, busy_timeout=5000

-- 1. targets 表（资产目标）
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

-- 2. scan_state 表（扫描状态）
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
    call_count INTEGER DEFAULT 0
);

-- 3. pages 表（页面队列）
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
    crawled_at TEXT
);

-- 4. js_files 表（JS 文件库）
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

-- 5. suspicious_points 表（可疑点）
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

-- 6. findings 表（确认漏洞）
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
    burp_request_id INTEGER
);

-- 7. auth 表（认证信息）
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
    username TEXT DEFAULT NULL,
    password TEXT DEFAULT NULL
);

-- 8. schema_version 表（DB 迁移版本追踪）
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now', 'localtime')),
    description TEXT
);

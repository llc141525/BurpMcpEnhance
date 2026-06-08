-- migrations/013_plugins_reflect.sql
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

ALTER TABLE scan_state ADD COLUMN reflect_ran_at TEXT;
ALTER TABLE scan_state ADD COLUMN plugins_added_json TEXT;

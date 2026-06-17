-- 011: 允许 hunt_queue.source = 'auth_explore'（auth_explore 写入）
-- SQLite 不支持 ALTER COLUMN，需重建表
PRAGMA foreign_keys=OFF;

CREATE TABLE hunt_queue_new (
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

INSERT INTO hunt_queue_new SELECT * FROM hunt_queue;
DROP TABLE hunt_queue;
ALTER TABLE hunt_queue_new RENAME TO hunt_queue;

CREATE INDEX IF NOT EXISTS idx_hunt_queue_status ON hunt_queue(status);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_target ON hunt_queue(target_id);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_source ON hunt_queue(source);

PRAGMA foreign_keys=ON;

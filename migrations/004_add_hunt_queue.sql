-- 004: business-logic-hunt 队列表
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
    UNIQUE(method, url, query_string)
);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_status ON hunt_queue(status);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_target ON hunt_queue(target_id);

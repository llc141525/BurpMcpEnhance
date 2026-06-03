-- 003: auth_sessions 增加过期时间和检查时间字段
ALTER TABLE auth_sessions ADD COLUMN expires_at TEXT;
ALTER TABLE auth_sessions ADD COLUMN last_checked_at TEXT;

-- 005: auth_sessions 增加角色字段（支持双账号/三层重放）
ALTER TABLE auth_sessions ADD COLUMN role TEXT DEFAULT 'primary';

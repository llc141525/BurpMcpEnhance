-- 010: store login credentials for session re-login
ALTER TABLE auth_sessions ADD COLUMN username TEXT DEFAULT NULL;
ALTER TABLE auth_sessions ADD COLUMN password TEXT DEFAULT NULL;

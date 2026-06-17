DROP INDEX IF EXISTS idx_auth_sessions_name_domain;

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_role_name_domain
    ON auth_sessions(role, token_name, domain);

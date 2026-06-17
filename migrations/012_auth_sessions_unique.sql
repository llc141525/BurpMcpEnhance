-- 012: auth_sessions 增加 UNIQUE(token_name, domain) 去重索引
-- ON CONFLICT 需要列上有 UNIQUE 约束才生效
-- 先清理同一 (token_name, domain) 的重复行（保留最新的）
DELETE FROM auth_sessions
WHERE id NOT IN (
    SELECT MAX(id) FROM auth_sessions GROUP BY token_name, domain
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_name_domain
    ON auth_sessions(token_name, domain);

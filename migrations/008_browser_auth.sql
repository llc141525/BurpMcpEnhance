-- 008: browser_auth integration
-- chrome_manager 写入 CDP 连接地址
ALTER TABLE scan_state ADD COLUMN cdp_url TEXT DEFAULT NULL;

-- 区分 cookie 来源：manual(Burp手动) / browser_use(自动提取)
ALTER TABLE auth_sessions ADD COLUMN cookie_source TEXT DEFAULT 'manual';

-- migrations/017_framework_cve_cache.sql
-- 未知框架 CVE 搜索结果缓存（供未来扩展，本期脚本不写入，仅建表）
CREATE TABLE IF NOT EXISTS framework_cve_cache (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    framework     TEXT NOT NULL UNIQUE,
    attack_paths_json TEXT,
    searched_at   TEXT
);

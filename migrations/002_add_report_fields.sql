-- 002: findings 表追加报告/审核字段（替代 migrate_findings_v2.py）
ALTER TABLE findings ADD COLUMN review_status TEXT DEFAULT NULL;
ALTER TABLE findings ADD COLUMN review_notes TEXT;
ALTER TABLE findings ADD COLUMN reported_platforms TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN report_file TEXT;
ALTER TABLE findings ADD COLUMN audit_status TEXT DEFAULT 'pending';
ALTER TABLE findings ADD COLUMN audit_notes TEXT;

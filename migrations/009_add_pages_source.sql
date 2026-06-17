-- 009: pages 表增加 source 字段，标记 URL 来源（zoomeye/browser_use/manual 等）
ALTER TABLE pages ADD COLUMN source TEXT DEFAULT NULL;

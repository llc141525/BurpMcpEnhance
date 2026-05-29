-- 006: hunt_queue 增加 source/flow_id 字段（manual-replay 工作流）
ALTER TABLE hunt_queue ADD COLUMN source TEXT DEFAULT 'auto' CHECK(source IN ('auto','manual_replay'));
ALTER TABLE hunt_queue ADD COLUMN flow_id TEXT;
CREATE INDEX IF NOT EXISTS idx_hunt_queue_source ON hunt_queue(source);

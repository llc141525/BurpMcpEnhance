-- Migration 007: Add audit columns for vuln-auditor skill

ALTER TABLE findings ADD COLUMN audit_status TEXT DEFAULT 'pending';
ALTER TABLE findings ADD COLUMN audit_notes TEXT DEFAULT NULL;

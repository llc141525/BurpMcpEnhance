ALTER TABLE suspicious_points ADD COLUMN endpoint_fingerprint TEXT;
ALTER TABLE suspicious_points ADD COLUMN response_summary TEXT;
ALTER TABLE suspicious_points ADD COLUMN risk_score INTEGER DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_suspicious_points_auth_fingerprint
    ON suspicious_points(source, endpoint_fingerprint, test_type)
    WHERE endpoint_fingerprint IS NOT NULL;

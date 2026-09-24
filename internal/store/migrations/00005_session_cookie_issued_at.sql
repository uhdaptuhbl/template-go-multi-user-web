-- +goose Up
ALTER TABLE sessions ADD COLUMN cookie_issued_at TIMESTAMPTZ;
UPDATE sessions SET cookie_issued_at = created_at;
ALTER TABLE sessions ALTER COLUMN cookie_issued_at SET NOT NULL;

-- +goose Down
ALTER TABLE sessions DROP COLUMN cookie_issued_at;

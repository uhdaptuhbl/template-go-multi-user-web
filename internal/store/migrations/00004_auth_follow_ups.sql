-- +goose Up
ALTER TABLE users ADD COLUMN rejected_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN bootstrap_admin_granted_at TIMESTAMPTZ;
ALTER TABLE users ADD CONSTRAINT users_rejected_implies_deleted CHECK (
    rejected_at IS NULL OR status = 'deleted'
);

CREATE INDEX audit_events_occurred_at_id_idx ON audit_events (occurred_at DESC, id DESC);
DROP INDEX audit_events_occurred_at_idx;

UPDATE roles
SET description = 'An ordinary account: access to its own resources, plus issuing invites within the configured quota.'
WHERE name = 'member';

-- +goose Down
UPDATE roles
SET description = 'An ordinary account with access only to its own resources.'
WHERE name = 'member';

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
DROP INDEX audit_events_occurred_at_id_idx;

ALTER TABLE users DROP CONSTRAINT users_rejected_implies_deleted;
ALTER TABLE users DROP COLUMN bootstrap_admin_granted_at;
ALTER TABLE users DROP COLUMN rejected_at;

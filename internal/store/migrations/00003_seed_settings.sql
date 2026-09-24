-- +goose Up
INSERT INTO settings (
    id, signup_enabled, signup_require_invite, signup_require_approval,
    invite_default_quota, invite_default_ttl_secs, invite_max_uses_limit,
    updated_at, updated_by, updated_by_ref
) VALUES (
    TRUE, TRUE, TRUE, FALSE,
    0, 1209600, 100,
    now(), NULL, 'anonymous'
) ON CONFLICT (id) DO NOTHING;

-- +goose Down
DELETE FROM settings WHERE id;

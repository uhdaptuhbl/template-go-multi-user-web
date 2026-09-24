-- +goose Up
CREATE TABLE users (
    id                UUID PRIMARY KEY,
    display_name      TEXT NOT NULL,
    email             TEXT,
    email_verified_at TIMESTAMPTZ,
    status            TEXT NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'deleted')),
    deleted_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    CONSTRAINT users_deleted_at_matches_status CHECK (
        (status = 'deleted') = (deleted_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
CREATE INDEX users_deleted_at_idx ON users (deleted_at) WHERE status = 'deleted';

CREATE TABLE identities (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX identities_provider_subject_key ON identities (provider, subject);
CREATE INDEX identities_user_id_idx ON identities (user_id);

CREATE TABLE credentials (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    BYTEA NOT NULL,
    public_key       BYTEA NOT NULL,
    attestation_type TEXT NOT NULL,
    transports       JSONB NOT NULL DEFAULT '[]'::jsonb,
    aaguid           BYTEA NOT NULL,
    sign_count       BIGINT NOT NULL DEFAULT 0,
    clone_warning    BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible  BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state     BOOLEAN NOT NULL DEFAULT FALSE,
    name             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    last_used_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX credentials_credential_id_key ON credentials (credential_id);
CREATE INDEX credentials_user_id_idx ON credentials (user_id);

CREATE TABLE sessions (
    id                  BYTEA PRIMARY KEY,
    public_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at          TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    client_ip           INET,
    user_agent          TEXT NOT NULL,
    methods             JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE UNIQUE INDEX sessions_public_id_key ON sessions (public_id);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_idle_expires_at_idx ON sessions (idle_expires_at);

CREATE TABLE auth_flows (
    id         BYTEA PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('oidc', 'oidc_link', 'webauthn_register', 'webauthn_login')),
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX auth_flows_expires_at_idx ON auth_flows (expires_at);

CREATE TABLE settings (
    id                      BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    signup_enabled          BOOLEAN NOT NULL,
    signup_require_invite   BOOLEAN NOT NULL,
    signup_require_approval BOOLEAN NOT NULL,
    invite_default_quota    INTEGER NOT NULL CHECK (invite_default_quota >= 0),
    invite_default_ttl_secs INTEGER NOT NULL CHECK (invite_default_ttl_secs > 0),
    invite_max_uses_limit   INTEGER NOT NULL CHECK (invite_max_uses_limit > 0),
    updated_at              TIMESTAMPTZ NOT NULL,
    updated_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by_ref          TEXT NOT NULL
);

CREATE TABLE invites (
    id             UUID PRIMARY KEY,
    token_hash     BYTEA NOT NULL,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by_ref TEXT NOT NULL,
    email          TEXT,
    note           TEXT NOT NULL DEFAULT '',
    max_uses       INTEGER NOT NULL CHECK (max_uses > 0),
    uses           INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    CONSTRAINT invites_uses_within_max CHECK (uses <= max_uses)
);
CREATE UNIQUE INDEX invites_token_hash_key ON invites (token_hash);
CREATE INDEX invites_created_by_idx ON invites (created_by);
CREATE INDEX invites_expires_at_idx ON invites (expires_at);
CREATE INDEX invites_email_lower_idx ON invites (lower(email)) WHERE email IS NOT NULL;

CREATE TABLE invite_redemptions (
    id          UUID PRIMARY KEY,
    invite_id   UUID NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    user_ref    TEXT NOT NULL,
    redeemed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX invite_redemptions_invite_id_idx ON invite_redemptions (invite_id);
CREATE UNIQUE INDEX invite_redemptions_user_id_key ON invite_redemptions (user_id);

CREATE TABLE otp_codes (
    id          UUID PRIMARY KEY,
    email       TEXT NOT NULL,
    code_hash   BYTEA NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    invite_id   UUID REFERENCES invites(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX otp_codes_email_idx ON otp_codes (lower(email));
CREATE INDEX otp_codes_expires_at_idx ON otp_codes (expires_at);

CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX roles_name_key ON roles (name);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE UNIQUE INDEX permissions_name_key ON permissions (name);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE audit_events (
    id          UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ref   TEXT NOT NULL,
    subject     TEXT NOT NULL,
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    client_ip   INET,
    request_id  TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_actor_id_idx ON audit_events (actor_id);
CREATE INDEX audit_events_action_idx ON audit_events (action);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE user_roles;
DROP TABLE role_permissions;
DROP TABLE permissions;
DROP TABLE roles;
DROP TABLE otp_codes;
DROP TABLE invite_redemptions;
DROP TABLE invites;
DROP TABLE settings;
DROP TABLE auth_flows;
DROP TABLE sessions;
DROP TABLE credentials;
DROP TABLE identities;
DROP TABLE users;

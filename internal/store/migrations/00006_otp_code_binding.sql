-- +goose Up
DELETE FROM otp_codes;
ALTER TABLE otp_codes ADD COLUMN binding_hash BYTEA NOT NULL;
CREATE INDEX otp_codes_email_binding_idx ON otp_codes (email, binding_hash);

-- +goose Down
DROP INDEX otp_codes_email_binding_idx;
ALTER TABLE otp_codes DROP COLUMN binding_hash;

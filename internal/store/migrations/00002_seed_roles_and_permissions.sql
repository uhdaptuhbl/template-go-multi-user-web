-- +goose Up
INSERT INTO roles (id, name, description, created_at) VALUES
    ('ec248ecc-0619-502c-99ba-1391b2d73bc4', 'admin', 'Full administrative access to every account and the audit log.', now()),
    ('f3973e45-0f03-52b3-a043-ef632f21c4b4', 'member', 'An ordinary account with access only to its own resources.', now())
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (id, name, description) VALUES
    ('7778a61a-417b-5dfa-83bc-dfea057e1033', 'user.read', 'List and read any user account.'),
    ('8a092991-9026-5902-b011-de59f369452a', 'user.write', 'Modify or suspend any user account.'),
    ('80421fa2-f68c-530e-849c-b97be82ccc8e', 'user.role.grant', 'Grant or revoke a role on any user.'),
    ('78fa948a-c1c0-5465-b35f-6f151c5efdc5', 'session.revoke.any', 'Revoke another user''s sessions.'),
    ('f391a3ee-718f-52b0-be48-831516163fb0', 'audit.read', 'Read the audit log.'),
    ('5663fafd-8964-53d2-ba8b-ea381663d636', 'user.approve', 'Approve or reject an account awaiting approval.'),
    ('2c9a5405-b2a3-54a6-b3d7-44e9ac513f58', 'invite.create', 'Issue an invite, within the issuer''s quota.'),
    ('18289f32-c1db-5385-8663-ec8f725acfc6', 'invite.manage', 'List, inspect, and revoke any invite regardless of issuer.'),
    ('f10cdb2a-2f83-58f1-98eb-aa250dc42755', 'settings.manage', 'Read and change the runtime settings.')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles, permissions
WHERE roles.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles, permissions
WHERE roles.name = 'member' AND permissions.name = 'invite.create'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions
USING roles, permissions
WHERE role_permissions.role_id = roles.id
  AND role_permissions.permission_id = permissions.id
  AND roles.name IN ('admin', 'member')
  AND permissions.name IN (
    'user.read', 'user.write', 'user.role.grant', 'session.revoke.any',
    'audit.read', 'user.approve', 'invite.create', 'invite.manage', 'settings.manage'
  );
DELETE FROM permissions WHERE name IN (
    'user.read', 'user.write', 'user.role.grant', 'session.revoke.any',
    'audit.read', 'user.approve', 'invite.create', 'invite.manage', 'settings.manage'
);
DELETE FROM roles WHERE name IN ('admin', 'member');

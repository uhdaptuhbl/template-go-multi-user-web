package authz

// PermissionUserRead allows listing and reading any user account.
const PermissionUserRead = "user.read"

// PermissionUserWrite allows modifying or suspending any user account.
const PermissionUserWrite = "user.write"

// PermissionUserRoleGrant allows granting or revoking a role on any user.
const PermissionUserRoleGrant = "user.role.grant"

// PermissionSessionRevokeAny allows revoking another user's sessions.
const PermissionSessionRevokeAny = "session.revoke.any"

// PermissionAuditRead allows reading the audit log.
const PermissionAuditRead = "audit.read"

// PermissionUserApprove allows approving or rejecting an account that is
// awaiting approval.
const PermissionUserApprove = "user.approve"

// PermissionInviteCreate allows issuing an invite, subject to the issuer's
// quota. It does not allow seeing or revoking an invite somebody else issued.
const PermissionInviteCreate = "invite.create"

// PermissionInviteManage allows listing, inspecting, and revoking any invite
// regardless of who issued it.
const PermissionInviteManage = "invite.manage"

// PermissionSettingsManage allows reading and changing the runtime settings.
const PermissionSettingsManage = "settings.manage"

// RoleAdmin is the role that carries every permission.
const RoleAdmin = "admin"

// RoleMember is the role every new account receives. It carries
// PermissionInviteCreate and nothing else, and that permission is inert while
// the invite quota is zero. Every other self-service action is authorized by
// an ownership predicate in the query, not by a permission.
const RoleMember = "member"

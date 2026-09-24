package audit

// ActionOIDCStarted marks an OpenID Connect sign-in flow being started.
const ActionOIDCStarted = "auth.oidc.started"

// ActionOIDCCompleted marks an OpenID Connect sign-in flow completing.
const ActionOIDCCompleted = "auth.oidc.completed"

// ActionPasskeyRegistered marks a passkey being registered to an account.
const ActionPasskeyRegistered = "auth.passkey.registered"

// ActionPasskeyRemoved marks a passkey being removed from an account.
const ActionPasskeyRemoved = "auth.passkey.removed"

// ActionPasskeyCompleted marks a passkey authentication completing.
const ActionPasskeyCompleted = "auth.passkey.completed"

// ActionOTPRequested marks a one-time code being requested.
const ActionOTPRequested = "auth.otp.requested"

// ActionOTPCompleted marks a one-time code authentication completing.
const ActionOTPCompleted = "auth.otp.completed"

// ActionLogout marks a session ending at the holder's own request.
const ActionLogout = "auth.logout"

// ActionSessionRevoked marks a session being revoked, whether by its own
// holder or by an administrator.
const ActionSessionRevoked = "session.revoked"

// ActionRateLimited records the first refused request from a client against
// an authentication rate limit, until that client is admitted again.
const ActionRateLimited = "auth.rate_limited"

// ActionUserCreated marks an account being created.
const ActionUserCreated = "user.created"

// ActionUserUpdated marks an account's profile being updated.
const ActionUserUpdated = "user.updated"

// ActionUserSuspended marks an account being suspended.
const ActionUserSuspended = "user.suspended"

// ActionUserReactivated marks a suspended account being reactivated.
const ActionUserReactivated = "user.reactivated"

// ActionUserDeleted marks an account being deleted by its owner.
const ActionUserDeleted = "user.deleted"

// ActionRoleGranted marks a role being granted to an account.
const ActionRoleGranted = "user.role.granted"

// ActionRoleRevoked marks a role being revoked from an account.
const ActionRoleRevoked = "user.role.revoked"

// ActionUserRestored marks a deleted account being restored within its grace
// period.
const ActionUserRestored = "user.restored"

// ActionUserPurged marks a deleted account being permanently purged.
const ActionUserPurged = "user.purged"

// ActionIdentityLinked marks an identity being linked to an account.
const ActionIdentityLinked = "identity.linked"

// ActionIdentityUnlinked marks an identity being unlinked from an account.
const ActionIdentityUnlinked = "identity.unlinked"

// ActionSignupBlocked marks a signup attempt being blocked.
const ActionSignupBlocked = "signup.blocked"

// ActionUserApproved marks a pending account being approved.
const ActionUserApproved = "user.approved"

// ActionUserRejected marks a pending account being rejected.
const ActionUserRejected = "user.rejected"

// ActionInviteCreated marks an invite being created.
const ActionInviteCreated = "invite.created"

// ActionInviteRevoked marks an invite being revoked.
const ActionInviteRevoked = "invite.revoked"

// ActionInviteRedeemed marks an invite being redeemed.
const ActionInviteRedeemed = "invite.redeemed"

// ActionSettingsUpdated marks a settings value being updated.
const ActionSettingsUpdated = "settings.updated"

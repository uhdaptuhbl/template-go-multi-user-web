// Package audit appends the service's security audit trail: authentication
// attempts, session revocations, and account and role changes that an
// operator needs after an incident and cannot reconstruct later.
//
// Its records deliberately carry no credential material. Detail drops any
// field whose name suggests a secret before the event is persisted, because a
// redacted placeholder still records that a credential was present and
// invites someone to log the real one "just this once".
package audit

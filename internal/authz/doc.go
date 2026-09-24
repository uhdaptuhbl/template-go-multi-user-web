// Package authz owns authorization: the permission and role names, their
// storage, and the single checker every protected route consults. Ownership
// of a resource is enforced by the query that selects the resource and is a
// separate control from a permission.
package authz

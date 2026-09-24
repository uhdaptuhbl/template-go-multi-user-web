package authz

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"
)

// Checker answers whether an account holds a permission. Every authorization
// decision in this service goes through it, so substituting a policy engine
// later is a change to this type rather than to every handler.
type Checker struct {
	repo *Repository
}

// NewChecker returns a checker backed by repo.
func NewChecker(repo *Repository) *Checker {
	return &Checker{repo: repo}
}

// Has reports whether the account holds the named permission.
func (c *Checker) Has(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	permissions, err := c.repo.PermissionsFor(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("authz: checking permission: %w", err)
	}

	return slices.Contains(permissions, permission), nil
}

// Permissions returns every permission the account holds, sorted, for
// inclusion in a response describing the caller.
func (c *Checker) Permissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	permissions, err := c.repo.PermissionsFor(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("authz: listing permissions: %w", err)
	}

	return permissions, nil
}

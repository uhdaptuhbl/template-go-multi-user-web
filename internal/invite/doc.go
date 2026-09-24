// Package invite issues and redeems invitations to create an account. An
// invite's token is stored only as a digest and disclosed only at issuance;
// ADR 0012 records why an invite travels in server-side ceremony state rather
// than in a cookie.
package invite

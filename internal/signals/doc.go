// Package signals handles process termination signals that the graceful
// shutdown path does not.
//
// Graceful shutdown itself is started by signal.NotifyContext in the
// composition root and carried out by the packages that own each resource.
// This package covers the case that leaves behind: an operator who signals
// again because the drain is taking longer than they are willing to wait.
package signals

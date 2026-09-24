package config

import (
	"go.uber.org/zap"
)

// LogEffective writes the configuration the process actually resolved.
//
// Defaults, environment overrides, and validation all happen before anything
// else runs, so the only way to know what a process is using is to have it say
// so. The value is rendered through encoding/json, which is what makes
// SecretString redact: its MarshalJSON returns the placeholder, so a secret
// cannot reach the log through this path even though the whole struct is
// passed in.
func LogEffective(logger *zap.Logger, cfg Config) {
	logger.Info("configuration loaded", zap.Any("config", cfg))
}

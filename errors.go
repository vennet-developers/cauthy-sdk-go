package cauthy

import "github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"

// ConfigError is a configuration the SDK refuses at start, before it serves
// anything. Its message names what to change.
type ConfigError = cfgerr.Error

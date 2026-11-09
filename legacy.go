package cauthy

import (
	"log/slog"
	"sync"
)

// told are the deprecations said in this process: each is said once.
var told sync.Map

// deprecated says, once per process, that what leaves in 2.0 and what to do
// instead: a warning with "deprecated" true on log.
func deprecated(log *slog.Logger, what, instead string) {
	if _, said := told.LoadOrStore(what, true); !said {
		log.Warn("cauthy: "+what+" is deprecated and leaves in 2.0. "+instead, "deprecated", true)
	}
}

// forgetDeprecations forgets what was said, for tests.
func forgetDeprecations() { told.Clear() }

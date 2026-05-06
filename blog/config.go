package blog

// This file specifies the format used to configure our loggers. It is
// embedded in almost every Config struct in //cmd/*/main.go.

import (
	"log/slog"
)

// Config defines the config for logging to syslog and stdout/stderr. The
// level meanings are as follows:
//
//	-1: suppress all output
//	0: default, which is -1 for stdout and 6 for syslog
//	3: log only errors
//	4: log warnings and above
//	6: log info and above
//	7: log debug and above
//
// Values less than -1 or greater than 7 are invalid. Values in between the
// numbers documented above (e.g. 1) have the same effect as the next larger
// value (e.g. 3).
type Config struct {
	// When absent or zero, this causes no logs to be emitted on stdout/stderr.
	// Errors and warnings will be emitted on stderr if the configured level
	// allows.
	StdoutLevel int `validate:"min=-1,max=7"`
	// When absent or zero, this defaults to logging all messages of level 6
	// or below. To disable syslog logging entirely, set this to -1.
	SyslogLevel int `validate:"min=-1,max=7"`
}

// syslogToSlogLevelMap allows us to map the integers used in our log config
// (which originally come from syslog levels) to the values used by slog.
func configToSlogLevel(l int) slog.Level {
	switch l {
	case 1, 2, 3:
		return slog.LevelError
	case 4, 5:
		return slog.LevelWarn
	case 6:
		return slog.LevelInfo
	case 7:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

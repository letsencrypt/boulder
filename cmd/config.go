// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmd

// GoogleSafeBrowsingConfig is the JSON config struct for the VA's use of the
// Google Safe Browsing API.
type GoogleSafeBrowsingConfig struct {
	APIKey  string
	DataDir string
}

// SyslogConfig defines the config for syslogging.
type SyslogConfig struct {
	Network     string
	Server      string
	StdoutLevel *int
}

// StatsdConfig defines the config for Statsd.
type StatsdConfig struct {
	Server string
	Prefix string
}

package main

import (
	"errors"
	"os"

	safebrowsingv4 "github.com/google/safebrowsing"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/va"
	safebrowsing "github.com/letsencrypt/go-safe-browsing-api"
)

var (
	NilConfigErr   = errors.New("Google Safe Browsing config was nil")
	EmptyAPIKeyErr = errors.New("a Google Safe Browsing config was given but " +
		"it did not include a Google API key in APIKey")
	EmptyDataDirErr = errors.New("a Google Safe Browsing config was given but " +
		"it did not include a DataDir for persistence")
	MissingDataDirErr = errors.New("a Google Safe Browsing data directory was " +
		"given but it does not exist")
	BadDataDirErr = errors.New("a Google Safe Browsing data directory was " +
		"given but it cannot be opened")
)

// configCheck returns an error if:
// * the gsb config struct given is nil
// * the gsb config struct's APIKey is empty
// * the gsb config struct's DataDir is empty
// * the gsb config struct's DataDir doesn't exist or isn't readable
func configCheck(gsb *cmd.GoogleSafeBrowsingConfig) error {
	if gsb == nil {
		return NilConfigErr
	}
	if gsb.APIKey == "" {
		return EmptyAPIKeyErr
	}
	if gsb.DataDir == "" {
		return EmptyDataDirErr
	}
	f, err := os.Open(gsb.DataDir)
	// NOTE: Using `defer f.Close()` instead makes errcheck unhappy.
	defer func() { _ = f.Close() }()
	if err != nil {
		if os.IsNotExist(err) {
			return MissingDataDirErr
		}
		return BadDataDirErr
	}
	return nil
}

// gsbAdapter adapts the Google safebrowsing's `SafeBrowser` type to the
// `va.SafeBrowsing` interface Boulder uses.
type gsbAdapter struct {
	*safebrowsingv4.SafeBrowser
}

// IsListed provides the va.SafeBrowsing interface by using the
// `safebrowsing4v.SafeBrowser` to look up one URL and return the first threat
// list it is found on, or "" if the URL is safe.
func (sb gsbAdapter) IsListed(url string) (string, error) {
	threats, err := sb.LookupURLs([]string{url})
	if err != nil {
		return "error", err
	}
	if len(threats) > 0 {
		// NOTE: We only return the _first_ URL threat's first ThreatType here. It's
		// possible a URL could return multiple threat's with distinct ThreatTypes,
		// but the va.SafeBrowser interface only returns 1 string that is compared
		// against "" to make a "safe or not" decision. We do not need more
		// granularity.
		if len(threats[0]) == 0 {
			return "error", fmt.Errorf("Empty URLThreat from LookupURLs[0]")
		}
		return threats[0][0].ThreatType.String(), nil
	}
	return "", nil
}

// newGoogleSafeBrowsingV4 constructs a va.SafeBrowsing instance using the new
// Google upstream Safe Browsing version 4 client.
func newGoogleSafeBrowsingV4(gsb *cmd.GoogleSafeBrowsingConfig) va.SafeBrowsing {
	// If there is no GSB configuration, don't create a client
	if gsb == nil {
		return nil
	}
	if err := configCheck(gsb); err != nil {
		cmd.FailOnError(err, "unable to create new safe browsing v4 client")
	}
	sb, err := safebrowsingv4.NewSafeBrowser(safebrowsingv4.Config{
		APIKey: gsb.APIKey,
		DBPath: gsb.DataDir,
	})
	if err != nil {
		cmd.FailOnError(err, "unable to create new safe browsing v4 client")
	}
	return gsbAdapter{SafeBrowser: sb}
}

// newGoogleSafeBrowsing constructs a va.SafeBrowsing instance using the legacy
// letsencrypt fork of the go-safebrowsing-api client.
func newGoogleSafeBrowsing(gsb *cmd.GoogleSafeBrowsingConfig) va.SafeBrowsing {
	// If there is no GSB configuration, don't create a client
	if gsb == nil {
		return nil
	}
	if err := configCheck(gsb); err != nil {
		cmd.FailOnError(err, "unable to create new safe browsing client")
	}
	sbc, err := safebrowsing.NewSafeBrowsing(gsb.APIKey, gsb.DataDir)
	if err != nil {
		cmd.FailOnError(err, "unable to create new safe browsing client")
	}
	return sbc
}

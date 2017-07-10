// go:generate mockgen -source ../../va/gsb.go -package mock_gsb -destination mock_gsb.go SafeBrowsingV4

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	safebrowsingv4 "github.com/google/safebrowsing"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/va"
	safebrowsing "github.com/letsencrypt/go-safe-browsing-api"
)

const (
	// Filename used for the v4 safebrowsing client's local database in the
	// configured GSB data directory. The file contents are a gzipped GOB encoding
	// of the client's in-memory cache.
	v4DbFilename = "safebrowsing.v4.cache.bin"
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
	EmptyURLThreatErr = errors.New("Empty URLThreat from LookupURLs[0]")
	BadDBFileErr      = errors.New("unable to create Google Safe Browsing v4 db " +
		"file in data directory")
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
	if _, err := os.Stat(gsb.DataDir); err != nil {
		if os.IsNotExist(err) {
			return MissingDataDirErr
		} else {
			return BadDataDirErr
		}
	}
	return nil
}

// gsbAdapter adapts the Google safebrowsing's `SafeBrowser` type to the
// `va.SafeBrowsing` interface Boulder uses.
type gsbAdapter struct {
	va.SafeBrowsingV4
}

// IsListed provides the va.SafeBrowsing interface by using the
// `safebrowsing4v.SafeBrowser` to look up one URL and return the first threat
// list it is found on, or "" if the URL is safe.
func (sb gsbAdapter) IsListed(url string) (string, error) {
	threats, err := sb.LookupURLs([]string{url})
	if err != nil {
		return "error", err
	}
	if len(threats) > 0 && threats[0] != nil {
		// Note: We don't bother to examine the threats for their ThreatType or
		// other information. The va.SafeBrowser interface expects a "hit" return
		// string that is compared against "" to make a "safe or not" decision. For
		// our purposes it is sufficient to return a fixed string instead of further
		// processing of the results.
		return "v4-gsb-hit", nil
	}
	return "", nil
}

// gsbLogAdapter adapts a blog.Logger to the io.Writer interface used by the
// Google safebrowsing client for a logger. All messages written to the Writer
// by the library will be adapter to the logger's Info method.
type gsbLogAdapter struct {
	log blog.Logger
}

func (a gsbLogAdapter) Write(b []byte) (int, error) {
	a.log.Info(string(b))
	return len(b), nil
}

// newGoogleSafeBrowsingV4 constructs a va.SafeBrowsing instance using the new
// Google upstream Safe Browsing version 4 client.
func newGoogleSafeBrowsingV4(gsb *cmd.GoogleSafeBrowsingConfig, logger blog.Logger) (va.SafeBrowsing, error) {
	// If there is no GSB configuration, don't create a client
	if gsb == nil {
		return nil, nil
	}
	if err := configCheck(gsb); err != nil {
		return nil, err
	}

	dbFile := filepath.Join(gsb.DataDir, v4DbFilename)
	sb, err := safebrowsingv4.NewSafeBrowser(safebrowsingv4.Config{
		APIKey:    gsb.APIKey,
		DBPath:    dbFile,
		ServerURL: gsb.ServerURL,
		Logger:    gsbLogAdapter{logger},
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel() // avoid leak
	err = sb.WaitUntilReady(ctx)
	if err != nil {
		return nil, err
	}
	return gsbAdapter{sb}, nil
}

// newGoogleSafeBrowsing constructs a va.SafeBrowsing instance using the legacy
// letsencrypt fork of the go-safebrowsing-api client.
func newGoogleSafeBrowsing(gsb *cmd.GoogleSafeBrowsingConfig) (va.SafeBrowsing, error) {
	// If there is no GSB configuration, don't create a client
	if gsb == nil {
		return nil, nil
	}
	if err := configCheck(gsb); err != nil {
		return nil, err
	}
	sbc, err := safebrowsing.NewSafeBrowsing(gsb.APIKey, gsb.DataDir)
	if err != nil {
		return nil, err
	}
	return sbc, nil
}

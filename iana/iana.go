package iana

import (
	"fmt"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	zlintutil "github.com/zmap/zlint/v3/util"
)

// ExtractSuffix returns the public suffix of the domain using only the "ICANN"
// section of the Public Suffix List database.
// If the domain does not end in a suffix that belongs to an IANA-assigned
// domain, ExtractSuffix returns an error.
// It confirms with zlint's TLD list.
func ExtractSuffix(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("Blank name argument passed to ExtractSuffix")
	}

	if !zlintutil.HasValidTLD(name, time.Now()) {
		return "", fmt.Errorf("%s has an unknown TLD", name)
	}

	rule := publicsuffix.DefaultList.Find(name, &publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if rule == nil {
		return "", fmt.Errorf("Domain %s has no IANA TLD", name)
	}

	suffix := rule.Decompose(name)[1]

	// If the TLD is empty, it means name is actually a suffix.
	// In fact, decompose returns an array of empty strings in this case.
	if suffix == "" {
		suffix = name
	}

	return suffix, nil
}

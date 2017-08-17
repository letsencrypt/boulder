//go:generate go run gen.go

package tlds

import "errors"

// CheckTLD Verifies that the provided TLD is present in the
// IANA root DNS zone file
func CheckTLD(tld string) error {
	_, present := tlds[tld]
	if !present {
		return errors.New("Name doesn't end in a IANA TLD")
	}
	return nil
}

//go:generate go run gen.go

package tlds

// Valid checks that the provided TLD is present in the
// IANA root DNS zone file
func Valid(tld string) bool {
	_, present := tlds[tld]
	if !present {
		return false
	}
	return true
}

package va

// replaceInvalidUTF8 replaces all invalid UTF-8 encodings with
// Unicode REPLACEMENT CHARACTER.
func replaceInvalidUTF8(input []byte) string {
	var ret string
	// Ranging over a string in Go produces runes. When the range keyword
	// encounters an invalid UTF-8 encoding, it returns REPLACEMENT CHARACTER.
	for _, v := range string(input) {
		ret = ret + string(v)
	}
	return ret
}

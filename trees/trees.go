package trees

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// MaxSize is the largest size of tree that can exist, per MTC spec.
const MaxSize = 1<<48 - 1

// CheckName returns an error if name does not follow the cosigner name
// construction in https://c2sp.org/tlog-cosignature#cosigners, which log
// origins also follow: a non-empty UTF-8 string of at most 255 bytes with no
// Unicode spaces, plus signs, or control characters below U+0020.
func CheckName(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("%d bytes, want at most 255", len(name))
	}
	if !utf8.ValidString(name) {
		return errors.New("not valid UTF-8")
	}
	for _, r := range name {
		if unicode.IsSpace(r) || r == '+' || r < 0x20 {
			return fmt.Errorf("contains %q", r)
		}
	}
	return nil
}

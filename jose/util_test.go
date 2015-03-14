package jose

import (
	"bytes"
	"fmt"
	"testing"
)

func TestB64Enc(t *testing.T) {
	fmt.Println("--> TestB64Enc")
	in := []byte{0x00, 0xff}
	out := "AP8"
	if x := B64enc(in); x != out {
		t.Errorf("b64enc(%v) = %v, want %v", in, x, out)
	}
}

func TestB64Dec(t *testing.T) {
	fmt.Println("--> TestB64Dec")
	in := "_wA"
	out := []byte{0xFF, 0x00}
	x, err := B64dec(in)
	if (err != nil) || (bytes.Compare(x, out) != 0) {
		t.Errorf("b64dec(%v) = %v, want %v", in, x, out)
	}
}

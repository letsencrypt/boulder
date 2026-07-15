package tiles

import "testing"

func TestN(t *testing.T) {
	in := uint64(1234067)
	out := N(in)

	want := "x001/x234/067"

	if out != want {
		t.Errorf("N(%d): got %q, want %q", in, out, want)
	}

	in = uint64(0)
	out = N(in)

	want = "000"
	if out != want {
		t.Errorf("N(%d): got %q, want %q", in, out, want)
	}
}

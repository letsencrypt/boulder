package blog

import (
	"errors"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/letsencrypt/boulder/identifier"
)

func TestAttrHelpers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		got     slog.Attr
		wantKey string
		wantVal slog.Value
	}{
		{
			name:    "Acct",
			got:     Acct(42),
			wantKey: "acct",
			wantVal: slog.Int64Value(42),
		},
		{
			name:    "Order",
			got:     Order(17),
			wantKey: "order",
			wantVal: slog.Int64Value(17),
		},
		{
			name:    "Authz",
			got:     Authz(99),
			wantKey: "authz",
			wantVal: slog.Int64Value(99),
		},
		{
			name:    "Serial",
			got:     Serial("deadbeef"),
			wantKey: "serial",
			wantVal: slog.StringValue("deadbeef"),
		},
		{
			name:    "Error",
			got:     Error(errors.New("boom")),
			wantKey: "error",
			wantVal: slog.StringValue("boom"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got.Key != tc.wantKey {
				t.Errorf("attr key = %q, want %q", tc.got.Key, tc.wantKey)
			}
			if !tc.got.Value.Equal(tc.wantVal) {
				t.Errorf("attr value = %v, want %v", tc.got.Value, tc.wantVal)
			}
		})
	}
}

func TestIdentsAttr(t *testing.T) {
	t.Parallel()

	// This test is separate from the above because the Idents helper accepts
	// a variadic number of arguments.
	attr := Idents(identifier.NewDNS("example.com"), identifier.NewIP(netip.MustParseAddr("12.34.56.78")))
	if attr.Key != "idents" {
		t.Errorf("attr key = %q, want %q", attr.Key, "idents")
	}

	idents, ok := attr.Value.Any().([]identifier.ACMEIdentifier)
	if !ok {
		t.Fatalf("idents attr value should be a slice of ACMEIdentifier, got %T", attr.Value.Any())
	}
	if len(idents) != 2 {
		t.Fatalf("got %d idents, want 2", len(idents))
	}
	if idents[0].Value != "example.com" {
		t.Errorf("idents[0].Value = %q, want %q", idents[0].Value, "example.com")
	}
	if idents[1].Value != "12.34.56.78" {
		t.Errorf("idents[1].Value = %q, want %q", idents[1].Value, "12.34.56.78")
	}
}

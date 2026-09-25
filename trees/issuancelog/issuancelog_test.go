package issuancelog

import (
	"strings"
	"testing"
)

// TestIDDerivations pins the derived names to mtc-tlog's own examples and
// the identifiers the dev environment uses.
func TestIDDerivations(t *testing.T) {
	for _, tc := range []struct {
		id               ID
		expectString     string
		expectOrigin     string
		expectTilePrefix string
	}{
		{
			id:               ID{CAID: "32473.2", LogNumber: 42},
			expectString:     "32473.2.0.42",
			expectOrigin:     "oid/1.3.6.1.4.1.32473.2.0.42",
			expectTilePrefix: "32473.2/42",
		},
		{
			id:               ID{CAID: "44947.4.1", LogNumber: 44},
			expectString:     "44947.4.1.0.44",
			expectOrigin:     "oid/1.3.6.1.4.1.44947.4.1.0.44",
			expectTilePrefix: "44947.4.1/44",
		},
		{
			id:               ID{CAID: "1", LogNumber: 1},
			expectString:     "1.0.1",
			expectOrigin:     "oid/1.3.6.1.4.1.1.0.1",
			expectTilePrefix: "1/1",
		},
	} {
		t.Run(tc.expectString, func(t *testing.T) {
			if tc.id.String() != tc.expectString {
				t.Errorf("String = %q, want %q", tc.id.String(), tc.expectString)
			}
			if tc.id.Origin() != tc.expectOrigin {
				t.Errorf("Origin = %q, want %q", tc.id.Origin(), tc.expectOrigin)
			}
			if tc.id.TilePrefix() != tc.expectTilePrefix {
				t.Errorf("TilePrefix = %q, want %q", tc.id.TilePrefix(), tc.expectTilePrefix)
			}
		})
	}
}

func TestParseID(t *testing.T) {
	for _, tc := range []struct {
		in        string
		expectID  ID
		expectErr string
	}{
		{in: "32473.2.0.42", expectID: ID{CAID: "32473.2", LogNumber: 42}},
		{in: "44947.4.1.0.44", expectID: ID{CAID: "44947.4.1", LogNumber: 44}},
		{in: "1.0.1", expectID: ID{CAID: "1", LogNumber: 1}},
		{in: "44947.0.1.0.5", expectID: ID{CAID: "44947.0.1", LogNumber: 5}},
		{in: "44947.4.1.0.65535", expectID: ID{CAID: "44947.4.1", LogNumber: 65535}},
		{in: "", expectErr: "not of the form"},
		{in: "44947.4.1", expectErr: "not of the form"},
		{in: ".0.44", expectErr: "not of the form"},
		{in: "44947.4.1.0.", expectErr: "parsing log number"},
		{in: "44947.4.1.0.x", expectErr: "parsing log number"},
		{in: "44947.4.1.0.65536", expectErr: "parsing log number"},
		{in: "44947.4.1.0.0", expectErr: "log number 0"},
		{in: "44947.4.1.0.044", expectErr: "canonical form"},
		{in: "44947.4.1.0.+44", expectErr: "parsing log number"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			id, err := ParseID(tc.in)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("ParseID(%q) = %v, want error containing %q", tc.in, id, tc.expectErr)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Errorf("ParseID(%q) error = %q, want it to contain %q", tc.in, err, tc.expectErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseID(%q): %s", tc.in, err)
			}
			if id != tc.expectID {
				t.Errorf("ParseID(%q) = %v, want %v", tc.in, id, tc.expectID)
			}
		})
	}
}

package issuancelog

import "testing"

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

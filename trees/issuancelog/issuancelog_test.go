package issuancelog

import (
	"reflect"
	"strings"
	"testing"
)

// mustLoad loads the given Config, failing the test if it is invalid.
func mustLoad(t *testing.T, c Config) *ID {
	t.Helper()
	id, err := c.Load()
	if err != nil {
		t.Fatalf("Config{CAID: %q, LogNumber: %d}.Load() = %s, want success", c.CAID, c.LogNumber, err)
	}
	return id
}

// TestIDDerivations pins the derived names to mtc-tlog's own examples and
// the identifiers the dev environment uses.
func TestIDDerivations(t *testing.T) {
	for _, tc := range []struct {
		id               *ID
		expectString     string
		expectOrigin     string
		expectTilePrefix string
	}{
		{
			id:               mustLoad(t, Config{CAID: "32473.2", LogNumber: 42}),
			expectString:     "32473.2.0.42",
			expectOrigin:     "oid/1.3.6.1.4.1.32473.2.0.42",
			expectTilePrefix: "32473.2/42",
		},
		{
			id:               mustLoad(t, Config{CAID: "44947.4.1", LogNumber: 3}),
			expectString:     "44947.4.1.0.3",
			expectOrigin:     "oid/1.3.6.1.4.1.44947.4.1.0.3",
			expectTilePrefix: "44947.4.1/3",
		},
		{
			id:               mustLoad(t, Config{CAID: "1", LogNumber: 1}),
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
		expectID  *ID
		expectErr string
	}{
		{in: "32473.2.0.42", expectID: mustLoad(t, Config{CAID: "32473.2", LogNumber: 42})},
		{in: "44947.4.1.0.3", expectID: mustLoad(t, Config{CAID: "44947.4.1", LogNumber: 3})},
		{in: "1.0.1", expectID: mustLoad(t, Config{CAID: "1", LogNumber: 1})},
		{in: "44947.0.1.0.5", expectID: mustLoad(t, Config{CAID: "44947.0.1", LogNumber: 5})},
		{in: "44947.4.1.0.65535", expectID: mustLoad(t, Config{CAID: "44947.4.1", LogNumber: 65535})},
		{in: "", expectErr: "at least three arcs"},
		{in: "44947.0", expectErr: "at least three arcs"},
		{in: "44947.4.1", expectErr: "must have 0 before its log number"},
		{in: ".0.3", expectErr: "invalid CA ID"},
		{in: "44947.4.1.0.", expectErr: "parsing log number"},
		{in: "44947.4.1.0.x", expectErr: "parsing log number"},
		{in: "44947.-4.1.0.3", expectErr: "invalid CA ID"},
		{in: "44947.4.1.0.+3", expectErr: "parsing log number"},
		{in: "44947.4.1.0.65536", expectErr: "parsing log number"},
		{in: "44947.4.1.0.0", expectErr: "log number 0"},
		{in: "44947.4.1.0.03", expectErr: "leading zero"},
		{in: "44947.4.1.00.3", expectErr: "must have 0 before its log number"},
		{in: "44947.04.1.0.3", expectErr: "invalid CA ID"},
		{in: "044947.4.1.0.3", expectErr: "invalid CA ID"},
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
			if !reflect.DeepEqual(id, tc.expectID) {
				t.Errorf("ParseID(%q) = {CAID: %s, LogNumber: %d}, want {CAID: %s, LogNumber: %d}",
					tc.in, id.CAID(), id.LogNumber(), tc.expectID.CAID(), tc.expectID.LogNumber())
			}
		})
	}
}

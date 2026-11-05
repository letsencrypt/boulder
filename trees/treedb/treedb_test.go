package treedb

import (
	"testing"
)

func TestSubtreesModelValid(t *testing.T) {
	valid := SubtreesModel{
		MTCLogID:     "44947.1",
		SubtreeStart: 0,
		SubtreeEnd:   8,
		SubtreeHash:  make([]byte, 32),
	}
	err := valid.Valid()
	if err != nil {
		t.Fatalf("Valid() on a valid subtree: got %s, want nil", err)
	}

	testCases := []struct {
		name    string
		distort func(*SubtreesModel)
	}{
		{"empty MTCLogID", func(s *SubtreesModel) { s.MTCLogID = "" }},
		{"end equals start", func(s *SubtreesModel) { s.SubtreeEnd = s.SubtreeStart }},
		{"end before start", func(s *SubtreesModel) { s.SubtreeStart = 9 }},
		{"end at 2^48", func(s *SubtreesModel) { s.SubtreeEnd = 1 << 48 }},
		{"empty hash", func(s *SubtreesModel) { s.SubtreeHash = nil }},
		{"short hash", func(s *SubtreesModel) { s.SubtreeHash = make([]byte, 31) }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			tc.distort(&s)
			err := s.Valid()
			if err == nil {
				t.Errorf("Valid(): got nil, want error")
			}
		})
	}
}

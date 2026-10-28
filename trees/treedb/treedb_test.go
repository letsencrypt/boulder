package treedb

import (
	"testing"
)

func TestCheckpointSubtreeModelValid(t *testing.T) {
	valid := CheckpointSubtreeModel{
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
		distort func(*CheckpointSubtreeModel)
	}{
		{"empty MTCLogID", func(s *CheckpointSubtreeModel) { s.MTCLogID = "" }},
		{"end equals start", func(s *CheckpointSubtreeModel) { s.SubtreeEnd = s.SubtreeStart }},
		{"end before start", func(s *CheckpointSubtreeModel) { s.SubtreeStart = 9 }},
		{"end at 2^48", func(s *CheckpointSubtreeModel) { s.SubtreeEnd = 1 << 48 }},
		{"empty hash", func(s *CheckpointSubtreeModel) { s.SubtreeHash = nil }},
		{"short hash", func(s *CheckpointSubtreeModel) { s.SubtreeHash = make([]byte, 31) }},
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

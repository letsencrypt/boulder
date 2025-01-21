package allowlist

import (
	"testing"
)

func TestNewFromYAML(t *testing.T) {
	tests := []struct {
		name          string
		yamlData      string
		check         []string
		expectAnswers []bool
		expectErr     bool
	}{
		{
			name:          "valid YAML",
			yamlData:      "- oak\n- maple\n- cherry",
			check:         []string{"oak", "walnut", "maple", "cherry"},
			expectAnswers: []bool{true, false, true, true},
			expectErr:     false,
		},
		{
			name:          "empty YAML",
			yamlData:      "",
			check:         nil,
			expectAnswers: nil,
			expectErr:     true,
		},
		{
			name:          "invalid YAML",
			yamlData:      "{ invalid_yaml",
			check:         []string{},
			expectAnswers: []bool{},
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := NewFromYAML[string]([]byte(tt.yamlData))
			if (err != nil) != tt.expectErr {
				t.Fatalf("NewFromYAML() error = %v, expectErr = %v", err, tt.expectErr)
			}

			if err == nil {
				for i, item := range tt.check {
					got := list.Contains(item)
					if got != tt.expectAnswers[i] {
						t.Errorf("Contains(%q) got %v, want %v", item, got, tt.expectAnswers[i])
					}
				}
			}
		})
	}
}

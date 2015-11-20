package cmd

import (
	"encoding/json"
	"os"
	"path"
	"testing"
)

func TestConfigSecret(t *testing.T) {
	type hasASecret struct {
		Value ConfigSecret
	}
	var twocankeep hasASecret
	err := json.Unmarshal([]byte(`{"value": "hi"}`), &twocankeep)
	if err != nil {
		t.Fatalf("Error unmarshaling: %s", err)
	}
	if twocankeep.Value != "hi" {
		t.Errorf("Expected parsed value to be \"hi\", got %q", twocankeep.Value)
	}

	os.Chdir(path.Base(os.Args[0]))
	var oneofthemisdead hasASecret
	err = json.Unmarshal([]byte(`{"value": "secret:testdata/secret"}`), &oneofthemisdead)
	if err != nil {
		t.Fatalf("Error unmarshaling: %s", err)
	}
	if oneofthemisdead.Value != "test secret" {
		t.Errorf("Expected parsed value to be \"test secret\", got %q", twocankeep.Value)
	}
}

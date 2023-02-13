package strictyaml

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

var (
	validConfig = []byte(`
a: c
d: c
`)
	invalidConfig1 = []byte(`
x: y
`)

	invalidConfig2 = []byte(`
a: c
d: c
x:
  - hey
`)
)

func TestCeremonyConfigUnmarshal(t *testing.T) {
	var config struct {
		A string `yaml:"a"`
		D string `yaml:"d"`
	}

	err := Unmarshal(validConfig, &config)
	test.AssertNotError(t, err, "yaml: unmarshal errors")

	err = Unmarshal(invalidConfig1, &config)
	test.AssertError(t, err, "yaml: unmarshal errors")

	err = Unmarshal(invalidConfig2, &config)
	test.AssertError(t, err, "yaml: unmarshal errors")
}

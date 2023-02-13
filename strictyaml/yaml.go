// Package strictyaml provides a strict YAML unmarshaller based on `go-yaml/yaml`
package strictyaml

import (
	"bytes"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// Unmarshal takes a byte array and an arbitrary interface as arguments and
// attempts to unmarshal the contents of the byte array into a defined struct. Any
// config keys from the incoming YAML document which do not correspond to
// expected keys in the config struct will result in errors.
//
// TODO(https://github.com/go-yaml/yaml/issues/639): Replace this function with
// yaml.Unmarshal once a more ergonomic way to set unmarshal options is added upstream.
func Unmarshal(b []byte, yamlObj interface{}) error {
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)

	err := decoder.Decode(yamlObj)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return err
}

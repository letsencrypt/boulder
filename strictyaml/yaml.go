// Package strictyaml provides a strict YAML unmarshaller based on `go-yaml/yaml`
package strictyaml

import (
	"bytes"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// Unmarshal takes a byte array and an interface passed by reference. The
// decode.Decode will read the next YAML-encoded value from its input and store
// it in the value pointed to by yamlObj. Any config keys from the incoming YAML
// document which do not correspond to expected keys in the config struct will
// result in errors.
//
// TODO(https://github.com/go-yaml/yaml/issues/639): Replace this function with
// yaml.Unmarshal once a more ergonomic way to set unmarshal options is added
// upstream.
func Unmarshal(b []byte, yamlObj interface{}) error {
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)

	// decoder.Decode will mutate yamlObj
	err := decoder.Decode(yamlObj)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// Package strictyaml provides a strict YAML unmarshaller based on `go-yaml/yaml`
package strictyaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Unmarshal takes a byte array and an interface passed by reference. The
// d.Decode will read the next YAML-encoded value from its input and store it in
// the value pointed to by yamlObj. Any config keys from the incoming YAML
// document which do not correspond to expected keys in the config struct will
// result in errors.
//
// TODO(https://github.com/go-yaml/yaml/issues/639): Replace this function with
// yaml.Unmarshal once a more ergonomic way to set unmarshal options is added
// upstream.
func Unmarshal(b []byte, yamlObj interface{}) error {
	r := bytes.NewReader(b)

	d := yaml.NewDecoder(r)
	d.KnownFields(true)

	// d.Decode will mutate yamlObj
	err := d.Decode(yamlObj)

	// As bytes are read, the length of the byte buffer should decrease. If it
	// doesn't, there's a problem.
	if r.Len() != 0 {
		return fmt.Errorf("yaml object of size %d bytes had %d bytes of unexpected unconsumed trailers", r.Size(), r.Len())
	}

	// Show potential error other than EOF which we'll handle later.
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	// When Decode() attempts to parse an empty buffer (config file), an io.EOF is ultimately returned.
	// 1) Parsing until the end of file returns a nil:
	//    https://github.com/go-yaml/yaml/blob/f6f7691b1fdeb513f56608cd2c32c51f8194bf51/decode.go#L160-L162
	// 2) The Decode() checks for that nil and returns the io.EOF
	//    https://github.com/go-yaml/yaml/blob/f6f7691b1fdeb513f56608cd2c32c51f8194bf51/yaml.go#L123-L126
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("yaml object is empty: %s", err)
	}

	return nil
}

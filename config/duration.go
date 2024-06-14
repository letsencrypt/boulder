package config

import (
	"encoding/json"
	"errors"
	"time"
)

// Duration is a new time.Duration type definition that allows serialization to
// YAML as well as JSON.
type Duration time.Duration

// Get returns a time.Duration from the Duration.
func (d *Duration) Get() time.Duration {
	return time.Duration(*d)
}

// Set allows configuring the Duration's value.
func (d *Duration) Set(td time.Duration) {
	*d = Duration(td)
}

// ErrDurationMustBeString is returned when a non-string value is
// presented to be deserialized as a ConfigDuration
var ErrDurationMustBeString = errors.New("cannot JSON unmarshal something other than a string into a ConfigDuration")

// UnmarshalJSON parses a string into a ConfigDuration using
// time.ParseDuration.  If the input does not unmarshal as a
// string, then UnmarshalJSON returns ErrDurationMustBeString.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := ""
	err := json.Unmarshal(b, &s)
	if err != nil {
		var jsonUnmarshalTypeErr *json.UnmarshalTypeError
		if errors.As(err, &jsonUnmarshalTypeErr) {
			return ErrDurationMustBeString
		}
		return err
	}
	dur, err := time.ParseDuration(s)
	d.Set(dur)

	return err
}

// MarshalJSON returns the string form of the duration, as a byte array.
func (d Duration) MarshalJSON() ([]byte, error) {
	td := time.Duration(d)
	return []byte(td.String()), nil
}

// UnmarshalYAML uses the same format as JSON, but is called by the YAML
// parser (vs. the JSON parser).
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Set(dur)

	return nil
}

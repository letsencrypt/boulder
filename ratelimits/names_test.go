package ratelimits

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestNameIsValid(t *testing.T) {
	t.Parallel()
	type args struct {
		name Name
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Unknown", args: args{name: Unknown}, want: false},
		{name: "9001", args: args{name: 9001}, want: false},
		{name: "NewRegistrationsPerIPAddress", args: args{name: NewRegistrationsPerIPAddress}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.name.isValid()
			test.AssertEquals(t, tt.want, got)
		})
	}
}

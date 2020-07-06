package main

import (
	"github.com/letsencrypt/boulder/test"
	"testing"
)

func TestLineValid(t *testing.T) {
	err := lineValid("2020-07-06T18:07:43.109389+00:00 70877f679c72 datacenter 6 boulder-wfe[1595]: xxxxxxx Caught SIGTERM")
	test.AssertError(t, err, "didn't error on invalid checksum")

	err2 := lineValid(err.Error())
	test.AssertNotError(t, err2, "expected no error when feeding lineValid's error output into itself")
}

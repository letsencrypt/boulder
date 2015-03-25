#!/bin/bash -ex
# Run all tests and coverage checks. Called from Travis automatically, also
# suitable to run manually. See list of prerequisite packages in .travis.yml
# NOTE: Currently this must be run from the fully-expanded letsencrypt path
# under your GOPATH, not a symlink.

# Path for installed go package binaries. If yours is different, override with
# GOBIN=/my/path/to/bin ./test.sh
GOBIN=${GOBIN:-$HOME/gopath/bin}
go vet -x ./...
$GOBIN/golint ./...
go test -covermode=count -coverprofile=analysis.coverprofile ./analysis/
go test -covermode=count -coverprofile=ca.coverprofile ./ca/
go test -covermode=count -coverprofile=core.coverprofile ./core/
go test -covermode=count -coverprofile=log.coverprofile ./log/
go test -covermode=count -coverprofile=ra.coverprofile ./ra/
go test -covermode=count -coverprofile=rpc.coverprofile ./rpc/
go test -covermode=count -coverprofile=sa.coverprofile ./sa/
go test -covermode=count -coverprofile=test.coverprofile ./test/
go test -covermode=count -coverprofile=va.coverprofile ./va/
go test -covermode=count -coverprofile=wfe.coverprofile ./wfe/
$GOBIN/gover
$GOBIN/goveralls -coverprofile=gover.coverprofile -service=travis-ci

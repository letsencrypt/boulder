package test

import "github.com/golang/mock/mockgen/model"

// This assignment exists solely for the purpose of convincing
// go mod vendor to vendor github.com/golang/mock/mockgen/model as
// gomock will fail to generate code if it doesn't exist in the
// users GOPATH, but it isn't actually imported by any boulder or
// gomock code.
var _ = model.Package{}

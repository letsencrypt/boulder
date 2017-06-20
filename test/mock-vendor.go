package test

import "github.com/golang/mock/mockgen/model"

// This assignment exists solely for the purpose of convincing godep
// to vendor github.com/golang/mock/mockgen/model as gomock will fail
// to generate code if it doesn't exist in the users GOPATH but isn't
// actually imported by any boulder or gomock code. The variable name
// is chosen so that it is unlikely to clash with anything else in this
// package.
var _ignore = model.Package{}

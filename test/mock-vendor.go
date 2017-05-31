package test

import "github.com/golang/mock/mockgen/model"

// This assignment exists solely for the purpose of convincing godep
// to vendor github.com/golang/mock/mockgen/model so that we don't
// require users of the boulder-tools image to have extra packages
// in their GOPATH to properly run boulder tests. Variable name is
// chosen so that it is unlikely to clash with anything else in this
// package.
var _ignore = model.Package{}

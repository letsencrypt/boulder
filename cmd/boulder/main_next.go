//go:build go1.27

package main

import (
	_ "github.com/letsencrypt/boulder/cmd/boulder-mtca"
	_ "github.com/letsencrypt/boulder/cmd/boulder-mtpublisher"
)

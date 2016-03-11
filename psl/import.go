package publicsuffix

import (
	// Include an ignored import so godep save -r ./... doesn't delete the
	// vendored publicsuffix.
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/net/publicsuffix"
)

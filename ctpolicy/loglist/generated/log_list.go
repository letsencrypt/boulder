//go:build !integration

package generated

import _ "embed"

//go:generate ./update.sh

//go:embed log_list.json
var LogListJSON []byte

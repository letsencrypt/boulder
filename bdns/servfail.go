package bdns

import "strings"

var caaServfailException map[string]bool

func init() {
	const exceptions = `
servfailexception.example.com
`
	caaServfailException = make(map[string]bool)
	for _, v := range strings.Split(exceptions, "\n") {
		if len(v) > 0 {
			caaServfailException[v] = true
		}
	}
}

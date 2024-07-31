package db

import (
	"fmt"
	"strings"
)

// QuestionMarks returns a string consisting of N Postgres placeholders ($1, $2, $3, etc),
// separated by commas. If n is <= 0, panics. The first placeholder's number is `starting` + 1.
func QuestionMarks(starting, n int) string {
	if n <= 0 {
		panic("db.QuestionMarks called with n <=0")
	}
	var qmarks strings.Builder
	qmarks.Grow(2 * n)
	for i := range n {
		if i == 0 {
			fmt.Fprintf(&qmarks, "$%d", starting+i+1)
		} else {
			fmt.Fprintf(&qmarks, ",$%d", starting+i+1)
		}
	}
	return qmarks.String()
}

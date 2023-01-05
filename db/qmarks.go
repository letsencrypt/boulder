package db

import "strings"

// QuestionMarks returns a string consisting of N question marks, joined by
// commas.
func QuestionMarks(n int) string {
	var qmarks strings.Builder
	qmarks.Grow(2 * n)
	for i := 0; i < n; i++ {
		if i == 0 {
			qmarks.WriteString("?")
		} else {
			qmarks.WriteString(",?")
		}
	}
	return qmarks.String()
}

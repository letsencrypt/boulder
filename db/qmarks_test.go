package db

import "testing"
import "github.com/letsencrypt/boulder/test"

func TestQuestionMarks(t *testing.T) {
	test.AssertEquals(t, QuestionMarks(0), "")
	test.AssertEquals(t, QuestionMarks(1), "?")
	test.AssertEquals(t, QuestionMarks(2), "?,?")
	test.AssertEquals(t, QuestionMarks(3), "?,?,?")
}

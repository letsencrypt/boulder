package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

var (
	validPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "http-01": true }
}`)
	invalidPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "nonsense": true }
}`)
	noChallengesPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false
}`)

	emptyChallengesPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": {}
}`)
)

func TestPAConfigUnmarshal(t *testing.T) {
	var pc1 PAConfig
	err := json.Unmarshal(validPAConfig, &pc1)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertNotError(t, pc1.CheckChallenges(), "Flagged valid challenges as bad")

	var pc2 PAConfig
	err = json.Unmarshal(invalidPAConfig, &pc2)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc2.CheckChallenges(), "Considered invalid challenges as good")

	var pc3 PAConfig
	err = json.Unmarshal(noChallengesPAConfig, &pc3)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc3.CheckChallenges(), "Disallow empty challenges map")

	var pc4 PAConfig
	err = json.Unmarshal(emptyChallengesPAConfig, &pc4)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc4.CheckChallenges(), "Disallow empty challenges map")
}

func TestMysqlLogger(t *testing.T) {
	log := blog.UseMock()
	mLog := mysqlLogger{log}

	testCases := []struct {
		args     []interface{}
		expected string
	}{
		{
			[]interface{}{nil},
			`ERR: [AUDIT] [mysql] <nil>`,
		},
		{
			[]interface{}{""},
			`ERR: [AUDIT] [mysql] `,
		},
		{
			[]interface{}{"Sup ", 12345, " Sup sup"},
			`ERR: [AUDIT] [mysql] Sup 12345 Sup sup`,
		},
	}

	for _, tc := range testCases {
		// mysqlLogger proxies blog.AuditLogger to provide a Print() method
		mLog.Print(tc.args...)
		logged := log.GetAll()
		// Calling Print should produce the expected output
		test.AssertEquals(t, len(logged), 1)
		test.AssertEquals(t, logged[0], tc.expected)
		log.Clear()
	}
}

func TestCaptureStdlibLog(t *testing.T) {
	logger := blog.UseMock()
	oldDest := log.Writer()
	defer func() {
		log.SetOutput(oldDest)
	}()
	log.SetOutput(logWriter{logger})
	log.Print("thisisatest")
	results := logger.GetAllMatching("thisisatest")
	if len(results) != 1 {
		t.Fatalf("Expected logger to receive 'thisisatest', got: %s",
			strings.Join(logger.GetAllMatching(".*"), "\n"))
	}
}

func TestVersionString(t *testing.T) {
	core.BuildID = "TestBuildID"
	core.BuildTime = "RightNow!"
	core.BuildHost = "Localhost"

	versionStr := VersionString()
	expected := fmt.Sprintf("Versions: cmd.test=(TestBuildID RightNow!) Golang=(%s) BuildHost=(Localhost)", runtime.Version())
	test.AssertEquals(t, versionStr, expected)
}

func TestReadConfigFile(t *testing.T) {
	err := ReadConfigFile("", nil)
	test.AssertError(t, err, "ReadConfigFile('') did not error")

	type config struct {
		NotifyMailer struct {
			DB DBConfig
			SMTPConfig
		}
		Syslog SyslogConfig
	}
	var c config
	err = ReadConfigFile("../test/config/notify-mailer.json", &c)
	test.AssertNotError(t, err, "ReadConfigFile(../test/config/notify-mailer.json) errored")
	test.AssertEquals(t, c.NotifyMailer.SMTPConfig.Server, "localhost")
}

func TestLogWriter(t *testing.T) {
	mock := blog.UseMock()
	lw := logWriter{mock}
	_, _ = lw.Write([]byte("hi\n"))
	lines := mock.GetAllMatching(".*")
	test.AssertEquals(t, len(lines), 1)
	test.AssertEquals(t, lines[0], "INFO: hi")
}

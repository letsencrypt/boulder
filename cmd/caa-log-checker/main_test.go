package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func TestOpenFile(t *testing.T) {
	tmpPlain, err := ioutil.TempFile(os.TempDir(), "plain")
	test.AssertNotError(t, err, "failed to create temporary file")
	defer os.Remove(tmpPlain.Name())
	_, err = tmpPlain.Write([]byte("test-1\ntest-2"))
	test.AssertNotError(t, err, "failed to write to temp file")
	tmpPlain.Close()

	tmpGzip, err := ioutil.TempFile(os.TempDir(), "gzip-*.gz")
	test.AssertNotError(t, err, "failed to create temporary file")
	defer os.Remove(tmpGzip.Name())
	gzipWriter := gzip.NewWriter(tmpGzip)
	_, err = gzipWriter.Write([]byte("test-1\ntest-2"))
	test.AssertNotError(t, err, "failed to write to temp file")
	gzipWriter.Flush()
	gzipWriter.Close()
	tmpGzip.Close()

	checkFile := func(path string) {
		t.Helper()
		scanner, err := openFile(path)
		test.AssertNotError(t, err, fmt.Sprintf("failed to open %q", path))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		test.AssertNotError(t, scanner.Err(), fmt.Sprintf("failed to read from %q", path))
		test.AssertEquals(t, len(lines), 2)
		test.AssertDeepEquals(t, lines, []string{"test-1", "test-2"})
	}

	checkFile(tmpPlain.Name())
	checkFile(tmpGzip.Name())
}

func TestLoadMap(t *testing.T) {
	testTime := time.Time{}.Add(time.Hour).Add(time.Nanosecond * 123456000)
	testTime = testTime.In(time.FixedZone("UTC-8", -8*60*60))

	tmpA, err := ioutil.TempFile(os.TempDir(), "va-a")
	test.AssertNotError(t, err, "failed to create temporary file")
	defer os.Remove(tmpA.Name())
	formattedTime := testTime.Format(time.RFC3339Nano)
	_, err = tmpA.Write([]byte(fmt.Sprintf(`random
%s Checked CAA records for example.com, [Present: true, asd
random
%s Checked CAA records for beep.boop.com, [Present: false, asd`, formattedTime, formattedTime)))
	test.AssertNotError(t, err, "failed to write to temp file")
	tmpA.Close()
	tmpB, err := ioutil.TempFile(os.TempDir(), "va-b")
	test.AssertNotError(t, err, "failed to create temporary file")
	defer os.Remove(tmpB.Name())
	formattedTime = testTime.Add(time.Hour).Format(time.RFC3339Nano)
	_, err = tmpB.Write([]byte(fmt.Sprintf(`random
%s Checked CAA records for example.com, [Present: true, asd
random
%s Checked CAA records for beep.boop.com, [Present: false, asd`, formattedTime, formattedTime)))
	test.AssertNotError(t, err, "failed to write to temp file")
	tmpB.Close()

	m, err := loadMap([]string{tmpA.Name(), tmpB.Name()})
	test.AssertNotError(t, err, "fail to load log files")
	test.AssertEquals(t, len(m), 3)
	test.Assert(t, m["example.com"][0].Equal(testTime), "wrong time")
	test.Assert(t, m["example.com"][1].Equal(testTime.Add(time.Hour)), "wrong time")
	test.Assert(t, m["beep.boop.com"][0].Equal(testTime), "wrong time")
	test.Assert(t, m["beep.boop.com"][1].Equal(testTime.Add(time.Hour)), "wrong time")
	test.Assert(t, m["boop.com"][0].Equal(testTime), "wrong time")
	test.Assert(t, m["boop.com"][1].Equal(testTime.Add(time.Hour)), "wrong time")
}

func TestCheckIssuances(t *testing.T) {
	testTime := time.Time{}.Add(time.Hour).Add(time.Nanosecond * 123456000)
	testTime = testTime.In(time.FixedZone("UTC-8", -8*60*60))

	checkedMap := map[string][]time.Time{
		"example.com": {
			testTime.Add(time.Hour),
			testTime.Add(3 * time.Hour),
		},
		"2.example.com": {
			testTime.Add(time.Hour),
		},
		"4.example.com": {
			testTime.Add(time.Hour),
		},
		"5.example.com": {
			testTime.Add(time.Hour),
		},
		"6.example.com": {
			testTime.Add(time.Hour + time.Minute),
		},
	}

	raString := fmt.Sprintf(`random
%s Certificate request - successful JSON={"SerialNumber": "1", "Names":["example.com"], "Requester":0}
random
%s Certificate request - successful JSON={"SerialNumber": "2", "Names":["2.example.com", "3.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "3", "Names":["4.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "4", "Names":["5.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "5", "Names":["6.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "7", "Names":["7.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "8", "Names":["8.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "9", "Names":["9.example.com"], "Requester":0}
%s Certificate request - successful JSON={"SerialNumber": "10", "Names":["10.example.com"], "Requester":0}
random`,
		// example.com: CAA @ +1:00, Issue @ +2:00, CAA @ +3:00. (PASS, one valid CAA check, one invalid)
		testTime.Add(time.Hour*2).Format(time.RFC3339Nano),
		// 2.example.com: CAA @ +1:00, Issue @ +2:00. (PASS)
		// 3.example.com: Issue @ +2:00. (FAIL, no CAA check)
		testTime.Add(time.Hour*2).Format(time.RFC3339Nano),
		// 4.example.com: Issue @ +0:30, CAA @ +1:00. (FAIL, but has CAA check within 1h)
		testTime.Add(30*time.Minute).Format(time.RFC3339Nano),
		// 5.example.com: CAA @ +1:00, Issue @ +10:00. (FAIL, CAA check expired >8h)
		testTime.Add(10*time.Hour).Format(time.RFC3339Nano),
		// 6.example.com: Issue @ +1:00, CAA @ +1:01. (PASS, has CAA check within tolerance)
		testTime.Add(time.Hour).Format(time.RFC3339Nano),
		// 7.example.com: Issue @ +12:00 (PASS, no CAA check but issued after latest)
		testTime.Add(12*time.Hour).Format(time.RFC3339Nano),
		// 8.example.com: Issue @ +11:00 (FAIL, no CAA check and on latest boundary)
		testTime.Add(11*time.Hour).Format(time.RFC3339Nano),
		// 9.example.com: Issue @ -2:00 (PASS, no CAA check but issued before earliest)
		testTime.Add(-2*time.Hour).Format(time.RFC3339Nano),
		// 10.example.com: Issue @ -1:00 (FAIL, no CAA check and issued at earliest boundary)
		testTime.Add(-1*time.Hour).Format(time.RFC3339Nano),
	)

	for _, testCase := range []struct {
		name           string
		expectedErrors string
		earliest       time.Time
		latest         time.Time
	}{
		{
			"with-timespan",
			"Issuance missing CAA checks: issued at=0000-12-31 19:00:00.123456 -0800 -0800, serial=2, requester=0, names=[2.example.com 3.example.com], missing checks for names=[3.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0000-12-31 17:30:00.123456 -0800 -0800, serial=3, requester=0, names=[4.example.com], missing checks for names=[4.example.com], timeError=[1800.000]\n" +
				"Issuance missing CAA checks: issued at=0001-01-01 03:00:00.123456 -0800 -0800, serial=4, requester=0, names=[5.example.com], missing checks for names=[5.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0001-01-01 04:00:00.123456 -0800 -0800, serial=8, requester=0, names=[8.example.com], missing checks for names=[8.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0000-12-31 16:00:00.123456 -0800 -0800, serial=10, requester=0, names=[10.example.com], missing checks for names=[10.example.com], timeError=[+Inf]\n",
			testTime.Add(-1 * time.Hour),
			testTime.Add(11 * time.Hour),
		},
		{
			"no-timespan",
			"Issuance missing CAA checks: issued at=0000-12-31 19:00:00.123456 -0800 -0800, serial=2, requester=0, names=[2.example.com 3.example.com], missing checks for names=[3.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0000-12-31 17:30:00.123456 -0800 -0800, serial=3, requester=0, names=[4.example.com], missing checks for names=[4.example.com], timeError=[1800.000]\n" +
				"Issuance missing CAA checks: issued at=0001-01-01 03:00:00.123456 -0800 -0800, serial=4, requester=0, names=[5.example.com], missing checks for names=[5.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0001-01-01 05:00:00.123456 -0800 -0800, serial=7, requester=0, names=[7.example.com], missing checks for names=[7.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0001-01-01 04:00:00.123456 -0800 -0800, serial=8, requester=0, names=[8.example.com], missing checks for names=[8.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0000-12-31 15:00:00.123456 -0800 -0800, serial=9, requester=0, names=[9.example.com], missing checks for names=[9.example.com], timeError=[+Inf]\n" +
				"Issuance missing CAA checks: issued at=0000-12-31 16:00:00.123456 -0800 -0800, serial=10, requester=0, names=[10.example.com], missing checks for names=[10.example.com], timeError=[+Inf]\n",
			time.Time{},
			time.Time{},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raScanner := bufio.NewScanner(bytes.NewBuffer([]byte(raString)))
			stderr, err := ioutil.TempFile(os.TempDir(), "stderr")
			test.AssertNotError(t, err, "failed creating temporary file")
			defer os.Remove(stderr.Name())

			timeTolerance := 10 * time.Minute
			err = checkIssuances(raScanner, checkedMap, timeTolerance, testCase.earliest, testCase.latest, stderr)
			test.AssertNotError(t, err, "checkIssuances failed")

			stderrCont, err := ioutil.ReadFile(stderr.Name())
			test.AssertNotError(t, err, "failed to read temporary file")
			test.AssertEquals(t, string(stderrCont), testCase.expectedErrors)
		})
	}
}

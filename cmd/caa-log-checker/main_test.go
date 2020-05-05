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
	tmpPlain.Write([]byte("test-1\ntest-2"))
	tmpPlain.Close()

	tmpGzip, err := ioutil.TempFile(os.TempDir(), "gzip-*.gz")
	test.AssertNotError(t, err, "failed to create temporary file")
	defer os.Remove(tmpGzip.Name())
	gzipWriter := gzip.NewWriter(tmpGzip)
	gzipWriter.Write([]byte("test-1\ntest-2"))
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
	tmpA.Write([]byte(fmt.Sprintf(`random
%s Checked CAA records for example.com, [Present: true, asd
random
%s Checked CAA records for beep.boop.com, [Present: false, asd`, formattedTime, formattedTime)))
	tmpA.Close()
	tmpB, err := ioutil.TempFile(os.TempDir(), "va-b")
	test.AssertNotError(t, err, "failed to create temporary file")
	defer os.Remove(tmpB.Name())
	formattedTime = testTime.Add(time.Hour).Format(time.RFC3339Nano)
	tmpB.Write([]byte(fmt.Sprintf(`random
%s Checked CAA records for example.com, [Present: true, asd
random
%s Checked CAA records for beep.boop.com, [Present: false, asd`, formattedTime, formattedTime)))
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
	checkedMap := map[string][]time.Time{
		"example.com": []time.Time{
			time.Time{}.Add(time.Hour),
			time.Time{}.Add(3 * time.Hour),
		},
		"2.example.com": []time.Time{
			time.Time{}.Add(time.Hour),
		},
		"4.example.com": []time.Time{
			time.Time{}.Add(time.Hour),
		},
	}

	raBuf := bytes.NewBuffer([]byte(fmt.Sprintf(`random
Certificate request - successful JSON={"SerialNumber": "1", "Names":["example.com"], "ResponseTime":"%s", "Requester":0}
random
Certificate request - successful JSON={"SerialNumber": "2", "Names":["2.example.com", "3.example.com"], "ResponseTime":"%s", "Requester":0}
Certificate request - successful JSON={"SerialNumber": "3", "Names":["4.example.com"], "ResponseTime":"%s", "Requester":0}
random`,
		time.Time{}.Add(time.Hour*2).Format(time.RFC3339Nano),
		time.Time{}.Add(time.Hour*2).Format(time.RFC3339Nano),
		time.Time{}.Format(time.RFC3339Nano),
	)))
	raScanner := bufio.NewScanner(raBuf)

	stderr, err := ioutil.TempFile(os.TempDir(), "stderr")
	test.AssertNotError(t, err, "failed creating temporary file")
	defer os.Remove(stderr.Name())

	err = checkIssuances(raScanner, checkedMap, stderr)
	test.AssertNotError(t, err, "checkIssuances failed")

	stderrCont, err := ioutil.ReadFile(stderr.Name())
	test.AssertNotError(t, err, "failed to read temporary file")
	test.AssertEquals(t, string(stderrCont), `Issuance missing CAA checks: issued at=0001-01-01 02:00:00 +0000 UTC, serial=2, requester=0, names hash=87424e6a210a7f067af05576e64957de28ea88be7edfeccc90865ceb27e938b1, names=[2.example.com 3.example.com], missing checks for names=[3.example.com]
Issuance missing CAA checks: issued at=0001-01-01 00:00:00 +0000 UTC, serial=3, requester=0, names hash=2811971efc0a8db4f95c268ca75a949d4d1c6fefd70e09be5da42e4eeee1f3b5, names=[4.example.com], missing checks for names=[4.example.com]
`)
}

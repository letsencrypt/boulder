package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_model/go"
)

func fatalf(t *testing.T, format string, args ...interface{}) {
	fmt.Printf("\t"+format+"\n", args...)
	t.FailNow()
}

// Return short format caller info for printing errors, so errors don't all
// appear to come from test-tools.go.
func caller() string {
	_, file, line, _ := runtime.Caller(2)
	splits := strings.Split(file, "/")
	filename := splits[len(splits)-1]
	return fmt.Sprintf("%s:%d:", filename, line)
}

// Assert a boolean
func Assert(t *testing.T, result bool, message string) {
	if !result {
		fatalf(t, "%s %s", caller(), message)
	}
}

// AssertNotNil checks an object to be non-nil
func AssertNotNil(t *testing.T, obj interface{}, message string) {
	if obj == nil {
		fatalf(t, "%s %s", caller(), message)
	}
}

// AssertNotError checks that err is nil
func AssertNotError(t *testing.T, err error, message string) {
	if err != nil {
		fatalf(t, "%s %s: %s", caller(), message, err)
	}
}

// AssertError checks that err is non-nil
func AssertError(t *testing.T, err error, message string) {
	if err == nil {
		fatalf(t, "%s %s: expected error but received none", caller(), message)
	}
}

// AssertEquals uses the equality operator (==) to measure one and two
func AssertEquals(t *testing.T, one interface{}, two interface{}) {
	if one != two {
		fatalf(t, "%s %#v != %#v", caller(), one, two)
	}
}

// AssertDeepEquals uses the reflect.DeepEqual method to measure one and two
func AssertDeepEquals(t *testing.T, one interface{}, two interface{}) {
	t.Helper()
	if !reflect.DeepEqual(one, two) {
		fatalf(t, "%s [%+v] !(deep)= [%+v]", caller(), one, two)
	}
}

// AssertMarshaledEquals marshals one and two to JSON, and then uses
// the equality operator to measure them
func AssertMarshaledEquals(t *testing.T, one interface{}, two interface{}) {
	oneJSON, err := json.Marshal(one)
	AssertNotError(t, err, "Could not marshal 1st argument")
	twoJSON, err := json.Marshal(two)
	AssertNotError(t, err, "Could not marshal 2nd argument")

	if !bytes.Equal(oneJSON, twoJSON) {
		fatalf(t, "%s [%s] !(json)= [%s]", caller(), oneJSON, twoJSON)
	}
}

// AssertUnmarshaledEquals unmarshals two JSON strings (got and expected) to
// a map[string]interface{} and then uses reflect.DeepEqual to check they are
// the same
func AssertUnmarshaledEquals(t *testing.T, got, expected string) {
	t.Helper()
	var gotMap, expectedMap map[string]interface{}
	err := json.Unmarshal([]byte(got), &gotMap)
	AssertNotError(t, err, "Could not unmarshal 'got'")
	err = json.Unmarshal([]byte(expected), &expectedMap)
	AssertNotError(t, err, "Could not unmarshal 'expected'")
	for k, v := range expectedMap {
		if !reflect.DeepEqual(v, gotMap[k]) {
			t.Errorf("Field %q: Expected \"%v\", got \"%v\"", k, v, gotMap[k])
		}
	}
}

// AssertNotEquals uses the equality operator to measure that one and two
// are different
func AssertNotEquals(t *testing.T, one interface{}, two interface{}) {
	if one == two {
		fatalf(t, "%s %#v == %#v", caller(), one, two)
	}
}

// AssertByteEquals uses bytes.Equal to measure one and two for equality.
func AssertByteEquals(t *testing.T, one []byte, two []byte) {
	if !bytes.Equal(one, two) {
		fatalf(t, "%s Byte [%s] != [%s]",
			caller(),
			base64.StdEncoding.EncodeToString(one),
			base64.StdEncoding.EncodeToString(two))
	}
}

// AssertIntEquals uses the equality operator to measure one and two.
func AssertIntEquals(t *testing.T, one int, two int) {
	if one != two {
		fatalf(t, "%s Int [%d] != [%d]", caller(), one, two)
	}
}

// AssertBigIntEquals uses the big.Int.cmp() method to measure whether
// one and two are equal
func AssertBigIntEquals(t *testing.T, one *big.Int, two *big.Int) {
	if one.Cmp(two) != 0 {
		fatalf(t, "%s Int [%d] != [%d]", caller(), one, two)
	}
}

// AssertContains determines whether needle can be found in haystack
func AssertContains(t *testing.T, haystack string, needle string) {
	if !strings.Contains(haystack, needle) {
		fatalf(t, "%s String [%s] does not contain [%s]", caller(), haystack, needle)
	}
}

// AssertNotContains determines if needle is not found in haystack
func AssertNotContains(t *testing.T, haystack string, needle string) {
	if strings.Contains(haystack, needle) {
		fatalf(t, "%s String [%s] contains [%s]", caller(), haystack, needle)
	}
}

// AssertSeverity determines if a string matches the Severity formatting
func AssertSeverity(t *testing.T, data string, severity int) {
	expected := fmt.Sprintf("\"severity\":%d", severity)
	AssertContains(t, data, expected)
}

// AssertBetween determines if a is between b and c
func AssertBetween(t *testing.T, a, b, c int64) {
	if a < b || a > c {
		fatalf(t, "%d is not between %d and %d", a, b, c)
	}
}

// CountCounterVec returns the count by label and value of a prometheus metric
func CountCounterVec(labelName string, value string, counterVec *prometheus.CounterVec) int {
	return CountCounter(counterVec.With(prometheus.Labels{labelName: value}))
}

// CountCounter returns the count by label and value of a prometheus metric
func CountCounter(counter prometheus.Counter) int {
	ch := make(chan prometheus.Metric, 10)
	counter.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		panic("timed out collecting metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)
	return int(iom.Counter.GetValue())
}

func CountHistogramSamples(hist prometheus.Histogram) int {
	ch := make(chan prometheus.Metric, 10)
	hist.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		panic("timed out collecting metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)
	return int(iom.Histogram.GetSampleCount())
}

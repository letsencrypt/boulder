package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/test"
)

func TestCheckpointIntervalOK(t *testing.T) {
	// Test a number of intervals know to be OK, ensure that no error is
	// produced when calling `ok()`.
	okCases := []struct {
		testInterval interval
	}{
		{interval{}},
		{interval{start: 10}},
		{interval{end: 10}},
		{interval{start: 10, end: 15}},
	}
	for _, testcase := range okCases {
		err := testcase.testInterval.ok()
		test.AssertNotError(t, err, "valid interval produced ok() error")
	}

	// Test a number of intervals known to be invalid, ensure that the produced
	// error has the expected message.
	failureCases := []struct {
		testInterval  interval
		expectedError string
	}{
		{interval{start: -1}, "interval start (-1) and end (0) must both be positive integers"},
		{interval{end: -1}, "interval start (0) and end (-1) must both be positive integers"},
		{interval{start: -1, end: -1}, "interval start (-1) and end (-1) must both be positive integers"},
		{interval{start: 999, end: 10}, "interval start value (999) is greater than end value (10)"},
	}
	for _, testcase := range failureCases {
		err := testcase.testInterval.ok()
		test.AssertNotNil(t, err, fmt.Sprintf("Invalid interval %#v was ok", testcase.testInterval))
		test.AssertEquals(t, err.Error(), testcase.expectedError)
	}
}

func TestSleepInterval(t *testing.T) {
	const sleepLen = 10
	mc := &mocks.Mailer{}

	// Set up a mock mailer that sleeps for `sleepLen` seconds
	m := &mailer{
		mailer:        mc,
		emailTemplate: "",
		sleepInterval: sleepLen * time.Second,
		checkpoint:    interval{start: 0, end: 3},
		clk:           newFakeClock(t),
		destinations:  []string{"test@example.com", "test2@example.com", "test3@example.com"},
	}

	// Call run() - this should sleep `sleepLen` per destination address
	// After it returns, we expect (sleepLen * number of destinations) seconds has
	// elapsed
	err := m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	expectedEnd := newFakeClock(t)
	expectedEnd.Add(time.Second * time.Duration(sleepLen*len(m.destinations)))
	test.AssertEquals(t, m.clk.Now(), expectedEnd.Now())

	// Set up a mock mailer that doesn't sleep at all
	m = &mailer{
		mailer:        mc,
		emailTemplate: "",
		sleepInterval: 0,
		checkpoint:    interval{start: 0, end: 3},
		clk:           newFakeClock(t),
		destinations:  []string{"test@example.com", "test2@example.com", "test3@example.com"},
	}

	// Call run() - this should blast through all destinations without sleep
	// After it returns, we expect no clock time to have elapsed on the fake clock
	err = m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	expectedEnd = newFakeClock(t)
	test.AssertEquals(t, m.clk.Now(), expectedEnd.Now())
}

func TestMailCheckpointing(t *testing.T) {
	const testSubject = "Test Subject"

	testDestinationsBody, err := ioutil.ReadFile("testdata/test_msg_recipients.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_recipients.txt")
	testDestinations := strings.Split(string(testDestinationsBody), "\n")

	testBody, err := ioutil.ReadFile("testdata/test_msg_body.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_body.txt")
	mc := &mocks.Mailer{}

	// Create a mailer with a checkpoint interval larger than the number of
	// destinations
	m := &mailer{
		mailer:        mc,
		subject:       testSubject,
		destinations:  testDestinations,
		emailTemplate: string(testBody),
		checkpoint:    interval{start: 99999, end: 900000},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. It should produce an error about the interval start
	mc.Clear()
	err = m.run()
	test.AssertEquals(t, len(mc.Messages), 0)
	test.AssertEquals(t, err.Error(), "interval start value (99999) is greater than number of destinations (7)")

	// Create a mailer with a negative sleep interval
	m = &mailer{
		mailer:        mc,
		subject:       testSubject,
		destinations:  testDestinations,
		emailTemplate: string(testBody),
		checkpoint:    interval{},
		sleepInterval: -10,
		clk:           newFakeClock(t),
	}

	// Run the mailer. It should produce an error about the sleep interval
	mc.Clear()
	err = m.run()
	test.AssertEquals(t, len(mc.Messages), 0)
	test.AssertEquals(t, err.Error(), "sleep interval (-10) is < 0")

	// Create a mailer with a checkpoint interval starting after 4 destinations from
	// the start of the file
	m = &mailer{
		mailer:        mc,
		subject:       testSubject,
		destinations:  testDestinations,
		emailTemplate: string(testBody),
		checkpoint:    interval{start: 4},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Two messages should have been produced, one to
	// test-test-test@example.com (Line 5 of test_msg_recipients.txt), and one to
	// example-example-example@example.com (Line 6).
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-test-test@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example-example-example@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[1])

	// Create a mailer with a checkpoint interval ending after 3 destinations from
	// the start of the file
	m = &mailer{
		mailer:        mc,
		subject:       testSubject,
		destinations:  testDestinations,
		emailTemplate: string(testBody),
		checkpoint:    interval{end: 3},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Three messages should have been produced, one to
	// test@example.com (Line 1 of test_msg_recipients.txt), one to
	// example@example.com (Line 2), and one to example-test@example.com (Line 3)
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 3)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[1])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example-test@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[2])

	// Create a mailer with a checkpoint interval covering 2 destinations from the
	// middle of the file
	m = &mailer{
		mailer:        mc,
		subject:       testSubject,
		destinations:  testDestinations,
		emailTemplate: string(testBody),
		checkpoint:    interval{start: 3, end: 5},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Two messages should have been produced, one to
	// test-example@example.com (Line 4 of test_msg_recipients.txt) and another
	// one destined to test-test-test@example.com (Line 5)
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-example@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-test-test@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[1])

}

func TestMessageContent(t *testing.T) {
	// Create a mailer with fixed content
	const (
		testDestination = "test@example.com"
		testSubject     = "Test Subject"
	)
	testBody, err := ioutil.ReadFile("testdata/test_msg_body.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_body.txt")
	mc := &mocks.Mailer{}
	m := &mailer{
		mailer:        mc,
		subject:       testSubject,
		destinations:  []string{testDestination},
		emailTemplate: string(testBody),
		checkpoint:    interval{start: 0, end: 1},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer, one message should have been created with the content
	// expected
	err = m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      testDestination,
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
}

func newFakeClock(t *testing.T) clock.FakeClock {
	const fakeTimeFormat = "2006-01-02T15:04:05.999999999Z"
	ft, err := time.Parse(fakeTimeFormat, fakeTimeFormat)
	if err != nil {
		t.Fatal(err)
	}
	fc := clock.NewFake()
	fc.Set(ft.UTC())
	return fc
}

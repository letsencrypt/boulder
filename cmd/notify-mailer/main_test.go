package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	const numMessages = 3
	mc := &mocks.Mailer{}
	dbMap := mockEmailResolver{}

	testDestinationsBody, err := ioutil.ReadFile("testdata/test_msg_recipients.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_recipients.txt")

	// Set up a mock mailer that sleeps for `sleepLen` seconds
	m := &mailer{
		mailer:        mc,
		emailTemplate: "",
		sleepInterval: sleepLen * time.Second,
		checkpoint:    interval{start: 0, end: numMessages},
		clk:           newFakeClock(t),
		destinations:  testDestinationsBody,
		dbMap:         dbMap,
	}

	// Call run() - this should sleep `sleepLen` per destination address
	// After it returns, we expect (sleepLen * number of destinations) seconds has
	// elapsed
	err = m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	expectedEnd := newFakeClock(t)
	expectedEnd.Add(time.Second * time.Duration(sleepLen*numMessages))
	test.AssertEquals(t, m.clk.Now(), expectedEnd.Now())

	// Set up a mock mailer that doesn't sleep at all
	m = &mailer{
		mailer:        mc,
		emailTemplate: "",
		sleepInterval: 0,
		checkpoint:    interval{start: 0, end: 3},
		clk:           newFakeClock(t),
		destinations:  testDestinationsBody,
		dbMap:         dbMap,
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
	dbMap := mockEmailResolver{}

	testDestinationsBody, err := ioutil.ReadFile("testdata/test_msg_recipients.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_recipients.txt")

	testBody, err := ioutil.ReadFile("testdata/test_msg_body.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_body.txt")
	mc := &mocks.Mailer{}

	// Create a mailer with a checkpoint interval larger than the number of
	// destinations
	m := &mailer{
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  testDestinationsBody,
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
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  testDestinationsBody,
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
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  testDestinationsBody,
		emailTemplate: string(testBody),
		checkpoint:    interval{start: 4},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Three messages should have been produced, one to
	// you've.got.mail@example.com (id 5 of the fake DB), one to
	// mail@example.com (id 6), and one to example-example-example@example.com (id 4).
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 3)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "youve.got.mail@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "mail@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[1])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example-example-example@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[2])

	// Create a mailer with a checkpoint interval ending after 3 destinations
	m = &mailer{
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  testDestinationsBody,
		emailTemplate: string(testBody),
		checkpoint:    interval{end: 3},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Three messages should have been produced, one to
	// example@example.com (ID 1), one to test-example-updated@example.com (ID 2),
	// and one to test-test-test@example.com (ID 3)
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 3)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-example-updated@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[1])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-test-test@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[2])

	// Create a mailer with a checkpoint interval covering 2 destinations from the
	// middle of the file
	m = &mailer{
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  testDestinationsBody,
		emailTemplate: string(testBody),
		checkpoint:    interval{start: 3, end: 5},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Two messages should have been produced, one to
	// example-example-example@example.com (ID 4) and another
	// one destined to youve.got.mail@example.com (ID 5)
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example-example-example@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "youve.got.mail@example.com",
		Subject: testSubject,
		Body:    string(testBody),
	}, mc.Messages[1])

}

func TestMessageContent(t *testing.T) {
	// Create a mailer with fixed content
	const (
		testSubject     = "Test Subject"
		testDestination = "example@example.com"
	)
	testDestinationsBody, err := ioutil.ReadFile("testdata/test_msg_recipients.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_recipients.txt")

	testBody, err := ioutil.ReadFile("testdata/test_msg_body.txt")
	test.AssertNotError(t, err, "failed to read testdata/test_msg_body.txt")

	dbMap := mockEmailResolver{}
	mc := &mocks.Mailer{}
	m := &mailer{
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  testDestinationsBody,
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

// the `mockEmailResolver` implements the `dbSelector` interface from
// `notify-mailer/main.go` to allow unit testing without using a backing
// database
type mockEmailResolver struct{}

// the `mockEmailResolver` select method treats the requested reg ID as an index
// into a list of anonymous structs
func (bs mockEmailResolver) SelectOne(output interface{}, _ string, args ...interface{}) error {
	// The "db" is just a list in memory
	db := []contactJSON{
		contactJSON{
			ID:      1,
			Contact: []byte(`["mailto:example@example.com"]`),
		},
		contactJSON{
			ID:      2,
			Contact: []byte(`["mailto:test-example-updated@example.com"]`),
		},
		contactJSON{
			ID:      3,
			Contact: []byte(`["mailto:test-test-test@example.com"]`),
		},
		contactJSON{
			ID:      4,
			Contact: []byte(`["mailto:example-example-example@example.com"]`),
		},
		contactJSON{
			ID:      5,
			Contact: []byte(`["mailto:youve.got.mail@example.com"]`),
		},
		contactJSON{
			ID:      6,
			Contact: []byte(`["mailto:mail@example.com"]`),
		},
	}

	// Play the type cast game so that we can dig into the arguments map and get
	// out an integer "id" parameter
	argsRaw := args[0]
	argsMap, ok := argsRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("incorrect args type %T", args)
	}
	idRaw := argsMap["id"]
	id, ok := idRaw.(int)
	if !ok {
		return fmt.Errorf("incorrect args ID type %T", id)
	}

	// Play the type cast game to get a pointer to the output `contactJSON`
	// pointer so we can write the result from the db list
	outputPtr, ok := output.(*contactJSON)
	if !ok {
		return fmt.Errorf("incorrect output type %T", output)
	}

	// If the ID (shifted by 1 to account for zero indexing) is within the range
	// of the DB list, return the DB entry
	if (id-1) > 0 || int(id-1) < len(db) {
		*outputPtr = db[id-1]
	}
	return nil
}

func TestResolveEmails(t *testing.T) {
	// Start with three reg. IDs. Note: the IDs have been matched with fake
	// results in the `db` slice in `mockEmailResolver`'s `SelectOne`. If you add
	// more test cases here you must also add the corresponding DB result in the
	// mock.
	regs := []regID{
		regID{
			ID: 1,
		},
		regID{
			ID: 2,
		},
		regID{
			ID: 3,
		},
	}
	contactsJSON, err := json.Marshal(regs)
	test.AssertNotError(t, err, "failed to marshal test regs")

	dbMap := mockEmailResolver{}
	mc := &mocks.Mailer{}
	m := &mailer{
		mailer:        mc,
		dbMap:         dbMap,
		subject:       "Test",
		destinations:  contactsJSON,
		emailTemplate: "Hi",
		checkpoint:    interval{start: 0},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	destinations, err := m.resolveDestinations()
	test.AssertNotError(t, err, "failed to resolveDestinations")

	expected := []string{
		"example@example.com",
		"test-example-updated@example.com",
		"test-test-test@example.com",
	}

	test.AssertEquals(t, len(destinations), len(expected))
	for i := range expected {
		test.AssertEquals(t, destinations[i], expected[i])
	}
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

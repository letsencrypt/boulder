package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"text/template"
	"time"

	"github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/test"
)

func TestIntervalOK(t *testing.T) {
	// Test a number of intervals know to be OK, ensure that no error is
	// produced when calling `ok()`.
	okCases := []struct {
		testInterval interval
	}{
		{interval{}},
		{interval{start: "aa", end: "\xFF"}},
		{interval{end: "aa"}},
		{interval{start: "aa", end: "bb"}},
	}
	for _, testcase := range okCases {
		err := testcase.testInterval.ok()
		test.AssertNotError(t, err, "valid interval produced ok() error")
	}

	badInterval := interval{start: "bb", end: "aa"}
	if err := badInterval.ok(); err == nil {
		t.Errorf("Bad interval %#v was considered ok", badInterval)
	}
}

// makeFile writes the given content into a temporary file, returning
// the filename (which should be deleted when done).
func makeFile(content string) (string, error) {
	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", err
	}

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		return "", err
	}
	if err := tmpfile.Close(); err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}

func TestReadRecipientsListMismatchedColumns(t *testing.T) {
	bad := `id, domainName, date
10,example.com,2018-11-21
23,example.net`
	badFileName, err := makeFile(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(badFileName)
	recipients, err := readRecipientsList(badFileName)
	if err == nil {
		t.Fatalf("reading bad CSV file should have errored, but got %v",
			recipients)
	}
}

func TestSleepInterval(t *testing.T) {
	const sleepLen = 10
	mc := &mocks.Mailer{}
	dbMap := mockEmailResolver{}
	tmpl := template.Must(template.New("letter").Parse("an email body"))
	recipients := []recipient{{id: 1}, {id: 2}, {id: 3}}
	// Set up a mock mailer that sleeps for `sleepLen` seconds
	m := &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		emailTemplate: tmpl,
		sleepInterval: sleepLen * time.Second,
		targetRange:   interval{start: "", end: "\xFF"},
		clk:           newFakeClock(t),
		destinations:  recipients,
		dbMap:         dbMap,
	}

	// Call run() - this should sleep `sleepLen` per destination address
	// After it returns, we expect (sleepLen * number of destinations) seconds has
	// elapsed
	err := m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	expectedEnd := newFakeClock(t)
	expectedEnd.Add(time.Second * time.Duration(sleepLen*len(recipients)))
	test.AssertEquals(t, m.clk.Now(), expectedEnd.Now())

	// Set up a mock mailer that doesn't sleep at all
	m = &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		emailTemplate: tmpl,
		sleepInterval: 0,
		targetRange:   interval{end: "\xFF"},
		clk:           newFakeClock(t),
		destinations:  recipients,
		dbMap:         dbMap,
	}

	// Call run() - this should blast through all destinations without sleep
	// After it returns, we expect no clock time to have elapsed on the fake clock
	err = m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	expectedEnd = newFakeClock(t)
	test.AssertEquals(t, m.clk.Now(), expectedEnd.Now())
}

func TestMailIntervals(t *testing.T) {
	const testSubject = "Test Subject"
	dbMap := mockEmailResolver{}

	tmpl := template.Must(template.New("letter").Parse("an email body"))
	recipients := []recipient{{id: 1}, {id: 2}, {id: 3}}

	mc := &mocks.Mailer{}

	// Create a mailer with a checkpoint interval larger than any of the
	// destination email addresses.
	m := &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  recipients,
		emailTemplate: tmpl,
		targetRange:   interval{start: "\xFF", end: "\xFF\xFF"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. It should produce an error about the interval start
	mc.Clear()
	err := m.run()
	test.AssertEquals(t, len(mc.Messages), 0)

	// Create a mailer with a negative sleep interval
	m = &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  recipients,
		emailTemplate: tmpl,
		targetRange:   interval{},
		sleepInterval: -10,
		clk:           newFakeClock(t),
	}

	// Run the mailer. It should produce an error about the sleep interval
	mc.Clear()
	err = m.run()
	test.AssertEquals(t, len(mc.Messages), 0)
	test.AssertEquals(t, err.Error(), "sleep interval (-10) is < 0")

	// Create a mailer with an interval starting with a specific email address.
	// It should send email to that address and others alphabetically higher.
	m = &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  []recipient{{id: 1}, {id: 2}, {id: 3}, {id: 4}},
		emailTemplate: tmpl,
		targetRange:   interval{start: "test-example-updated@example.com", end: "\xFF"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Two messages should have been produced, one to
	// test-example-updated@example.com (beginning of the range),
	// and one to test-test-test@example.com.
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-example-updated@example.com",
		Subject: testSubject,
		Body:    "an email body",
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "test-test-test@example.com",
		Subject: testSubject,
		Body:    "an email body",
	}, mc.Messages[1])

	// Create a mailer with a checkpoint interval ending before
	// "test-example-updated@example.com"
	m = &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  []recipient{{id: 1}, {id: 2}, {id: 3}, {id: 4}},
		emailTemplate: tmpl,
		targetRange:   interval{end: "test-example-updated@example.com"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer. Two messages should have been produced, one to
	// example@example.com (ID 1), one to example-example-example@example.com (ID 2)
	mc.Clear()
	err = m.run()
	test.AssertNotError(t, err, "run() produced an error")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example-example-example@example.com",
		Subject: testSubject,
		Body:    "an email body",
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example@example.com",
		Subject: testSubject,
		Body:    "an email body",
	}, mc.Messages[1])
}

func TestMessageContentStatic(t *testing.T) {
	// Create a mailer with fixed content
	const (
		testSubject = "Test Subject"
	)
	dbMap := mockEmailResolver{}
	mc := &mocks.Mailer{}
	m := &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		dbMap:         dbMap,
		subject:       testSubject,
		destinations:  []recipient{{id: 1}},
		emailTemplate: template.Must(template.New("letter").Parse("an email body")),
		targetRange:   interval{end: "\xFF"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer, one message should have been created with the content
	// expected
	err := m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example@example.com",
		Subject: testSubject,
		Body:    "an email body",
	}, mc.Messages[0])
}

// Send mail with a variable interpolated.
func TestMessageContentInterpolated(t *testing.T) {
	recipients := []recipient{
		{
			id: 1,
			Extra: map[string]string{
				"validationMethod": "eyeballing it",
			},
		},
	}
	dbMap := mockEmailResolver{}
	mc := &mocks.Mailer{}
	m := &mailer{
		log:          blog.UseMock(),
		mailer:       mc,
		dbMap:        dbMap,
		subject:      "Test Subject",
		destinations: recipients,
		emailTemplate: template.Must(template.New("letter").Parse(
			`issued by {{range .}}{{ .Extra.validationMethod }}{{end}}`)),
		targetRange:   interval{end: "\xFF"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer, one message should have been created with the content
	// expected
	err := m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "example@example.com",
		Subject: "Test Subject",
		Body:    "issued by eyeballing it",
	}, mc.Messages[0])
}

// Send mail with a variable interpolated multiple times for accounts that share
// an email address.
func TestMessageContentInterpolatedMultiple(t *testing.T) {
	recipients := []recipient{
		{
			id: 200,
			Extra: map[string]string{
				"domain": "blog.example.com",
			},
		},
		{
			id: 201,
			Extra: map[string]string{
				"domain": "nas.example.net",
			},
		},
		{
			id: 202,
			Extra: map[string]string{
				"domain": "mail.example.org",
			},
		},
		{
			id: 203,
			Extra: map[string]string{
				"domain": "panel.example.net",
			},
		},
	}
	dbMap := mockEmailResolver{}
	mc := &mocks.Mailer{}
	m := &mailer{
		log:          blog.UseMock(),
		mailer:       mc,
		dbMap:        dbMap,
		subject:      "Test Subject",
		destinations: recipients,
		emailTemplate: template.Must(template.New("letter").Parse(
			`issued for:
{{range .}}{{ .Extra.domain }}
{{end}}Thanks`)),
		targetRange:   interval{end: "\xFF"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	// Run the mailer, one message should have been created with the content
	// expected
	err := m.run()
	test.AssertNotError(t, err, "error calling mailer run()")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      "gotta.lotta.accounts@example.net",
		Subject: "Test Subject",
		Body: `issued for:
blog.example.com
nas.example.net
mail.example.org
panel.example.net
Thanks`,
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
		{
			ID:      1,
			Contact: []byte(`["mailto:example@example.com"]`),
		},
		{
			ID:      2,
			Contact: []byte(`["mailto:test-example-updated@example.com"]`),
		},
		{
			ID:      3,
			Contact: []byte(`["mailto:test-test-test@example.com"]`),
		},
		{
			ID:      4,
			Contact: []byte(`["mailto:example-example-example@example.com"]`),
		},
		{
			ID:      5,
			Contact: []byte(`["mailto:youve.got.mail@example.com"]`),
		},
		{
			ID:      6,
			Contact: []byte(`["mailto:mail@example.com"]`),
		},
		{
			ID:      7,
			Contact: []byte(`["mailto:***********"]`),
		},
		{
			ID:      200,
			Contact: []byte(`["mailto:gotta.lotta.accounts@example.net"]`),
		},
		{
			ID:      201,
			Contact: []byte(`["mailto:gotta.lotta.accounts@example.net"]`),
		},
		{
			ID:      202,
			Contact: []byte(`["mailto:gotta.lotta.accounts@example.net"]`),
		},
		{
			ID:      203,
			Contact: []byte(`["mailto:gotta.lotta.accounts@example.net"]`),
		},
		{
			ID:      204,
			Contact: []byte(`["mailto:gotta.lotta.accounts@example.net"]`),
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

	for _, v := range db {
		if v.ID == id {
			*outputPtr = v
		}
	}
	if outputPtr.ID == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func TestResolveEmails(t *testing.T) {
	// Start with three reg. IDs. Note: the IDs have been matched with fake
	// results in the `db` slice in `mockEmailResolver`'s `SelectOne`. If you add
	// more test cases here you must also add the corresponding DB result in the
	// mock.
	recipients := []recipient{
		{
			id: 1,
		},
		{
			id: 2,
		},
		{
			id: 3,
		},
		// This registration ID deliberately doesn't exist in the mock data to make
		// sure this case is handled gracefully
		{
			id: 999,
		},
		// This registration ID deliberately returns an invalid email to make sure any
		// invalid contact info that slipped into the DB once upon a time will be ignored
		{
			id: 7,
		},
		{
			id: 200,
		},
		{
			id: 201,
		},
		{
			id: 202,
		},
		{
			id: 203,
		},
		{
			id: 204,
		},
	}

	tmpl := template.Must(template.New("letter").Parse("an email body"))

	dbMap := mockEmailResolver{}
	mc := &mocks.Mailer{}
	m := &mailer{
		log:           blog.UseMock(),
		mailer:        mc,
		dbMap:         dbMap,
		subject:       "Test",
		destinations:  recipients,
		emailTemplate: tmpl,
		targetRange:   interval{end: "\xFF"},
		sleepInterval: 0,
		clk:           newFakeClock(t),
	}

	addressesToRecipients, err := m.resolveEmailAddresses()
	test.AssertNotError(t, err, "failed to resolveEmailAddresses")

	expected := []string{
		"example@example.com",
		"test-example-updated@example.com",
		"test-test-test@example.com",
		"gotta.lotta.accounts@example.net",
	}

	test.AssertEquals(t, len(addressesToRecipients), len(expected))
	for _, address := range expected {
		if _, ok := addressesToRecipients[address]; !ok {
			t.Errorf("missing entry in addressesToRecipients: %q", address)
		}
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

package reloader

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"
)

func noop([]byte, error) error {
	return nil
}

func TestNoStat(t *testing.T) {
	filename := os.TempDir() + "/doesntexist.123456789"
	_, err := New(filename, noop)
	if err == nil {
		t.Errorf("Expected New to return error when the file doesn't exist.")
	}
}

func TestNoRead(t *testing.T) {
	f, _ := ioutil.TempFile("", "test-no-read.txt")
	defer os.Remove(f.Name())
	f.Chmod(0) // no read permissions
	_, err := New(f.Name(), noop)
	if err == nil {
		t.Errorf("Expected New to return error when permission denied.")
	}
}

func TestFirstError(t *testing.T) {
	f, _ := ioutil.TempFile("", "test-first-error.txt")
	defer os.Remove(f.Name())
	_, err := New(f.Name(), func([]byte, error) error {
		return fmt.Errorf("i die")
	})
	if err == nil {
		t.Errorf("Expected New to return error when the callback returned error the first time.")
	}
}

func TestFirstSuccess(t *testing.T) {
	f, _ := ioutil.TempFile("", "test-first-success.txt")
	defer os.Remove(f.Name())
	_, err := New(f.Name(), func([]byte, error) error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected New to succeed, got %s", err)
	}
}

// Override makeTicker for testing.
// Returns a channel on which to send artificial ticks, and a function to
// restore the default makeTicker.
func makeFakeMakeTicker() (chan<- time.Time, func()) {
	origMakeTicker := makeTicker
	fakeTickChan := make(chan time.Time)
	makeTicker = func() (func(), <-chan time.Time) {
		return func() {}, fakeTickChan
	}
	return fakeTickChan, func() {
		makeTicker = origMakeTicker
	}
}

func TestReload(t *testing.T) {
	// Mock out makeTicker
	fakeTick, restoreMakeTicker := makeFakeMakeTicker()

	f, _ := ioutil.TempFile("", "test-reload.txt")
	filename := f.Name()
	defer func() {
		restoreMakeTicker()
		os.Remove(filename)
	}()

	f.Write([]byte("first body"))
	f.Close()

	var bodies []string
	reloads := make(chan []byte, 1)
	_, err := New(filename, func(b []byte, err error) error {
		if err != nil {
			t.Fatalf("Got error in callback: %s", err)
		}
		bodies = append(bodies, string(b))
		reloads <- b
		return nil
	})
	if err != nil {
		t.Errorf("Expected New to succeed, got %s", err)
	}
	expected := []string{"first body"}
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}
	fakeTick <- time.Now()
	<-reloads
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}

	// Write to the file, expect a reload. Sleep a few milliseconds first so the
	// timestamps actually differ.
	time.Sleep(15 * time.Millisecond)
	ioutil.WriteFile(filename, []byte("second body"), 0644)
	fakeTick <- time.Now()
	<-reloads
	expected = []string{"first body", "second body"}
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}

	// Send twice on this blocking channel to make sure we go through at least on
	// iteration of the reloader's loop.
	fakeTick <- time.Now()
	fakeTick <- time.Now()
	if !reflect.DeepEqual(bodies, expected) {
		t.Errorf("Expected bodies = %#v, got %#v", expected, bodies)
	}
}

func TestReloadFailure(t *testing.T) {
	// Mock out makeTicker
	fakeTick, restoreMakeTicker := makeFakeMakeTicker()

	f, _ := ioutil.TempFile("", "test-reload-failure.txt")
	filename := f.Name()
	defer func() {
		restoreMakeTicker()
		os.Remove(filename)
	}()

	f.Write([]byte("first body"))
	f.Close()

	type res struct {
		b   []byte
		err error
	}

	reloads := make(chan res, 1)
	_, err := New(filename, func(b []byte, err error) error {
		reloads <- res{b, err}
		return nil
	})
	if err != nil {
		t.Fatalf("Expected New to succeed.")
	}
	<-reloads
	os.Remove(filename)
	fakeTick <- time.Now()
	select {
	case r := <-reloads:
		if r.err == nil {
			t.Errorf("Expected error trying to read missing file.")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for reload")
	}

	time.Sleep(15 * time.Millisecond)
	// Create a file with no permissions
	ioutil.WriteFile(filename, []byte("second body"), 0)
	fakeTick <- time.Now()
	fakeTick <- time.Now()
	select {
	case r := <-reloads:
		if r.err == nil {
			t.Errorf("Expected error trying to read file with no permissions.")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for reload")
	}

	err = os.Remove(filename)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(filename, []byte("third body"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	fakeTick <- time.Now()
	for {
		select {
		case r := <-reloads:
			if r.err != nil {
				continue
			}
			if string(r.b) != "third body" {
				t.Errorf("Expected 'third body' reading file after restoring it.")
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for successful reload")
		}
	}
}

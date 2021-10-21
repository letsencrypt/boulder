package notmain

import (
	"io/ioutil"
	"testing"
)

func TestWriteFileSuccess(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	err = writeFile(dir+"/example", []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteFileFail(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	err = writeFile(dir+"/example", []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	err = writeFile(dir+"/example", []byte("hi"))
	if err == nil {
		t.Fatal("expected error, got none")
	}
}

package blog

import (
	"log"
	"strings"
	"testing"
)

func TestMysqlLogger(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		args []any
		want string
	}{
		{
			name: "nil",
			args: []any{nil},
			want: `level=ERROR msg="mysql error" error=<nil>`,
		},
		{
			name: "empty string",
			args: []any{""},
			want: `level=ERROR msg="mysql error" error=""`,
		},
		{
			name: "multiple args",
			args: []any{"Sup ", 12345, " Sup sup"},
			want: `level=ERROR msg="mysql error" error="Sup 12345 Sup sup"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			log := NewMock()
			mLog := mysqlLogger{log}

			mLog.Print(tc.args...)

			got := log.GetAll()
			if len(got) != 1 {
				t.Fatalf("Unexpected number of lines logged: %d", len(got))
			}
			if !strings.Contains(got[0], tc.want) {
				t.Errorf("mysqlLogger.Print(%v) = %q, but want %q", tc.args, got[0], tc.want)
			}
			log.Clear()
		})
	}
}

func TestLogWriter(t *testing.T) {
	logger := NewMock()
	lw := logWriter{logger}

	_, _ = lw.Write([]byte("hello, world\n"))

	got := logger.GetAll()
	if len(got) != 1 {
		t.Fatalf("Unexpected number of lines logged: %d", len(got))
	}
	if !strings.Contains(got[0], `level=INFO msg="hello, world"`) {
		t.Errorf(`logWriter.Write("hi") = %#v, but want "hi"`, got[0])
	}
}

func TestGRPCLoggerWarningFilter(t *testing.T) {
	logger := NewMock()
	gl := grpcLogger{logger}

	gl.Warningln("asdf", "qwer")
	got := logger.GetAll()
	if len(got) != 1 {
		t.Fatalf("Unexpected number of lines logged: %d", len(got))
	}

	logger.Clear()
	gl.Warningln("Server.processUnaryRPC failed to write status: connection error: desc = \"transport is closing\"")
	got = logger.GetAll()
	if len(got) != 0 {
		t.Fatalf("Unexpected number of lines logged: %d", len(got))
	}
}

func TestCaptureStdlibLog(t *testing.T) {
	logger := NewMock()

	// Replace the stdlib log package's default log output, temporarily.
	oldDest := log.Writer()
	log.SetOutput(logWriter{logger})
	defer func() {
		log.SetOutput(oldDest)
	}()

	log.Print("thisisatest")
	got := logger.GetAllMatching("thisisatest")
	if len(got) != 1 {
		t.Fatalf("Expected logger to receive 'thisisatest', got: %s",
			strings.Join(logger.GetAll(), "\n"))
	}
}

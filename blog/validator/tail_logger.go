package validator

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/blog"
)

// tailLogger is an adapter to the nxadm/tail module's logging interface. It is
// defined here instead of in //blog/adapters.go because it is only used locally,
// not set as a package-level default.
type tailLogger struct {
	blog.Logger
}

func (tl tailLogger) Fatal(v ...any) {
	tl.Logger.Error(context.Background(), "tail fatal", errors.New(fmt.Sprint(v...)))
	os.Exit(1)
}
func (tl tailLogger) Fatalf(format string, v ...any) {
	tl.Logger.Error(context.Background(), "tail fatal", fmt.Errorf(format, v...))
	os.Exit(1)
}
func (tl tailLogger) Fatalln(v ...any) {
	tl.Logger.Error(context.Background(), "tail fatal", errors.New(fmt.Sprint(v...)))
	os.Exit(1)
}
func (tl tailLogger) Panic(v ...any) {
	msg := fmt.Sprint(v...)
	tl.Logger.Error(context.Background(), "tail panic", errors.New(msg))
	panic(msg)
}
func (tl tailLogger) Panicf(format string, v ...any) {
	err := fmt.Errorf(format, v...)
	tl.Logger.Error(context.Background(), "tail panic", err)
	panic(err)
}
func (tl tailLogger) Panicln(v ...any) {
	msg := fmt.Sprint(v...)
	tl.Logger.Error(context.Background(), "tail panic", errors.New(msg))
	panic(msg)
}
func (tl tailLogger) Print(v ...any) {
	tl.Logger.Info(context.Background(), fmt.Sprint(v...))
}
func (tl tailLogger) Printf(format string, v ...any) {
	tl.Logger.Info(context.Background(), fmt.Sprintf(format, v...))
}
func (tl tailLogger) Println(v ...any) {
	tl.Logger.Info(context.Background(), fmt.Sprint(v...))
}

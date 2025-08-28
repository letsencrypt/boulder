package validator

import (
	"fmt"

	"github.com/letsencrypt/boulder/log"
)

// tailLogger is an adapter to the nxadm/tail module's logging interface.
type tailLogger struct {
	log.Logger
}

func (tl tailLogger) Fatal(v ...any) {
	tl.AuditErr(fmt.Sprint(v...))
}
func (tl tailLogger) Fatalf(format string, v ...any) {
	tl.AuditErrf(format, v...)
}
func (tl tailLogger) Fatalln(v ...any) {
	tl.AuditErr(fmt.Sprint(v...) + "\n")
}
func (tl tailLogger) Panic(v ...any) {
	tl.AuditErr(fmt.Sprint(v...))
}
func (tl tailLogger) Panicf(format string, v ...any) {
	tl.AuditErrf(format, v...)
}
func (tl tailLogger) Panicln(v ...any) {
	tl.AuditErr(fmt.Sprint(v...) + "\n")
}
func (tl tailLogger) Print(v ...any) {
	tl.Info(fmt.Sprint(v...))
}
func (tl tailLogger) Printf(format string, v ...any) {
	tl.Infof(format, v...)
}
func (tl tailLogger) Println(v ...any) {
	tl.Info(fmt.Sprint(v...) + "\n")
}

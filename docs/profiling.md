# Profiling

Boulder components expose profiling endpoints on the port specified
by their --debug-addr flag. An index of available endpoints can be
found at /debug/pprof/ on each service.

Additionally, if the environment variable $GOMEMLIMIT is set, Boulder
components will automatically write a heap and goroutine dump when
it's hit. Note that $GOMEMLIMIT also sets a soft memory limit for
the runtime. See https://pkg.go.dev/runtime#hdr-Environment_Variables.
The dump will happen at most once per hour.

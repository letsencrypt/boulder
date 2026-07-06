# Logging

## Input

We use the `blog` package, maintained here in this repo, as the mediator for
all log output from Boulder. See that package for documentation of its API.

We have several best practices for how we use that package, above and beyond
what its API enforces. Expect these to evolve over time as we improve and
learn:

1. Only use static strings as log messages. Never use `fmt.Sprintf` to create
   the string that becomes the log message. Anything you would format into that
   message, instead attach to the log line as an attribute.

2. By default, avoid deferred logging statements. We do use these to great
   effect in certain places where there are many possible error returns and we
   MUST log no matter what, but it's not a pattern we want to perpetuate. It
   generally leads to difficult-to-enforce constraints around variable scoping
   and redeclaration.

3. Only attach attributes to the context if a) you truly want *every* subsequent
   log line to contain them, and b) there are multiple possible subsequent log
   lines which would otherwise duplicate those attributes. Keep in mind that we
   do not, and do not intend to ever, transmit log attributes across the gRPC
   boundary.

4. In service of the above, err on the side of only attaching `blog.Attrs`
   (i.e., slog.Attrs which are so widely-used that we gave them helper functions
   in the blog package) to the context. When you do attach such attributes to
   the context, do so at the earliest possible moment, such as immediately after
   a `IsAnyNilOrZero` check. This is to reduce spooky action at a distance: at
   any given logging site, it can be difficult to tell what log attributes have
   already been attached. If we stick to a convention of only attaching things
   like accounts, orders, authzs, and serials to contexts, we can act with more
   confidence at logging sites.

## Output

The blog package can send output to stdout, syslog, or both (see below for how to configure this). Regardless of output location, the output is identical.

All log lines are prefixed by a checksum. This is not a cryptographically secure
hash, but is intended to let us catch corruption in the log system. This is a
short chunk of base64 encoded data near the beginning of the log line. It is
consumed by cmd/log-validator.

All lines logged via `blog.AuditInfo` or `blog.AuditError` are prefixed by the constant string `[AUDIT]`. This is used by internal infrastructure to ensure that audit-level logs have extra persistence and durability.

All log lines have attributes for the datacenter, host, program, and pid. These are replicating information usually prepended to log lines by syslog. In the integration test environment, these attributes are suppressed for readability.

In production, all lines are logged in JSON format. This is to optimize for machine-readability in our log analysis systems. In the unit and integration tests, all lines are logged in text format, to optimize for human readability.

## Configuration

Boulder components generally have a `syslog` portion of their JSON config that
indicates the maximum level of log that should be sent to a given destination.
For instance, in `test/config/wfe2.json`:

```json
  "syslog": {
    "stdoutlevel": 4,
    "sysloglevel": 6
  },
```

This indicates that logs of level 4 or below (error and warning) should be
emitted to stdout, and logs of level 6 or below (error, warning, and
info) should be emitted to syslog, using the local Unix socket method. The
highest meaningful value is 7, which enables debug logging.

The default value for these fields is 6 (INFO) for syslogLevel and 0 (no logs)
for stdoutLevel. To turn off syslog logging entirely, set syslogLevel to -1.

In the integration test environment, we enable stdout logging because that
makes it easier to see what's going on quickly. In production, we disable stdout
logging because it would duplicate the syslog logging. We preferred the syslog
logging because it provides things like severity level in a consistent way with
other components, but intend to switch to stdout-only in the future.

## Other Notes

Boulder has a number of adapters to take other packages' log APIs and send them
to the configured logger as expected. For instance, we provide custom loggers
for mysql, grpc, and prometheus. These are initialized in StatsAndLogging in
cmd/shell.go.

There are some cases where we output to stdout regardless of the JSON config
settings:

- Panics are always emitted to stdout.
- Packages that Boulder relies on may occasionally emit to stdout (though this
  is generally not ideal and we try to get it changed).

Typically these output lines will be collected by systemd and forwarded to
syslog.

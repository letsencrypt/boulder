# beeline-go changelog

## 1.9.0 2022-07-01

### Enhancements

- Use simple concat for prepending "app." field prefix (#328) | [@lizthegrey](https://github.com/lizthegrey)

### Maintenance

- Bump github.com/gobuffalo/pop/v6 from 6.0.2 to 6.0.4 (#326)
- Bump github.com/felixge/httpsnoop from 1.0.2 to 1.0.3 (#324)
- Bump google.golang.org/grpc from 1.45.0 to 1.47.0 (#325)
- Bump github.com/jmoiron/sqlx from 1.3.4 to 1.3.5 (#321)
- Bump github.com/gobuffalo/pop/v6 from 6.0.1 to 6.0.2 (#323)

## 1.8.0 2022-04-04

### !!! Note !!!

Minimum Go version required is now 1.16.

### Maintenance

* Update gobuffalo/pop from v5 to v6, which uses features introduced in Go version 1.16.
* Update google.golang.org/protobuf from 1.26.0 to 1.28.0.
* Update google.golang.org/grpc from 1.43.0 to 1.45.0.
* Update labstack/echo from 4.6.1 to 4.7.2.
* Remove support for Go 1.14 and 1.15.
* Add support for Go 1.18.

## v1.7.0 2022-03-03

### Enhancements

- Add Environment & Services support (#309) | [@JamieDanielson](https://github.com/JamieDanielson)

## 1.6.0 2022-02-10

### Enhancements

- feat: pass process root span id as pprof profile id tag (#305) | [@lizthegrey](https://github.com/lizthegrey)

## Fixes

- fix: preserve previous pprof labels after span end (#306) | [@lizthegrey](https://github.com/lizthegrey)

## 1.5.1 2022-02-02

### Enhancements

- Add RebindContext method to Tx struct (#303) | [@paulosman](https://github.com/paulosman)

## 1.5.0 2022-02-02

### Enhancements

- Add a RebindContext method to hnysqlx.DB wrapper (#301) | [@paulosman](https://github.com/paulosman)

### Maintenance

- Bump google.golang.org/grpc from 1.42.0 to 1.43.0 (#296)

## v1.4.1 2022-01-05

### Maintenance

- Bump libhoney-go to v1.15.8 (#297) | [@mikegoldsmith](https://github.com/mikegoldsmith)
- Add re-triage workflow (#295) | [@vreynolds](https://github.com/vreynolds)

## v1.4.0 2021-12-22

### Improvements

- accept both w3c and honeycomb propagation headers by default (#293) | [@vreynolds](https://github.com/vreynolds)

### Maintenance

- Bump google.golang.org/grpc from 1.40.0 to 1.42.0 (#288) | [@dependabot](https://github.com/dependabot)
- Bump github.com/gin-gonic/gin from 1.7.4 to 1.7.7 (#292) | [@dependabot](https://github.com/dependabot)

## v1.3.2 2021-11-19

### Features

- [hnygrpc] add a human readable version of the grpc status code to auto instrumentation (#287) | [@maplebed](https://github.com/maplebed)

### Maintenance

- test: remove flake-prone test case (#289) | [@vreynolds](https://github.com/vreynolds)

## Release v1.3.1 (2021-11-03)

### Fixed

- [sql instrumentation] set name field to db call, not caller (#282) | [@maplebed](https://github.com/maplebed)

### Maintenance

- update libhoney-go to v1.15.6 (#284)
- empower apply-labels action to apply labels (#283)
- Bump github.com/labstack/echo/v4 from 4.5.0 to 4.6.1 (#276)
- Bump github.com/honeycombio/libhoney-go from 1.15.4 to 1.15.5 (#278)

## Release v1.3.0 (2021-10-15)

### Maintenance

- Remove dependency on opentelemetry-go (#267) | [@paulosman](https://github.com/paulosman)
- Provide more context for sampler test failures (#270) | [@vreynolds](https://github.com/vreynolds)
- Spruce up CI (#266) | [@vreynolds](https://github.com/vreynolds)
- add min go verison to readme (#279) | [@vreynolds](https://github.com/vreynolds)
- Change maintenance badge to maintained (#274) | [@JamieDanielson](https://github.com/JamieDanielson)
- Adds Stalebot (#275) | [@JamieDanielson](https://github.com/JamieDanielson)
- Add NOTICE (#271) | [@cartermp](https://github.com/cartermp)
- Add issue and PR templates (#261) | [@vreynolds](https://github.com/vreynolds)
- Add OSS lifecycle badge (#260) | [@vreynolds](https://github.com/vreynolds)
- Add community health files (#259) | [@vreynolds](https://github.com/vreynolds)
- Bump google.golang.org/grpc from 1.38.0 to 1.40.0 (#263)
- Bump github.com/labstack/echo/v4 from 4.4.0 to 4.5.0 (#264)
- Bump github.com/gin-gonic/gin from 1.7.2 to 1.7.4 (#265)
- Bump go.opentelemetry.io/otel from 1.0.0-RC1 to 1.0.0-RC2 (#256)

## Release v1.2.0 (2021-07-21)

### Dependencies

- Update libhoney from 1.15.3 to 1.15.4 (#253)
- Bump github.com/labstack/echo/v4 from 4.3.0 to 4.4.0 (#251)
- Bump github.com/google/uuid from 1.2.0 to 1.3.0 (#250)

### Added

- feat: span.AddField() support adding error (#246)

### Fixed

- Avoid hnynethttp.WrapHandler panic with non-pointer handlers (#92)
- fix(echo): this change ensures honeycomb captures errors correctly (#249)
- Use PingContext in the wrapped PingContext method (#245)

## Release v1.1.3 (2021-07-13)

### Dependencies

- Bump go.opentelemetry.io/contrib/propagators from 0.20.0 to 0.21.0 (#237)
- Bump github.com/honeycombio/libhoney-go from 1.15.2 to 1.15.3 (#236)

### Maintenance

- Updates Github Action Workflows (#243)
- Updates Dependabot Config (#240)
- Switches CODEOWNERS to telemetry-team (#239)

## Release v1.1.2 (2021-06-03)

### Dependencies

- Bump github.com/gin-gonic/gin from 1.7.1 to 1.7.2 (#234)
- Bump github.com/felixge/httpsnoop from 1.0.1 to 1.0.2 (#233)
- Bump go.opentelemetry.io/contrib/propagators from 0.19.0 to 0.20.0 (#232)
- Bump go.opentelemetry.io/otel from 0.19.0 to 0.20.0 (#232)
- Bump go.opentelemetry.io/otel/trace from 0.19.0 to 0.20.0 (#232)

## Release v1.1.1 (2021-05-21)

### Fixed

- Add missing go.sum entry, which caused issues with go 1.16+ builds (#227) | [@vreynolds](https://github.com/vreynolds)

## Release v1.1.0 (2021-05-18)

### Added

- Add gRPC UnaryClientInterceptor which includes trace context in the outgoing request metadata (#217) | [@aarongable](https://github.com/aarongable)

### Fixed

- Capture request.host property on http client redirects (#216) | [@mccutchen](https://github.com/mccutchen)

### Dependencies

- Bump github.com/labstack/echo/v4 from 4.2.1 to 4.3.0 (#218)
- Bump github.com/gin-gonic/gin from 1.6.3 to 1.7.1 (#213)
- Bump github.com/jmoiron/sqlx from 1.3.1 to 1.3.4 (#221)

## Release v1.0.0 (2021-04-12)

### Minimum Go version required: 1.14

### Changed

- trace.NewTrace now takes *propagation.PropagationContext instead of serialized headers (#209)
  - You can still use trace.NewTraceFromSerializedHeaders to ease migration

### Removed

- propagation.Propagation: use propagation.PropagationContext (#209)
- propagation.MarshalTraceContext: use propagation.MarshalHoneycombTraceContext (#209)
- propagation.UnmarshalTraceContext: use propagation.UnmarshalHoneycombTraceContext (#209)
- propagation.UnmarshalTraceContextV1: use propagation.UnmarshalHoneycombTraceContext (#209)

### Deprecated

- trace.NewTraceFromPropagationContext: use trace.NewTrace instead (#209)

### Added

- Set additional response header values in hnygorilla wrapper (#196) | [@nathancoleman](https://github.com/nathancoleman)

### Dependencies

- Bump go.opentelemetry.io/otel from 0.15.0 to 0.19.0 (#179) (#208)
- Bump go.opentelemetry.io/contrib/propagators from 0.15.1 to 0.18.0 (#180) (#193) (#200)
- Bump github.com/go-sql-driver/mysql from 1.5.0 to 1.6.0 (#204)
- Bump google.golang.org/grpc from 1.27.0 to 1.36.1 (#178) (#203)
- Bump github.com/labstack/echo/v4 from 4.1.17 to 4.2.1 (#194)
- Bump github.com/jmoiron/sqlx from 1.2.0 to 1.3.1 (#188)
- Bump github.com/google/uuid from 1.1.4 to 1.2.0 (#186)
- Bump github.com/honeycombio/libhoney-go from 1.15.0 to 1.15.2 (#183)

## Release v0.11.1 (2021-01-22)

- Bump github.com/google/uuid from 1.1.2 to 1.1.4 (#171, #174)

### Fixed

- Ensure rollup fields are included on subroot spans (#173) | [@BRMatt](https://github.com/BRMatt)
- Default the w3c propagation header sampled flag to `01` (#176)

## Release v0.11.0 (2020-12-29)

- Add hnygrpc package including support for gRPC interceptor wrapping. (#169)

## Release v0.10.2 (2020-12-23)

- Bump otel dependencies from 0.13.0 to 0.15.1

## Release v0.10.1 (2020-12-15)

- Bump github.com/honeycombio/libhoney-go from 0.14.1 to 0.15.0
- Write keys / API keys will now be masked in debug / console logs.

## Release v0.10.0 (2020-11-20)

- Add GitHub release publish step (#159)
- Bump go.opentelemetry.io/contrib/propagators from 0.12.0 to 0.13.0 (#156)
- Bump github.com/gobuffalo/pop/v5 from 5.2.4 to 5.3.1 (#155)

## Release v0.9.0 (2020-11-06)

- Add DB.BindNamed to hnysql wrapper (#157) | @matiasanaya

## Release v0.8.0 (2020-10-07)

- Implemented B3 Propagator (#146) Thanks @Wilhansen!

## Release v0.7.1 (2020-09-24)

- Add .editorconfig to help provide consistent IDE styling (#143)

## Release v0.7.0 (2020-09-16)

- Update dependencies
- Add extra warnings when enabling STDOUT (#134)
- Add log when event is rejected with invalid api key (#135)

## Release v0.6.2 (2020-08-21)

- Upgrade dependencies
- Fixing some flaky tests
- Protection from potential data race condition in propagation context generating code.

## Release v0.6.1 (2020-07-31)

### Bugfixes

- Calling IsValid() on Honeycomb header unmarshal was preventing manual creation of trace from PropagationContext. Only verify that trace_id is provided whenever parent_id is.

## Release v0.6.0 (2020-07-31)

### Additions

- Generated Span and Trace IDs have changed from UUID4 strings to 16 and 32 character hex encoded strings. These are compatible with the W3C Trace Context specification.
- Auto-instrumentation support for Gingonic applications (thank you @Nalum!)
- Marshal / unmarshal functions for Amazon load balancer trace headers and W3C Trace Context headers (used by OpenTelemetry).
- The hnynethttp package now supports configurable hooks for parsing trace context headers from incoming HTTP requests and injecting trace context headers in outgoing HTTP requests

## Release v0.4.10 (2020-02-19)

### Additions

- Added content encoding field to `hnynethttp` responses.
- Added context methods to `hnypop.DB`. Now working with latest version of `pop`.

## Release v0.4.9 (2019-12-31)

### Additions

- Added getter methods for trace and span IDs and parent IDs.

## Release v0.4.8 (2019-12-20)

### Additions

- Added response content-type and content-length to the automatic instrumentation for HTTP spans.

## Release v0.4.7 (2019-11-07)

### Additions

- Add additional go database stats to `hnysql` and `hnysqlx` wrapppers. In go 1.11 and later, we additionally report `db.conns_in_use`, `db.conns_idle`, `db.wait_count`, and `db.wait_duration`. See https://golang.org/pkg/database/sql/#DB.Stats

## Release v0.4.6 (2019-10-31)

### Bugfixes

- added missing `Close` function to the `Stmt` type
- renamed `echo` example binary for using the echo web framework so it doesn't collide with the builtin shell `echo` command
- updated transaction's `QueryxContext` to use a span instead of an event

## Release v0.4.5 (2019-09-17)

### Bugfixes

- Fixed `db.error` not being added by `hnysql` and `hnysqlx` wrappers.
- Reduction in heap allocations when creating a span.

## Release v0.4.4 (2019-04-09)

### Bugfixes

- Fixed an issue where the libhoney transmission was being spun up without a default batch timeout, so spans were only getting sent when they hit the batch max (50) rather than after a 100ms timeout.
- Use libhoney defaults for all missing parameters during initialization (previously the beeline had a few values that differed from the libhoney defaults).

### Additions

- Added the Contributors file listing people that have made contributions to the Beeline

## Release v0.4.3 (2019-04-09)

### Bugfixes

- Fix race condition when concurrently adding children and sending a non-root
  span. Contribution by @carlosgaldino

## Release v0.4.2 (2019-04-08)

### Additions

- @jamietsao contributed middleware for the Echo router (https://echo.labstack.com/)

### Bugfixes

- Events that were coming in with an existing sample rate to a beeline
  configured to do additional sampling were not computing the final sample rate
  correctly. This change fixes the sample rate in that specific case.
- Added missing comment describing the semantics of the `dataset` field in the
  trace propagation header added in v0.3.5

## Release v0.4.1 (2019-03-21)

### Bugfixes

- Sample rate returned by the sampler hook was incorrectly being multiplied with the default global sample rate.

## Release v0.4.0 (2018-11-28)

### Additions

- Add a `libhoney.Client` as a configurable item in the beeline initial config.
  This allows full control over the underlying transmission of spans, so you can
  replace the HTTP transport or adjust queue sizes and so on

## Release v0.3.6 (2018-11-28)

### Additions

- Add `CopyContext` function to simplify moving trace metadata to a new context
  (for example, when trying to avoid a cancellation in an async span).
- Improve handling of broken or partial trace propagation headers

## Release v0.3.5 (2018-11-28)

### Additions

- Add `dataset` to serialized trace headers to allow one service with multiple
  upstream callers to send spans to the right destination dataset

## Release v0.3.4 (2018-11-28)

### Additions

- Delete spans from the trace when they're sent for improved memory management
- Add a benchmark

## Release v0.3.3 (2018-11-28)

### Additions

- Add URL queries and add name even when empty

## Release v0.3.2 (2018-11-28)

### Bugfixes

- Fix multiple races when sending spans. (https://github.com/honeycombio/beeline-go/pull/39 and https://github.com/honeycombio/beeline-go/pull/40)

## Release v0.3.1 (2018-10-25)

### Bugfixes

- Fix race condition on map access that can occur with Sampler and Presend hooks when AddField is called concurrently with Send.

## Release v0.3.0 (2018-10-23)

### Breaking Changes

- `NewResponseWriter` no longer returns a concrete type directly usable as an `http.ResponseWriter`. It now exposes the wrapped `http.ResponseWriter` through the field `Wrapped`.

Code that would have previously looked like:

```
wrappedWriter := common.NewResponseWriter(w)
handler.ServeHTTP(wrappedWriter, r)
```

now looks like:

```
wrappedWriter := common.NewResponseWriter(w)
handler.ServeHTTP(wrappedWriter.Wrapped, r)
```

## Release v0.2.4 (2018-10-05)

### Minor Changes

- Allow override of MaxConcurrentBatches, MaxBatchSize, and PendingWorkCapacity in `beeline.Config`
- Sets default value for MaxConcurrentBatches to 20 (from 80), and PendingWorkCapacity to 1000 (from 10000).

## Release v0.2.3 (2018-09-14)

### Bug Fixes

- rollup fields were not getting the rolled up values added to the root span

### New Field

- sql and sqlx wrappers get both the DB call being made (eg Select) as well as the name of the function making the call (eg FetchThingsByID)

## Release v0.2.2 (2018-09-1)

### Bug Fixes

- fix version number inconsistency with a patch bump

## Release v0.2.1 (2018-09-14)

### Bug Fixes

- fix propagation bug when an incoming request has a serialized beeline trace header

## Release v0.2.0 (2018-09-12)

This is the second major release of the beeline. It changes the model from "one
current span" to a to a doubly-linked tree of events (now dubbed "spans")
representing a trace.

### Major Changes

- introduces the concept of a span
- adds functions to create new spans in a trace and add fields to specific spans
- adds the ability to create and accept a serialized chunk of data from an upstream service to connect in-process traces in a distributed infrastructure into one large trace.
- adds trace level fields that get copied to every downstream span
- adds rollup fields that sum their values and push them in to the root span
- adds a pre-send hook to modify spans before sending them to Honeycomb
- adds trace-aware deterministic sampling as the default
- adds a sampler hook to manually manage sampling if necessary

### Breaking Changes

- removed `ContextEvent` and `ContextWithEvent` functions; replaced by spans

### Wrapper Changes

- augment the net/http wrapper to wrap `RoundTripper`s and handle outbound HTTP calls
- adding a wrapper for the `pop` package

## Release v0.1.2 (2018-08-30)

### New Features

- add new sqlx functions to add context to transactions and rollbacks
- add HTTP Headers X-Forwarded-For and X-Forwarded-Proto to events if they exist

### Bug Fixes

- use the passed in context in sqlx instead of creating a background context

## Release v0.1.1 (2018-08-20)

### Bug Fixes

- Use the right Host header for incoming HTTP requests
- Recognize struct HTTP handlers and add their name
- Fix nil route bug

## Release v0.1.0 (2018-05-16)

Initial Release

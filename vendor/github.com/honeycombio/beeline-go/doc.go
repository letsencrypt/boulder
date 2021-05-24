// Package beeline aids adding instrumentation to go apps using Honeycomb.
//
// Summary
//
// This package and its subpackages contain bits of code to use to make your
// life easier when instrumenting a Go app to send events to Honeycomb. Most
// applications will use something out of the `wrappers` package and the
// `beeline` package.
//
// The `beeline` package provides the entry point - initialization and the basic
// method to add fields to events.
//
// The `trace` package offers more direct control over the generated events and
// how they connect together to form traces. It can be used if you need more
// functionality (eg asynchronous spans, other field naming standards, trace
// propagation).
//
// The `propagation`, `sample`, and `timer` packages are used internally and not
// very interesting.
//
// The `wrappers` package contains middleware to use with other existing
// packages such as HTTP routers (eg goji, gorilla, or just plain net/http) and
// SQL packages (including sqlx and pop).
//
// Finally the `examples` package contains small example applications that use
// the various wrappers and the beeline.
//
// Regardless of which subpackages are used, there is a small amount of global
// configuration to add to your application's startup process. At the bare
// minimum, you must pass in your team write key and identify a dataset name to
// authorize your code to send events to Honeycomb and tell it where to send
// events.
//
//   func main() {
//     beeline.Init(beeline.Config{
//       WriteKey: "abcabc123123defdef456456",
//       Dataset: "myapp",
//     })
//     ...
//
// Once configured, use one of the subpackages to wrap HTTP handlers and SQL db
// objects.
//
// Examples
//
// There are runnable examples at
// https://github.com/honeycombio/beeline-go/tree/main/examples and examples
// of each wrapper in the godoc.
//
// The most complete example is in `nethttp`; it covers
// - beeline initialization
// - using the net/http wrapper
// - creating additional spans for larger chunks of work
// - wrapping an outbound http call
// - modifying spans on the way out to scrub information
// - a custom sampling method
//
// TODO create two comprehensive examples, one showing basic beeline use and the
// other the more exciting things you can do with direct access to the trace and
// span objects.
package beeline

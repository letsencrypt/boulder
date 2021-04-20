/*
Package hnynethttp provides Honeycomb wrappers for net/http Handlers.

Summary

hnynethttp provides wrappers for the `net/http` types: Handler and HandlerFunc

For best results, use WrapHandler to wrap the mux passed to http.ListenAndServe
- this will get you an event for every HTTP request handled by the server.

Wrapping individual Handlers or HandleFuncs will generate events only for the
endpoints that are wrapped; 404s, for example, will not generate events.

For a complete example showing this wrapper in use, please see the examples in
https://github.com/honeycombio/beeline-go/tree/main/examples

*/
package hnynethttp

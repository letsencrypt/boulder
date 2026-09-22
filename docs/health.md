# gRPC Health checking

We automatically implement the [gRPC health service] automatically for all our
gRPC servers.

There are two ways a service implementation can offer health information:

 - By implementing `Health(context.Context) error`, which will be called every
   5s. If it returns `nil`, the service is set to healthy. If it returns
   non-`nil`, the service is set to unhealthy. The health check interval can be
   controlled with `grpc.serverBuilder.WithCheckInterval` at build time.
 - By implementing `OnHealthy(func())`. This will be called by
   `grpc.serverBuilder.Build`, passing in a closure that sets the service status
   to healthy. This is useful for services that start unhealthy and then become
   healthy exactly once. At a protocol layer, setting the service healthy [pushes]
   out a message to clients immediately, so they don't need to wait on the next
   health check poll.

[gRPC health service]: https://pkg.go.dev/google.golang.org/grpc/health
[pushes]: https://github.com/grpc/grpc/blob/5b6492ea90b2b867a6adad1b10a6edda28e860d1/src/proto/grpc/health/v1/health.proto#L47-L62

package caaChecker

//go:generate sh -c "protoc --go_out=plugins=grpc:. caaChecker.proto && sed -i 's,golang.org/x/net/context\\|google.golang.org/grpc,github.com/letsencrypt/boulder/Godeps/_workspace/src/&', caaChecker.pb.go"

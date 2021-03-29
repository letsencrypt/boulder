package proto

//go:generate sh -c "cd ../.. && protoc -I core/proto/ -I . --go_out=core/proto --go-grpc_out=core/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative core/proto/core.proto"

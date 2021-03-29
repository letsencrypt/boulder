package proto

//go:generate sh -c "cd ../.. && protoc -I publisher/proto/ -I . --go_out=publisher/proto --go-grpc_out=publisher/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative publisher/proto/publisher.proto"

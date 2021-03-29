package proto

//go:generate sh -c "cd ../.. && protoc -I ca/proto/ -I . --go_out=ca/proto --go-grpc_out=ca/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative ca/proto/ca.proto"

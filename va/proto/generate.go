package proto

//go:generate sh -c "cd ../.. && protoc -I va/proto/ -I . --go_out=va/proto --go-grpc_out=va/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative va/proto/va.proto"

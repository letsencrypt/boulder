package proto

//go:generate sh -c "cd ../.. && protoc -I sa/proto/ -I . --go_out=sa/proto --go-grpc_out=sa/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative sa/proto/sa.proto"

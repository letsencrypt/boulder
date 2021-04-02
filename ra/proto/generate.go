package proto

//go:generate sh -c "cd ../.. && protoc -I ra/proto/ -I . --go_out=ra/proto --go-grpc_out=ra/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative ra/proto/ra.proto"

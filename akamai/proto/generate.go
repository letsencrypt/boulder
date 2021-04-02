package proto

//go:generate sh -c "cd ../.. && protoc -I akamai/proto/ -I . --go_out=akamai/proto --go-grpc_out=akamai/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative akamai/proto/akamai.proto"

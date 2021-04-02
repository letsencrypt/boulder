package proto

//go:generate sh -c "cd ../.. && protoc -I nonce/proto/ -I . --go_out=nonce/proto --go-grpc_out=nonce/proto --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative nonce/proto/nonce.proto"

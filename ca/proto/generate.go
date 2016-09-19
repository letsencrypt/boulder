package proto

//go:generate sh -c "cd ../.. && protoc --go_out=plugins=grpc,Mcore/proto/core.proto=github.com/letsencrypt/boulder/core/proto:. ca/proto/ca.proto"

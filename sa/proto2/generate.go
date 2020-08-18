package proto2

//go:generate sh -c "cd ../.. && protoc --go_opt=paths=source_relative --go_out=plugins=grpc,Mcore/proto/core.proto=github.com/letsencrypt/boulder/core/proto:. sa/proto2/sa.proto"

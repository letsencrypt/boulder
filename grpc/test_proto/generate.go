package test_proto

//go:generate sh -c "cd ../.. && protoc --go_opt=paths=source_relative --go_out=plugins=grpc,Mcore/proto/core.proto=github.com/letsencrypt/boulder/grpc/test_proto:. grpc/test_proto/interceptors_test.proto"

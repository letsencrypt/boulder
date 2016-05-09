package grpc

//go:generate sh -c cd .. && protoc --go_out=plugins=grpc:. core/proto/core.proto
//go:generate sh -c cd .. && protoc --proto_path=. --go_out=plugins=grpc,Mcore/proto/core.proto=github.com/letsencrypt/boulder/rpc/pb/core:. va/proto/va.proto
